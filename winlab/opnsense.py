"""OPNsense as a lab machine: the configuration winlab writes for it from
the lab file, and the volume that carries it to the appliance.

The appliance is OPNsense's own nano image (a preinstalled FreeBSD system
with the serial console first), fetched from the OPNsense mirror and never
modified on disk. What makes it this lab's firewall is `config.xml`, built
here from the lab: the interfaces assigned by adapter (vtnet0, vtnet1 ... in
the lab file's order; the adapter on a `wan` segment is WAN, the first other
one LAN, the rest OPT1, OPT2 ... named after their segment), static
addresses, the WAN gateway (the lab router's address on the WAN segment),
the lab's DNS servers, the root account with the lab's password (a SHA-512
crypt hash; the password itself is never written), SSH and the web GUI on,
NAT outbound automatic, and the stock "allow to any" rule on every inside
interface so the lab works before the lessons tighten it.

OPNsense's own importer copies `conf/config.xml` from a plain FAT volume
(winlab/consoleagent.py drives that step over the console on the first boot
and whenever the generated configuration changes), so the volume is laid
out exactly as the importer and a student with a USB stick expect.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

from . import fatfs
from .model import Lab, Node
from .netplan import TopologyPlan

IMAGE = "opnsense"
CONFIG_LABEL = "WLOPN"
CONFIG_MB = 16
CONSOLE_USER = "root"


@dataclass
class Iface:
    name: str        # lan, wan, opt1 ...
    descr: str       # what the GUI shows
    dev: str         # vtnet0 ...
    network: str     # the lab segment
    ip: str
    prefix: int
    gateway: str = ""   # WAN only: the lab router on the WAN segment
    wan: bool = False
    rules: list[str] = field(default_factory=list)


def is_firewall(node: Node) -> bool:
    return node.image == IMAGE


def interfaces_of(node: Node, lab: Lab, plan: TopologyPlan) -> list[Iface]:
    """The appliance's interfaces in OPNsense's terms, from the node's
    adapters: WAN is the adapter on a wan segment, LAN the first other one,
    the rest OPT1, OPT2 ... (described by their segment's name)."""
    out: list[Iface] = []
    opt = 0
    lan_taken = False
    wan_taken = False
    for link in plan.links_for(node.id):
        nic = node.nics[link.nic_index]
        net = lab.networks[link.network_id]
        seg = plan.segment_of(link.network_id)
        dev = f"vtnet{link.nic_index}"
        if net.wan and not wan_taken:
            name, descr, wan_taken = "wan", "WAN", True
        elif not net.wan and not lan_taken:
            name, descr, lan_taken = "lan", "LAN", True
        else:
            opt += 1
            name, descr = f"opt{opt}", net.id.upper().replace("-", "_")[:20]
        out.append(Iface(name=name, descr=descr, dev=dev, network=net.id, ip=nic.ip or "",
                         prefix=seg.network.prefixlen,
                         # A WAN segment the lab router is not cabled to (one flat
                         # public subnet, as in the edge-firewall lab) has no
                         # upstream router: everything on it is on-link.
                         gateway=seg.network.router_ip if net.wan and net.routed else "",
                         wan=bool(net.wan)))
    return out


def _rule(seq: int, iface: str, descr: str, action: str = "pass", source: str = "",
          dest: str = "any", proto: str = "any", port: str = "", log: bool = False) -> str:
    source = source or iface
    return f"""          <rule>
            <enabled>1</enabled>
            <statetype>keep</statetype>
            <state-policy/>
            <sequence>{seq}</sequence>
            <action>{action}</action>
            <quick>1</quick>
            <interfacenot>0</interfacenot>
            <interface>{iface}</interface>
            <direction>in</direction>
            <ipprotocol>inet</ipprotocol>
            <protocol>{proto}</protocol>
            <source_net>{source}</source_net>
            <source_not>0</source_not>
            <source_port/>
            <destination_net>{dest}</destination_net>
            <destination_not>0</destination_not>
            <destination_port>{port}</destination_port>
            <disablereplyto>0</disablereplyto>
            <log>{1 if log else 0}</log>
            <allowopts>0</allowopts>
            <nosync>0</nosync>
            <nopfsync>0</nopfsync>
            <statetimeout/>
            <tcpflags_any>0</tcpflags_any>
            <description>{escape(descr)}</description>
          </rule>
"""


def render_config(node: Node, lab: Lab, plan: TopologyPlan) -> str:
    """The appliance's config.xml for this lab, following the layout of
    OPNsense's own default configuration (src/etc/config.xml.sample)."""
    from . import shacrypt
    from .provision import _dns_servers
    from .naming import hostname_of

    ifaces = interfaces_of(node, lab, plan)
    hostname = hostname_of(node).lower()
    dns = [d for d in _dns_servers(lab, node) if d] if lab.nodes else []
    salt = hashlib.sha256(f"{lab.name}/{node.id}".encode()).hexdigest()[:16]
    pw_hash = shacrypt.sha512_crypt(lab.admin_password, salt)

    out = ['<?xml version="1.0"?>', "<opnsense>", "  <theme>opnsense</theme>", "  <system>",
           "    <optimization>normal</optimization>",
           f"    <hostname>{escape(hostname)}</hostname>",
           f"    <domain>{escape(lab.domain)}</domain>",
           "    <dnsallowoverride>0</dnsallowoverride>",
           "    <dnsallowoverride_exclude/>"]
    for d in dns:
        out.append(f"    <dnsserver>{d}</dnsserver>")
    out += ["    <group>", "      <name>admins</name>",
            "      <description>System Administrators</description>",
            "      <scope>system</scope>", "      <gid>1999</gid>", "      <member>0</member>",
            "      <priv>page-all</priv>", "    </group>",
            "    <user>", f"      <name>{CONSOLE_USER}</name>",
            "      <descr>System Administrator</descr>", "      <scope>system</scope>",
            "      <groupname>admins</groupname>",
            f"      <password>{escape(pw_hash)}</password>", "      <uid>0</uid>", "    </user>",
            f"    <timezone>{escape(lab.timezone or 'Etc/UTC')}</timezone>",
            "    <timeservers/>",
            "    <webgui>", "      <protocol>https</protocol>", "      <noroot>0</noroot>",
            "    </webgui>",
            "    <disablenatreflection>yes</disablenatreflection>",
            "    <usevirtualterminal>1</usevirtualterminal>",
            "    <primaryconsole>serial</primaryconsole>",
            "    <serialspeed>115200</serialspeed>",
            "    <ipv6allow>0</ipv6allow>",
            "    <powerd_ac_mode>hadp</powerd_ac_mode>",
            "    <powerd_battery_mode>hadp</powerd_battery_mode>",
            "    <powerd_normal_mode>hadp</powerd_normal_mode>",
            "    <bogons>", "      <interval>never</interval>", "    </bogons>",
            "    <pf_share_forward>1</pf_share_forward>",
            "    <lb_use_sticky>1</lb_use_sticky>",
            "    <ssh>", "      <enabled>enabled</enabled>",
            "      <permitrootlogin>1</permitrootlogin>", "      <group>admins</group>",
            "    </ssh>",
            "  </system>", "  <interfaces>"]
    for i in ifaces:
        out += [f"    <{i.name}>", "      <enable>1</enable>", f"      <if>{i.dev}</if>",
                f"      <descr>{escape(i.descr)}</descr>", "      <spoofmac/>"]
        if i.ip:
            out += [f"      <ipaddr>{i.ip}</ipaddr>", f"      <subnet>{i.prefix}</subnet>"]
        else:
            out.append("      <ipaddr>dhcp</ipaddr>")
        if i.wan:
            # The lab's "Internet" is TEST-NET and RFC 1918 space: the stock
            # bogon and private filters would drop every neighbour.
            out += ["      <blockpriv>0</blockpriv>", "      <blockbogons>0</blockbogons>"]
            if i.gateway:
                out.append("      <gateway>WAN_GW</gateway>")
        out.append(f"    </{i.name}>")
    out.append("  </interfaces>")
    wan = next((i for i in ifaces if i.wan and i.gateway), None)
    out.append("  <gateways>")
    if wan:
        out += ["    <gateway_item>", "      <interface>wan</interface>",
                f"      <gateway>{wan.gateway}</gateway>", "      <name>WAN_GW</name>",
                "      <priority>255</priority>", "      <weight>1</weight>",
                "      <ipprotocol>inet</ipprotocol>", "      <interval/>",
                "      <descr>the lab router on the WAN segment</descr>",
                "      <defaultgw>1</defaultgw>", "    </gateway_item>"]
    out.append("  </gateways>")
    out += ["  <dnsmasq/>", "  <unbound>", "    <enable>0</enable>", "  </unbound>",
            "  <nat>", "    <outbound>", "      <mode>automatic</mode>", "    </outbound>",
            "  </nat>", "  <filter>", "  </filter>", "  <rrd>", "    <enable/>", "  </rrd>",
            "  <ntpd>", "    <prefer/>", "    <ispool/>", "  </ntpd>",
            "  <OPNsense>", "    <Firewall>", "      <Filter>", "        <rules>"]
    seq = 1
    for i in ifaces:
        if i.wan:
            continue
        label = "LAN" if i.name == "lan" else i.descr
        out.append(_rule(seq, i.name, f"Default allow {label} to any rule"
                         + ("" if i.name == "lan" else " (the interface-rules lesson replaces it)")))
        seq += 10
    out += ["        </rules>", "        <snatrules/>", "        <npt/>", "        <onetoone/>",
            "      </Filter>", "    </Firewall>", "  </OPNsense>", "</opnsense>", ""]
    return "\n".join(out)


def fingerprint(xml: str) -> str:
    """What the console driver compares to decide whether the appliance
    already runs this configuration."""
    return hashlib.sha256(xml.encode("utf-8")).hexdigest()[:16]


def config_disk(node: Node, lab: Lab, plan: TopologyPlan, dest: Path) -> Path:
    """The configuration volume: `conf/config.xml` as OPNsense's importer
    (and a student with a USB stick) expects it, the fingerprint beside it."""
    xml = render_config(node, lab, plan)
    img = fatfs.disk(CONFIG_MB, CONFIG_LABEL)
    img.add_file("conf/config.xml", xml)
    img.add_file("winlab.sha", fingerprint(xml) + "\n")
    img.add_file("README.txt", (
        f"winlab configuration volume for {node.id} (OPNsense).\r\n"
        "conf/config.xml is generated from the lab file at every start; winlab applies it over\r\n"
        "the console when it changes. To import it by hand: opnsense-importer and pick this disk.\r\n"))
    dest.parent.mkdir(parents=True, exist_ok=True)
    return img.write(dest)


def describe(node: Node, lab: Lab, plan: TopologyPlan) -> list[str]:
    out = [f"{node.id}: OPNsense firewall, root with the lab password, GUI https on every inside address"]
    for i in interfaces_of(node, lab, plan):
        extra = f" via {i.gateway}" if i.gateway else ""
        out.append(f"  {i.name:<5} {i.descr:<12} {i.dev:<7} {i.ip}/{i.prefix}{extra}  ({i.network})")
    return out
