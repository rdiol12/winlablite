"""Network automation against the lab's router and switches (CCNA 6.x):
Python with Netmiko and NAPALM, Ansible's cisco.ios collection, and JSON.

The tools a network engineer automates IOS with all drive the same thing a
person does: an SSH session to the command line (winlab/iosssh.py), where
they type ``terminal length 0``, ``show ...`` and ``configure terminal``
and read what comes back with regular expressions and TextFSM templates.
So what makes them work here is the console being IOS enough for them, and
this module is the part of the console they need beyond what a person types:

* ``terminal width <0-512>`` (Netmiko sends 511, Ansible 512 then 0),
  ``show privilege`` (Ansible's become asks it), ``show hosts`` (NAPALM's
  get_facts reads the domain from it);
* on a switch, ``show interfaces`` as IOS prints it (one block per port,
  which NAPALM's get_interfaces and Ansible's ios_facts parse; the table
  is ``show interfaces status``), ``show ip interface`` and ``show arp``
  (the switch's management namespace's own ARP table, read on the router);
* ``show version`` carries the hardware line, the processor board ID and the
  image name the drivers read the model, serial and image from.
* ``show inventory`` (the chassis, its PID and serial) on every device and
  ``show vtp status`` on a switch: with ``show version`` and ``show
  running-config``, what Oxidized's ``ios`` model runs for a backup
  (winlab/netops.py); a command it sends that a device does not have (``show
  vtp status`` on the router) gets IOS's Invalid input, which the model drops.

Tested how: Netmiko 4.3.0 (Ubuntu 24.04's python3-netmiko) and 4.8, NAPALM
5.0.0 with the Ubuntu versions of its dependencies, ansible-core 2.16.3 with
Ubuntu's ansible 9.2 collections (cisco.ios 5.3.0, ansible.netcommon 5.3.0)
and ansible-core 2.21 with cisco.ios 11, all against these consoles behind a
local paramiko SSH server that carries the sessions through iosssh.Bridge
exactly as the router's ttyS2 does. tests/test_winlab.py replays the exact
command sequences they send. Oxidized was not run against them: the tests replay
the sequence its ios model (lib/oxidized/model/ios.rb, read Nov 2026) sends
and apply its prompt regex and its cut_both / cut_head(3) trimming.

What works: Netmiko send_command / send_config_set / save_config / enable;
NAPALM get_facts, get_interfaces, get_interfaces_ip, get_arp_table,
get_interfaces_counters, get_mac_address_table (switches), get_vlans,
get_users, get_config, cli, is_alive; Ansible network_cli with ios_command,
ios_config (lines/parents, check mode, idempotence, save_when) and ios_facts
(min, interfaces, config). What does not: NAPALM's load_merge_candidate /
load_replace_candidate / commit_config, which copy a file to flash: over SCP
(``ip scp server enable``): the SSH session is the console and nothing else,
so there is no SCP, and NAPALM says so when it tries. get_lldp_neighbors
and get_lldp_neighbors_detail read ``show lldp neighbors detail`` from
winlab/lldp.py (lldpd's real table, once ``lldp run`` is on): its layout
was checked offline against NAPALM 5.0.0's own parser, not on a booted lab.
RESTCONF is winlab/restconf.py.

The control node's tools come on the 'netauto' pack (winlab/debpacks.py):
Ubuntu's ansible (which carries cisco.ios and ansible.netcommon),
python3-netmiko and python3-paramiko (network_cli's SSH: Ubuntu has no
ansible-pylibssh), jq, and the Python modules NAPALM needs from the Ubuntu
archive. NAPALM itself, junos-eznc (NAPALM imports every driver it has),
netutils, ttp and ttp-templates are not in Ubuntu: they are PyPI wheels,
pinned here by version and SHA-256 and fetched beside the .debs
(fetch_extra), installed with pip into a venv that sees the system's
packages. Nothing is fetched inside the lab.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from pathlib import Path

from . import devcli

# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    add("terminal width <num>", lambda a: _width(a[0]), "Set width of the display terminal", U)
    add("show privilege", lambda a: show_privilege(con), "Show current privilege level", U)
    add("show hosts", lambda a: show_hosts(con), "IP domain-name, lookup style, nameservers, and host table", U)
    add("show inventory", lambda a: show_inventory(con), "Show the physical inventory", U)
    if con.device != devcli.ROUTER:
        add("show vtp status", lambda a: show_vtp_status(con), "VTP domain status", U)
        add("show ip interface", lambda a: sw_ip_interface(con), "IP interface status and configuration", U)
        add("show arp", lambda a: sw_arp(con), "ARP table", U)
        add("show ip arp", lambda a: sw_arp(con), "IP ARP table", U)
        add("show vlan id <num>", lambda a: sw_vlan_id(con, int(a[0])), "VTP VLAN status by VLAN id", U)
    else:
        from . import restconf  # ip http secure-server, restconf: the router's RESTCONF API
        restconf.add_specs(con, add, U, C, I)


def _width(text: str) -> str:
    if not 0 <= int(text) <= 512:
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    return ""


def show_privilege(con) -> str:
    return f"Current privilege level is {1 if con.s.mode == 'user' else 15}"


def show_hosts(con) -> str:
    dom = con.lab.devices.get(con.device, {}).get("domain", "")
    return "\n".join([f"Default domain is {dom or 'not set'}", "Name/address lookup uses domain service",
                      "Name servers are 255.255.255.255", "",
                      "Codes: UN - unknown, EX - expired, OK - OK, ?? - revalidate",
                      "       temp - temporary, perm - permanent", "       NA - Not Applicable None - Not defined",
                      "", f"{'Host':<26}{'Port':<6}{'Flags':<11}{'Age':<4}{'Type':<7}Address(es)"])


def show_inventory(con) -> str:
    """show inventory: the chassis with its PID and serial (Oxidized's ios
    model keeps it as a comment at the top of the backup; NAPALM's
    get_facts reads the serial from show version)."""
    lab, dev = con.lab, con.device
    if dev == devcli.ROUTER:
        name, descr = "Chassis", f"Cisco {devcli.PLATFORM[dev]} Chassis"
    else:
        name, descr = "1", devcli.MODEL["switch"]
    pid = devcli.MODEL[devcli.ROUTER if dev == devcli.ROUTER else "switch"]
    return f'NAME: "{name}", DESCR: "{descr}"\nPID: {pid:<18}, VID: V01  , SN: {serial(lab, dev)}\n'


def show_vtp_status(con) -> str:
    """show vtp status on a switch. winlab's switches keep each its own VLAN
    list (nothing is learnt from a neighbour over VTP), which is what a
    switch in VTP transparent mode does, so that is the mode shown."""
    sid = devcli.switch_id(con.device)
    up = [(n, a) for n, a, on in con.svis() if a and on]
    upd = (f"Local updater ID is {up[0][1].split('/')[0]} on interface {up[0][0].replace('Vlan', 'Vl')} "
           "(lowest numbered VLAN interface found)") if up else "Local updater ID is 0.0.0.0 (no valid interface found)"
    return "\n".join([
        "VTP Version capable             : 1 to 3", "VTP version running             : 1",
        "VTP Domain Name                 : ", "VTP Pruning Mode                : Disabled",
        "VTP Traps Generation            : Disabled", f"Device ID                       : {con._sw_mac()}",
        "Configuration last modified by 0.0.0.0 at 0-0-00 00:00:00", upd, "",
        "Feature VLAN:", "--------------",
        "VTP Operating Mode                : Transparent",
        "Maximum VLANs supported locally   : 255",
        f"Number of existing VLANs          : {len(devcli.vlans_of(con.lab, sid))}",
        "Configuration Revision            : 0"])


def serial(lab, device: str) -> str:
    """The device's processor board ID: eleven characters, fixed for the lab."""
    h = hashlib.sha256(f"winlab-serial/{lab.name}/{device}".encode()).hexdigest().upper()
    return ("FDO" if device == devcli.ROUTER else "FOC") + h[:8]


def sw_interfaces(con) -> str:
    """show interfaces on a switch: the VLAN interfaces, then every port."""
    out = [con._show_iface_one([f"vlan {v[4:]}"]) for v, _, _ in con.svis()]
    out += [con._switch_block(n) for n in con._if_names()]
    return "\n".join(out)


def sw_ip_interface(con) -> str:
    out = []
    for vname, addr, up in con.svis():
        st = "up" if up and con.powered() else ("administratively down" if not up else "down")
        out.append(f"{vname} is {st}, line protocol is {'up' if st == 'up' else 'down'}")
        if not addr:
            out.append("  Internet protocol processing disabled")
            continue
        out += [f"  Internet address is {addr}", "  Broadcast address is 255.255.255.255", "  MTU is 1500 bytes",
                "  Helper address is not set", "  Outgoing access list is not set",
                "  Inbound  access list is not set", "  Proxy ARP is enabled"]
    rows = {r.split()[0]: r for r in con._show_status([]).splitlines()[1:] if r.split()}
    for name in con._if_names():
        row = rows.get(devcli.short_if(name), "")
        up = " connected " in row
        st = "up" if up else "administratively down" if " disabled " in row else "down"
        out += [f"{name} is {st}, line protocol is {'up' if up else 'down'}",
                "  Inbound  access list is not set"]
    return "\n".join(out)


def sw_vlan_id(con, tag: int) -> str:
    """show vlan id <n>: the show vlan rows of that VLAN (NAPALM's get_vlans
    asks it VLAN by VLAN)."""
    lines = con._show_vlan([]).splitlines()
    rows, inside = [], False
    for line in lines[2:]:
        if re.match(r"^\d+\s", line):
            inside = line.split()[0] == str(tag)
        elif line and not line.startswith(" "):
            inside = False
        if inside:
            rows.append(line)
    if not rows:
        return f"VLAN id {tag} not found in current VLAN database"
    return "\n".join(lines[:2] + rows)


def sw_arp(con) -> str:
    """The switch's ARP table: its own VLAN addresses and what its management
    namespace on the router has learnt (ip neigh there)."""
    from . import iosl2
    sid = devcli.switch_id(con.device)
    head = f"{'Protocol':<10}{'Address':<17}{'Age (min)':<11}{'Hardware Addr':<16}{'Type':<6}Interface"
    nets = []
    rows = []
    for vname, addr, up in con.svis():
        if addr and up:
            iface = ipaddress.ip_interface(addr)
            nets.append((iface.network, vname))
            rows.append(f"{'Internet':<10}{str(iface.ip):<17}{'-':<11}{con._sw_mac():<16}{'ARPA':<6}{vname}")
    ns = iosl2.netns(con.lab, sid)
    text = ""
    if ns and con.powered():
        try:
            text = con._on_router(f"ip -n {ns} neigh show 2>/dev/null", timeout=10)
        except devcli.CliError:
            text = ""
    for line in text.splitlines():
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+) .*lladdr ([0-9a-f:]{17})", line)
        if not m or "FAILED" in line or "INCOMPLETE" in line:
            continue
        ip = ipaddress.ip_address(m.group(1))
        vname = next((v for n, v in nets if ip in n), "")
        rows.append(f"{'Internet':<10}{str(ip):<17}{'0':<11}{devcli.dotted_mac(m.group(2)):<16}{'ARPA':<6}{vname}")
    return "\n".join([head] + rows)


# ------------------------------------------------------------------ the pack's wheels
class ExtraError(Exception):
    pass


# (file, url, sha256, size, licence): what is not in Ubuntu 24.04, from PyPI.
# Pinned to one set that works with Ubuntu's python3-netmiko 4.3.0 and the
# Ubuntu versions of everything else NAPALM imports (tested together).
WHEELS = [
    ("napalm-5.0.0-py2.py3-none-any.whl",
     "https://files.pythonhosted.org/packages/85/ca/7e7d4f2b53240a82a8a48b41decc490ca854e6c6c56cfed607ed4d32a840/"
     "napalm-5.0.0-py2.py3-none-any.whl",
     "458837932e527ca06a4bab7e600b0ca6e6bc3bb4b33fad9c9ef2befc7df6d2f5", 263761, "Apache-2.0"),
    ("junos_eznc-2.7.1-py3-none-any.whl",
     "https://files.pythonhosted.org/packages/f3/ec/69bb3fe55c1666acd02ef7e1cc403506d3003973096491300b837229d311/"
     "junos_eznc-2.7.1-py3-none-any.whl",
     "8a7918faa8f0570341cac64c1210c1cd3e3542162d1e7449c3364f8d805716b2", 198054, "Apache-2.0"),
    ("netutils-1.10.0-py3-none-any.whl",
     "https://files.pythonhosted.org/packages/2a/de/963bd0666982cf5200f1a9fd5a6c7980db68c584053e67b721b544bea740/"
     "netutils-1.10.0-py3-none-any.whl",
     "19b8cc3d2cf567a986f916c90f298d241af03a71c62ec6d38d6dc3395347670b", 514091, "Apache-2.0"),
    ("ttp-0.9.5-py2.py3-none-any.whl",
     "https://files.pythonhosted.org/packages/03/38/d475e7bde8d192ca5d64ccc0988f3d58f36211bd68c32b6c5883332a8abf/"
     "ttp-0.9.5-py2.py3-none-any.whl",
     "2c9fcf560b3f696e9fdd3554dc8e4622cbb10cac1d4fca13a7cf608c4a7fd137", 85763, "MIT"),
    ("ttp_templates-0.3.7-py3-none-any.whl",
     "https://files.pythonhosted.org/packages/cb/8e/53b0d67a394ff742dbfda62543a1c48c0f32ea630acce6ccadeb09194344/"
     "ttp_templates-0.3.7-py3-none-any.whl",
     "2328304fb4c957ee60db6f301143e8a4556b22a12b3e2f30511e8ef97fc78f7e", 76514, "MIT"),
]
VENV = "/home/ubuntu/venv"


def fetch_extra(pack, d: Path, closure, get, download, say) -> dict:
    """After the pack's .debs (debpacks.fetch): the pinned PyPI wheels, each
    checked against its SHA-256 as it arrives."""
    from .bootstrap import BootstrapError
    for i, (name, url, sha, _size, _lic) in enumerate(WHEELS, 1):
        say(f"wheel {i}/{len(WHEELS)} {name}")
        try:
            download(url, d / name, expect_sha=sha, label=name)
        except BootstrapError as exc:
            raise ExtraError(str(exc)) from exc
    (d / "INSTALL.txt").write_text(install_text(), encoding="utf-8", newline="\r\n")
    return {"files": [w[0] for w in WHEELS] + ["INSTALL.txt"],
            "wheels": [{"file": w[0], "sha256": w[2], "license": w[4]} for w in WHEELS],
            "fetched": time.strftime("%Y-%m-%d")}


def extra_ready(d: Path, man: dict) -> bool:
    files = (man.get("extra") or {}).get("files") or []
    return bool(files) and all((d / f).is_file() and (d / f).stat().st_size > 0 for f in files)


def install_text() -> str:
    """The note beside the wheels on the stick: where they go, never the
    lessons' work itself."""
    return "\n".join([
        "winlab pack 'netauto': network automation on the control node",
        "",
        "First the packages from this stick (README.txt): ansible, python3-netmiko, python3-paramiko,",
        "python3-venv, jq and the Python modules NAPALM uses.",
        "",
        "NAPALM is not in Ubuntu: its wheels are here, from PyPI, each checked against its SHA-256:",
        *[f"  {w[0]}  ({w[4]})" for w in WHEELS],
        "",
        "Install them in a virtual environment that also sees the system's packages:",
        f"  python3 -m venv --system-site-packages {VENV}",
        f"  {VENV}/bin/pip install --no-index --no-deps /mnt/winlab-pack/*.whl",
        f"  {VENV}/bin/python -c 'import napalm, netmiko; print(napalm.__name__, netmiko.__version__)'",
        "",
    ])


# ------------------------------------------------------------------ grading and the drill
PROJECT = "/home/ubuntu/netauto"   # where the lessons build the project on the netauto box
SWITCH = "office"                  # the router-protocols lab's switch the lessons automate
VLANS = {30: "staff", 40: "printers"}


def _ssh_ready(lab, device: str) -> str:
    """'' when the device takes SSH logins as the automation tools need them."""
    from . import iosssh
    own = lab.devices.get(device, {})
    if not iosssh.serving(lab, device):
        return "no SSH server: hostname, ip domain-name, crypto key generate rsa modulus 2048"
    if own.get("line-vty:login") != "local":
        return "line vty 0 4 has no login local"
    if own.get("line-vty:transport", "").lower().split() != ["ssh"]:
        return "line vty 0 4 should take SSH alone (transport input ssh)"
    if not any(own.get(k, "").startswith("15 ") and iosssh.login_hash(lab, device, k[5:])
               for k in own if k.startswith("user:")):
        return "no privilege 15 user who can log in over SSH (username ... privilege 15 secret ...)"
    return ""


def check_ssh_ready(lab) -> tuple[bool, str]:
    for dev in (devcli.ROUTER, f"sw:{SWITCH}"):
        why = _ssh_ready(lab, dev)
        if why:
            return False, f"{devcli.hostname(lab, dev)}: {why}"
    return True, "the router and the office switch take SSH logins with login local"


def check_vlans(lab) -> tuple[bool, str]:
    for tag, name in VLANS.items():
        net = devcli.vlan_net(lab, SWITCH, tag)
        if net is None:
            return False, f"the office switch has no VLAN {tag}"
        if (net.description or "").lower() != name:
            return False, f"VLAN {tag} is named {net.description or '(no name)'!r}, not {name}"
    return True, "VLANs 30 staff and 40 printers are on the office switch"


def check_restconf(lab) -> tuple[bool, str]:
    from . import restconf
    own = lab.devices.get(devcli.ROUTER, {})
    if not restconf.serving(lab):
        return False, "RESTCONF is off: ip http secure-server and restconf"
    if own.get("http-auth") != "local":
        return False, "ip http authentication local is not set"
    for name in devcli.router_port_names(lab):
        net = devcli.iface_net(lab, name)
        if net is not None and net.id == "office":
            desc = own.get(f"desc:{name}", "")
            if "restconf" in desc.lower():
                return True, f"{name}: description {desc!r}"
            return False, f"{name} (the office interface) has description {desc!r}"
    return False, "the router has no interface in the office network"


def _register() -> None:
    from . import exercises
    exercises.register_winlab_check("netauto-ssh-ready", check_ssh_ready)
    exercises.register_winlab_check("netauto-vlans", check_vlans)
    exercises.register_winlab_check("netauto-restconf", check_restconf)


FAULT_IDS = ("ansible-ios-connection",)
_SAVED = "/root/.winlab-netauto"


def _faults():
    from .guestfaults import LINUX, GuestFault
    files = (f"{PROJECT}/inventory.ini {PROJECT}/group_vars/*.yml {PROJECT}/group_vars/*/*.yml "
             f"{PROJECT}/host_vars/*.yml")
    nc = "ansible_connection *[:=] *\"?(ansible\\.netcommon\\.)?network_cli"
    return [GuestFault(
        id="ansible-ios-connection",
        images=("ubuntu",),
        title="Every network task fails before it reaches the switch",
        os=LINUX,
        teaches="how Ansible reaches network devices (ansible_connection network_cli, ansible_network_os "
                "cisco.ios.ios), where a variable comes from (ansible-inventory --host), and reading the "
                "first line of an error",
        symptom="on netauto, ansible-playbook vlans.yml fails on every host at the first task with 'Connection "
                "type ssh is not valid for this module'; ssh to the switch from the same box still works",
        apply=(f"hit=''; for f in {files}; do [ -f \"$f\" ] && grep -qE '{nc}' \"$f\" && hit=\"$hit $f\"; done; "
               "[ -n \"$hit\" ] || { echo 'no network_cli in the project yet: build it first (lesson "
               f"netauto-ansible-ios)'; exit 1; }}; mkdir -p {_SAVED}; for f in $hit; do "
               f"cp -p \"$f\" {_SAVED}/$(echo \"$f\" | tr / _); "
               "sed -i -E 's/(ansible_connection *[:=] *\"?)(ansible\\.netcommon\\.)?network_cli/\\1ssh/' \"$f\"; "
               f"done; echo \"$hit\" > {_SAVED}/files; echo broken"),
        clear=(f"[ -f {_SAVED}/files ] && for f in $(cat {_SAVED}/files); do "
               f"b={_SAVED}/$(echo \"$f\" | tr / _); [ -f \"$b\" ] && cp -p \"$b\" \"$f\"; done; "
               f"rm -rf {_SAVED}; echo ok"),
        shell="sh",
        hints=(
            "Read the error's first line, not the traceback: Connection type ssh is not valid for this module. "
            "cisco.ios modules do not run Python on the switch (it has none); they need a connection plugin "
            "that drives the device's command line.",
            "Ask the inventory what a switch's variables are now: ansible-inventory --host <switch>, in the "
            "project folder. ansible_connection says ssh. grep -rn ansible_connection . finds the file.",
            "Put ansible.netcommon.network_cli back (with ansible_network_os cisco.ios.ios beside it). Then "
            "ansible-playbook vlans.yml -k --check --diff reaches the switch again and reports changed=0.",
        ),
        verify=(f"runuser -l ubuntu -c 'cd {PROJECT} && ansible-inventory --list 2>/dev/null' | python3 -c "
                "'import json, sys\ntry:\n    d = json.load(sys.stdin)\nexcept ValueError:\n    print(False); "
                "sys.exit()\nhv = d.get(\"_meta\", {}).get(\"hostvars\", {})\n"
                "net = [h for h, v in hv.items() if \"ansible_network_os\" in v]\n"
                "print(bool(net) and all(hv[h].get(\"ansible_connection\", \"\").split(\".\")[-1] == "
                "\"network_cli\" for h in net))'"),
    )]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)


_register()
