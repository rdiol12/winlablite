"""OpenWrt as a lab device: the access points and the UPS's network card.

A real office access point and a UPS's network management card are small
Linux boxes with their own web pages. In winlab both are OpenWrt, the
project's own x86-64 image (a pinned release, fetched from
downloads.openwrt.org at preparation and checked against the release's
sha256sums), one small VM per device, cabled into a switch port like the
real thing. The student manages it in LuCI, OpenWrt's web interface, from a
browser on a lab PC: the Wi-Fi's name, security, key, channel and RADIUS
server on an AP (Network > Wireless, written to /etc/config/wireless), the
UPS monitor's thresholds and notifications on the card (Services >
Network UPS Tools, with NUT's own status pages under /cgi-bin/nut/).

What the image lacks, the release's own package feeds have: the radio
(QEMU has no Wi-Fi card, so OpenWrt's software radio, mac80211_hwsim, gives
LuCI a real radio to configure), hostapd (wpad-mbedtls), and NUT. Those
packages are fetched with the image, each checked against the feed's
Packages index, and carried to the VM on a small volume (a plain tar
written to a raw disk: the image has no filesystem driver for anything
else). Nothing third-party is in winlab itself.

winlab gives each one only what the lab's wiring decides: its address on
its VLAN (a static LAN address, the router as gateway, the lab's DNS), its
host name, and its own DHCP server off (it would hand out addresses on the
office VLAN). Everything else is OpenWrt's factory state: the radio
disabled, SSID "OpenWrt", no encryption, root with no password until the
student sets one (LuCI asks), NUT with no users and no monitor.

winlab reads the device over its serial console (winlab/consoleagent.py,
which logs in the way it does on OPNsense): an AP's /etc/config/wireless
drives the simulated air (winlab/wifi.py: who hears the AP, joins, keys,
WPA2-Enterprise), and winlab writes the UPS's battery state into the
card's NUT driver (dummy-ups) as the battery model changes.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import re
import tarfile
import time
import zlib
from dataclasses import dataclass
from pathlib import Path

IMAGE = "openwrt"
RELEASE = "24.10.4"
SITE = f"https://downloads.openwrt.org/releases/{RELEASE}/"
TARGET = SITE + "targets/x86/64/"
IMAGE_FILE = f"openwrt-{RELEASE}-x86-64-generic-ext4-combined.img.gz"
MANIFEST_FILE = f"openwrt-{RELEASE}-x86-64.manifest"
SUMS = "sha256sums"
FEEDS = ("base", "luci", "packages")
FEED_URL = SITE + "packages/x86_64/{feed}/"
KMODS_URL = TARGET + "kmods/"
LICENSE = "GPL-2.0 (OpenWrt; its packages under their own free licences, NUT GPL-2.0+)"
VOLUME_MB = 24
MARK = "devvm"               # node var: the VM behind a device on the canvas ("ap", "ups")
SHA_FILE = "/etc/winlab.sha"
CONSOLE_USER = "root"
RADIUS_RELAY = "winlab_radius"  # the nft table that carries the router's EAP relay out of the AP

# What each kind of device needs beyond the image (their dependencies are
# resolved against the feeds and the image's own manifest).
ROLES = {
    "ap": ("kmod-mac80211-hwsim", "wpad-mbedtls", "rpcd-mod-iwinfo"),
    "ups": ("nut-server", "nut-upsmon", "nut-upsc", "nut-web-cgi", "nut-driver-dummy-ups", "luci-app-nut"),
    # A vendor AP (winlab/apos): its CLI and web pages run on Python.
    "apvendor": ("python3-light",),
    # OpenWISP's agent for a plain OpenWrt AP: not installed, offered in
    # /root/openwisp for the student to opkg install (winlab/openwisp.py).
    "openwisp": ("openwisp-config",),
}
VENDOR_VAR = "apvendor"           # node var: the vendor an AP plays ("" = OpenWrt's own LuCI)
APOS_DIR = "/usr/lib/winlab-ap"
# LuCI's pages for them: without one the device still works (NUT's own CGI
# pages; LuCI's wireless page needs rpcd-mod-iwinfo only for its scans).
OPTIONAL = {"luci-app-nut", "rpcd-mod-iwinfo", "openwisp-config"}
UPS_DEV = "/etc/winlab-ups.dev"   # the dummy-ups file winlab keeps current
UPS_NAME = "ups"


class OpenWrtError(Exception):
    pass


# ------------------------------------------------------------------ fetching
@dataclass
class Pkg:
    name: str
    version: str
    depends: list[str]
    provides: list[str]
    filename: str
    sha256: str
    size: int
    url: str = ""


def parse_packages(text: str, base_url: str = "") -> dict[str, Pkg]:
    """An opkg feed's Packages index: one stanza per package."""
    out: dict[str, Pkg] = {}
    for stanza in re.split(r"\n\s*\n", text.replace("\r\n", "\n")):
        f: dict[str, str] = {}
        key = ""
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t") and key:
                f[key] += " " + line.strip()
                continue
            k, sep, v = line.partition(":")
            if sep:
                key = k.strip()
                f[key] = v.strip()
        if not f.get("Package") or not f.get("Filename"):
            continue
        out[f["Package"]] = Pkg(
            name=f["Package"], version=f.get("Version", ""),
            depends=[d for d in (_dep_name(x) for x in f.get("Depends", "").split(",")) if d],
            provides=[p for p in (_dep_name(x) for x in f.get("Provides", "").split(",")) if p],
            filename=f["Filename"], sha256=f.get("SHA256sum", "").lower(), size=int(f.get("Size", "0") or 0),
            url=base_url + f["Filename"])
    return out


def _dep_name(text: str) -> str:
    """'libc', 'hostapd-common (>= 2024)', 'a | b' -> the first name."""
    return text.split("|")[0].strip().split(" ")[0].split("(")[0].strip()


def manifest_names(text: str) -> set[str]:
    """The image's manifest: 'name - version' a line."""
    return {line.split(" - ")[0].strip() for line in text.splitlines() if " - " in line}


def resolve(wanted, index: dict[str, Pkg], installed: set[str]) -> list[Pkg]:
    """The packages to install, dependencies first, without what the image has."""
    provided = {p: pkg.name for pkg in index.values() for p in pkg.provides}
    have = set(installed) | {"libc", "kernel"}
    have |= {p for pkg_name in installed if pkg_name in index for p in index[pkg_name].provides}
    order: list[Pkg] = []
    seen: set[str] = set()

    def visit(name: str, chain: tuple[str, ...]) -> None:
        if name in have or name in seen:
            return
        real = name if name in index else provided.get(name, "")
        if not real:
            raise OpenWrtError(f"{name} (needed by {' > '.join(chain) or 'winlab'}) is in none of "
                               f"OpenWrt {RELEASE}'s feeds")
        if real in have or real in seen:
            return
        seen.add(name)
        seen.add(real)
        for dep in index[real].depends:
            visit(dep, chain + (real,))
        order.append(index[real])
    for w in wanted:
        visit(w, ())
    return order


def kmods_dir(listing: str) -> str:
    """The release's one kernel-module folder (<kernel>-<rel>-<hash>/)."""
    found = sorted(set(re.findall(r'href="(\d+\.\d+\.\d+-\d+-[0-9a-f]+)/"', listing)))
    if not found:
        raise OpenWrtError("the release lists no kernel-module feed")
    return found[-1]


def gunzip_to(src: Path, dest: Path) -> Path:
    """The .img.gz to a raw image. OpenWrt pads its gzip images, so the
    stream is read up to the end of the first member and the rest ignored."""
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as fin, dest.open("wb") as fout:
        while not dec.eof:
            chunk = fin.read(1 << 20)
            if not chunk:
                break
            fout.write(dec.decompress(chunk))
        fout.write(dec.flush())
    if not dec.eof:
        raise OpenWrtError(f"{src.name} ends before its gzip stream does")
    return dest


def packages_dir() -> Path:
    from .images import base_path
    return base_path(IMAGE, "-packages")


def fetched_packages() -> dict:
    try:
        return json.loads((packages_dir() / "roles.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def fetch(app, say, get, download, convert=None) -> Path:
    """The image (verified against the release's sha256sums), converted to
    the qcow2 base the devices are cloned from, its manifest, and the
    packages each role needs from the release's feeds (each verified
    against its index)."""
    from .appliances import raw_to_qcow2
    from .bootstrap import BootstrapError
    from .images import write_base_meta
    from . import paths
    try:
        say(f"reading OpenWrt {RELEASE}'s checksum file ({TARGET}{SUMS})")
        from .appliances import parse_sums
        sums = get(TARGET + SUMS).decode("utf-8", "replace")
        sha = parse_sums(sums, IMAGE_FILE)
        down = paths.downloads_dir() / IMAGE_FILE
        say(f"fetching OpenWrt {RELEASE}: {IMAGE_FILE} (verified against {sha[:12]}…)")
        download(TARGET + IMAGE_FILE, down, expect_sha=sha, label=f"OpenWrt {RELEASE}")
        text = get(TARGET + MANIFEST_FILE).decode("utf-8", "replace")
        installed = manifest_names(text)
        say("reading the release's package feeds")
        index: dict[str, Pkg] = {}
        kdir = kmods_dir(get(KMODS_URL).decode("utf-8", "replace"))
        for url in [KMODS_URL + kdir + "/"] + [FEED_URL.format(feed=f) for f in FEEDS]:
            for name, pkg in parse_packages(get(url + "Packages").decode("utf-8", "replace"), url).items():
                index.setdefault(name, pkg)
        roles: dict[str, list[str]] = {}
        want: dict[str, Pkg] = {}
        for role, names in ROLES.items():
            got: list[Pkg] = []
            for name in names:
                try:
                    got += resolve([name], index, installed | {p.name for p in got})
                except OpenWrtError as exc:
                    if name not in OPTIONAL:
                        raise
                    say(f"{exc}: the {role} goes without it")
            roles[role] = [p.filename.rsplit("/", 1)[-1] for p in got]
            for p in got:
                want[p.name] = p
        pdir = packages_dir()
        pdir.mkdir(parents=True, exist_ok=True)
        for p in want.values():
            if not p.sha256:
                raise OpenWrtError(f"{p.name}: the feed gives no SHA-256 for it")
            download(p.url, pdir / p.filename.rsplit("/", 1)[-1], expect_sha=p.sha256, label=p.name)
        (pdir / "roles.json").write_text(json.dumps({"release": RELEASE, "roles": roles}, indent=1), encoding="utf-8")
    except BootstrapError as exc:
        raise OpenWrtError(str(exc)) from exc
    raw = down.with_suffix("")
    say("unpacking the image")
    gunzip_to(down, raw)
    from .appliances import image_path, manifest_path
    dest = image_path(IMAGE)
    say(f"converting to qcow2: {dest}")
    (convert or raw_to_qcow2)(raw, dest)
    raw.unlink(missing_ok=True)
    down.unlink(missing_ok=True)
    manifest_path(IMAGE).write_text(text, encoding="utf-8")
    write_base_meta(IMAGE, appliance=True, sha256=sha, source=TARGET + IMAGE_FILE, version=RELEASE,
                          fetched=time.strftime("%Y-%m-%d"), packages=len(installed), user=CONSOLE_USER,
                          console="serial")
    say(f"OpenWrt {RELEASE} ready: {dest}, {len(want)} packages for the access points and the UPS card")
    return dest


# ------------------------------------------------------------------ the devices' VMs
def is_openwrt(node) -> bool:
    return node.image == IMAGE


def role_of(node) -> str:
    return str(node.vars.get(MARK) or "")


def device_vm(node_id: str, role: str, network: str, ip: str, hostname: str = "", vendor: str = "",
              air: bool = False):
    """The VM behind a device: OpenWrt with one port, cabled where the
    device is. Never written to the lab file (editor.emit skips it): it is
    made again from the device each time the lab is loaded. A vendor AP
    runs Python as well, so it gets more memory. An AP on the real air
    (winlab/vwifi.py) has a second card, never cabled on the canvas: its
    radio's link to the router's vwifi-server."""
    from .model import LINUX, Nic, Node
    v = {MARK: role}
    if vendor:
        v[VENDOR_VAR] = vendor
    if air:
        from .vwifi import AIR_VAR
        v[AIR_VAR] = "1"
    what = "access point" if role == "ap" else "UPS network card"
    return Node(id=node_id, image=IMAGE, kind=LINUX, cpus=1, memory_mb=192 if vendor else 128, hostname=hostname,
                nics=[Nic(network=network, ip=ip or None)] + ([Nic(network="")] if air else []), boot_order=20, vars=v,
                description=f"OpenWrt {RELEASE}: the {what}" + (f" playing {vendor}" if vendor else ""))


def vendor_of(node) -> str:
    return str(node.vars.get(VENDOR_VAR) or "")


def role_packages(node) -> list[str]:
    """The package files the device's volume carries."""
    roles = fetched_packages().get("roles", {})
    out = list(roles.get(role_of(node), []))
    if vendor_of(node):
        out += [f for f in roles.get("apvendor", []) if f not in out]
    return out


def offered_packages(node) -> list[str]:
    """Package files a plain OpenWrt AP carries but does not install: the
    OpenWISP agent, for the student to install with opkg."""
    if role_of(node) != "ap" or vendor_of(node):
        return []
    have = set(role_packages(node))
    return [f for f in fetched_packages().get("roles", {}).get("openwisp", []) if f not in have]


def apos_files() -> dict[str, bytes]:
    """winlab/apos, as it is copied onto a vendor AP: {relative path: bytes}."""
    root = Path(__file__).resolve().parent / "apos"
    return {f"apos/{f.name}": f.read_bytes() for f in sorted(root.iterdir())
            if f.suffix in (".py", ".json") and f.is_file()}


def free_ip(lab, network: str, taken: set[str] = frozenset()) -> str:
    """An address for a device of the lab: from the top of the subnet down
    (clear of the DHCP pool and the servers' low addresses)."""
    net = lab.networks[network]
    used = {net.router_ip} | set(taken)
    for n in lab.nodes.values():
        used |= {c.ip for c in n.nics if c.ip}
        if n.vars.get("bmc_ip"):
            used.add(str(n.vars["bmc_ip"]))
    for own in lab.devices.values():
        if own.get("ip"):
            used.add(str(own["ip"]))
    hosts = [str(h) for h in net.net.hosts()]
    for h in reversed(hosts[150:-1] if len(hosts) > 160 else hosts[1:]):
        if h not in used:
            return h
    raise OpenWrtError(f"{network} has no free address for a device")


# ------------------------------------------------------------------ what winlab gives it
def setup_script(node, lab, plan) -> str:
    """Run once per change of what the lab decides (fingerprint), from the
    volume: the role's packages (first time), the address, the host name,
    the LAN's DHCP server off; and for the role its hardware link: the
    software radio (AP), the card's NUT driver (UPS). Nothing the student
    sets is touched."""
    from .naming import hostname_of
    from .provision import _dns_servers
    role = role_of(node)
    nic = node.nics[0] if node.nics else None
    ip = nic.ip if nic and nic.ip else ""
    net = lab.networks.get(nic.network) if nic and nic.network else None
    seg_net = plan.segment_of(net.id).network if net is not None else None
    mask = str(net.net.netmask) if net is not None else "255.255.255.0"
    gw = seg_net.router_ip if seg_net is not None and seg_net.routed else ""
    dns = [d for d in _dns_servers(lab, node) if d] if lab.nodes else []
    host = hostname_of(node).lower()
    lines = [
        "#!/bin/sh",
        f"# winlab: what the lab's wiring decides for {node.id} (winlab/openwrt.py)",
        "V=$(dirname \"$0\")",
        "if [ ! -f /etc/winlab.pkgs ]; then",
        "  opkg install $V/pkgs/*.ipk >/tmp/winlab-opkg.log 2>&1 || { tail -n 5 /tmp/winlab-opkg.log >&2; exit 3; }",
        "  touch /etc/winlab.pkgs; FIRST=1",
        "fi",
        f"uci set system.@system[0].hostname='{host}'",
    ]
    if ip:
        lines += ["uci set network.lan.proto='static'", f"uci set network.lan.ipaddr='{ip}'",
                  f"uci set network.lan.netmask='{mask}'",
                  f"uci set network.lan.gateway='{gw}'" if gw else "uci -q delete network.lan.gateway",
                  "uci -q delete network.lan.dns"]
        lines += [f"uci add_list network.lan.dns='{d}'" for d in dns]
    lines += ["uci set dhcp.lan.ignore='1'", "uci commit", "/etc/init.d/network reload >/dev/null 2>&1",
              "/etc/init.d/dnsmasq restart >/dev/null 2>&1", "/etc/init.d/system reload >/dev/null 2>&1"]
    vendor = vendor_of(node)
    if role == "ap" and vendor:
        lines += vendor_lines(node, vendor, lab.domain)
    elif role == "ap":
        # One radio, as an access point has: OpenWrt's software radio, which
        # LuCI configures like a real card. The air is winlab's simulation,
        # or, in a lab with a Linux laptop on the real air, vwifi's: the
        # radio's frames go to the router's vwifi-server (winlab/vwifi.py).
        sim = ["for f in /etc/modules.d/*hwsim*; do echo 'mac80211_hwsim radios=1' > $f; done",
               "if [ -n \"$FIRST\" ]; then",
               "  rmmod mac80211_hwsim 2>/dev/null; insmod mac80211_hwsim radios=1",
               "  sleep 2; rm -f /etc/config/wireless; wifi config", "fi"]
        from . import vwifi
        if vwifi.wants_air(node):
            lines += vwifi.ap_lines(node, lab) + ["  " + x for x in sim] + ["fi"]
        else:
            lines += sim
        # OpenWISP's agent, offered: opkg install /root/openwisp/*.ipk (winlab/openwisp.py)
        lines += ["if [ -d $V/offer ]; then mkdir -p /root/openwisp; cp $V/offer/*.ipk /root/openwisp/ 2>/dev/null; fi"]
    elif role == "ups":
        lines += [f"[ -f {UPS_DEV} ] || printf 'ups.status: OL\\nbattery.charge: 100\\n' > {UPS_DEV}",
                  # The card's link to its UPS: the driver section, made once.
                  f"if ! uci -q get nut_server.{UPS_NAME} >/dev/null; then",
                  f"  uci set nut_server.{UPS_NAME}=driver",
                  f"  uci set nut_server.{UPS_NAME}.driver='dummy-ups'",
                  f"  uci set nut_server.{UPS_NAME}.port='{UPS_DEV}'",
                  f"  uci set nut_server.{UPS_NAME}.desc='the UPS this card is fitted in'",
                  "  uci commit nut_server", "fi",
                  "/etc/init.d/nut-server enable; /etc/init.d/nut-server restart >/dev/null 2>&1"]
    lines += ["echo \"$1\" > " + SHA_FILE, "sync", "echo applied", ""]
    return "\n".join(lines)


def vendor_lines(node, vendor: str, domain: str = "") -> list[str]:
    """A vendor AP (winlab/apos): two software radios (2.4 and 5 GHz, as a
    dual-band AP has), the apos program copied in, the vendor's CLI as the
    login shell of the accounts an admin types at SSH, its web pages on
    port 80 in place of LuCI, and the AP's identity. Its configuration is
    the vendor's own (factory state the first time), never winlab's."""
    from . import wifi
    idn = {"vendor": vendor, "model": wifi.MODELS.get(vendor, "")}
    if vendor in ("unifi", "lap") and domain:   # where a controller's DNS name is looked up, as a DHCP search domain does
        idn["domain"] = domain
    ident = json.dumps(idn)
    # A UniFi AP and a Cisco lightweight AP have no web pages: their daemon
    # finds the controller instead; the Cisco-style controller serves its
    # pages and CAPWAP (UDP 5246) from one daemon.
    daemon = {"unifi": "inform", "lap": "capwap", "wlc": "wlc"}.get(vendor, "web 80")
    users = ["admin", "cisco", "Cisco", "super", "ubnt"]   # the names admins type at "ssh <name>@<AP>"
    lines = [
        "for f in /etc/modules.d/*hwsim*; do echo 'mac80211_hwsim radios=2' > $f; done",
        "if [ \"$(ls /sys/class/ieee80211 2>/dev/null | wc -l)\" != 2 ]; then",
        "  rmmod mac80211_hwsim 2>/dev/null; insmod mac80211_hwsim radios=2; sleep 2", "fi",
        f"mkdir -p {APOS_DIR} /etc/winlab-ap", f"rm -rf {APOS_DIR}/apos; cp -r $V/apos {APOS_DIR}/",
        # the identity: vendor and model from the canvas (apos reads the MAC itself)
        f"cat > /etc/winlab-ap/ident.json <<'WINLAB_EOF'", ident, "WINLAB_EOF",
        "cat > /usr/bin/winlab-apcli <<'WINLAB_EOF'", "#!/bin/sh", f"cd {APOS_DIR} && exec python3 -m apos cli", "WINLAB_EOF",
        "chmod 755 /usr/bin/winlab-apcli", "grep -qx /usr/bin/winlab-apcli /etc/shells || echo /usr/bin/winlab-apcli >> /etc/shells",
    ]
    for i, u in enumerate(users):
        uid = 1000 + i
        lines += [f"grep -q '^{u}:' /etc/passwd || echo '{u}:x:{uid}:{uid}:{u}:/tmp:/usr/bin/winlab-apcli' >> /etc/passwd",
                  f"grep -q '^{u}:' /etc/shadow || echo '{u}::0:0:99999:7:::' >> /etc/shadow"]
    lines += [
        # SSH answers the CLI's accounts (they have no SSH password: the CLI asks for its own sign-in)
        "uci set dropbear.@dropbear[0].PasswordAuth='on'", "uci commit dropbear", "/etc/init.d/dropbear restart >/dev/null 2>&1",
        # the vendor's web pages in place of LuCI
        "/etc/init.d/uhttpd stop >/dev/null 2>&1; /etc/init.d/uhttpd disable >/dev/null 2>&1",
        "cat > /etc/init.d/winlab-ap <<'WINLAB_EOF'", "#!/bin/sh /etc/rc.common", "START=99", "USE_PROCD=1",
        "start_service() {", f"  (cd {APOS_DIR} && python3 -m apos boot)", "  procd_open_instance",
        f"  procd_set_param command /bin/sh -c 'cd {APOS_DIR} && exec python3 -m apos {daemon}'",
        "  procd_set_param respawn", "  procd_close_instance", "}", "WINLAB_EOF",
        "chmod 755 /etc/init.d/winlab-ap", "/etc/init.d/winlab-ap enable",
        f"[ -f /etc/winlab-ap/startup.json ] || (cd {APOS_DIR} && python3 -m apos factory)",
        "/etc/init.d/winlab-ap restart >/dev/null 2>&1",
    ]
    return lines


def fingerprint(node, lab, plan) -> str:
    """What the console agent compares with /etc/winlab.sha: the setup and
    the packages and program it carries."""
    pk = role_packages(node) + offered_packages(node)
    extra = b"".join(apos_files().values()) if vendor_of(node) else b""
    from . import vwifi
    if vwifi.wants_air(node):
        pk.append(f"{vwifi.ASSET} {vwifi.ready()}")   # the AP's real-air radio, once the build is fetched
    return hashlib.sha256((setup_script(node, lab, plan) + "\n".join(pk)).encode() + extra).hexdigest()[:16]


def config_disk(node, lab, plan, dest: Path) -> Path:
    """The volume: setup.sh and the role's packages, a tar written straight
    to a raw disk (busybox tar reads it from /dev/vdb)."""
    buf = io.BytesIO()
    pdir = packages_dir()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        def add(name: str, data: bytes, mode: int = 0o644) -> None:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, 0
            tar.addfile(info, io.BytesIO(data))
        add("setup.sh", setup_script(node, lab, plan).encode(), 0o755)
        add("winlab.sha", (fingerprint(node, lab, plan) + "\n").encode())
        for fname in role_packages(node):
            f = pdir / fname
            if f.exists():
                add("pkgs/" + fname, f.read_bytes())
        for fname in offered_packages(node):
            f = pdir / fname
            if f.exists():
                add("offer/" + fname, f.read_bytes())
        if vendor_of(node):
            for name, data in apos_files().items():
                add(name, data)
        from . import vwifi
        if vwifi.wants_air(node) and vwifi.ready():   # the programs for its radio on the real air
            add("vwifi.tar.gz", vwifi.asset_path().read_bytes())
    data = buf.getvalue()
    size = max(VOLUME_MB << 20, (len(data) + (1 << 20)) & ~((1 << 20) - 1))
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as fh:
        fh.write(data)
        fh.truncate(size)
    return dest


APPLY = ("mkdir -p /tmp/wl; ok=0; for d in /dev/vdb /dev/vdc /dev/vdd /dev/sdb; do "
         "[ -b $d ] || continue; rm -rf /tmp/wl/*; tar -xf $d -C /tmp/wl 2>/dev/null; "
         "[ -f /tmp/wl/setup.sh ] && {{ ok=1; break; }}; done; "
         "[ $ok = 1 ] || {{ echo 'no configuration volume' >&2; exit 2; }}; sh /tmp/wl/setup.sh {fp}")


# ------------------------------------------------------------------ reading it
def parse_uci(text: str) -> list[dict]:
    """A UCI file (/etc/config/<name>): its sections in order, each
    {"type", "name", "options": {}, "lists": {}}."""
    out: list[dict] = []
    cur: dict | None = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = _uci_words(line)
        if not words:
            continue
        if words[0] == "config" and len(words) >= 2:
            cur = {"type": words[1], "name": words[2] if len(words) > 2 else "", "options": {}, "lists": {}}
            out.append(cur)
        elif cur is not None and words[0] == "option" and len(words) >= 2:
            cur["options"][words[1]] = words[2] if len(words) > 2 else ""
        elif cur is not None and words[0] == "list" and len(words) >= 3:
            cur["lists"].setdefault(words[1], []).append(words[2])
    return out


def _uci_words(line: str) -> list[str]:
    out, i = [], 0
    while i < len(line):
        c = line[i]
        if c.isspace():
            i += 1
            continue
        if c == "#":
            break
        if c in "'\"":
            j = line.find(c, i + 1)
            j = len(line) if j < 0 else j
            out.append(line[i + 1:j])
            i = j + 1
        else:
            j = i
            while j < len(line) and not line[j].isspace():
                j += 1
            out.append(line[i:j])
            i = j
    return out


def wireless_settings(text: str) -> dict:
    """What the AP broadcasts, from its /etc/config/wireless, in the terms
    of winlab's air (winlab/wifi.py): radio on or off, SSID, security
    (open, wpa2, wpa2-ent), key, channel, RADIUS server, port and secret."""
    secs = parse_uci(text)
    radios = {s["name"]: s for s in secs if s["type"] == "wifi-device"}
    ifaces = [s for s in secs if s["type"] == "wifi-iface" and s["options"].get("mode", "ap") == "ap"]
    out = {"radio": "off", "ssid": "OpenWrt", "security": "open", "key": "", "channel": 1,
           "radius": "", "radius_port": 1812, "radius_key": "", "wlans": []}
    pick = None
    for i in ifaces:
        r = radios.get(i["options"].get("device", ""))
        if r is not None and r["options"].get("disabled", "0") != "1" and i["options"].get("disabled", "0") != "1":
            pick = (i, r)
            break
    if pick is None and ifaces:
        i = ifaces[0]
        pick = (i, radios.get(i["options"].get("device", ""), {"options": {}}))
        out["radio"] = "off"
    elif pick is not None:
        out["radio"] = "on"
    if pick is None:
        return out
    i, r = pick
    o, ro = i["options"], r["options"]
    out["ssid"] = o.get("ssid", "OpenWrt")[:32] or "OpenWrt"
    enc = o.get("encryption", "none").lower()
    if enc.startswith(("psk", "sae")):
        out["security"], out["key"] = "wpa2", o.get("key", "")
    elif enc.startswith("wpa"):
        out["security"] = "wpa2-ent"
        out["radius"] = o.get("auth_server", o.get("server", ""))
        port = o.get("auth_port", o.get("port", "1812"))
        out["radius_port"] = int(port) if port.isdigit() else 1812
        out["radius_key"] = o.get("auth_secret", o.get("key", ""))
    band = ro.get("band", "2g")
    ch = ro.get("channel", "auto")
    out["channel"] = int(ch) if ch.isdigit() else (36 if band == "5g" else 1)
    out["width"], out["txpower"] = radio_width(ro), radio_txpower(ro)
    out["iface"] = i["name"]
    # Every network on the air (a vendor AP broadcasts several, on both
    # radios): one entry per interface whose radio and itself are enabled.
    out["wlans"] = []
    for i in ifaces:
        r = radios.get(i["options"].get("device", ""))
        if r is None or r["options"].get("disabled", "0") == "1" or i["options"].get("disabled", "0") == "1":
            continue
        out["wlans"].append(_iface_air(i["options"], r["options"]))
    return out


def _iface_air(o: dict, ro: dict) -> dict:
    """One broadcasting interface in winlab's air terms."""
    w = {"ssid": (o.get("ssid", "OpenWrt")[:32] or "OpenWrt"), "security": "open", "key": "",
         "radius": "", "radius_port": 1812, "radius_key": "", "hidden": o.get("hidden", "0") == "1"}
    enc = o.get("encryption", "none").lower()
    if enc.startswith(("psk", "sae")):
        w["security"], w["key"] = "wpa2", o.get("key", "")
    elif enc.startswith("wpa"):
        w["security"] = "wpa2-ent"
        w["radius"] = o.get("auth_server", o.get("server", ""))
        port = o.get("auth_port", o.get("port", "1812"))
        w["radius_port"] = int(port) if port.isdigit() else 1812
        w["radius_key"] = o.get("auth_secret", o.get("key", ""))
    band = ro.get("band", "2g")
    ch = ro.get("channel", "auto")
    w["channel"] = int(ch) if ch.isdigit() else (36 if band == "5g" else 1)
    w["width"], w["txpower"] = radio_width(ro), radio_txpower(ro)
    return w


def radio_width(ro: dict) -> int:
    """The radio's channel width in MHz, from LuCI's Width (option htmode:
    HT20, HT40, VHT80, HE160...; NOHT and nothing are 20)."""
    m = re.search(r"(\d+)", str(ro.get("htmode", "")))
    w = int(m.group(1)) if m else 20
    return w if w in (20, 40, 80, 160) else 20


def radio_txpower(ro: dict) -> int:
    """LuCI's Maximum transmit power (option txpower, dBm); 0 when it is
    left on the driver's default, which is the radio's full power."""
    v = str(ro.get("txpower", "")).strip()
    return int(v) if v.isdigit() else 0


def lan_address(text: str) -> str:
    """The AP's LAN address, from its /etc/config/network."""
    for s in parse_uci(text):
        if s["type"] == "interface" and s["name"] == "lan":
            ip = s["options"].get("ipaddr", "")
            if not ip and s["lists"].get("ipaddr"):
                ip = s["lists"]["ipaddr"][0]
            return ip.split("/")[0]
    return ""


READ_AP = "cat /etc/config/wireless 2>/dev/null; echo '#winlab-network'; cat /etc/config/network 2>/dev/null"


def split_read(text: str) -> tuple[str, str]:
    w, _, n = (text or "").partition("#winlab-network")
    return w, n


def uci_wireless(ssid: str = "OpenWrt", encryption: str = "none", key: str = "", channel="1",
                 disabled: bool = True, server: str = "", port: int = 1812, secret: str = "") -> str:
    """/etc/config/wireless as OpenWrt writes it for one radio: its factory
    form by default. The model answers (`winlab roles apply`) and the tests
    write the student's settings in this form."""
    band = "5g" if str(channel).isdigit() and int(channel) >= 36 else "2g"
    out = ["config wifi-device 'radio0'", "\toption type 'mac80211'", "\toption path 'virtual/mac80211_hwsim/hwsim0'",
           f"\toption channel '{channel}'", f"\toption band '{band}'", "\toption htmode 'HT20'"]
    if disabled:
        out.append("\toption disabled '1'")
    out += ["", "config wifi-iface 'default_radio0'", "\toption device 'radio0'", "\toption network 'lan'",
            "\toption mode 'ap'", f"\toption ssid '{ssid}'", f"\toption encryption '{encryption}'"]
    if key:
        out.append(f"\toption key '{key}'")
    if server:
        out += [f"\toption auth_server '{server}'", f"\toption auth_port '{port}'", f"\toption auth_secret '{secret}'"]
    return "\n".join(out) + "\n"


def relay_script(ap: dict, router_ip: str) -> str:
    """The AP's side of WPA2-Enterprise in winlab: the laptops' EAP is
    relayed on the router (the air is simulated there), whose RADIUS
    requests go to the AP; the AP sends them on to its RADIUS server from
    its own address, as a real AP's would come, and the answers back.
    Empty set of rules when the AP is not Enterprise."""
    lines = [f"nft delete table ip {RADIUS_RELAY} 2>/dev/null"]
    if ap.get("security") == "wpa2-ent" and ap.get("radius") and router_ip:
        port = int(ap.get("radius_port") or 1812)
        lines += [f"nft -f - <<'WINLAB_EOF'", f"table ip {RADIUS_RELAY} {{",
                  "  chain pre { type nat hook prerouting priority dstnat; policy accept;",
                  f"    ip saddr {router_ip} udp dport 1812 dnat to {ap['radius']}:{port}", "  }",
                  "  chain post { type nat hook postrouting priority srcnat; policy accept;",
                  f"    ip daddr {ap['radius']} udp dport {port} masquerade", "  }", "}", "WINLAB_EOF"]
    return "\n".join(lines + ["true"]) + "\n"


def ups_dev(hid: dict, low: int = 20) -> str:
    """The card's dummy-ups file from winlab's battery model (ups.hid_state)."""
    status = ["OL" if hid.get("ac") else "OB"]
    if hid.get("charging"):
        status.append("CHRG")
    if hid.get("discharging"):
        status.append("DISCHRG")
    if hid.get("imminent") or (not hid.get("ac") and int(hid.get("percent", 100)) <= low):
        status.append("LB")
    if hid.get("overload"):
        status.append("OVER")
    rt = int(hid.get("runtime", 0))
    return "\n".join([
        "device.mfr: winlab", f"device.model: {hid.get('model', 'UPS')}", f"ups.mfr: winlab",
        f"ups.model: {hid.get('model', 'UPS')}", f"ups.status: {' '.join(status)}",
        f"ups.load: {int(hid.get('load', 0))}", f"battery.charge: {int(hid.get('percent', 0))}",
        f"battery.charge.low: {low}", f"battery.runtime: {rt if rt != 0xFFFF else 86400}",
        f"battery.voltage: {hid.get('volts', 13)}", f"input.voltage: {230 if hid.get('ac') else 0}",
        f"output.voltage: {230 if hid.get('ac') or hid.get('discharging') else 0}", ""])


def write_ups_cmd(hid: dict) -> str:
    body = ups_dev(hid)
    return f"cat > {UPS_DEV}.new <<'WINLAB_EOF'\n{body}WINLAB_EOF\nmv {UPS_DEV}.new {UPS_DEV}\n"


# ------------------------------------------------------------------ talking to it
def run(lab_name: str, node_id: str, script: str, timeout: float = 30.0, factory=None) -> str:
    """A command on the device's shell, over the console agent. Raises
    OpenWrtError when it is off or still starting."""
    from . import state
    from .guestctl import GuestChannel, GuestError
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    if not ns or not state.pid_alive(ns.pid) or not ns.serial_port:
        raise OpenWrtError(f"{node_id} is off")
    try:
        ch = (factory or GuestChannel)(ns.serial_port).connect(retries=1, connect_timeout=2.0)
    except (GuestError, OSError) as exc:
        raise OpenWrtError(f"{node_id} is still starting ({exc})") from None
    try:
        r = ch.run(script, shell="sh", timeout=timeout)
    except GuestError as exc:
        raise OpenWrtError(f"{node_id}: {exc}") from None
    finally:
        ch.close()
    return r.out


# ------------------------------------------------------------------ management pages
def luci(role: str):
    from .adminui import AdminGui
    if role == "ups":
        return AdminGui(software=f"OpenWrt {RELEASE} LuCI with Network UPS Tools", scheme="http", port=80,
                        path="/", sign_in="root, no password until you set one (LuCI asks you to)",
                        license="GPL-2.0 (OpenWrt), GPL-2.0+ (NUT)",
                        note=("Services > Network UPS Tools: the UPS's users, the monitor's shutdown and "
                              "notifications; NUT's status pages at /cgi-bin/nut/upsstats.cgi."))
    return AdminGui(software=f"OpenWrt {RELEASE} LuCI", scheme="http", port=80, path="/",
                    sign_in="root, no password until you set one (LuCI asks you to)", license="GPL-2.0",
                    note="Factory state: the radio disabled.")


def check_ip(lab, network: str, ip: str) -> None:
    net = lab.networks[network]
    addr = ipaddress.ip_address(ip)
    if addr not in net.net:
        raise OpenWrtError(f"{ip} is not an address of {network} ({net.cidr})")



def attach(lab) -> None:
    """The devices' VMs into a freshly loaded lab: one per cabled access
    point, and the UPS's network card when its cable is in."""
    from . import ups, wifi
    wifi.vm_nodes(lab)
    ups.card_vm(lab)


def hidden(node) -> bool:
    """A device's VM: drawn as its device on the canvas, not as a machine."""
    return bool(node.vars.get(MARK))
