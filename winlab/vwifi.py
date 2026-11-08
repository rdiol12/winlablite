"""vwifi: real 802.11 between the lab's Linux machines.

QEMU has no Wi-Fi card, so the air between the access points and Windows
laptops is winlab's simulation (winlab/wifi.py), and stays so: Windows has
no mac80211_hwsim. vwifi (LGPL-3.0, github.com/Raizo62/vwifi) makes the air
real for Linux guests: each one loads Linux's software radio
(mac80211_hwsim) and runs ``vwifi-client``, which carries every frame its
radio sends to ``vwifi-server``; the server hands them to the other radios,
losing more of them the further apart the machines stand
(``vwifi-ctrl set <cid> X Y Z``). hostapd on an OpenWrt AP and
wpa_supplicant (under NetworkManager) on a Linux laptop then really scan,
associate and run WPA2's 4-way handshake, with real beacons and EAPOL frames
a capture on a monitor interface shows.

How it is wired (render, ap_lines, the wifi-laptop role):

* The server runs inside the lab's router VM, in a network namespace of its
  own (``wlair``) with one leg on a hidden "air" VLAN of the router's own
  switch (AIR_NET, a link-local subnet no lab network uses). Nothing of it
  is routed: the router has no address on that VLAN, OpenWrt keeps the AP's
  air interface out of its firewall zones, and the laptop does not forward.
  The clients reach the server over that VLAN, never through this PC, so the
  lab stays as isolated as it is.
* Each air client has one extra network card with no cable on the canvas
  (an unplugged port, which the router's switch would park in a VLAN of its
  own); render moves exactly those ports into the air VLAN. An OpenWrt AP in
  a lab with real air gets that card as eth1 (wifi.vm_nodes), a Linux laptop
  names it in its vars (``air = "0"``).
* Positions: where the student puts the AP and the laptop on the canvas
  (wifi.py's canvas coordinates, the same centres its range circles use)
  goes to the server with vwifi-ctrl, scaled by METERS_PER_UNIT, and again
  whenever something is moved (push), so range and loss follow the canvas.
* A Windows laptop keeps the simulated air; a vendor AP (winlab/apos), which
  needs two radios of its own, keeps it too.

Nothing is bundled. vwifi publishes source only, so this repository's
workflow (.github/workflows/vwifi.yml) builds it at the pinned commit as
static Linux x86-64 programs (Alpine's musl, with libnl built from its own
pinned release; they run as is on Alpine, on OpenWrt and on Ubuntu) and
publishes them as an asset of a release of rdiol12/winlablite, together with the
complete corresponding source of both (LGPL), the licence and a NOTICE
(tools/pack_vwifi.py). At preparation this module fetches that asset onto
this PC, checked against the SHA-256 pinned here; the router gets it on the
repository volume, an AP on its configuration volume, a laptop on its
``wifi`` pack stick.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to

PRODUCT = "vwifi"
LICENSE = "LGPL-3.0 (vwifi); LGPL-2.1 (libnl, linked in)"
UPSTREAM = "https://github.com/Raizo62/vwifi"
COMMIT = "c3822baaae468b7d5c50be78431f9ad8ec49cbeb"  # 2026-10-25, master
SHORT = COMMIT[:7]
LIBNL_VERSION = "3.11.0"
LIBNL_URL = f"https://github.com/thom311/libnl/releases/download/libnl3_11_0/libnl-{LIBNL_VERSION}.tar.gz"
LIBNL_SHA256 = "2a56e1edefa3e68a7c00879496736fdbf62fc94ed3232c0baba127ecfa76874d"
ALPINE = "alpine:3.22"   # the build container: musl, so the programs are fully static
TAG = f"vwifi-{SHORT}"
ASSET = f"{TAG}.tar.gz"
RELEASE = f"https://github.com/rdiol12/winlablite/releases/download/{TAG}"
# Pinned from the first published build (the workflow printed it, 6 Nov
# 2026: release vwifi-c3822ba); empty would mean not published, and nothing
# would be fetched.
ASSET_SHA256 = "29c18f590ef85e6438b6b1649105ea42096f7fc3ab90f39adac1ec2a703f69b5"
ASSET_SIZE = 2796700
PROGRAMS = ("vwifi-server", "vwifi-client", "vwifi-ctrl", "vwifi-add-interfaces")
# vwifi's own defaults: the clients' port, the spy's, the control port.
PORT_TCP, PORT_SPY, PORT_CTRL = 8212, 8213, 8214
VOLUME_DIR = "vwifi"


class VwifiError(Exception):
    pass


def published() -> bool:
    return len(ASSET_SHA256) == 64


def store() -> Path:
    return paths.downloads_dir() / "vwifi"


def asset_path() -> Path:
    return store() / ASSET


def ready() -> bool:
    """The pinned build is on this PC (fetched and verified)."""
    try:
        meta = json.loads((store() / "vwifi.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (published() and asset_path().is_file() and asset_path().stat().st_size == ASSET_SIZE
            and meta.get("sha256") == ASSET_SHA256)


def fetch(progress=None, download=_download_to) -> Path | None:
    """The pinned build from winlab's release onto this PC, verified against
    its SHA-256; None (and nothing fetched) while no build is pinned."""
    say = progress or (lambda _m: None)
    if not published():
        say(f"{PRODUCT}: no build published yet (Actions > vwifi > Run workflow), skipped")
        return None
    dest = asset_path()
    if ready():
        say(f"{PRODUCT} {SHORT} already fetched")
        return dest
    say(f"{PRODUCT} {SHORT} from {RELEASE}/{ASSET}")
    try:
        download(f"{RELEASE}/{ASSET}", dest, expect_sha=ASSET_SHA256, label=ASSET)
    except BootstrapError as exc:
        raise VwifiError(str(exc)) from exc
    for f in store().iterdir():
        if f.name not in (ASSET, "vwifi.json"):
            f.unlink()
    (store() / "vwifi.json").write_text(json.dumps({
        "name": PRODUCT, "commit": COMMIT, "license": LICENSE, "sha256": ASSET_SHA256,
        "source": UPSTREAM, "asset": f"{RELEASE}/{ASSET}", "fetched": time.strftime("%Y-%m-%d")}, indent=1),
        encoding="utf-8")
    say(f"{PRODUCT} ready: {dest}")
    return dest


def render_status() -> str:
    head = f"real Wi-Fi between Linux machines: {PRODUCT} {SHORT} ({LICENSE})"
    if not published():
        return head + "\n  not built yet: run the vwifi workflow, then pin its SHA-256 in winlab/vwifi.py"
    return head + (f"\n  ready in {store()}" if ready() else "\n  not fetched: 'winlab images prepare fabric'")


# ------------------------------------------------------------------ the air
# The hidden air segment: link-local, so it can never clash with a lab
# network, and nothing routes it. The server is .1; clients get stable
# addresses from their names (air_ips).
AIR_NET = "169.254.211.0/24"
AIR_SERVER = "169.254.211.1"
AIR_PREFIX = 24
AIR_VAR = "air"               # node var: the index of the card that is the radio's link to the air
NETNS = "wlair"               # the server's network namespace on the router
VETH = "wlair0"               # its leg on the router's switch
ROUTER_DIR = "/opt/vwifi"     # the programs, unpacked on the router from the repository volume
RUN = "/run/winlab-air"       # positions, the server's log, what vwifi-ctrl ls said
# Canvas units to metres for vwifi-ctrl: wifi.RANGE (340 units, the 2.4 GHz
# range circle) is 34 m, an office floor's worth for one AP. vwifi's loss
# curve over distance is its own; this scale is to be checked on a real run.
METERS_PER_UNIT = 0.1


def wants_air(node) -> bool:
    """A machine on the real air: a Linux laptop with the wifi-laptop role,
    or an OpenWrt AP's VM in a lab that has one (wifi.vm_nodes)."""
    v = node.vars.get(AIR_VAR)
    return v not in (None, "", False) and str(v).isdigit() and int(v) < len(node.nics)


def air_card(node) -> int:
    return int(node.vars[AIR_VAR]) if wants_air(node) else -1


def real_air(lab) -> bool:
    """Whether the lab has the real air: a Linux laptop on it. Its OpenWrt
    APs then join it too."""
    from . import openwrt
    return any(wants_air(n) and not openwrt.is_openwrt(n) for n in lab.nodes.values())


def members(lab) -> list:
    """The machines on the air, in a stable order."""
    return [n for n in lab.node_list() if wants_air(n)]


def air_ips(lab) -> dict[str, str]:
    """Each member's address on the air: from its name, so it stays the
    same while the lab changes; the server's .1 is never given out."""
    import hashlib
    import ipaddress
    base = ipaddress.ip_network(AIR_NET)
    out: dict[str, str] = {}
    used = {1}
    for n in sorted(members(lab), key=lambda x: x.id):
        h = 2 + int.from_bytes(hashlib.sha256(n.id.encode()).digest()[:2], "big") % 250
        while h in used:
            h = 2 + (h - 1) % 252
        used.add(h)
        out[n.id] = str(base.network_address + h)
    return out


def cid(ip: str) -> int:
    """vwifi-server's id for a client connected over TCP: its IPv4 address
    as a number (the server hashes the client's address, and adds the port
    only when started with -u, which winlab does not do)."""
    import ipaddress
    return int(ipaddress.IPv4Address(ip))


def radio_mac(lab_name: str, node_id: str) -> str:
    """The machine's Wi-Fi radio's own MAC (vwifi-add-interfaces gives it
    to the software radio), locally administered and stable per machine:
    two radios on the air must never share one, as mac80211_hwsim's default
    02:00:00:00:00:00 would."""
    from .model import stable_mac
    return "02" + stable_mac(lab_name, f"{node_id}/radio", 0)[2:]


def _canvas_key(node) -> str:
    from . import openwrt, wifi
    return wifi.PREFIX + node.id if openwrt.is_openwrt(node) else node.id


def positions(lab, layout: dict) -> list[tuple[str, int, int, int, int]]:
    """(machine, cid, x, y, z) in metres for every member: the centre of its
    box on the canvas, the point the simulated air's range circles measure
    from. A member with no position stands at the origin."""
    from . import wifi
    ips = air_ips(lab)
    out = []
    for n in members(lab):
        c = wifi._centre(layout, _canvas_key(n)) or (0.0, 0.0)
        out.append((n.id, cid(ips[n.id]), round(c[0] * METERS_PER_UNIT), round(c[1] * METERS_PER_UNIT), 0))
    return out


def positions_file(lab, layout: dict) -> str:
    return "".join(f"{c} {x} {y} {z} {nid}\n" for nid, c, x, y, z in positions(lab, layout))


def _write_positions(lab, layout: dict) -> list[str]:
    return [f"mkdir -p {RUN}", f"cat > {RUN}/positions.new <<'WINLAB_AIR'",
            positions_file(lab, layout).rstrip("\n"), "WINLAB_AIR", f"mv {RUN}/positions.new {RUN}/positions"]


def air_vid(plan) -> int:
    """The air's VLAN on the router's switch: one no segment uses, above
    the parked ports' range (netplan.park_vid)."""
    used = {s.vid for s in plan.segments.values()}
    return next(v for v in range(4090, 4000, -1) if v not in used)


def render(plan) -> list[str]:
    """The router's part (netplan.render_fabric_setup): the air's VLAN, the
    server in its namespace on it, the members' radio cards moved onto it,
    and the positions kept applied (a client that reconnects gets its place
    back within seconds)."""
    from .netplan import park_vid
    lab = plan.lab
    ctl = f"ip netns exec {NETNS} {ROUTER_DIR}/bin/vwifi-ctrl"
    out = ["### real Wi-Fi (winlab/vwifi.py): vwifi-server on the hidden air VLAN",
           f"[ -f {RUN}/loop.pid ] && kill $(cat {RUN}/loop.pid) 2>/dev/null; rm -f {RUN}/loop.pid",
           f"ip netns pids {NETNS} 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del {NETNS} 2>/dev/null; "
           f"ip link del {VETH} 2>/dev/null; true"]
    mem = members(lab)
    if not mem:
        return out + [""]
    ports = {(l.node_id, l.nic_index): l for l in plan.ports}
    vid = air_vid(plan)
    find = (f"for f in /media/*/{VOLUME_DIR}/vwifi-*.tar.gz; do [ -f \"$f\" ] && echo \"$f\"; done "
            "| sort | tail -n 1")
    new = f"{ROUTER_DIR}.new"
    out += [
        f"wl_vw=$({find})",
        'if [ -z "$wl_vw" ] && d=$(blkid -L WLAPK 2>/dev/null) && [ -n "$d" ]; then '
        'mkdir -p /media/wlapk; mountpoint -q /media/wlapk || mount -o ro "$d" /media/wlapk 2>/dev/null; '
        f"wl_vw=$({find}); fi",
        f'if [ -n "$wl_vw" ] && [ "$(cat {ROUTER_DIR}/.version 2>/dev/null)" != "$(basename "$wl_vw" .tar.gz)" ]; then '
        f'rm -rf {ROUTER_DIR} {new}; mkdir -p {new} && tar -xzf "$wl_vw" -C {new} && mv {new}/vwifi {ROUTER_DIR} '
        f'&& basename "$wl_vw" .tar.gz > {ROUTER_DIR}/.version; rm -rf {new}; fi',
        f"if [ -x {ROUTER_DIR}/bin/vwifi-server ]; then",
        f"  ip netns add {NETNS}",
        f"  ip link add {VETH} type veth peer name eth0 netns {NETNS}",
        f"  ip link set {VETH} master lab0",
        f"  bridge vlan del dev {VETH} vid 1 2>/dev/null || true",
        f"  bridge vlan add dev {VETH} vid {vid} pvid untagged",
        f"  ip link set {VETH} up",
        f"  ip -n {NETNS} link set lo up",
        f"  ip -n {NETNS} addr add {AIR_SERVER}/{AIR_PREFIX} dev eth0",
        f"  ip -n {NETNS} link set eth0 up",
    ]
    for n in mem:
        link = ports.get((n.id, air_card(n)))
        if link is None or not link.fabric_iface or link.plugged:
            out.append(f"  # {n.id}: its radio card has no port on the switch yet")
            continue
        out += [f"  bridge vlan del dev {link.fabric_iface} vid {park_vid(link.port)} 2>/dev/null || true",
                f"  bridge vlan add dev {link.fabric_iface} vid {vid} pvid untagged   # {n.id}: its radio's link to the air"]
    out += [f"  mkdir -p {RUN}",
            f"  ip netns exec {NETNS} {ROUTER_DIR}/bin/vwifi-server > {RUN}/server.log 2>&1 &"]
    out += _write_positions(lab, _layout(lab))   # a here-document: its lines stay unindented
    out += [
        # applied again every few seconds: the server knows a client only
        # while it is connected
        f"  ( while :; do {ctl} loss yes >/dev/null 2>&1; "
        f"while read c x y z rest; do {ctl} set $c $x $y $z >/dev/null 2>&1; done < {RUN}/positions; "
        f"{ctl} ls > {RUN}/ls 2>&1; sleep 5; done ) >/dev/null 2>&1 &",
        f"  echo $! > {RUN}/loop.pid",
        "else",
        "  echo 'vwifi is not on the repository volume (winlab images prepare fabric): the Linux laptops have no air' >&2",
        "fi", ""]
    return out


def _layout(lab) -> dict:
    from .workbench import _auto_layout
    return _auto_layout(lab)


def push(lab, layout: dict | None = None, runner=None) -> str:
    """The canvas positions into the running router's air now (after a
    move): '' when the lab has no real air or the router is off."""
    if not real_air(lab):
        return ""
    from . import power
    run, _why = power._runner(lab.name, runner)
    if not run:
        return ""
    try:
        run("\n".join(_write_positions(lab, layout if layout is not None else _layout(lab))), timeout=15)
    except Exception:  # noqa: BLE001 - the router keeps the old ones; its next start writes them
        return ""
    finally:
        power._close(run)
    return " (the real air too)"


def wants_dhcp(lab, network_id: str) -> bool:
    """A segment an OpenWrt AP on the real air bridges laptops onto: their
    wlan0 asks for an address there, though no lab card on it does."""
    from . import wifi
    if not real_air(lab):
        return False
    return any(lab.segment_id(a["network"]) == network_id
               for a in wifi.aps(lab).values() if a["network"] in lab.networks and a["vendor"] == "openwrt")


def volume_files() -> list[tuple[str, Path]]:
    """What the repository volume carries for the router (apkrepo.build_image)."""
    return [(f"{VOLUME_DIR}/{ASSET}", asset_path())] if ready() else []


def network_config(node, lab) -> dict:
    """The laptop's radio card in its cloud-init network-config: its air
    address, no gateway, no DNS, never waited for at boot."""
    if not wants_air(node):
        return {}
    from .model import stable_mac
    idx = air_card(node)
    mac = node.nics[idx].mac or stable_mac(lab.name, node.id, idx)
    return {f"nic{idx}": {"match": {"macaddress": mac}, "set-name": "air0", "dhcp4": False, "dhcp6": False,
                          "link-local": [], "optional": True,
                          "addresses": [f"{air_ips(lab)[node.id]}/{AIR_PREFIX}"]}}


def sh_env_lines(lab, node) -> list[str]:
    """For a laptop's role: the air's server, its own radio's MAC."""
    if not wants_air(node):
        return []
    return [f"WINLAB_AIR_SERVER={AIR_SERVER}", f"WINLAB_AIR_IP={air_ips(lab)[node.id]}",
            f"WINLAB_RADIO_MAC={radio_mac(lab.name, node.id)}", f"WINLAB_VWIFI={ASSET}"]


# ------------------------------------------------------------------ an OpenWrt AP on the air
def ap_lines(node, lab) -> list[str]:
    """An OpenWrt AP's radio on the real air (openwrt.setup_script), the
    opening of an if/else whose else is the simulated air's radio: the
    programs from its volume, its air card (eth1) addressed and kept out of
    every firewall zone, one software radio with its own MAC, and
    vwifi-client as a service, respawned for ever."""
    ip = air_ips(lab).get(node.id, "")
    mac = radio_mac(lab.name, node.id)
    init = [
        "#!/bin/sh /etc/rc.common",
        "# winlab: this AP's radio on the lab's real air (winlab/vwifi.py)",
        "START=19", "USE_PROCD=1",
        "start_service() {",
        f"  [ -e /sys/class/ieee80211/phy0 ] || vwifi-add-interfaces 1 {mac} >/dev/null 2>&1",
        "  procd_open_instance",
        f"  procd_set_param command /usr/bin/vwifi-client {AIR_SERVER}",
        "  procd_set_param respawn 3600 5 0",
        "  procd_close_instance",
        "}",
    ]
    return [
        "if [ -f $V/vwifi.tar.gz ]; then",
        "  rm -rf /tmp/vw; mkdir -p /tmp/vw /usr/share/vwifi && tar -xzf $V/vwifi.tar.gz -C /tmp/vw && "
        "cp /tmp/vw/vwifi/bin/vwifi-client /tmp/vw/vwifi/bin/vwifi-add-interfaces /usr/bin/ && "
        "cp /tmp/vw/vwifi/LICENSE.md /tmp/vw/vwifi/NOTICE /usr/share/vwifi/; rm -rf /tmp/vw",
        "  uci set network.air=interface", "  uci set network.air.device='eth1'", "  uci set network.air.proto='static'",
        f"  uci set network.air.ipaddr='{ip}'", "  uci set network.air.netmask='255.255.255.0'",
        "  uci commit network; /etc/init.d/network reload >/dev/null 2>&1",
        "  for f in /etc/modules.d/*hwsim*; do echo 'mac80211_hwsim radios=0' > $f; done",
        "  cat > /etc/init.d/winlab-vwifi <<'WINLAB_EOF'", *init, "WINLAB_EOF",
        "  chmod 755 /etc/init.d/winlab-vwifi; /etc/init.d/winlab-vwifi enable",
        f"  if [ \"$(cat /sys/class/ieee80211/phy0/macaddress 2>/dev/null)\" != '{mac}' ]; then",
        "    rmmod mac80211_hwsim 2>/dev/null; insmod mac80211_hwsim radios=0",
        f"    vwifi-add-interfaces 1 {mac} >/dev/null 2>&1; sleep 2",
        "  fi",
        "  if [ -n \"$FIRST\" ] || ! uci -q get wireless.radio0 >/dev/null; then rm -f /etc/config/wireless; wifi config; fi",
        "  /etc/init.d/winlab-vwifi restart >/dev/null 2>&1; wifi >/dev/null 2>&1",
        "else",
    ]


# ------------------------------------------------------------------ the laptop's pack stick
ExtraError = VwifiError


def fetch_extra(pack, d: Path, closure, get, download, say) -> dict:
    """The ``wifi`` pack's file beside its .debs: this build as published
    (the programs, the licence, the NOTICE and the complete source)."""
    import shutil
    src = fetch(progress=say, download=download)
    if src is None:
        raise VwifiError("vwifi has no published build pinned")
    shutil.copyfile(src, d / ASSET)
    return {"files": [ASSET], "install": [], "vwifi": SHORT}


def extra_ready(d: Path, man: dict) -> bool:
    f = d / ASSET
    return f.is_file() and f.stat().st_size == ASSET_SIZE and ASSET in man.get("extra", {}).get("files", [])


# ------------------------------------------------------------------ tickets
# Two Wi-Fi tickets on a laptop on the real air (lessons ts-wifi-saved-key-wrong
# and ts-wifi-band-pinned). Both verify the same thing inside the laptop:
# wlan0 associated with an AP and holding an address that is not link-local.
VERIFY_ON_AIR = ("iw dev wlan0 link 2>/dev/null | grep -q '^Connected to' "
                 "&& ip -4 -o addr show dev wlan0 2>/dev/null | grep ' inet ' | grep -vq ' inet 169\\.254\\.' "
                 "&& echo True || echo False")
# The laptop's saved Wi-Fi profile: NetworkManager's first wireless connection.
_PROFILE = "c=$(nmcli -t -f NAME,TYPE con show 2>/dev/null | awk -F: '$2==\"802-11-wireless\" {print $1; exit}')"
HOST_KEY = "wifi-key-rotated"
QUICK = True


def _air_ap(lab) -> str:
    """The OpenWrt AP on the real air a ticket works with: the first cabled one."""
    from . import wifi
    return next((a["id"] for a in wifi.aps(lab).values()
                 if a["vendor"] == "openwrt" and a["network"] and a["id"] in lab.nodes
                 and wants_air(lab.nodes[a["id"]])), "")


def _new_key() -> str:
    """A fresh WPA2 passphrase for the AP, as the network team would set
    one: random, never written in winlab's code."""
    import secrets
    return "office-" + secrets.token_hex(5)


# On the AP: its first wireless network turned on as WPA2-Personal with the
# key given as $1 (keeping the SSID the student chose; "Office" for one never
# set up), and what it was before.
_AP_ROTATE = r'''i=$(uci show wireless | sed -n 's/^wireless\.\([^.=]*\)=wifi-iface$/\1/p' | head -n 1)
[ -n "$i" ] || { echo 'the AP has no wireless network to change' >&2; exit 1; }
r=$(uci -q get wireless.$i.device)
s=$(uci -q get wireless.$i.ssid); [ -n "$s" ] && [ "$s" != OpenWrt ] || s=Office
echo "SSID=$s"; echo "OLD=$(uci -q get wireless.$i.key)"
uci set wireless.$r.disabled='0'; uci -q delete wireless.$i.disabled
uci set wireless.$i.ssid="$s"; uci set wireless.$i.encryption='psk2'; uci set wireless.$i.key="$1"
uci commit wireless; wifi reload >/dev/null 2>&1; echo rotated
'''
_AP_KEY = r'''i=$(uci show wireless | sed -n 's/^wireless\.\([^.=]*\)=wifi-iface$/\1/p' | head -n 1)
echo "SSID=$(uci -q get wireless.$i.ssid)"; echo "KEY=$(uci -q get wireless.$i.key)"
'''


def laptop_profile(ssid: str, key: str) -> str:
    """On the laptop: its saved profile for the network (made when there is
    none, as a laptop that joined it before would have) holding this key,
    then a try to connect with it."""
    import shlex
    s, k = shlex.quote(ssid), shlex.quote(key)
    return "\n".join([
        _PROFILE,
        f'if [ -z "$c" ]; then nmcli con add type wifi ifname wlan0 con-name {s} ssid {s} '
        f'wifi-sec.key-mgmt wpa-psk wifi-sec.psk {k} >/dev/null && c={s}; '
        f'else nmcli con modify "$c" 802-11-wireless.ssid {s} wifi-sec.key-mgmt wpa-psk wifi-sec.psk {k}; fi',
        'nmcli con modify "$c" connection.autoconnect yes',
        'nmcli con down "$c" >/dev/null 2>&1; nmcli --wait 25 con up "$c" >/dev/null 2>&1; '
        'echo "profile $c: $(nmcli -t -f GENERAL.STATE con show "$c" 2>/dev/null || echo not active)"',
    ])


def _vals(out: str) -> dict[str, str]:
    return {k: v for k, _, v in (ln.strip().partition("=") for ln in str(out or "").splitlines()) if k.isupper()}


def key_rotated_break(lab_name: str, node: str, clear: bool = False, say=lambda _l: None) -> tuple[bool, str]:
    """The saved-key ticket's Break: the network team rotates the AP's
    WPA2 key (a new random one, on the AP itself, over its console), and
    the laptop keeps its profile with the key it had. Clear gives the
    laptop's profile the AP's key."""
    from . import oncall, openwrt, schema
    try:
        lab = schema.load(lab_name)
    except Exception as exc:  # noqa: BLE001 - a lab that does not load cannot be broken
        return False, str(exc)
    ap = _air_ap(lab)
    if not ap:
        return False, f"{lab_name} has no OpenWrt access point on the real air"
    run = oncall.guest_runner(lab_name)
    try:
        if clear:
            got = _vals(openwrt.run(lab_name, ap, _AP_KEY, timeout=30))
            ok, out = run(node, laptop_profile(got.get("SSID") or "Office", got.get("KEY", "")), "sh")
            last = [ln for ln in str(out or "").splitlines() if ln.strip()][-1:] or ["no answer"]
            msg = f"{node}'s profile now has {ap}'s key: {last[0]}"
            say(msg)
            return ok, msg
        new = _new_key()
        got = _vals(openwrt.run(lab_name, ap, f"set -- {new}\n" + _AP_ROTATE, timeout=40))
    except openwrt.OpenWrtError as exc:
        return False, str(exc)
    ssid = got.get("SSID") or "Office"
    old = got.get("OLD") or ""
    if len(old) < 8 or old == new:
        old = _new_key()   # the AP had no key yet: the laptop's profile is from "before"
    ok, _out = run(node, laptop_profile(ssid, old), "sh")
    msg = (f"{ap} now broadcasts {ssid} with a new WPA2 key (the network team's change, in its LuCI); "
           f"{node}'s saved profile still has the old one")
    say(msg)
    return ok, msg


def register_faults(reg) -> None:
    from .guestfaults import LINUX, GuestFault
    reg(GuestFault(
        id="wifi-saved-key-wrong",
        images=("ubuntu",),
        roles=("wifi-laptop",),
        host=HOST_KEY,
        title="The laptop's saved Wi-Fi profile has the key from before the access point's key changed",
        os=LINUX,
        shell="sh",
        teaches="reading NetworkManager and wpa_supplicant when a WPA2-Personal handshake fails, telling a wrong "
                "pre-shared key from an AP that is out of reach, and fixing the saved profile instead of making a "
                "second one",
        symptom="the laptop connected to the office Wi-Fi yesterday; today it sees the network, tries, and keeps "
                "asking for the password",
        apply="echo 'this problem is set from outside the laptop: winlab break <laptop> wifi-saved-key-wrong "
              "changes the access point key'",
        clear="echo 'give the saved profile the access point key: nmcli con modify <profile> wifi-sec.psk <key>'",
        hints=(
            "Is it the radio or the key? nmcli dev wifi list shows the network with good bars, and iw dev wlan0 "
            "scan dump lists its beacon, so the laptop hears the AP.",
            "Read the supplicant: journalctl -u NetworkManager -u wpa_supplicant -n 40. '4-Way Handshake failed - "
            "pre-shared key may be incorrect' after message 1 of 4 is the AP turning the laptop's key down.",
            "Find the key in force on the AP (LuCI, Network > Wireless, Edit, Wireless Security), then change the "
            "saved profile: nmcli con modify <profile> wifi-sec.psk <key> and nmcli con up <profile>. Do not add a "
            "second profile for the same SSID.",
        ),
        verify=VERIFY_ON_AIR,
    ))
    reg(GuestFault(
        id="wifi-band-pinned",
        images=("ubuntu",),
        roles=("wifi-laptop",),
        title="The laptop's Wi-Fi profile is pinned to the band the access point does not use",
        os=LINUX,
        shell="sh",
        teaches="2.4 GHz and 5 GHz, channels and bands as a client sees them (nmcli, iw), and a profile setting "
                "that hides a network the radio hears perfectly well",
        symptom="since a colleague 'made the Wi-Fi faster' on the laptop it says the office network is not found, "
                "though other people's laptops in the same room connect",
        apply="\n".join([
            _PROFILE,
            "[ -n \"$c\" ] || { echo 'no saved Wi-Fi profile on this laptop: join the network first "
            "(lesson wifi-linux-real-air)' >&2; exit 1; }",
            # the other band than the one it is on (5 GHz when it is not connected)
            "f=$(iw dev wlan0 link 2>/dev/null | awk '/freq:/ {print int($2)}')",
            "if [ -n \"$f\" ] && [ \"$f\" -ge 5000 ]; then b=bg; else b=a; fi",
            "nmcli con modify \"$c\" 802-11-wireless.band $b",
            "nmcli con down \"$c\" >/dev/null 2>&1; nmcli --wait 15 con up \"$c\" >/dev/null 2>&1; "
            "echo \"profile $c pinned to band $b\"",
        ]),
        clear="\n".join([
            _PROFILE,
            "nmcli con modify \"$c\" 802-11-wireless.band '' 802-11-wireless.channel 0 && "
            "nmcli --wait 25 con up \"$c\" >/dev/null 2>&1; echo \"profile $c: any band\"",
        ]),
        hints=(
            "Compare what the radio hears with what the profile asks for: nmcli -f SSID,CHAN,FREQ,SIGNAL dev wifi "
            "list shows the office network, and on which channel and frequency.",
            "nmcli -f 802-11-wireless.band,802-11-wireless.channel con show <profile>: a is 5 GHz, bg is 2.4 GHz. "
            "wpa_supplicant then scans only that band and never finds an AP on the other one.",
            "Clear the pin: nmcli con modify <profile> 802-11-wireless.band '' (or the AP's band), then nmcli con up "
            "<profile>. iw dev wlan0 link shows the frequency it joined on.",
        ),
        verify=VERIFY_ON_AIR,
    ))
