"""Wi-Fi on the workbench: access points and the laptops that join them.

An access point is cabled to a switch port like any device (it takes its
power over that cable, as a ceiling AP does over PoE, so one with no cable
is off) and puts the wireless clients it lets in on that port's VLAN. It
broadcasts one network name (SSID), open, WPA2-Personal or WPA2-Enterprise
(802.1X against the student's RADIUS server, winlab/wpaent.py), on a channel.

Each AP is a real OpenWrt access point (winlab/openwrt.py): a small VM,
cabled into the switch port, whose own web pages (LuCI, on its address on
the VLAN) are where the network name, security, key, channel and RADIUS
server are set, exactly as on a real one. QEMU has no Wi-Fi card, so the
air between the APs and the laptops stays winlab's: winlab reads the AP's
/etc/config/wireless over its console (read_ap) and drives what follows
from it (apply_wireless). A new AP is OpenWrt out of the box: its radio
disabled, so it broadcasts nothing until the student turns it on in LuCI.

A laptop's wireless card is a real network card of the machine. Where the
laptop stands on the canvas decides what it hears: every AP within range,
with fewer bars the further away it is. Joining checks the network security
key the way Windows does; the laptop then keeps a profile, and when it is
carried out of range it roams to another AP with the same name it knows,
or drops off the network. Inside the laptop Windows sees the card connect
and disconnect, gets its address from the AP's VLAN, and changes subnet if
it roams onto an AP on another VLAN, as a real one would. (The air itself
is simulated: QEMU has no wireless card, so Windows lists the card as a
network adapter, and the Wi-Fi is joined on the laptop's panel.)

APs live in the lab's ``[devices."ap:<id>"]`` tables (the cable, the
AP's address, and what was last read from its wireless configuration) and
sit on the canvas at ``layout."ap:<id>"``; a laptop's cards and profiles
are in its vars. The AP's VM is made from that table each time the lab is
loaded (vm_nodes), never written to the lab file.
"""

from __future__ import annotations

import json
import math
import re

from . import editor

PREFIX = "ap:"
# Canvas geometry the range is measured on (the page draws the same boxes).
AP_W, AP_H = 96, 64
MACHINE_W, MACHINE_H = 128, 104
RANGE = 340                       # 2.4 GHz, in canvas units
RANGE_5GHZ = 260                  # 5 GHz carries less far through walls
CHANNELS_24 = list(range(1, 12))
CHANNELS_5 = [36, 40, 44, 48]
SECURITY = ("wpa2", "wpa2-ent", "open")
ENT = "802.1X"                    # an Enterprise network's profile: no key, Windows' 802.1X signs in
SSID_RE = re.compile(r"^[\x20-\x7e]{1,32}$")
MAX_APS = 16


class WifiError(Exception):
    pass


# ------------------------------------------------------------------ APs
def aps(lab) -> dict[str, dict]:
    """The access points, by id: their settings with defaults filled in."""
    out = {}
    for key, own in sorted(lab.devices.items()):
        if key.startswith(PREFIX):
            ap_id = key[len(PREFIX):]
            out[ap_id] = {"id": ap_id, "ssid": own.get("ssid") or ap_id, "security": own.get("security") or "wpa2",
                          "key": own.get("key", ""), "network": own.get("network", ""),
                          "channel": int(own.get("channel") or 6), "name": own.get("hostname") or ap_id,
                          # A table from before the APs ran OpenWrt has no radio
                          # key: its settings stand until the AP is first read.
                          "radio": own.get("radio", "on"), "seen": own.get("seen", ""), "iface": own.get("iface", ""),
                          **_radius(own)}
    return out


def _radius(own: dict) -> dict:
    """WPA2-Enterprise: the RADIUS server the AP asks, its shared secret,
    and the AP's own address (where its requests come from)."""
    ip, port = (str(own.get("radius") or "").split() + ["", ""])[:2]
    return {"radius": ip, "radius_port": int(port) if port.isdigit() else 1812,
            "radius_key": own.get("radius-key", ""), "ip": own.get("ip", "")}


def _own(lab, ap_id: str) -> dict:
    if PREFIX + ap_id not in lab.devices:
        raise WifiError(f"no access point {ap_id!r}")
    return lab.devices[PREFIX + ap_id]


FACTORY = {"radio": "off", "ssid": "OpenWrt", "security": "open", "channel": "1"}  # OpenWrt out of the box
SETTINGS = ("ssid", "security", "key", "channel", "radius", "radius_port", "radius_key")


def add_ap(lab, pos: list[int] | None = None, ap_id: str = "") -> str:
    have = aps(lab)
    if len(have) >= MAX_APS:
        raise WifiError(f"a network here takes at most {MAX_APS} access points")
    if not ap_id:
        ap_id = next(f"ap{i:02d}" for i in range(1, 100)
                     if f"ap{i:02d}" not in have and f"ap{i:02d}" not in lab.nodes)
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,15}", ap_id) or ap_id in have or ap_id in lab.nodes:
        raise WifiError(f"{ap_id!r} is not a free name for an access point")
    # A new AP is what comes out of the box: OpenWrt's defaults, its radio
    # off. The student sets it up in its own web pages (LuCI).
    lab.devices[PREFIX + ap_id] = dict(FACTORY)
    if pos:
        lab.layout[PREFIX + ap_id] = list(pos)
    return ap_id


def set_ap(lab, ap_id: str, **changes) -> dict:
    """The AP's cable: network (a switch VLAN, "" = no cable). Its Wi-Fi
    settings are the AP's own (LuCI); apply_wireless takes what it says."""
    own = _own(lab, ap_id)
    if any(changes.get(k) not in (None, "") for k in SETTINGS + ("ip",)):
        raise WifiError("the access point's Wi-Fi settings are set in its own web pages (LuCI): "
                        "type its address into a browser on a lab PC")
    return _set(lab, ap_id, own, changes)


def _set(lab, ap_id: str, own: dict, changes: dict) -> dict:
    if "network" in changes and changes["network"] is not None:
        net = str(changes["network"])
        if net and net not in lab.networks:
            raise WifiError(f"no switch {net!r} on the canvas")
        if net:
            own["network"] = net
            _address(lab, own, net)
        else:
            own.pop("network", None)
    vm_nodes(lab)
    return aps(lab)[ap_id]


def _address(lab, own: dict, net: str) -> None:
    """The AP's management address on its VLAN: kept while it fits, else
    one from the top of the subnet (the lab's wiring, like a server's)."""
    import ipaddress
    from . import openwrt
    ip = own.get("ip", "")
    try:
        if ip and ipaddress.ip_address(ip) in lab.networks[net].net:
            return
    except ValueError:
        pass
    own.pop("ip", None)
    own["ip"] = openwrt.free_ip(lab, net)


def apply_wireless(lab, ap_id: str, wireless: str, network: str = "", when: str = "") -> list[str]:
    """What the AP's own configuration says (its /etc/config/wireless, and
    /etc/config/network for its address) into the air: returns what it
    now broadcasts, in words, when that changed."""
    from . import openwrt
    own = _own(lab, ap_id)
    cfg = openwrt.wireless_settings(wireless)
    new = {"radio": cfg["radio"], "ssid": cfg["ssid"], "security": cfg["security"], "channel": str(cfg["channel"]),
           "iface": cfg.get("iface")}
    if cfg["security"] == "wpa2" and cfg["key"]:
        new["key"] = cfg["key"]
    if cfg["security"] == "wpa2-ent":
        if cfg["radius"]:
            new["radius"] = f"{cfg['radius']} {cfg['radius_port']}"
        if cfg["radius_key"]:
            new["radius-key"] = cfg["radius_key"]
    before = aps(lab).get(ap_id, {})
    changed = False
    for k in ("radio", "ssid", "security", "key", "channel", "radius", "radius-key", "iface"):
        if own.get(k) != new.get(k):
            changed = changed or k != "iface"
            if new.get(k) is None:
                own.pop(k, None)
            else:
                own[k] = new[k]
    lan = openwrt.lan_address(network) if network else ""
    if lan and lan != own.get("ip"):
        own["ip"] = lan
        changed = True
    if when:
        own["seen"] = when
    if not changed:
        return []
    after = aps(lab)[ap_id]
    if after["radio"] == "off":
        return [f"{after['name']}: its radio is off" + ("" if before.get("radio") == "on" else " (as OpenWrt ships)")]
    sec = {"wpa2": "WPA2-Personal", "wpa2-ent": "WPA2-Enterprise"}.get(after["security"], "open")
    return [f"{after['name']} broadcasts {after['ssid']} ({sec}), channel {after['channel']}"]


def vm_nodes(lab) -> None:
    """Each cabled AP's OpenWrt VM in lab.nodes (an AP with no cable has no
    power, so no VM); a VM whose AP is gone or unplugged goes."""
    from . import openwrt
    have = aps(lab)
    for nid in [n.id for n in lab.nodes.values() if openwrt.role_of(n) == "ap"]:
        if nid not in have or not have[nid]["network"]:
            del lab.nodes[nid]
    for ap_id, ap in have.items():
        if not ap["network"] or ap["network"] not in lab.networks:
            continue
        old = lab.nodes.get(ap_id)
        if old is not None and openwrt.role_of(old) != "ap":
            continue  # a machine of that name: the AP keeps no VM
        own = lab.devices[PREFIX + ap_id]
        if not own.get("ip"):
            _address(lab, own, ap["network"])
        lab.nodes[ap_id] = openwrt.device_vm(ap_id, "ap", ap["network"], own["ip"], own.get("hostname", ""))


def read_ap(lab_name: str, ap_id: str) -> tuple[str, str]:
    """The AP's /etc/config/wireless and /etc/config/network, over its
    console (raises openwrt.OpenWrtError when it is off or starting)."""
    from . import openwrt
    return openwrt.split_read(openwrt.run(lab_name, ap_id, openwrt.READ_AP))


def remove_ap(lab, ap_id: str) -> None:
    _own(lab, ap_id)
    del lab.devices[PREFIX + ap_id]
    lab.layout.pop(PREFIX + ap_id, None)
    vm_nodes(lab)


def on_switch(lab, home: str) -> list[str]:
    """The APs cabled into a switch (any of its VLANs)."""
    family = {n.id for n in lab.networks.values() if n.home == home}
    return [a["id"] for a in aps(lab).values() if a["network"] in family]


def band(channel: int) -> str:
    return "5 GHz" if channel >= 36 else "2.4 GHz"


def interference(lab, layout: dict) -> dict[str, list[str]]:
    """Per AP, the APs near enough on an overlapping channel to slow both
    down: two 2.4 GHz channels overlap unless they are 5 apart (1, 6, 11)."""
    live = [a for a in aps(lab).values() if a["network"]]
    out: dict[str, list[str]] = {a["id"]: [] for a in aps(lab).values()}
    for i, a in enumerate(live):
        for b in live[i + 1:]:
            if band(a["channel"]) != band(b["channel"]):
                continue
            overlap = abs(a["channel"] - b["channel"]) < (5 if a["channel"] < 36 else 4)
            if overlap and _dist(layout, PREFIX + a["id"], PREFIX + b["id"]) < 1.5 * _reach(a):
                out[a["id"]].append(b["id"])
                out[b["id"]].append(a["id"])
    return out


# ------------------------------------------------------------------ distance
def _centre(layout: dict, key: str) -> tuple[float, float] | None:
    pos = layout.get(key)
    if not pos:
        return None
    w, h = (AP_W, AP_H) if key.startswith(PREFIX) else (MACHINE_W, MACHINE_H)
    return pos[0] + w / 2, pos[1] + h / 2


def _dist(layout: dict, a: str, b: str) -> float:
    pa, pb = _centre(layout, a), _centre(layout, b)
    if pa is None or pb is None:
        return math.inf
    return math.hypot(pa[0] - pb[0], pa[1] - pb[1])


def _reach(ap: dict) -> int:
    return RANGE_5GHZ if ap["channel"] >= 36 else RANGE


def bars(layout: dict, ap: dict, node_id: str) -> int:
    """0 (out of range) to 4 bars, as the laptop hears ``ap``."""
    if not ap["network"] or ap.get("radio") == "off":
        return 0  # no cable, no power; or its radio is disabled
    r = _dist(layout, PREFIX + ap["id"], node_id) / _reach(ap)
    return 4 if r <= .35 else 3 if r <= .6 else 2 if r <= .8 else 1 if r <= 1 else 0


# ------------------------------------------------------------------ laptops
def wireless(node) -> list[int]:
    """The machine's wireless cards (nic indexes)."""
    out = []
    for tok in str(node.vars.get("wireless") or "").split():
        if tok.isdigit() and int(tok) < len(node.nics):
            out.append(int(tok))
    return out


def card(node) -> int:
    w = wireless(node)
    if not w:
        raise WifiError(f"{node.id} has no wireless card")
    return w[0]


def profiles(node) -> dict[str, str]:
    """Networks the laptop has joined and remembers: {ssid: key}."""
    try:
        data = json.loads(str(node.vars.get("wifi_profiles") or "{}"))
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except ValueError:
        return {}


def _set_profiles(node, data: dict[str, str]) -> None:
    if data:
        node.vars["wifi_profiles"] = json.dumps(data, sort_keys=True)
    else:
        node.vars.pop("wifi_profiles", None)


def joined(lab, node) -> str:
    """The AP the laptop is on now, or ""."""
    ap_id = str(node.vars.get("wifi_ap") or "")
    return ap_id if ap_id in aps(lab) else ""


def heard(lab, layout: dict, node) -> list[dict]:
    """The networks the laptop hears, strongest first (one row per SSID,
    with the best AP for it)."""
    best: dict[str, dict] = {}
    for ap in aps(lab).values():
        b = bars(layout, ap, node.id)
        if b and (ap["ssid"] not in best or b > best[ap["ssid"]]["bars"]):
            best[ap["ssid"]] = {"ssid": ap["ssid"], "ap": ap["id"], "bars": b, "security": ap["security"],
                                "channel": ap["channel"], "band": band(ap["channel"])}
    return sorted(best.values(), key=lambda x: (-x["bars"], x["ssid"]))


def _attach(lab, node, ap: dict) -> None:
    idx = card(node)
    nic = node.nics[idx]
    if nic.network != ap["network"]:
        editor.cable(lab, node.id, idx, ap["network"])
    node.vars["wifi_ap"] = ap["id"]


def _detach(lab, node) -> None:
    idx = card(node)
    if node.nics[idx].plugged:
        editor.unplug(lab, node.id, idx)
    node.vars.pop("wifi_ap", None)


def join(lab, layout: dict, node_id: str, ssid: str, key: str = "") -> str:
    node = lab.nodes.get(node_id)
    if node is None:
        raise WifiError(f"no machine {node_id!r}")
    card(node)
    cands = [ap for ap in aps(lab).values() if ap["ssid"] == ssid and bars(layout, ap, node_id)]
    if not cands:
        raise WifiError(f"{node_id} does not hear a network called {ssid!r} here: move it closer to an AP")
    ap = max(cands, key=lambda a: bars(layout, a, node_id))
    known = profiles(node)
    if ap["security"] == "wpa2":
        key = key or known.get(ssid, "")
        if key != ap["key"]:
            raise WifiError("the network security key isn't correct")
    known[ssid] = key if ap["security"] == "wpa2" else ENT if ap["security"] == "wpa2-ent" else ""
    _set_profiles(node, known)
    _attach(lab, node, ap)
    n = bars(layout, ap, node_id)
    ent = ("; it passes nothing but 802.1X until the RADIUS server lets Windows' sign-in through"
           if ap["security"] == "wpa2-ent" else "")
    return (f"{node_id} connected to {ssid} through {ap['name']} ({n} bar{'' if n == 1 else 's'}, "
            f"channel {ap['channel']}){ent}")


def leave(lab, node_id: str, forget: bool = False) -> str:
    node = lab.nodes.get(node_id)
    if node is None:
        raise WifiError(f"no machine {node_id!r}")
    ap_id = joined(lab, node)
    ssid = aps(lab)[ap_id]["ssid"] if ap_id else ""
    _detach(lab, node)
    if forget:
        known = profiles(node)
        known.pop(ssid, None)
        _set_profiles(node, known)
    return f"{node_id} disconnected" + (f" from {ssid}" if ssid else "") + (" and forgot it" if forget else "")


def _usable(ap: dict, known: dict[str, str]) -> bool:
    if ap["ssid"] not in known:
        return False
    if ap["security"] == "wpa2-ent":
        return known[ap["ssid"]] == ENT
    return ap["security"] == "open" or known[ap["ssid"]] == ap["key"]


def settle(lab, layout: dict) -> list[str]:
    """After anything moved or changed: every laptop is on the AP it would
    be on now. One out of range roams to the strongest AP it has a working
    profile for, or drops off; one whose AP changed VLAN follows it."""
    said = []
    every = aps(lab)
    for node in lab.node_list():
        if not wireless(node):
            continue
        known = profiles(node)
        cur = every.get(str(node.vars.get("wifi_ap") or ""))
        cur_bars = bars(layout, cur, node.id) if cur else 0
        ok = cur is not None and cur_bars > 0 and _usable(cur, known)
        better = max((ap for ap in every.values() if _usable(ap, known) and bars(layout, ap, node.id)),
                     key=lambda a: bars(layout, a, node.id), default=None)
        # Windows roams when the signal gets weak and a better AP is there.
        if ok and cur_bars <= 1 and better and bars(layout, better, node.id) >= cur_bars + 2:
            ok = False
        if ok:
            if node.nics[card(node)].network != cur["network"]:
                _attach(lab, node, cur)
                said.append(f"{node.id} follows {cur['name']} onto {cur['network']}")
            continue
        if better is not None:
            moved = cur is not None and better["id"] != cur["id"]
            _attach(lab, node, better)
            if moved or cur is None:
                said.append(f"{node.id} {'roamed' if moved else 'connected'} to {better['ssid']} "
                            f"through {better['name']}")
        elif cur is not None or node.nics[card(node)].plugged:
            _detach(lab, node)
            why = ": out of range" if cur is not None and not cur_bars else ""
            said.append(f"{node.id} lost the Wi-Fi{why}")
    return said


def clients(lab, ap_id: str) -> list[str]:
    return [n.id for n in lab.node_list() if wireless(n) and str(n.vars.get("wifi_ap") or "") == ap_id]


# ------------------------------------------------------------------ its own pages
def _targets(lab) -> list:
    """Each cabled AP's LuCI, on its address (winlab/adminui.py)."""
    from . import adminui, openwrt
    return [adminui.Target(key=PREFIX + ap["id"], title=f"{ap['name']} (OpenWrt access point)", host=ap["ip"],
                           gui=openwrt.luci("ap"))
            for ap in aps(lab).values() if ap["network"] and ap["ip"]]


def _register() -> None:
    from . import adminui
    adminui.register(targets=_targets)


_register()
