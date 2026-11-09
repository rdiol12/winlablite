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
# Channel width and transmit power, as LuCI sets them (option htmode and
# option txpower). The range circles above are an AP at full power on a
# 20 MHz channel. Indoors a signal falls off about 30 dB per tenfold distance
# (log-distance exponent 3, the same office model as the site survey in
# winlab/campus.py), so every dB less power shrinks the reach by 10^(1/30);
# each doubling of the width spreads the same power over twice the
# spectrum, which costs about 3 dB at the receiver. An AP's neighbours hear
# it, and wait for it, well beyond where a laptop gets a usable signal:
# HEAR (the reach times 1.5) is that distance, and CELL (0.8, the edge of
# two bars, about -67 dBm) is where a client still works well, the edge a
# roaming plan overlaps.
MAX_TXPOWER = 20                  # dBm: the radio's full power (LuCI's "driver default")
WIDTHS = (20, 40, 80, 160)
HEAR = 1.5
CELL = 0.8
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
                          "width": _int_in(own.get("width"), WIDTHS, 20),
                          "txpower": _power(own.get("txpower")),
                          # A table from before the APs ran OpenWrt has no radio
                          # key: its settings stand until the AP is first read.
                          "radio": own.get("radio", "on"), "seen": own.get("seen", ""), "iface": own.get("iface", ""),
                          "vendor": own.get("vendor") or "openwrt", **_radius(own)}
            out[ap_id]["wlans"] = _wlans(own, out[ap_id])
    return out


def _wlans(own: dict, ap: dict) -> list[dict]:
    """Every network the AP broadcasts: [{ssid, security, key, channel,
    radius, radius_port, radius_key, hidden}]. The first is the AP's own
    fields (what one-network code reads); a vendor AP adds more, read from
    its configuration as JSON."""
    if ap["radio"] == "off":
        return []
    try:
        more = json.loads(str(own.get("wlans") or "[]"))
    except ValueError:
        more = []
    if isinstance(more, list) and more:
        out = []
        for w in more:
            if not isinstance(w, dict) or not w.get("ssid"):
                continue
            out.append({"ssid": str(w["ssid"]), "security": str(w.get("security") or "open"), "key": str(w.get("key") or ""),
                        "channel": int(w.get("channel") or ap["channel"]),
                        "width": _int_in(w.get("width"), WIDTHS, ap["width"]),
                        "txpower": _power(w.get("txpower")) if w.get("txpower") else ap["txpower"],
                        "radius": str(w.get("radius") or ""),
                        "radius_port": int(w.get("radius_port") or 1812), "radius_key": str(w.get("radius_key") or ""),
                        "hidden": bool(w.get("hidden"))})
        if out:
            return out
    return [{k: ap[k] for k in ("ssid", "security", "key", "channel", "width", "txpower", "radius", "radius_port",
                                "radius_key")} | {"hidden": False}]


def _int_in(v, allowed, default: int) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return n if n in allowed else default


def _power(v) -> int:
    """Transmit power in dBm: what LuCI saved, at most the radio's full
    power; nothing (or 0, the driver's default) is full power."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return MAX_TXPOWER
    return MAX_TXPOWER if n <= 0 else min(n, MAX_TXPOWER)


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


VENDORS = {"openwrt": "OpenWrt (LuCI)", "ruckus": "Ruckus Unleashed", "aruba": "Aruba Instant",
           "cisco": "Cisco Catalyst EWC", "mikrotik": "MikroTik RouterOS", "unifi": "Ubiquiti UniFi",
           "wlc": "Cisco Catalyst 9800 WLC", "lap": "Cisco lightweight AP"}
MODELS = {"openwrt": "OpenWrt", "ruckus": "R650", "aruba": "AP-515", "cisco": "C9130AXI", "mikrotik": "hAP ax2",
          "unifi": "UAP-AC-Pro", "wlc": "C9800-L", "lap": "C9120AXI"}


def add_ap(lab, pos: list[int] | None = None, ap_id: str = "", vendor: str = "openwrt") -> str:
    if vendor not in VENDORS:
        raise WifiError(f"no access point maker {vendor!r}: " + ", ".join(VENDORS))
    have = aps(lab)
    if len(have) >= MAX_APS:
        raise WifiError(f"a network here takes at most {MAX_APS} access points")
    if not ap_id:
        pre = "wlc" if vendor == "wlc" else "ap"   # a controller is named like one
        ap_id = next(f"{pre}{i:02d}" for i in range(1, 100)
                     if f"{pre}{i:02d}" not in have and f"{pre}{i:02d}" not in lab.nodes)
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,15}", ap_id) or ap_id in have or ap_id in lab.nodes:
        raise WifiError(f"{ap_id!r} is not a free name for an access point")
    # A new AP is what comes out of the box: OpenWrt's defaults, its radio
    # off. The student sets it up in its own web pages (LuCI).
    lab.devices[PREFIX + ap_id] = dict(FACTORY)
    if vendor != "openwrt":
        # A vendor's AP (winlab/apos): its own CLI and web pages over the
        # same OpenWrt radio; until it is read, it broadcasts nothing known.
        lab.devices[PREFIX + ap_id]["vendor"] = vendor
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
    # Width and power only when LuCI moved them off 20 MHz and full power,
    # so an AP nobody tuned keeps the table it always had.
    if int(cfg.get("width") or 20) != 20:
        new["width"] = str(cfg["width"])
    if 0 < int(cfg.get("txpower") or 0) < MAX_TXPOWER:
        new["txpower"] = str(cfg["txpower"])
    air = cfg.get("wlans") or []
    if cfg["radio"] == "on" and len(air) > 1:
        new["wlans"] = json.dumps(air, sort_keys=True)
    if cfg["security"] == "wpa2" and cfg["key"]:
        new["key"] = cfg["key"]
    if cfg["security"] == "wpa2-ent":
        if cfg["radius"]:
            new["radius"] = f"{cfg['radius']} {cfg['radius_port']}"
        if cfg["radius_key"]:
            new["radius-key"] = cfg["radius_key"]
    before = aps(lab).get(ap_id, {})
    changed = False
    for k in ("radio", "ssid", "security", "key", "channel", "width", "txpower", "radius", "radius-key", "iface",
              "wlans"):
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
    sec = {"wpa2": "WPA2-Personal", "wpa2-ent": "WPA2-Enterprise"}
    said = "; ".join(f"{w['ssid']} ({sec.get(w['security'], 'open')}), channel {w['channel']}"
                     + (f" at {w['width']} MHz" if w.get("width", 20) != 20 else "")
                     + (f", {w['txpower']} dBm" if w.get("txpower", MAX_TXPOWER) < MAX_TXPOWER else "")
                     for w in _unique(after["wlans"]))
    return [f"{after['name']} broadcasts {said}"]


def _unique(wlans: list[dict]) -> list[dict]:
    seen, out = set(), []
    for w in wlans:
        if (w["ssid"], w["channel"]) not in seen:
            seen.add((w["ssid"], w["channel"]))
            out.append(w)
    return out


def vm_nodes(lab) -> None:
    """Each cabled AP's OpenWrt VM in lab.nodes (an AP with no cable has no
    power, so no VM); a VM whose AP is gone or unplugged goes."""
    from . import openwrt, vwifi
    have = aps(lab)
    real = vwifi.real_air(lab)
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
        # In a lab with a Linux laptop on the real air (winlab/vwifi.py), an
        # OpenWrt AP joins it; a vendor AP keeps the simulated air.
        lab.nodes[ap_id] = openwrt.device_vm(ap_id, "ap", ap["network"], own["ip"], own.get("hostname", ""),
                                             vendor=ap["vendor"] if ap["vendor"] != "openwrt" else "",
                                             air=ap["vendor"] == "openwrt" and real)


def read_ap(lab_name: str, ap_id: str, clients_json: str = "") -> tuple[str, str]:
    """The AP's /etc/config/wireless and /etc/config/network, over its
    console (raises openwrt.OpenWrtError when it is off or starting). With
    ``clients_json`` the same visit leaves the AP the list of who is on it
    (a vendor AP's CLI and pages show it)."""
    from . import openwrt
    script = openwrt.READ_AP
    if clients_json:
        script = (f"cat > /tmp/winlab-clients.json <<'WINLAB_EOF'\n{clients_json}\nWINLAB_EOF\n") + script
    return openwrt.split_read(openwrt.run(lab_name, ap_id, script))


def client_rows(lab, layout: dict, ap_id: str) -> list[dict]:
    """Who is on the AP, as the AP's own client table shows them: host
    name, MAC, the network and channel, signal bars (winlab's air)."""
    from .naming import hostname_of
    every = aps(lab)
    ap = every.get(ap_id)
    out = []
    if ap is None:
        return out
    for n in lab.node_list():
        if not wireless(n) or str(n.vars.get("wifi_ap") or "") != ap_id:
            continue
        ssid = str(n.vars.get("wifi_ssid") or ap["ssid"])
        w = _wlan_of(ap, ssid) or (ap["wlans"][0] if ap["wlans"] else None)
        ch = w["channel"] if w else ap["channel"]
        out.append({"name": hostname_of(n), "mac": n.nics[card(n)].mac or "", "ssid": ssid,
                    "band": "5g" if ch >= 36 else "2g", "channel": ch, "bars": bars(layout, ap, n.id, ch)})
    return out


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


def span(channel: int, width: int = 20) -> tuple[int, int]:
    """The spectrum a radio occupies, in MHz (low, high). 2.4 GHz channels
    are 5 MHz apart and a transmission is about 22 MHz wide, so only 1, 6
    and 11 stay clear of each other; a 40 MHz 2.4 GHz channel adds the
    channel four above (four below from 8 up). 5 GHz channels are 20 MHz
    apart and bond into fixed blocks: 40 MHz is 36+40 or 44+48, 80 MHz is
    36 to 48, 160 MHz 36 to 64 (and the same from 100 and from 149)."""
    if channel < 36:
        f = 2407 + 5 * channel
        if width >= 40:
            g = f + 20 if channel <= 7 else f - 20
            return min(f, g) - 11, max(f, g) + 11
        return f - 11, f + 11
    base = 149 if channel >= 149 else 100 if channel >= 100 else 36
    step = max(4, width // 5)
    lo = base + (channel - base) // step * step
    return 5000 + 5 * lo - 10, 5000 + 5 * lo - 10 + max(width, 20)


def channels_overlap(a: int, wa: int, b: int, wb: int) -> bool:
    """Whether two radios share any spectrum (the same band, spans that
    meet)."""
    if band(a) != band(b):
        return False
    la, ha = span(a, wa)
    lb, hb = span(b, wb)
    return la < hb and lb < ha


def radios(ap: dict) -> list[dict]:
    """The AP's radios on the air: one per channel it transmits on, with
    its width and power (a vendor AP's networks on one band share one)."""
    out, seen = [], set()
    for w in ap.get("wlans") or []:
        k = (w["channel"], w.get("width", 20))
        if k not in seen:
            seen.add(k)
            out.append({"channel": w["channel"], "width": w.get("width", 20),
                        "txpower": w.get("txpower", ap.get("txpower", MAX_TXPOWER))})
    return out or [{"channel": ap["channel"], "width": ap.get("width", 20),
                    "txpower": ap.get("txpower", MAX_TXPOWER)}]


def reach(channel: int, width: int = 20, txpower: int = MAX_TXPOWER) -> float:
    """How far (canvas units) a laptop hears one radio at all: the band's
    range, less for lower power and for a wider channel (see MAX_TXPOWER)."""
    base = RANGE_5GHZ if channel >= 36 else RANGE
    db = (min(txpower, MAX_TXPOWER) - MAX_TXPOWER) - 3 * math.log2(max(width, 20) / 20)
    return base * 10 ** (db / 30)


def interference(lab, layout: dict) -> dict[str, list[str]]:
    """Per AP, the APs near enough on an overlapping channel to slow both
    down: they hear each other (HEAR times the reach of the louder one) on
    spectrum that overlaps. 2.4 GHz channels overlap unless they are 5
    apart (1, 6, 11); 5 GHz ones overlap when their widths bond them into
    the same block."""
    live = [a for a in aps(lab).values() if a["network"] and a["vendor"] != "wlc"   # a controller has no radio
            and a.get("radio") != "off"]
    out: dict[str, list[str]] = {a["id"]: [] for a in aps(lab).values()}
    for i, a in enumerate(live):
        for b in live[i + 1:]:
            d = _dist(layout, PREFIX + a["id"], PREFIX + b["id"])
            if any(channels_overlap(ra["channel"], ra["width"], rb["channel"], rb["width"])
                   and d < HEAR * max(reach(**ra), reach(**rb))
                   for ra in radios(a) for rb in radios(b)):
                out[a["id"]].append(b["id"])
                out[b["id"]].append(a["id"])
    return out


def cell(ap: dict) -> float:
    """The AP's usable cell (canvas units): where a laptop still has two
    bars on its first radio. A roaming plan overlaps neighbours' cells."""
    return CELL * reach(**radios(ap)[0])


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


def _reach(ap: dict, channel: int | None = None) -> float:
    """The AP's reach on one of its channels (its first when not given),
    with that radio's width and power."""
    ch = channel if channel is not None else ap["channel"]
    r = next((x for x in radios(ap) if x["channel"] == ch), None)
    if r is None:
        return reach(ch, ap.get("width", 20), ap.get("txpower", MAX_TXPOWER))
    return reach(**r)


def bars(layout: dict, ap: dict, node_id: str, channel: int | None = None) -> int:
    """0 (out of range) to 4 bars, as the laptop hears ``ap`` (on one of
    its networks' channels: 5 GHz carries less far)."""
    if not ap["network"] or ap.get("radio") == "off":
        return 0  # no cable, no power; or its radio is disabled
    r = _dist(layout, PREFIX + ap["id"], node_id) / _reach(ap, channel)
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


def _wlan_of(ap: dict, ssid: str) -> dict | None:
    """The AP's network called ``ssid`` (the first, when it is on both bands)."""
    return next((w for w in ap.get("wlans", []) if w["ssid"] == ssid), None)


def _signals(lab, layout: dict, node_id: str):
    """(bars, ap, wlan) for every network the laptop hears from every AP."""
    for ap in aps(lab).values():
        for w in ap.get("wlans", []):
            b = bars(layout, ap, node_id, w["channel"])
            if b:
                yield b, ap, w


def heard(lab, layout: dict, node) -> list[dict]:
    """The networks the laptop hears, strongest first (one row per SSID,
    with the best AP and band for it). A hidden network is not listed."""
    best: dict[str, dict] = {}
    for b, ap, w in _signals(lab, layout, node.id):
        if w.get("hidden"):
            continue
        if w["ssid"] not in best or b > best[w["ssid"]]["bars"]:
            best[w["ssid"]] = {"ssid": w["ssid"], "ap": ap["id"], "bars": b, "security": w["security"],
                               "channel": w["channel"], "band": band(w["channel"])}
    return sorted(best.values(), key=lambda x: (-x["bars"], x["ssid"]))


def _attach(lab, node, ap: dict, ssid: str = "") -> None:
    idx = card(node)
    nic = node.nics[idx]
    if nic.network != ap["network"]:
        editor.cable(lab, node.id, idx, ap["network"])
    node.vars["wifi_ap"] = ap["id"]
    if ssid and ssid != ap["ssid"]:
        node.vars["wifi_ssid"] = ssid
    else:
        node.vars.pop("wifi_ssid", None)


def _detach(lab, node) -> None:
    idx = card(node)
    if node.nics[idx].plugged:
        editor.unplug(lab, node.id, idx)
    node.vars.pop("wifi_ap", None)
    node.vars.pop("wifi_ssid", None)


def joined_ssid(lab, node) -> str:
    ap = aps(lab).get(joined(lab, node))
    return str(node.vars.get("wifi_ssid") or (ap["ssid"] if ap else ""))


def join(lab, layout: dict, node_id: str, ssid: str, key: str = "") -> str:
    node = lab.nodes.get(node_id)
    if node is None:
        raise WifiError(f"no machine {node_id!r}")
    card(node)
    cands = [(b, ap, w) for b, ap, w in _signals(lab, layout, node_id) if w["ssid"] == ssid]
    if not cands:
        raise WifiError(f"{node_id} does not hear a network called {ssid!r} here: move it closer to an AP")
    n, ap, w = max(cands, key=lambda x: x[0])
    known = profiles(node)
    if w["security"] == "wpa2":
        key = key or known.get(ssid, "")
        if key != w["key"]:
            raise WifiError("the network security key isn't correct")
    known[ssid] = key if w["security"] == "wpa2" else ENT if w["security"] == "wpa2-ent" else ""
    _set_profiles(node, known)
    _attach(lab, node, ap, ssid)
    ent = ("; it passes nothing but 802.1X until the RADIUS server lets Windows' sign-in through"
           if w["security"] == "wpa2-ent" else "")
    return (f"{node_id} connected to {ssid} through {ap['name']} ({n} bar{'' if n == 1 else 's'}, "
            f"channel {w['channel']}){ent}")


def leave(lab, node_id: str, forget: bool = False) -> str:
    node = lab.nodes.get(node_id)
    if node is None:
        raise WifiError(f"no machine {node_id!r}")
    ap_id = joined(lab, node)
    ssid = joined_ssid(lab, node) if ap_id else ""
    _detach(lab, node)
    if forget:
        known = profiles(node)
        known.pop(ssid, None)
        _set_profiles(node, known)
    return f"{node_id} disconnected" + (f" from {ssid}" if ssid else "") + (" and forgot it" if forget else "")


def _usable(w: dict, known: dict[str, str]) -> bool:
    """A network (an AP's, or one of its WLANs) the laptop's profiles let it join."""
    if w["ssid"] not in known:
        return False
    if w["security"] == "wpa2-ent":
        return known[w["ssid"]] == ENT
    return w["security"] == "open" or known[w["ssid"]] == w["key"]


def settle(lab, layout: dict) -> list[str]:
    """After anything moved or changed: every laptop is on the AP it would
    be on now. One out of range roams to the strongest network it has a
    working profile for, or drops off; one whose AP changed VLAN follows it."""
    said = []
    every = aps(lab)
    for node in lab.node_list():
        if not wireless(node):
            continue
        known = profiles(node)
        cur = every.get(str(node.vars.get("wifi_ap") or ""))
        cur_w = _wlan_of(cur, str(node.vars.get("wifi_ssid") or cur["ssid"])) if cur else None
        cur_bars = bars(layout, cur, node.id, cur_w["channel"]) if cur and cur_w else 0
        ok = cur_w is not None and cur_bars > 0 and _usable(cur_w, known)
        better = max(((b, ap, w) for b, ap, w in _signals(lab, layout, node.id) if _usable(w, known)),
                     key=lambda x: x[0], default=None)
        # Windows roams when the signal gets weak and a better AP is there.
        if ok and cur_bars <= 1 and better and better[0] >= cur_bars + 2:
            ok = False
        if ok:
            if node.nics[card(node)].network != cur["network"]:
                _attach(lab, node, cur, cur_w["ssid"])
                said.append(f"{node.id} follows {cur['name']} onto {cur['network']}")
            continue
        if better is not None:
            _, bap, bw = better
            moved = cur is not None and bap["id"] != cur["id"]
            _attach(lab, node, bap, bw["ssid"])
            if moved or cur is None:
                said.append(f"{node.id} {'roamed' if moved else 'connected'} to {bw['ssid']} "
                            f"through {bap['name']}")
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
    return [adminui.Target(key=PREFIX + ap["id"],
                           title=f"{ap['name']} ({VENDORS[ap['vendor']]}{'' if ap['vendor'] == 'wlc' else ' access point'})",
                           host=ap["ip"], gui=openwrt.luci("ap") if ap["vendor"] == "openwrt" else vendor_gui(ap["vendor"]))
            for ap in aps(lab).values()
            if ap["network"] and ap["ip"] and ap["vendor"] not in ("unifi", "lap")]   # those two: their controller


SIGN_IN = {
    "ruckus": "the admin you create in its setup wizard (on the console before that: super)",
    "aruba": "admin, the factory password until you change it",
    "cisco": "the admin you create in its Day 0 wizard",
    "mikrotik": "admin with no password; it makes you set one",
    "wlc": "the admin you create in its Day 0 wizard",
}


def vendor_gui(vendor: str):
    """A vendor AP's own pages (winlab/apos): plain HTTP on port 80, and its
    CLI over SSH (ssh admin@<address>, then the vendor's own login)."""
    from .adminui import AdminGui
    return AdminGui(software=f"{VENDORS[vendor]} (winlab's imitation, on OpenWrt)", scheme="http", port=80, path="/",
                    sign_in=SIGN_IN[vendor], license="winlab's own code; GPL-2.0 (OpenWrt, hostapd underneath)",
                    note=f"Its CLI too: ssh admin@ the same address from a lab PC.")


def _register() -> None:
    from . import adminui
    adminui.register(targets=_targets)


_register()
