"""The rack: the lab's equipment as it stands in the comms room.

The workbench is a canvas of devices and cables; a real server room is a
19-inch rack, and an admin's day includes keeping its documentation true:
which box sits in which U, which cable goes from which port to which port
and what its label says, the asset tag stuck on each device. This module
draws that rack from what the student built, and nothing else: the
servers, the storage, the router and the switches, the UPS, the patch
panels the student fits; the PCs, phones, printers and access points are
listed as not racked (they live on desks and ceilings).

Where each device sits is kept in the lab file, in an additive [rack]
table read and written the way the workbench's [layout] is, and checked
when the lab loads (parse_table). A device the table does not place lands
in the next free U: network gear from the top down, servers and storage
and the UPS from the bottom up. The student drags it elsewhere; the first
move pins every position, so nothing shuffles when a machine is added.

Cables follow the real cabling: every machine port in a switch port, the
access points, the servers' management ports, the UPS's network card, the
uplinks between switches and to the router, the console cables, the UPS's
USB cable and the power cords into its outlets. Each is drawn port to port
on the back of the rack, coloured by its VLAN, through the patch panel
when there is one. A cable's label defaults to "<device>-<port> <-> <device>-
<port>"; the student can write another. Asset tags and serial numbers are
generated per device (stable for the lab) and can be edited too.

The audit drill ("Audit the rack") puts the documentation wrong on
purpose: two cables swap labels, or a device carries the wrong asset tag.
The student compares the labels with the ports they really join and the
tags with the asset register, and fixes the documentation by hand. Winlab
never corrects a label or a tag itself: Check my fix only says whether the
documentation is right now.

The drawing is one list of shapes (rect, line, text, circle), written out
as SVG for the desktop and the export, and as a PNG by a small rasteriser
here (stdlib only), so both pictures are the same rack.
"""

from __future__ import annotations

import html
import json
import random
import re
import struct
import time
import zlib
from pathlib import Path

from . import paths

UNITS = 42                 # a standard full-height rack
MAX_UNITS = 52
MAX_RACKS = 8
MAX_PANELS = 8
PANEL_PORTS = 24
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,31}$")
LABEL_MAX = 80
ARROW = "↔"           # the double arrow of a cable label
AUDIT_FILE = "rack-audit.json"
CHECK = "Check my fix"

# Heights in U by what the device is (the workbench shelf's ids).
HEIGHT = {"server": 1, "linux": 1, "firewall": 1, "iso": 2, "nas": 2, "san": 3, "pbx": 1, "ntp": 1,
          "router": 1, "switch": 1, "panel": 1, "ups": 2}
# What stays off the rack: on a desk, a wall or a ceiling.
DESK = ("pc", "laptop", "printer", "phone", "adminpc", "ap", "camera")
TOP = ("panel", "switch", "router", "firewall")     # filled from the top of the rack down
DESK_WHERE = {"pc": "desk", "laptop": "desk", "printer": "office floor", "phone": "desk",
              "adminpc": "desk", "ap": "ceiling", "camera": "ceiling or wall"}

# Colours: one per network (by VLAN), and the cables that are no network's.
PALETTE = ["#2563eb", "#0d9488", "#d97706", "#7c3aed", "#db2777", "#65a30d", "#0891b2", "#b45309",
           "#4f46e5", "#be123c"]
KIND_COLOR = {"trunk": "#475569", "power": "#111827", "console": "#38bdf8", "usb": "#a855f7"}


class RackError(Exception):
    pass


# ------------------------------------------------------------------ the [rack] table
def parse_table(raw, fname: str = "lab") -> dict:
    """The [rack] table of a lab file, checked: racks = [42, ...], panels =
    N, and the tables at (device = "rack:U"), tags, serials, labels (cable
    = "text"). Raises the lab loader's LabError on anything else."""
    from .schema import LabError
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise LabError(f"{fname}: [rack] must be a table")
    known = {"racks", "panels", "floor", "at", "tags", "serials", "labels"}
    extra = sorted(set(raw) - known)
    if extra:
        raise LabError(f"{fname}: [rack] has unknown key(s) {', '.join(extra)}")
    out: dict = {}
    racks = raw.get("racks", [UNITS])
    if (not isinstance(racks, list) or not 1 <= len(racks) <= MAX_RACKS
            or not all(isinstance(u, int) and not isinstance(u, bool) and 4 <= u <= MAX_UNITS for u in racks)):
        raise LabError(f"{fname}: [rack] racks must be a list of 1 to {MAX_RACKS} heights in U (4 to {MAX_UNITS})")
    out["racks"] = list(racks)
    panels = raw.get("panels", 0)
    if not isinstance(panels, int) or isinstance(panels, bool) or not 0 <= panels <= MAX_PANELS:
        raise LabError(f"{fname}: [rack] panels must be 0 to {MAX_PANELS}")
    out["panels"] = panels
    floor = raw.get("floor", [])
    if not isinstance(floor, list) or not all(isinstance(k, str) and 0 < len(k) <= 64 for k in floor):
        raise LabError(f"{fname}: [rack] floor must be a list of device names")
    out["floor"] = list(dict.fromkeys(floor))
    for key in ("at", "tags", "serials", "labels"):
        table = raw.get(key, {})
        if not isinstance(table, dict) or not all(isinstance(v, str) for v in table.values()):
            raise LabError(f"{fname}: [rack.{key}] must be a table of name = \"text\"")
        out[key] = {str(k): v for k, v in table.items()}
    for dev, where in out["at"].items():
        m = re.fullmatch(r"(\d+):(\d+)", where)
        if not m or not 1 <= int(m[1]) <= len(racks) or not 1 <= int(m[2]) <= racks[int(m[1]) - 1]:
            raise LabError(f"{fname}: [rack.at] {dev!r} must be \"<rack>:<U>\" inside a rack, not {where!r}")
    for table, limit in (("tags", 32), ("serials", 32), ("labels", LABEL_MAX)):
        for k, v in out[table].items():
            if len(v) > limit or any(ord(c) < 32 for c in v):
                raise LabError(f"{fname}: [rack.{table}] {k!r} is too long or has control characters")
    return out


def _q(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit_table(table: dict) -> list[str]:
    """The [rack] table as lab-file lines ([] when there is nothing to keep)."""
    if not table or not any(table.get(k) for k in ("at", "tags", "serials", "labels", "floor")) and \
            table.get("racks", [UNITS]) == [UNITS] and not table.get("panels"):
        return []
    out = ["[rack]", f"racks = [{', '.join(str(u) for u in table.get('racks') or [UNITS])}]"]
    if table.get("panels"):
        out.append(f"panels = {int(table['panels'])}")
    if table.get("floor"):
        out.append(f"floor = [{', '.join(_q(k) for k in table['floor'])}]")
    for key in ("at", "tags", "serials", "labels"):
        rows = table.get(key) or {}
        if rows:
            out.append(f"  [rack.{key}]")
            out += [f"  {_q(k)} = {_q(v)}" for k, v in sorted(rows.items())]
    out.append("")
    return out


def table(lab) -> dict:
    """The lab's [rack] table with every part present."""
    t = lab.rack
    t.setdefault("racks", [UNITS])
    t.setdefault("panels", 0)
    t.setdefault("floor", [])
    for k in ("at", "tags", "serials", "labels"):
        t.setdefault(k, {})
    return t


# ------------------------------------------------------------------ what is in the room
def _shelf(node) -> str:
    from .workbench import _shelf_of
    return _shelf_of(node)


def _sw_name(lab, sw: str) -> str:
    from . import devcli
    return devcli.hostname(lab, f"sw:{sw}")


def inventory(lab) -> tuple[list[dict], list[dict]]:
    """(rackable, desk): every device of the lab as {key, name, kind, h}.
    Keys: a machine's id, "router", "sw:<switch>", "ups", "pp<N>"."""
    from . import devcli, naming, ups, wifi
    rackable, desk = [], []
    for i in range(1, int(table(lab)["panels"]) + 1):
        rackable.append({"key": f"pp{i}", "name": f"PP{i}", "kind": "panel", "h": HEIGHT["panel"]})
    for sw in devcli.switches(lab):
        rackable.append({"key": f"sw:{sw}", "name": _sw_name(lab, sw), "kind": "switch", "h": 1})
    rackable.append({"key": "router", "name": devcli.hostname(lab, devcli.ROUTER), "kind": "router", "h": 1,
                     "ports": len(devcli.router_ports(lab))})
    for node in lab.node_list():
        if node.vars.get("devvm"):
            continue  # an access point's or the UPS card's own VM: drawn as that device
        kind = _shelf(node)
        row = {"key": node.id, "name": naming.hostname_of(node), "kind": kind}
        if kind in DESK:
            desk.append({**row, "where": DESK_WHERE.get(kind, "desk")})
            continue
        h = HEIGHT.get(kind, 1)
        if kind == "server" and len(node.data_disks_gb) >= 2:
            h = 2  # room for the extra drive bays
        rackable.append({**row, "h": h, "nics": max(1, len(node.nics))})
    if ups.load(lab.name).get("fitted"):
        rackable.append({"key": "ups", "name": "UPS", "kind": "ups", "h": HEIGHT["ups"]})
    for ap in wifi.aps(lab).values():
        desk.append({"key": wifi.PREFIX + ap["id"], "name": ap["name"], "kind": "ap", "where": "ceiling"})
    return rackable, desk


# ------------------------------------------------------------------ tags and serials
_TAG_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def default_tag(lab_name: str, key: str) -> str:
    """An asset tag made from the lab and the device: the same every time."""
    return f"AT-{zlib.crc32(f'{lab_name}/{key}'.encode()) % 90000 + 10000:05d}"


def default_serial(lab_name: str, key: str) -> str:
    n = zlib.crc32(f"serial:{lab_name}/{key}".encode()) | (zlib.crc32(f"{key}/{lab_name}".encode()) << 32)
    out = ""
    for _ in range(8):
        n, r = divmod(n, len(_TAG_CHARS))
        out += _TAG_CHARS[r]
    return "SN" + out


def tags(lab, keys: list[str], own: dict[str, str] | None = None) -> dict[str, str]:
    """Each device's asset tag: the one the student wrote, else its default
    (a default already taken by another device moves on by one). With own
    = {}, the tags as purchasing bought them."""
    own = table(lab)["tags"] if own is None else own
    out, taken = {}, {v.upper() for k, v in own.items() if k in keys}
    for k in sorted(keys):
        if k in own:
            out[k] = own[k]
            continue
        t = default_tag(lab.name, k)
        while t.upper() in taken:
            t = f"AT-{(int(t[3:]) + 1 - 10000) % 90000 + 10000:05d}"
        taken.add(t.upper())
        out[k] = t
    return out


def serial_of(lab, key: str) -> str:
    return table(lab)["serials"].get(key) or default_serial(lab.name, key)


# ------------------------------------------------------------------ where things sit
def placement(lab, rackable: list[dict] | None = None) -> tuple[dict[str, tuple[int, int]], list[dict]]:
    """({key: (rack, U)}, unplaced): the pinned positions first, then each
    device the table does not place in the next free U (network gear from
    the top down, the rest from the bottom up), rack 1 first. A device the
    student took out (the [rack] floor list) waits in the catalog: it is
    neither placed nor short of room."""
    if rackable is None:
        rackable, _ = inventory(lab)
    t = table(lab)
    racks = t["racks"]
    floor = set(t["floor"])
    used = [set() for _ in racks]
    out: dict[str, tuple[int, int]] = {}
    by_key = {d["key"]: d for d in rackable}
    for key, where in t["at"].items():
        d = by_key.get(key)
        if d is None or key in floor:
            continue
        r, u = (int(x) for x in where.split(":"))
        span = set(range(u, u + d["h"]))
        if r > len(racks) or u + d["h"] - 1 > racks[r - 1] or span & used[r - 1]:
            continue  # it no longer fits there: placed again below
        used[r - 1] |= span
        out[key] = (r, u)
    unplaced = []
    order = [d for d in rackable if d["kind"] == "panel"] + [d for d in rackable if d["kind"] == "switch"] + \
            [d for d in rackable if d["kind"] in ("router", "firewall")] + \
            [d for d in rackable if d["kind"] == "ups"] + \
            [d for d in rackable if d["kind"] not in TOP and d["kind"] != "ups"]
    for d in order:
        if d["key"] in out or d["key"] in floor:
            continue
        spot = _free(racks, used, d["h"], top=d["kind"] in TOP)
        if spot is None:
            unplaced.append(d)
            continue
        r, u = spot
        used[r - 1] |= set(range(u, u + d["h"]))
        out[d["key"]] = (r, u)
    return out, unplaced


def _free(racks: list[int], used: list[set], h: int, top: bool) -> tuple[int, int] | None:
    for r, units in enumerate(racks, 1):
        starts = range(units - h + 1, 0, -1) if top else range(1, units - h + 2)
        for u in starts:
            if not set(range(u, u + h)) & used[r - 1]:
                return r, u
    return None


# ------------------------------------------------------------------ the cables
def _color_map(lab, plan) -> dict[str, str]:
    segs = sorted({plan.segment_of(n).network.id for n in lab.networks},
                  key=lambda s: (plan.segment_of(s).vid, s))
    return {s: PALETTE[i % len(PALETTE)] for i, s in enumerate(segs)}


def cables(lab, plan) -> list[dict]:
    """Every cable of the lab, end to end: {id, kind, a, b, network, vlan,
    color, panel}. An end is {key, name, port}; `panel` is the patch-panel
    port ("PP1-03") the cable runs through, or ""."""
    from . import consolecable, devcli, naming, power, ups, wifi
    colors = _color_map(lab, plan)
    out: list[dict] = []

    def net_info(net_id: str) -> dict:
        if net_id not in lab.networks:
            return {"network": "", "vlan": 0, "color": KIND_COLOR["trunk"]}
        seg = plan.segment_of(net_id).network.id
        return {"network": net_id, "vlan": lab.networks[net_id].vlan_no, "color": colors.get(seg, PALETTE[0])}

    def sw_end(sw: str, port: str) -> dict:
        return {"key": f"sw:{sw}", "name": _sw_name(lab, sw), "port": port}

    def node_end(node_id: str, port: str) -> dict:
        if node_id == ups.CARD_ID:
            return {"key": "ups", "name": "UPS", "port": "NET"}
        return {"key": node_id, "name": naming.display(lab, node_id), "port": port}

    by_switch = devcli.switch_ports(lab, plan)
    slots = {sw: len(links) for sw, links in by_switch.items()}
    for sw, links in by_switch.items():
        for i, link in enumerate(links):
            if link is None:
                continue  # an empty port
            kind = "card" if link.node_id == ups.CARD_ID else "data"
            out.append({"id": link.label, "kind": kind, "a": node_end(link.node_id, f"NIC{link.nic_index + 1}"),
                        "b": sw_end(sw, f"Fa0/{i + 1}"), **net_info(link.network_id)})
    for sw in devcli.switches(lab):
        for ap_id in wifi.on_switch(lab, sw):
            ap = wifi.aps(lab)[ap_id]
            i = slots[sw]
            slots[sw] = i + 1
            out.append({"id": f"ap:{ap_id}", "kind": "ap",
                        "a": {"key": wifi.PREFIX + ap_id, "name": ap["name"], "port": "LAN"},
                        "b": sw_end(sw, f"Fa0/{i + 1}"), **net_info(ap["network"])})
    for node in lab.node_list():
        if not power.fitted(node):
            continue
        net = str(node.vars.get(power.PORT_VAR) or "")
        if net not in lab.networks:
            continue
        home = lab.networks[net].home
        i = slots.get(home, 0)
        slots[home] = i + 1
        out.append({"id": f"bmc:{node.id}", "kind": "mgmt", "a": node_end(node.id, "MGMT"),
                    "b": sw_end(home, f"Fa0/{i + 1}"), **net_info(net)})
    router_ports = {sw: name for name, sw in devcli.router_ports(lab) if sw}
    for sw in devcli.switches(lab):
        up = devcli.upstream(lab, sw)
        if up:
            port = dict((s, p) for p, s in devcli.downlinks(lab, up)).get(sw, "Gi0/2")
            out.append({"id": f"up:{sw}", "kind": "trunk", "a": sw_end(sw, "Gi0/1"),
                        "b": sw_end(up, devcli.short_if(port)), "network": "", "vlan": 0,
                        "color": KIND_COLOR["trunk"]})
        elif devcli.uplinked(lab, sw) and sw in router_ports:
            out.append({"id": f"up:{sw}", "kind": "trunk", "a": sw_end(sw, "Gi0/1"),
                        "b": {"key": "router", "name": devcli.hostname(lab, devcli.ROUTER),
                              "port": devcli.short_if(router_ports[sw])},
                        "network": "", "vlan": 0, "color": KIND_COLOR["trunk"]})
    for dev, node_id in consolecable.cables(lab).items():
        key = "router" if dev == devcli.ROUTER else dev
        name = devcli.hostname(lab, dev)
        out.append({"id": f"con:{dev}", "kind": "console", "a": {"key": key, "name": name, "port": "CON"},
                    "b": node_end(node_id, "COM"), "network": "", "vlan": 0, "color": KIND_COLOR["console"]})
    data = ups.load(lab.name)
    if data.get("fitted"):
        if data.get("usb") in lab.nodes:
            out.append({"id": "ups:usb", "kind": "usb", "a": {"key": "ups", "name": "UPS", "port": "USB"},
                        "b": node_end(data["usb"], "USB"), "network": "", "vlan": 0, "color": KIND_COLOR["usb"]})
        for i, plug in enumerate(data.get("plugs") or []):
            key = "sw:" + plug[len(ups.NET):] if plug.startswith(ups.NET) else plug
            name = ups.name_of(lab, plug)
            out.append({"id": f"pwr:{key}", "kind": "power", "a": {"key": key, "name": name, "port": "PSU"},
                        "b": {"key": "ups", "name": "UPS", "port": f"OUT{i + 1}"},
                        "network": "", "vlan": 0, "color": KIND_COLOR["power"]})
    # Through the patch panels, in order, while they have ports: every cable
    # from a machine, an access point or a management port to a switch.
    panels = int(table(lab)["panels"])
    n = 0
    for c in out:
        c["panel"] = ""
        if c["kind"] in ("data", "ap", "mgmt", "card") and n < panels * PANEL_PORTS:
            c["panel"] = f"PP{n // PANEL_PORTS + 1}-{n % PANEL_PORTS + 1:02d}"
            n += 1
    return out


def end_text(end: dict) -> str:
    return f"{end['name']}-{end['port']}"


def default_label(cable: dict) -> str:
    return f"{end_text(cable['a'])} {ARROW} {end_text(cable['b'])}"


def label_of(lab, cable: dict) -> str:
    return table(lab)["labels"].get(cable["id"]) or default_label(cable)


def _tokens(text: str) -> set[str]:
    t = text.upper()
    for sep in (ARROW, "<->", "<>", "->", "<-", "→", "←", "|", ",", ";"):
        t = t.replace(sep, " ")
    t = re.sub(r"\bTO\b", " ", t)
    return set(t.split())


def label_ok(lab, cable: dict) -> bool:
    """Whether a cable's label names both of its real ends ("SRV01-NIC1"
    and "SW1-Fa0/3", any case, in any order, with any arrow between)."""
    toks = _tokens(label_of(lab, cable))
    return end_text(cable["a"]).upper() in toks and end_text(cable["b"]).upper() in toks


# ------------------------------------------------------------------ power
def power_view(lab, placed: dict, running: set[str]) -> dict:
    """What the racked devices draw (the UPS's watt model, winlab/ups.py)
    against the UPS: now, on its outlets, and with everything running."""
    from . import ups
    data = ups.load(lab.name)
    keys = []
    for key in placed:
        if key == "router" or key in lab.nodes:
            keys.append(key)
        elif key.startswith("sw:"):
            keys.append(ups.NET + key[3:])
    now = sum(ups.draws(lab, k, running) for k in keys)
    full = sum(ups.rated(lab, k) for k in keys)
    fitted = bool(data.get("fitted"))
    m = ups.model(data)
    on_ups = ups.load_watts(lab, data, running) if fitted else 0
    plugged = set(data.get("plugs") or []) if fitted else set()
    left = ups.minutes_left(data, on_ups) if fitted else None
    status = ("off" if not ups.output_on(data) else "on battery" if not data["mains"] else "on line") \
        if fitted else ""
    return {"now_w": now, "full_w": full, "ups": fitted, "ups_title": m["title"] if fitted else "",
            "mains": bool(data["mains"]), "charge": int(round(100 * float(data.get("charge", 1.0)))),
            "minutes": int(left) if left is not None else None, "status": status,
            "ups_w": m["watts"] if fitted else 0, "on_ups_w": on_ups,
            "on_ups_full_w": sum(ups.rated(lab, k) for k in keys if k in plugged),
            "pct": int(round(100 * on_ups / m["watts"])) if fitted else 0,
            "full_pct": int(round(100 * full / m["watts"])) if fitted else 0,
            "not_on_ups": sorted(ups.name_of(lab, k) for k in keys if k not in plugged)}


# ------------------------------------------------------------------ changes (the student's)
def resolve(lab, what: str, rackable: list[dict] | None = None, desk: list[dict] | None = None) -> str:
    """A device's key from what was typed: its id, its name, a switch's id."""
    if rackable is None or desk is None:
        rackable, desk = inventory(lab)
    w = what.strip().lower()
    for d in rackable + desk:
        if w in (d["key"].lower(), d["name"].lower()) or (d["key"].startswith(("sw:", "ap:"))
                                                          and w == d["key"][3:].lower()):
            return d["key"]
    raise RackError(f"no device {what!r} in this lab (winlab rack <lab> show lists them)")


def parse_u(text: str) -> tuple[int, int]:
    """'12', 'U12', '2:12', 'R2:U12', 'r2 u12' -> (rack, U)."""
    m = re.fullmatch(r"\s*(?:r?(\d+)\s*[:/ ]\s*)?u?(\d+)\s*", text.lower())
    if not m:
        raise RackError(f"{text!r} is not a position: give a U number, or rack:U (2:12)")
    return int(m[1] or 1), int(m[2])


def move(lab, key: str, rack_no: int, u: int) -> str:
    """Puts a device at U `u` of rack `rack_no` (its lowest unit), if it
    fits and the units are free, and pins every position."""
    rackable, _ = inventory(lab)
    by_key = {d["key"]: d for d in rackable}
    d = by_key.get(key)
    if d is None:
        raise RackError(f"{key} does not go in the rack (it lives on a desk, a wall or a ceiling)")
    t = table(lab)
    if not 1 <= rack_no <= len(t["racks"]):
        raise RackError(f"there is no rack {rack_no}: the room has {len(t['racks'])}")
    units = t["racks"][rack_no - 1]
    if not 1 <= u <= units - d["h"] + 1:
        raise RackError(f"{d['name']} is {d['h']}U: in rack {rack_no} it fits from U1 to U{units - d['h'] + 1}")
    placed, _ = placement(lab, rackable)
    span = set(range(u, u + d["h"]))
    for other, (r, ou) in placed.items():
        if other != key and r == rack_no and span & set(range(ou, ou + by_key[other]["h"])):
            raise RackError(f"U{u}{'-U' + str(u + d['h'] - 1) if d['h'] > 1 else ''} of rack {rack_no} is taken "
                            f"by {by_key[other]['name']}")
    placed[key] = (rack_no, u)
    t["at"] = {k: f"{r}:{uu}" for k, (r, uu) in placed.items()}
    t["floor"] = [k for k in t["floor"] if k != key]
    return f"{d['name']} is in rack {rack_no} at U{u}" + (f"-U{u + d['h'] - 1}" if d["h"] > 1 else "")


def unrack(lab, key: str) -> str:
    """Takes a device out of the rack onto the floor (the window's catalog)
    and pins every other position, so nothing slides into the gap."""
    rackable, _ = inventory(lab)
    by_key = {d["key"]: d for d in rackable}
    if key not in by_key:
        raise RackError(f"{key} is not rack equipment")
    t = table(lab)
    if key in t["floor"]:
        return f"{by_key[key]['name']} is already out of the rack"
    placed, _ = placement(lab, rackable)
    placed.pop(key, None)
    t["at"] = {k: f"{r}:{u}" for k, (r, u) in placed.items()}
    t["floor"] = t["floor"] + [key]
    return f"{by_key[key]['name']} is out of the rack, on the floor of the comms room"


def unrack_all(lab) -> str:
    """Empties the racks: every device on the floor, as if just delivered.
    Nothing is unplugged or powered off: the cables and the machines are
    the lab's, not the rack's."""
    rackable, _ = inventory(lab)
    t = table(lab)
    t["at"] = {}
    t["floor"] = [d["key"] for d in rackable]
    return f"the rack is empty: {len(rackable)} devices wait on the floor to be racked"


def set_label(lab, plan, cable_id: str, text: str) -> str:
    """The student's label for a cable; an empty text puts the default back."""
    c = find_cable(lab, plan, cable_id)
    text = " ".join(str(text).split())
    if len(text) > LABEL_MAX or any(ord(ch) < 32 for ch in text):
        raise RackError(f"a cable label is at most {LABEL_MAX} characters on one line")
    labels = table(lab)["labels"]
    if not text:
        labels.pop(c["id"], None)
        return f"cable {c['id']}: label back to {default_label(c)}"
    labels[c["id"]] = text
    return f"cable {c['id']}: label {text}"


def find_cable(lab, plan, what: str) -> dict:
    """A cable by its id, by its label, or by one of its ends (SRV01-NIC1)."""
    all_c = cables(lab, plan)
    w = what.strip().upper()
    for c in all_c:
        if w == c["id"].upper() or w == label_of(lab, c).upper():
            return c
    hits = [c for c in all_c if w in (end_text(c["a"]).upper(), end_text(c["b"]).upper())]
    if len(hits) == 1:
        return hits[0]
    if hits:
        raise RackError(f"{what} is an end of {len(hits)} cables: name one by its id ({', '.join(c['id'] for c in hits)})")
    raise RackError(f"no cable {what!r} (winlab rack <lab> show lists them with their ids)")


def set_tag(lab, key: str, tag: str) -> str:
    tag = tag.strip()
    if not TAG_RE.match(tag):
        raise RackError("an asset tag is 1 to 32 letters, digits, spaces, dots, dashes or slashes")
    rackable, desk = inventory(lab)
    names = {d["key"]: d["name"] for d in rackable + desk}
    if key not in names:
        raise RackError(f"no device {key!r}")
    current = tags(lab, list(names))
    for other, t in current.items():
        if other != key and t.upper() == tag.upper():
            raise RackError(f"{tag} is {names[other]}'s asset tag: two devices never share one")
    table(lab)["tags"][key] = tag
    return f"{names[key]}: asset tag {tag}"


def set_serial(lab, key: str, serial: str) -> str:
    serial = serial.strip()
    a = audit_load(lab.name)
    if a.get("register") and not a.get("ended"):
        # The serial is printed on the device: the one fact the audit checks
        # tags against, so it cannot be rewritten while the audit runs.
        raise RackError("the serial number is printed on the device: it cannot change during an audit")
    if not TAG_RE.match(serial):
        raise RackError("a serial number is 1 to 32 letters, digits, spaces, dots, dashes or slashes")
    table(lab)["serials"][key] = serial
    return f"{key}: serial number {serial}"


def set_racks(lab, count: int, units: int = UNITS) -> str:
    t = table(lab)
    if not 1 <= count <= MAX_RACKS:
        raise RackError(f"the room holds 1 to {MAX_RACKS} racks")
    if not 4 <= units <= MAX_UNITS:
        raise RackError(f"a rack is 4 to {MAX_UNITS} U high")
    racks = list(t["racks"])[:count]
    racks += [units] * (count - len(racks))
    t["racks"] = racks
    t["at"] = {k: v for k, v in t["at"].items() if int(v.split(":")[0]) <= count}
    return f"{count} rack{'s' if count > 1 else ''} in the room"


def set_panels(lab, count: int) -> str:
    t = table(lab)
    if not 0 <= count <= MAX_PANELS:
        raise RackError(f"0 to {MAX_PANELS} patch panels")
    t["panels"] = count
    t["at"] = {k: v for k, v in t["at"].items() if not (k.startswith("pp") and k[2:].isdigit() and int(k[2:]) > count)}
    return (f"{count} patch panel{'s' if count != 1 else ''} of {PANEL_PORTS} ports: the cables from the machines "
            f"now run through {'them' if count > 1 else 'it'}") if count else "no patch panel: cables go straight into the switches"


def prune(lab) -> None:
    """Drops what the table keeps for devices and cables that are gone."""
    from .netplan import compile_topology
    t = table(lab)
    rackable, desk = inventory(lab)
    keys = {d["key"] for d in rackable + desk}
    for k in ("at", "tags", "serials"):
        t[k] = {a: b for a, b in t[k].items() if a in keys}
    t["floor"] = [k for k in t["floor"] if k in keys]
    try:
        ids = {c["id"] for c in cables(lab, compile_topology(lab, check_ports=False))}
        t["labels"] = {a: b for a, b in t["labels"].items() if a in ids}
    except Exception:  # a lab that does not compile now keeps its labels
        pass


# ------------------------------------------------------------------ the audit drill
def _audit_path(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / AUDIT_FILE


def audit_load(lab_name: str) -> dict:
    try:
        d = json.loads(_audit_path(lab_name).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _audit_save(lab_name: str, data: dict) -> None:
    p = _audit_path(lab_name)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    tmp.replace(p)


class AuditKind:
    """A documentation fault of the rack: how it is made and how it is
    proved gone (verify reads the documentation as the student left it)."""

    def __init__(self, id: str, title: str, hint: str, make, verify, where):
        self.id, self.title, self.hint, self.make, self.verify, self.where = id, title, hint, make, verify, where


def _make_swap(lab, plan, register, rng) -> dict | None:
    pool = [c for c in cables(lab, plan) if c["kind"] in ("data", "mgmt", "ap", "trunk", "card")
            and label_ok(lab, c)]
    if len(pool) < 2:
        return None
    a, b = rng.sample(pool, 2)
    la, lb = label_of(lab, a), label_of(lab, b)
    t = table(lab)["labels"]
    t[a["id"]], t[b["id"]] = lb, la
    return {"kind": "swap", "cables": [a["id"], b["id"]]}


def _verify_swap(lab, plan, rec, register) -> bool:
    by_id = {c["id"]: c for c in cables(lab, plan)}
    return all(cid not in by_id or label_ok(lab, by_id[cid]) for cid in rec["cables"])


def _where_swap(lab, plan, rec) -> str:
    by_id = {c["id"]: c for c in cables(lab, plan)}
    return " and ".join(f"{end_text(by_id[c]['a'])} to {end_text(by_id[c]['b'])}" for c in rec["cables"] if c in by_id)


def _make_mistag(lab, plan, register, rng) -> dict | None:
    keys = sorted(register)
    if not keys:
        return None
    key = rng.choice(keys)
    right = register[key]
    digits = right[3:] if right.startswith("AT-") and right[3:].isdigit() else ""
    wrong = (f"AT-{digits[:-2]}{digits[-1]}{digits[-2]}" if digits and digits[-1] != digits[-2]
             else default_tag(lab.name, key + "/old"))
    if wrong.upper() in {v.upper() for v in register.values()}:
        wrong = default_tag(lab.name, key + "/spare")
    table(lab)["tags"][key] = wrong
    return {"kind": "mistag", "device": key, "right": right, "wrong": wrong}


def _verify_mistag(lab, plan, rec, register) -> bool:
    rackable, desk = inventory(lab)
    keys = [d["key"] for d in rackable + desk]
    if rec["device"] not in keys:
        return True
    return tags(lab, keys)[rec["device"]].strip().upper() == rec["right"].upper()


def _where_mistag(lab, plan, rec) -> str:
    rackable, desk = inventory(lab)
    names = {d["key"]: d["name"] for d in rackable + desk}
    return f"{names.get(rec['device'], rec['device'])} was tagged {rec['wrong']}; the register says {rec['right']}"


AUDIT_KINDS: dict[str, AuditKind] = {
    "swap": AuditKind("swap", "Two cables carry each other's labels",
                      "Go along the back of the rack: does each label name the two ports its cable really joins?",
                      _make_swap, _verify_swap, _where_swap),
    "mistag": AuditKind("mistag", "A device carries the wrong asset tag",
                        "Read each device's serial number, then find it in the asset register: is the tag the same?",
                        _make_mistag, _verify_mistag, _where_mistag),
}


def register_of(lab) -> dict[str, str]:
    """The asset register (purchasing's list): serial -> tag as bought. In
    a drill, as it was when the drill started; otherwise the tags purchasing
    issued, whatever the documentation says (the tag stuck on each device
    must be the one here)."""
    rackable, desk = inventory(lab)
    keys = [d["key"] for d in rackable + desk]
    a = audit_load(lab.name)
    if a.get("register") and not a.get("ended"):
        return {k: v for k, v in a["register"].items() if k in keys}
    return tags(lab, keys, own={})


def audit_start(lab, plan, rng=None, kinds: tuple[str, ...] = ()) -> dict:
    """Starts the drill: one or two documentation faults, picked from the
    registry, made in the lab's [rack] table (the caller saves the lab)."""
    rng = rng or random.Random()
    cur = audit_load(lab.name)
    if cur.get("faults") and not cur.get("ended"):
        raise RackError("an audit is already running: Check my fix, or end it first")
    rackable, desk = inventory(lab)
    register = tags(lab, [d["key"] for d in rackable + desk], own={})  # purchasing's, as bought
    want = list(kinds) or rng.sample(list(AUDIT_KINDS), rng.choice((1, 2)))
    faults = []
    for k in want:
        rec = AUDIT_KINDS[k].make(lab, plan, register, rng)
        if rec:
            faults.append(rec)
    if not faults:
        raise RackError("the rack has too little in it to audit: cable at least two machines first")
    data = {"id": f"audit-{int(time.time())}", "started": time.time(), "register": register,
            "faults": faults, "hints": 0, "checks": 0}
    data["ticket"] = _ticket(lab, data)
    _audit_save(lab.name, data)
    return data


def _ticket(lab, data: dict) -> str:
    """The audit arrives as a ticket in the helpdesk queue (winlab/helpdesk.py)."""
    try:
        from . import helpdesk, people
        staff = people.load(lab)
        boss = next((p for p in staff if p.get("department") == "Operations" and p.get("manager")), None) \
            or people.admin(staff)
        t = helpdesk.open_ticket(
            lab.name, caller=boss["id"], source="mail", priority="P3", category="documentation",
            summary="Rack audit: the documentation must match the rack",
            body="The auditor checks the comms room this week. Every cable label must name the two ports its "
                 "cable joins, and every asset tag must match the asset register (by serial number). "
                 "Please go over the rack and correct the documentation.",
            fault={"kind": "rack", "id": data["id"], "node": "", "params": {}}, dedupe="rack-audit")
        return t["id"]
    except Exception:  # the queue is a courtesy: the drill runs without it
        return ""


def verify_fault(lab, fault: dict) -> bool:
    """For a helpdesk ticket backed by the rack audit (fault kind "rack"):
    whether the documentation is right again."""
    from .netplan import compile_topology
    a = audit_load(lab.name)
    if not a.get("faults") or a.get("id") != fault.get("id"):
        return True
    plan = compile_topology(lab, check_ports=False)
    return all(AUDIT_KINDS[r["kind"]].verify(lab, plan, r, a["register"]) for r in a["faults"])


def audit_check(lab, plan) -> dict:
    a = audit_load(lab.name)
    if not a.get("faults") or a.get("ended"):
        return {"ok": False, "message": "no audit is running: start one with Audit the rack"}
    a["checks"] = a.get("checks", 0) + 1
    left = [r for r in a["faults"] if not AUDIT_KINDS[r["kind"]].verify(lab, plan, r, a["register"])]
    if not left:
        a["ended"], a["passed"] = time.time(), True
        _audit_save(lab.name, a)
        found = [f"{AUDIT_KINDS[r['kind']].title}: {AUDIT_KINDS[r['kind']].where(lab, plan, r)}." for r in a["faults"]]
        return {"ok": True, "passed": True, "message": "Audit passed: the documentation matches the rack. "
                + " ".join(found), "found": found}
    _audit_save(lab.name, a)
    n = len(a["faults"])
    return {"ok": True, "passed": False,
            "message": f"Not yet: {len(left)} of {n} documentation error{'s' if n > 1 else ''} still there."}


def audit_hint(lab, plan) -> dict:
    a = audit_load(lab.name)
    if not a.get("faults") or a.get("ended"):
        return {"ok": False, "message": "no audit is running"}
    left = [r for r in a["faults"] if not AUDIT_KINDS[r["kind"]].verify(lab, plan, r, a["register"])]
    if not left:
        return {"ok": True, "message": "Everything looks right now: press Check my fix."}
    a["hints"] = a.get("hints", 0) + 1
    _audit_save(lab.name, a)
    r = left[0]
    k = AUDIT_KINDS[r["kind"]]
    if a["hints"] == 1:
        return {"ok": True, "message": k.hint}
    if r["kind"] == "swap":
        by_id = {c["id"]: c for c in cables(lab, plan)}
        c = by_id.get(r["cables"][0])
        return {"ok": True, "message": f"Look at the cable from {end_text(c['a'])}: what does its label say?"
                if c else k.hint}
    rackable, desk = inventory(lab)
    names = {d["key"]: d["name"] for d in rackable + desk}
    return {"ok": True, "message": f"Look up {names.get(r['device'], r['device'])}'s serial number in the asset register."}


def audit_end(lab, plan) -> dict:
    """Ends the drill and says what was wrong; the documentation stays as
    the student left it (fixing it is theirs)."""
    a = audit_load(lab.name)
    if not a.get("faults") or a.get("ended"):
        return {"ok": False, "message": "no audit is running"}
    a["ended"], a["passed"] = time.time(), False
    _audit_save(lab.name, a)
    lines = [f"{AUDIT_KINDS[r['kind']].title}: {AUDIT_KINDS[r['kind']].where(lab, plan, r)}"
             + ("." if AUDIT_KINDS[r["kind"]].verify(lab, plan, r, a["register"]) else " (still wrong).")
             for r in a["faults"]]
    return {"ok": True, "message": "Audit ended. " + " ".join(lines), "found": lines}


def audit_view(lab) -> dict:
    a = audit_load(lab.name)
    if not a.get("faults"):
        return {"running": False}
    return {"running": not a.get("ended"), "passed": bool(a.get("passed")), "started": a.get("started"),
            "faults": len(a["faults"]), "hints": a.get("hints", 0), "checks": a.get("checks", 0),
            "ticket": a.get("ticket", "")}


# ------------------------------------------------------------------ the model
def _plug_key(key: str) -> str:
    """A rack key as the UPS names its plug (a switch is net:<switch>)."""
    from . import ups
    return ups.NET + key[3:] if key.startswith("sw:") else key


def _watts(lab, key: str, running: set[str]) -> dict:
    """What a device draws when it runs and what it draws now (the UPS's
    watt model), for the hover card."""
    from . import ups
    k = _plug_key(key)
    if k != ups.ROUTER and not k.startswith(ups.NET) and k not in lab.nodes:
        return {"watts": 0, "draw": 0}
    return {"watts": ups.rated(lab, k), "draw": ups.draws(lab, k, running)}


def _link(c: dict, lit: dict[str, bool], ups_on: bool) -> bool:
    """Whether a cable's port lights show a link: both ends powered (a
    switch and the router by the fabric, a desk device by its own power)."""
    if c["kind"] == "power":
        return ups_on
    ends = [c["a"]["key"], c["b"]["key"]]
    return all(lit.get(k, k.startswith("pp")) for k in ends)


def model(lab, plan, running: set[str]) -> dict:
    """Everything the window, the drawing and the label sheet show."""
    from . import ups
    rackable, desk = inventory(lab)
    placed, unplaced = placement(lab, rackable)
    keys = [d["key"] for d in rackable + desk]
    tg = tags(lab, keys)
    up = ups.load(lab.name)
    ups_on = ups.output_on(up) if up.get("fitted") else False

    def on(d) -> bool:
        k = d["key"]
        if k == "router" or k.startswith("sw:"):
            return "fabric" in running
        if k == "ups":
            return ups_on
        if d["kind"] == "panel":
            return False
        if k.startswith("ap:"):
            return k[3:] in running
        return k in running
    floor = set(table(lab)["floor"])
    items = []
    for d in rackable:
        r, u = placed.get(d["key"], (0, 0))
        items.append({**d, "rack": r, "u": u, "running": on(d), "tag": tg[d["key"]],
                      "serial": serial_of(lab, d["key"]), "pinned": d["key"] in table(lab)["at"],
                      "floor": d["key"] in floor, **_watts(lab, d["key"], running)})
    desk_rows = [{**d, "running": on(d), "tag": tg[d["key"]], "serial": serial_of(lab, d["key"]),
                  **_watts(lab, d["key"], running)} for d in desk]
    cs = cables(lab, plan)
    lit = {d["key"]: on(d) for d in rackable + desk}
    used: dict[str, set] = {}
    ports: dict[str, dict] = {}
    for c in cs:
        c["link"] = _link(c, lit, ups_on)
        legs = [c["a"], c["b"]]
        if c.get("panel"):
            pp, n = c["panel"].split("-")
            legs.append({"key": pp.lower(), "port": f"P{int(n)}"})
        for e in legs:
            used.setdefault(e["key"], set()).add(e["port"])
            ports.setdefault(e["key"], {})[e["port"]] = {"cable": c["id"], "link": c["link"], "kind": c["kind"],
                                                         "color": c["color"]}
    for it in items:
        it["used"] = sorted(used.get(it["key"], ()))
        it["jacks"] = ports.get(it["key"], {})
    for c in cs:
        c["label"] = label_of(lab, c)
        c["default"] = default_label(c)
        c["own"] = c["id"] in table(lab)["labels"]
    reg = register_of(lab)
    serials = {d["key"]: serial_of(lab, d["key"]) for d in rackable + desk}
    names = {d["key"]: d["name"] for d in rackable + desk}
    return {"lab": lab.name, "racks": [{"index": i + 1, "units": u} for i, u in enumerate(table(lab)["racks"])],
            "panels": int(table(lab)["panels"]), "items": items, "unplaced": [d["key"] for d in unplaced],
            "catalog": [it["key"] for it in items if not it["rack"]],
            "desk": desk_rows, "cables": cs, "power": power_view(lab, placed, running),
            "register": sorted(({"serial": serials[k], "tag": t, "device": names.get(k, k)} for k, t in reg.items()),
                               key=lambda r: r["serial"]),
            "audit": audit_view(lab)}


def view(dash) -> dict:
    """The Rack window: the model and the drawing."""
    from . import state
    m = model(dash.lab, dash.plan, state.running(dash.lab.name))
    m["svg"] = svg(m, interactive=True)
    return m


# ------------------------------------------------------------------ the drawing
# Each kind of equipment has a front and a back of its own, drawn from plain
# shapes so the PNG rasteriser below draws the same picture: drive bays with
# their handles and lights, a switch's numbered RJ45 ports with the link and
# activity lights built into each jack, the UPS's display with the load and
# the charge, the patch panel's numbered keystones. The Rack window gets the
# racks once, front and back laid over each other (the window flips them);
# the export puts the two views side by side. Lights carry classes and the
# cable they belong to, so the window lights and blinks them from the live
# data the Workbench already reads (power from the desktop's state, traffic
# from the router's counters).
U_PX = 18
FACE_W = 228
RAIL = 12
NUM_W = 22
SIDE_GAP = 34
CHANNEL = 70
RACK_GAP = 40
TOP_Y = 46
BOTTOM = 34
PAD = 16
BG = "#eef1f5"
LED_OFF = "#3b4048"
GREEN, AMBER, RED, BLUE = "#34d058", "#f5a623", "#ef4444", "#38bdf8"
FACES = {"panel": "#2f343b", "switch": "#26303a", "router": "#2a3340", "ups": "#2b2f35", "nas": "#3b4049",
         "san": "#333944", "firewall": "#3a2d31", "pbx": "#2d3a36", "ntp": "#33363d", "linux": "#363c45"}


def _geom(m: dict, stacked: bool = False) -> dict:
    """x positions of each rack's front and back, and the drawing's size.
    Stacked (the window): front and back at the same place, one shown at a
    time; otherwise (the export) side by side."""
    out, x = [], PAD
    tallest = max((r["units"] for r in m["racks"]), default=UNITS)
    for r in m["racks"]:
        front = x + NUM_W
        back = front if stacked else front + RAIL * 2 + FACE_W + SIDE_GAP + NUM_W
        out.append({"index": r["index"], "units": r["units"], "front": front, "back": back,
                    "channel": back + RAIL * 2 + FACE_W + 6})
        x = back + RAIL * 2 + FACE_W + CHANNEL + RACK_GAP
    return {"racks": out, "w": x - RACK_GAP + PAD, "h": TOP_Y + tallest * U_PX + BOTTOM, "stacked": stacked}


def _uy(units: int, u: int, h: int) -> int:
    """The top y of a device whose lowest unit is u."""
    return TOP_Y + (units - (u + h - 1)) * U_PX


def port_xy(item: dict, port: str, face_x: int, top: int) -> tuple[int, int]:
    """Where a port is on the back of a device (its centre)."""
    k, h = item["kind"], item["h"] * U_PX
    if port == "PSU":
        return face_x + FACE_W - 14, top + h // 2
    if port in ("CON", "COM"):
        return face_x + FACE_W - 36, top + h // 2
    if k == "switch":
        m = re.fullmatch(r"(Fa|Gi)0/(\d+)", port)
        if m and m[1] == "Fa":
            n = int(m[2]) - 1
            return face_x + 12 + (n // 2) * 12, top + 5 + (n % 2) * 8
        if m:
            n = int(m[2]) - 1
            return face_x + 12 + 12 * 12 + 8 + (n // 2) * 12, top + 5 + (n % 2) * 8
        return face_x + 6, top + h // 2
    if k == "router":
        m = re.fullmatch(r"Gi0/(\d+)", port)
        n = int(m[1]) if m else 0
        return face_x + 16 + n * 15, top + h // 2
    if k == "panel":
        m = re.fullmatch(r"P(\d+)", port)
        n = int(m[1]) - 1 if m else 0
        return face_x + 10 + n * 9, top + h // 2
    if k == "ups":
        m = re.fullmatch(r"OUT(\d+)", port)
        if m:
            return face_x + 16 + (int(m[1]) - 1) * 22, top + h - 10
        return face_x + (FACE_W - 60 if port == "USB" else FACE_W - 40), top + 9
    if port == "MGMT":
        return face_x + 100, top + h // 2
    if port == "USB":
        return face_x + 136, top + h // 2
    m = re.fullmatch(r"NIC(\d+)", port)
    n = int(m[1]) - 1 if m else 0
    return face_x + 16 + n * 15, top + h // 2


def back_ports(it: dict) -> list[str]:
    """The ports a cable can go into, on the back of a device."""
    k = it["kind"]
    if k == "switch":
        return [f"Fa0/{n}" for n in range(1, 25)] + [f"Gi0/{n}" for n in range(1, 5)] + ["CON", "PSU"]
    if k == "router":
        return [f"Gi0/{n}" for n in range(0, max(4, it.get("ports", 4)))] + ["CON", "PSU"]
    if k == "panel":
        return [f"P{n}" for n in range(1, PANEL_PORTS + 1)]
    if k == "ups":
        return [f"OUT{n}" for n in range(1, 7)] + ["USB", "NET"]
    out = [f"NIC{n}" for n in range(1, it.get("nics", 2) + 1)] + ["PSU"]
    if k in ("server", "linux", "iso", "doctools"):
        out[it.get("nics", 2):it.get("nics", 2)] = ["MGMT", "USB"]
    return out


def shapes(m: dict, interactive: bool = False) -> tuple[list[tuple], int, int]:
    """The rack as a list of shapes: ("rect", x, y, w, h, fill, stroke, extra),
    ("line", [(x, y), ...], colour, width, extra), ("curve", [p0, c1, c2, p1],
    colour, width, extra), ("text", x, y, text, size, colour, anchor, bold[,
    extra]), ("circle", x, y, r, fill[, extra]), and ("g", attrs) / ("/g",)
    around a group (the SVG's only: the window flips and moves them)."""
    g = _geom(m, stacked=interactive)
    S: list[tuple] = []
    S.append(("rect", 0, 0, g["w"], g["h"], BG, "", {}))
    items = {it["key"]: it for it in m["items"] if it["rack"]}
    for rk in g["racks"]:
        units = rk["units"]
        for view, x in (("front", rk["front"]), ("back", rk["back"])):
            if interactive:
                S.append(("g", {"class": f"rk-face rk-{view}", "data-rack": rk["index"]}))
            _frame(S, rk, view, x, interactive)
            for it in sorted((i for i in items.values() if i["rack"] == rk["index"]), key=lambda i: -i["u"]):
                top = _uy(units, it["u"], it["h"])
                if interactive:
                    S.append(("g", {"class": "rk-dev", "data-key": it["key"], "data-rack": it["rack"],
                                    "data-u": it["u"], "data-h": it["h"], "data-view": view}))
                (_front if view == "front" else _back)(S, it, x + RAIL, top, m, interactive)
                if interactive:
                    S.append(("/g",))
            if interactive:
                S.append(("/g",))
    if interactive:
        S.append(("g", {"class": "rk-face rk-back rk-wires"}))
    _cables(S, m, g, items, interactive)
    if interactive:
        S.append(("/g",))
    return S, g["w"], g["h"]


def _frame(S, rk, view, x, interactive) -> None:
    """The rack itself: its posts with their square holes, the U numbers,
    a cap at the top and the bottom."""
    units = rk["units"]
    body_h = units * U_PX
    S.append(("text", x + RAIL + FACE_W // 2, 18, f"RACK {rk['index']} - {view.upper()}", 9, "#1f2937",
              "middle", True))
    S.append(("rect", x - 4, TOP_Y - 10, FACE_W + RAIL * 2 + 8, body_h + 20, "#2d3138", "#1b1e23",
              {"rx": 4, "data": {"rack": rk["index"], "view": view, "top": TOP_Y, "units": units, "upx": U_PX}}
              if interactive else {"rx": 4}))
    S.append(("rect", x - 4, TOP_Y - 10, FACE_W + RAIL * 2 + 8, 7, "#3d434c", "", {"rx": 3}))
    S.append(("rect", x - 4, TOP_Y + body_h + 3, FACE_W + RAIL * 2 + 8, 7, "#3d434c", "", {"rx": 3}))
    S.append(("rect", x + RAIL, TOP_Y, FACE_W, body_h, "#121417" if view == "front" else "#0d0f12", "", {}))
    for side in (x, x + RAIL + FACE_W):
        S.append(("rect", side, TOP_Y, RAIL, body_h, "#9aa3ae", "#6b7380", {}))
        S.append(("rect", side + RAIL - 2, TOP_Y, 1, body_h, "#c3c9d0", "", {}))
        for u in range(units):
            y = TOP_Y + u * U_PX
            for dy in (4, 9, 14):
                S.append(("rect", side + 4, y + dy - 1, 4, 2, "#4b5563", "", {}))
            S.append(("rect", side + 1, y + U_PX - 0.5, 3, 0.6, "#6b7380", "", {}))  # the U boundary mark
    for u in range(1, units + 1):
        y = _uy(units, u, 1)
        S.append(("text", x - 6, y + 12, str(u), 7, "#64748b", "end", False))


def _led(S, x, y, on: bool, color: str, cls: str, data: dict | None, r: float = 1.3) -> None:
    S.append(("circle", x, y, r, color if on else LED_OFF,
              {"cls": cls + (" on" if on else ""), "data": data}))


def _chassis(S, it, fx, top, h, face, front: bool, interactive) -> None:
    S.append(("rect", fx + 1, top + 0.5, FACE_W - 2, h - 1, face, "#16181c",
              {"rx": 1.5, "cls": "rk-body" if interactive else ""}))
    S.append(("rect", fx + 2, top + 1, FACE_W - 4, 0.8, "#6b727c", "", {}))     # a highlight on the top edge
    S.append(("rect", fx + 2, top + h - 1.8, FACE_W - 4, 0.8, "#16181c", "", {}))  # and a shadow on the bottom
    if not front:
        return
    for ex in (fx + 1, fx + FACE_W - 9):  # the rack ears, screwed to the posts
        S.append(("rect", ex, top + 0.5, 8, h - 1, "#8a929d", "#5b636e", {}))
        ys = [top + h / 2] if h <= U_PX else [top + 5, top + h - 5]
        for sy in ys:
            S.append(("circle", ex + 4, sy, 1.8, "#d5d9de", {"stroke": "#4b5563"}))
            S.append(("rect", ex + 2.9, sy - 0.3, 2.2, 0.6, "#4b5563", "", {}))


def _tag(S, it, fx, top, h) -> None:
    """The asset tag sticker, bottom right of the face."""
    y = top + h - 13 if h > U_PX else top + 4
    S.append(("rect", fx + FACE_W - 52, y, 40, 10, "#f8fafc", "#cbd5e1", {}))
    S.append(("text", fx + FACE_W - 32, y + 7.5, it["tag"][:9], 5, "#111827", "middle", False))


def _vents(S, x0, y0, cols: int, rows: int, dx: float = 3.2, dy: float = 3.2) -> None:
    for r in range(rows):
        for c in range(cols):
            S.append(("rect", x0 + c * dx, y0 + r * dy, dx - 1.2, dy - 1.6, "#15181c", "", {}))


def _power_button(S, it, x, y, interactive) -> None:
    on = it["running"]
    S.append(("circle", x, y, 3.8, "#1f2328", {"stroke": "#9aa3ae"}))
    _led(S, x, y, on, GREEN, "rk-pwr", {"key": it["key"]} if interactive else None, r=1.9)


def _front(S, it, fx, top, m, interactive) -> None:
    h = it["h"] * U_PX
    k = it["kind"]
    key = {"key": it["key"]} if interactive else None
    _chassis(S, it, fx, top, h, FACES.get(k, "#3a4049"), True, interactive)
    if k == "panel":
        S.append(("rect", fx + 10, top + h - 5, FACE_W - 20, 3.4, "#e5e7eb", "", {}))  # the label strip
        ports = it.get("jacks") or {}
        for n in range(PANEL_PORTS):
            px = fx + 10 + n * 9 - 3.5
            S.append(("rect", px, top + 2.5, 7, 6.5, "#0c0e12", "#80868f", {}))
            if f"P{n + 1}" in ports:  # a patch cord in the jack
                S.append(("rect", px + 1.5, top + 3.2, 4, 2.4, ports[f"P{n + 1}"].get("color", "#cbd5e1"), "", {}))
            S.append(("text", px + 3.5, top + h - 2.3, str(n + 1), 2.8, "#111827", "middle", False))
        S.append(("text", fx + 2, top + 7, it["name"], 3.2, "#cbd5e1", "start", True))
        return
    if k == "switch":
        run = it["running"]
        _led(S, fx + 14, top + 6, run, GREEN, "rk-pwr", key)
        _led(S, fx + 14, top + 12, run, GREEN, "rk-sys", key)
        S.append(("text", fx + 18, top + 7.4, "PWR", 3, "#9ca3af", "start", False))
        S.append(("text", fx + 18, top + 13.4, "SYS", 3, "#9ca3af", "start", False))
        S.append(("text", fx + 30, top + 11, it["name"][:8].upper(), 5.5, "#e5e7eb", "start", True))
        ports = it.get("jacks") or {}
        for n in range(24):  # the port lights, odd numbers on the top row as on the jacks
            x, y = fx + 70 + (n // 2) * 8, top + 6 + (n % 2) * 6
            p = ports.get(f"Fa0/{n + 1}")
            on = bool(p and p["link"])
            _led(S, x, y, on, GREEN, "rk-sled", {"cable": p["cable"]} if p and interactive else None, r=1.2)
            if n % 2 == 0:
                S.append(("text", x, top + 3.4, str(n + 1), 2.2, "#9ca3af", "middle", False))
            else:
                S.append(("text", x, top + h - 0.6, str(n + 1), 2.2, "#9ca3af", "middle", False))
        for n in range(4):
            p = ports.get(f"Gi0/{n + 1}")
            _led(S, fx + 170 + n * 6, top + 9, bool(p and p["link"]), GREEN, "rk-sled",
                 {"cable": p["cable"]} if p and interactive else None, r=1.2)
        S.append(("rect", fx + 196, top + 5.5, 8, 7, "#0c0e12", BLUE, {}))  # the console port
        S.append(("text", fx + 200, top + 16, "CON", 2.4, BLUE, "middle", False))
        return
    if k == "router":
        run = it["running"]
        _power_button(S, it, fx + 16, top + h / 2, interactive)
        for i, lbl in enumerate(("SYS", "ACT")):
            _led(S, fx + 28 + i * 12, top + 6, run, GREEN, "rk-sys" if i == 0 else "rk-dled", key, r=1.1)
            S.append(("text", fx + 28 + i * 12, top + 13, lbl, 2.6, "#9ca3af", "middle", False))
        S.append(("text", fx + 54, top + 11, it["name"][:12].upper(), 5.5, "#e5e7eb", "start", True))
        _vents(S, fx + 118, top + 4, 14, 3)
        S.append(("rect", fx + 164, top + 6, 7, 6, "#0c0e12", "#9aa3ae", {}))  # USB
        _tag(S, it, fx, top, h)
        return
    if k == "ups":
        _ups_front(S, it, fx, top, h, m, interactive)
        return
    # computers and appliances: a power button, the name, then what is
    # particular to the kind (drive bays, a display, status lights)
    _power_button(S, it, fx + 16, top + (9 if h > U_PX else h / 2), interactive)
    _led(S, fx + 24, top + 5, it["running"], BLUE, "rk-id", key, r=0.9)
    S.append(("text", fx + 29, top + 7, it["name"][:12].upper(), 5, "#f3f4f6", "start", True))
    S.append(("text", fx + 29, top + 13, k.upper() if k != "iso" else "SERVER", 3, "#9ca3af", "start", False))
    if k in ("nas", "san"):
        cols, rows = (4, 1) if k == "nas" else (4, 3)
        tw, th = (26, h - 6) if k == "nas" else (30, (h - 6) / 3)
        for r in range(rows):
            for c in range(cols):
                bx, by = fx + 70 + c * (tw + 2), top + 3 + r * th
                _tray(S, it, bx, by, tw, th - 1, interactive, vertical=k == "nas")
        S.append(("rect", fx + 26, top + h - 14, 36, 9, "#0f2a22" if it["running"] else "#1b1f24", "#5b6470", {}))
        S.append(("text", fx + 28, top + h - 7.8, "READY" if it["running"] else "", 4, "#6ee7b7", "start", True))
        _tag(S, it, fx, top, h)
        return
    if k in ("pbx", "ntp", "firewall"):
        lcd = {"pbx": "PHONES", "ntp": "LAB TIME", "firewall": "FILTER"}[k]
        S.append(("rect", fx + 70, top + 3.5, 46, 11, "#0f2a22" if it["running"] else "#1b1f24", "#5b6470", {}))
        S.append(("text", fx + 73, top + 11, lcd if it["running"] else "", 4.4, "#6ee7b7", "start", True))
        for i, lbl in enumerate({"pbx": ("LINE", "TRK", "MSG"), "ntp": ("SYNC", "REF", "ALM"),
                                 "firewall": ("WAN", "LAN", "ALM")}[k]):
            _led(S, fx + 126 + i * 15, top + 6, it["running"] and i < 2, GREEN if i < 2 else RED,
                 "rk-dled" if i == 1 else "rk-sys", key, r=1.1)
            S.append(("text", fx + 126 + i * 15, top + 13.5, lbl, 2.5, "#9ca3af", "middle", False))
        _tag(S, it, fx, top, h)
        return
    bays = 4 if h <= U_PX else 10
    per_row = 4 if h <= U_PX else 5
    for n in range(bays):
        r, c = divmod(n, per_row)
        _tray(S, it, fx + 70 + c * 21, top + 3 + r * U_PX, 20, U_PX - 6, interactive)
    _vents(S, fx + 70 + per_row * 21 + 2, top + 4, 4, int(h / 3.2) - 2)
    _tag(S, it, fx, top, h)


def _tray(S, it, x, y, w, h, interactive, vertical: bool = False) -> None:
    """A drive tray: its face, the release handle, its two lights."""
    S.append(("rect", x, y, w, h, "#1d2127", "#6b7380", {"rx": 0.8}))
    if vertical:
        S.append(("rect", x + w / 2 - 1.5, y + 6, 3, h - 10, "#9aa3ae", "", {}))
        lx, ly = x + 4, y + 3
    else:
        S.append(("rect", x + 2, y + h - 3.2, w - 4, 1.8, "#9aa3ae", "", {}))
        for i in range(3):
            S.append(("rect", x + 3 + i * 2.2, y + 2, 1.2, h - 6, "#2a2f36", "", {}))
        lx, ly = x + w - 3, y + 2.4
    _led(S, lx, ly, it["running"], GREEN, "rk-dled", {"key": it["key"]} if interactive else None, r=0.8)


def _ups_front(S, it, fx, top, h, m, interactive) -> None:
    """The UPS's front: its display (status, load and charge, each with a
    bar), its lights and its buttons."""
    p = m.get("power") or {}
    run = it["running"]
    status = (p.get("status") or ("on line" if run else "off")).upper()
    batt = status == "ON BATTERY"
    S.append(("rect", fx + 14, top + 4, 82, h - 8, "#0f2a22" if run else "#1b1f24", "#5b6470",
              {"rx": 1, "cls": "rk-lcd" + (" batt" if batt else "")}))
    if run:
        col = "#fcd34d" if batt else "#6ee7b7"
        load = max(0, min(100, int(p.get("pct", 0))))
        charge = max(0, min(100, int(p.get("charge", 100))))
        S.append(("text", fx + 17, top + 10.5, status + (f"  {p['minutes']} MIN" if batt and p.get("minutes")
                                                          is not None else ""), 4.4, col, "start", True))
        for i, (lbl, v) in enumerate((("LOAD", load), ("BATT", charge))):
            y = top + 14 + i * 7.5
            S.append(("text", fx + 17, y + 4, f"{lbl} {v:>3}%", 3.8, col, "start", False))
            S.append(("rect", fx + 52, y + 0.6, 40, 3.6, "#0b1d17", "#2f5a4b", {}))
            if v:
                S.append(("rect", fx + 52, y + 0.6, 40 * v / 100, 3.6,
                          RED if lbl == "LOAD" and v > 90 or lbl == "BATT" and v < 25 else col, "", {}))
    for i, (lbl, col, lit) in enumerate((("LINE", GREEN, run and not batt), ("BATT", AMBER, run and batt),
                                         ("FAULT", RED, False))):
        _led(S, fx + 106 + i * 13, top + 9, lit, col, "rk-upsled" + (" batt" if col == AMBER else ""),
             {"key": "ups"} if interactive else None, r=1.6)
        S.append(("text", fx + 106 + i * 13, top + 16, lbl, 2.5, "#9ca3af", "middle", False))
    for i in range(2):  # the power and mute buttons
        S.append(("rect", fx + 102 + i * 16, top + 22, 11, 6, "#1f2328", "#9aa3ae", {"rx": 1.5}))
    S.append(("circle", fx + 107.5, top + 25, 1.1, GREEN if run else LED_OFF, {"cls": "rk-pwr" + (" on" if run else ""),
                                                                               "data": {"key": "ups"}
                                                                               if interactive else None}))
    _vents(S, fx + 140, top + 20, 12, 3)
    _tag(S, it, fx, top, h)


def _rj45(S, it, port: str, x, y, interactive, w: float = 8, hh: float = 6, number: str = "") -> None:
    """An RJ45 jack with its link (green) and activity (amber) lights in
    its top corners, lit for a cable with link; the window blinks the
    activity light with the traffic the router counts."""
    info = (it.get("jacks") or {}).get(port)
    S.append(("rect", x - w / 2, y - hh / 2, w, hh, "#0c0e12", "#9ca3af",
              {"cls": "rk-port" + (" used" if info else ""), "data": {"key": it["key"], "port": port}}
              if interactive else {}))
    S.append(("rect", x - w / 2 + 2.2, y + hh / 2 - 1.8, w - 4.4, 1.6, "#2a2f36", "", {}))
    link = bool(info and info["link"])
    cab = {"cable": info["cable"]} if info and interactive else None
    S.append(("rect", x - w / 2 + 0.5, y - hh / 2 + 0.5, 1.9, 1.3, GREEN if link else LED_OFF, "",
              {"cls": "rk-lnk" + (" on" if link else ""), "data": cab}))
    S.append(("rect", x + w / 2 - 2.4, y - hh / 2 + 0.5, 1.9, 1.3, LED_OFF, "", {"cls": "rk-act", "data": cab}))
    if number:
        S.append(("text", x, y + 1.6, number, 2.4, "#7b828c", "middle", False))


def _port_box(S, it, port, x, y, w, hh, fill, stroke, interactive, label: str = "") -> None:
    info = (it.get("jacks") or {}).get(port)
    S.append(("rect", x - w / 2, y - hh / 2, w, hh, fill, stroke,
              {"cls": "rk-port" + (" used" if info else ""), "data": {"key": it["key"], "port": port}}
              if interactive else {}))
    if label:
        S.append(("text", x, y - hh / 2 - 0.8, label, 2.4, "#cbd5e1", "middle", False))


def _psu(S, it, fx, top, h, interactive) -> None:
    """A power supply at the right of the back: its fan, its inlet."""
    x0 = fx + FACE_W - 30
    S.append(("rect", x0, top + 1.5, 28, h - 3, "#2b2f35", "#16181c", {"rx": 1}))
    cy = top + (h / 2 if h <= U_PX else 9)
    S.append(("circle", x0 + 7, cy, min(6.5, h / 2 - 2.5), "#16181c", {"stroke": "#6b7280"}))
    if interactive:
        S.append(("g", {"class": "rk-fan" + (" on" if it["running"] else "")}))
    r = min(6.5, h / 2 - 2.5) - 1
    for a in range(4):  # the fan's blades (the window spins them while it runs)
        dx, dy = ((r, 0), (0, r), (-r, 0), (0, -r))[a]
        S.append(("line", [(x0 + 7 - dx * .25, cy - dy * .25), (x0 + 7 + dx, cy + dy)], "#5b636e", 1.4, {}))
    if interactive:
        S.append(("/g",))
    px, py = port_xy(it, "PSU", fx, top)
    _port_box(S, it, "PSU", px, py, 9, 7, "#111318", "#9ca3af", interactive)
    S.append(("rect", px - 2.5, py - 1.5, 1.2, 3, "#6b7280", "", {}))
    S.append(("rect", px + 1.3, py - 1.5, 1.2, 3, "#6b7280", "", {}))


def _back(S, it, fx, top, m, interactive) -> None:
    h = it["h"] * U_PX
    k = it["kind"]
    _chassis(S, it, fx, top, h, "#454b55" if k != "panel" else "#3a3f47", False, interactive)
    if k not in ("switch", "panel"):
        S.append(("text", fx + 150, top + 6, it["name"][:10], 3.6, "#d1d5db", "start", False))
    if k == "switch":
        for n in range(1, 25):
            x, y = port_xy(it, f"Fa0/{n}", fx, top)
            _rj45(S, it, f"Fa0/{n}", x, y, interactive, number=str(n))
        for n in range(1, 5):
            x, y = port_xy(it, f"Gi0/{n}", fx, top)
            _rj45(S, it, f"Gi0/{n}", x, y, interactive, number=f"G{n}")
        x, y = port_xy(it, "CON", fx, top)
        _port_box(S, it, "CON", x, y, 8, 6, "#0c0e12", BLUE, interactive)
        _psu(S, it, fx, top, h, interactive)
        return
    if k == "panel":
        for n in range(1, PANEL_PORTS + 1):
            x, y = port_xy(it, f"P{n}", fx, top)
            S.append(("rect", x - 3.5, top + 1.5, 7, h - 3, "#2a2f36", "", {}))  # the punch-down block
            _port_box(S, it, f"P{n}", x, y, 7, 6, "#0c0e12", "#80868f", interactive)
            S.append(("text", x, top + h - 1.4, str(n), 2.4, "#cbd5e1", "middle", False))
        return
    if k == "ups":
        for n in range(1, 7):
            x, y = port_xy(it, f"OUT{n}", fx, top)
            _port_box(S, it, f"OUT{n}", x, y, 12, 9, "#111318", "#9ca3af", interactive, label=f"OUT{n}")
            for dx in (-3, 3):
                S.append(("rect", x + dx - 0.6, y - 2.5, 1.2, 3, "#6b7280", "", {}))
            S.append(("rect", x - 0.6, y + 1.2, 1.2, 1.8, "#6b7280", "", {}))
        x, y = port_xy(it, "USB", fx, top)
        _port_box(S, it, "USB", x, y, 8, 4, "#111318", "#a855f7", interactive, label="USB")
        x, y = port_xy(it, "NET", fx, top)
        _rj45(S, it, "NET", x, y, interactive)
        S.append(("text", x, y - 4, "NET", 2.4, "#cbd5e1", "middle", False))
        S.append(("rect", fx + FACE_W - 22, top + 18, 18, 14, "#111318", "#9ca3af", {"rx": 1}))  # the inlet
        _vents(S, fx + 150, top + 22, 8, 3)
        return
    if k == "router":
        for p in back_ports(it):
            if p.startswith("Gi"):
                x, y = port_xy(it, p, fx, top)
                _rj45(S, it, p, x, y, interactive, number=p[4:])
        x, y = port_xy(it, "CON", fx, top)
        _port_box(S, it, "CON", x, y, 8, 6, "#0c0e12", BLUE, interactive)
        _psu(S, it, fx, top, h, interactive)
        return
    for p in back_ports(it):
        x, y = port_xy(it, p, fx, top)
        if p.startswith("NIC"):
            _rj45(S, it, p, x, y, interactive, number=p[3:])
        elif p == "MGMT":
            _rj45(S, it, p, x, y, interactive)
            S.append(("text", x, y + 5.6, "MGMT", 2.2, "#cbd5e1", "middle", False))
        elif p == "USB":
            for dy in (-2.2, 2.2):
                _port_box(S, it, "USB", x, y + dy, 7, 3, "#111318", "#9ca3af", interactive)
    if k in ("server", "linux", "iso", "doctools"):
        x, y = port_xy(it, "COM", fx, top)
        _port_box(S, it, "COM", x, y, 10, 5, "#1f2328", "#9ca3af", interactive)
        _vents(S, fx + 146, top + h - 8 if h > U_PX else top + 9, 8, 2)
    _psu(S, it, fx, top, h, interactive)


def _cables(S, m, g, items, interactive) -> None:
    """Every cable on the back, port to port, as a sagging curve in the
    colour of its network, through the patch panel when there is one; a
    cable to a device that is not racked leaves at the top right."""
    racks = {r["index"]: r for r in g["racks"]}
    floor_y = TOP_Y + max(r["units"] for r in g["racks"]) * U_PX + 22

    def where(key: str, port: str):
        it = items.get(key)
        if not it:
            return None
        rk = racks[it["rack"]]
        top = _uy(rk["units"], it["u"], it["h"])
        return port_xy(it, port, rk["back"] + RAIL, top), rk
    lane = 0
    for c in m["cables"]:
        if c.get("panel"):
            pp, n = c["panel"].split("-")
            mid = {"key": pp.lower(), "port": f"P{int(n)}"}
            legs = [(c["a"], mid), (mid, c["b"])]
        else:
            legs = [(c["a"], c["b"])]
        width = 2.2 if c["kind"] == "trunk" else 2.0 if c["kind"] == "power" else 1.6
        for leg, (a, b) in enumerate(legs):
            pa, pb = where(a["key"], a["port"]), where(b["key"], b["port"])
            if pa is None and pb is None:
                continue
            lane += 1
            if pa is None or pb is None:  # one end off the rack: up and out of the top right
                (x, y), rk = pa or pb
                ex, ey = rk["back"] + RAIL * 2 + FACE_W + 18 + (lane % 6) * 4, TOP_Y - 14
                pts = [(x, y), (x + 10, y + 26), (ex, ey + 60), (ex, ey)]
                if pa is None:
                    pts = list(reversed(pts))
            else:
                (xa, ya), ra = pa
                (xb, yb), rb = pb
                if ra is not rb:  # between racks: over the top
                    hy = max(6, min(ya, yb) - 70 - (lane % 5) * 6)
                    pts = [(xa, ya), (xa, hy), (xb, hy), (xb, yb)]
                else:
                    sag = 12 + min(56, abs(xa - xb) * 0.12 + abs(ya - yb) * 0.1) + (lane % 5) * 3
                    low = min(floor_y, max(ya, yb) + sag)
                    pts = [(xa, ya), (xa + (xb - xa) * 0.12, low), (xb - (xb - xa) * 0.12, low), (xb, yb)]
            extra = {"dash": c["kind"] in ("console", "usb")}
            if interactive:
                extra.update({"cable": c["id"], "leg": leg, "link": c.get("link", False)})
            S.append(("curve", pts, c["color"], width, extra))
            for (x, y), real in ((pts[0], pa is not None), (pts[-1], pb is not None)):
                if real:  # the plug's boot, in the jack
                    S.append(("rect", x - 1.8, y - 1.8, 3.6, 3.6, c["color"], "#0f1115", {"rx": 0.8}))


# ------------------------------------------------------------------ SVG
def _attrs(extra: dict) -> str:
    out = ""
    if extra.get("cls"):
        out += f' class="{html.escape(extra["cls"])}"'
    for k, v in (extra.get("data") or {}).items():
        out += f' data-{k}="{html.escape(str(v))}"'
    return out


def _bez(pts, steps: int = 24) -> list[tuple[float, float]]:
    """A cubic curve as a polyline (for the PNG)."""
    (x0, y0), (x1, y1), (x2, y2), (x3, y3) = pts
    out = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        out.append((u * u * u * x0 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x3,
                    u * u * u * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y3))
    return out


def svg(m: dict, interactive: bool = False) -> str:
    S, w, h = shapes(m, interactive)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" class="rk-svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
           f'font-family="Segoe UI, system-ui, sans-serif" role="img" aria-label="rack elevation of {html.escape(m["lab"])}">']
    for s in S:
        kind = s[0]
        if kind == "g":
            out.append("<g" + "".join(f' {k}="{html.escape(str(v))}"' for k, v in s[1].items()) + ">")
        elif kind == "/g":
            out.append("</g>")
        elif kind == "rect":
            _, x, y, rw, rh, fill, stroke, extra = s
            attrs = f'x="{x:g}" y="{y:g}" width="{rw:g}" height="{rh:g}" fill="{fill}"'
            if stroke:
                attrs += f' stroke="{stroke}" stroke-width="0.8"'
            if extra.get("rx"):
                attrs += f' rx="{extra["rx"]}"'
            attrs += _attrs(extra)
            title = f'<title>{html.escape(extra["title"])}</title>' if extra.get("title") else ""
            out.append(f"<rect {attrs}>{title}</rect>" if title else f"<rect {attrs}/>")
        elif kind == "line":
            _, pts, color, width, extra = s
            d = " ".join(f"{x:g},{y:g}" for x, y in pts)
            attrs = f'points="{d}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linejoin="round"'
            if extra.get("dash"):
                attrs += ' stroke-dasharray="3 2"'
            out.append(f"<polyline {attrs}/>")
        elif kind == "curve":
            _, pts, color, width, extra = s
            (x0, y0), (x1, y1), (x2, y2), (x3, y3) = pts
            d = f"M{x0:.1f},{y0:.1f} C{x1:.1f},{y1:.1f} {x2:.1f},{y2:.1f} {x3:.1f},{y3:.1f}"
            attrs = (f'd="{d}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linecap="round" '
                     f'opacity="0.95"')
            if extra.get("dash"):
                attrs += ' stroke-dasharray="3 2"'
            if extra.get("cable"):
                cid = html.escape(extra["cable"])
                out.append(f'<path d="{d}" class="rk-hit" data-cable="{cid}" fill="none" stroke="transparent" '
                           f'stroke-width="7"/>')
                attrs += (f' class="rk-cable{" up" if extra.get("link") else ""}" data-cable="{cid}" '
                          f'data-leg="{extra.get("leg", 0)}"')
            out.append(f"<path {attrs}/>")
        elif kind == "text":
            _, x, y, text, size, color, anchor, bold = s[:8]
            extra = s[8] if len(s) > 8 else {}
            out.append(f'<text x="{x:g}" y="{y:g}" font-size="{size}" fill="{color}" text-anchor="{anchor}"'
                       f'{" font-weight=" + chr(34) + "600" + chr(34) if bold else ""}{_attrs(extra)}>'
                       f'{html.escape(text)}</text>')
        elif kind == "circle":
            _, x, y, r, fill = s[:5]
            extra = s[5] if len(s) > 5 else {}
            stroke = f' stroke="{extra["stroke"]}" stroke-width="0.6"' if extra.get("stroke") else ""
            out.append(f'<circle cx="{x:g}" cy="{y:g}" r="{r:g}" fill="{fill}"{stroke}{_attrs(extra)}/>')
    out.append("</svg>")
    return "".join(out)


# ------------------------------------------------------------------ PNG (a small rasteriser)
# A 5x7 font for the PNG: capitals, digits and the few signs labels use.
_FONT = {
    "A": "01110 10001 10001 11111 10001 10001 10001", "B": "11110 10001 10001 11110 10001 10001 11110",
    "C": "01110 10001 10000 10000 10000 10001 01110", "D": "11110 10001 10001 10001 10001 10001 11110",
    "E": "11111 10000 10000 11110 10000 10000 11111", "F": "11111 10000 10000 11110 10000 10000 10000",
    "G": "01110 10001 10000 10111 10001 10001 01111", "H": "10001 10001 10001 11111 10001 10001 10001",
    "I": "01110 00100 00100 00100 00100 00100 01110", "J": "00111 00010 00010 00010 00010 10010 01100",
    "K": "10001 10010 10100 11000 10100 10010 10001", "L": "10000 10000 10000 10000 10000 10000 11111",
    "M": "10001 11011 10101 10101 10001 10001 10001", "N": "10001 10001 11001 10101 10011 10001 10001",
    "O": "01110 10001 10001 10001 10001 10001 01110", "P": "11110 10001 10001 11110 10000 10000 10000",
    "Q": "01110 10001 10001 10001 10101 10010 01101", "R": "11110 10001 10001 11110 10100 10010 10001",
    "S": "01111 10000 10000 01110 00001 00001 11110", "T": "11111 00100 00100 00100 00100 00100 00100",
    "U": "10001 10001 10001 10001 10001 10001 01110", "V": "10001 10001 10001 10001 10001 01010 00100",
    "W": "10001 10001 10001 10101 10101 10101 01010", "X": "10001 10001 01010 00100 01010 10001 10001",
    "Y": "10001 10001 01010 00100 00100 00100 00100", "Z": "11111 00001 00010 00100 01000 10000 11111",
    "0": "01110 10001 10011 10101 11001 10001 01110", "1": "00100 01100 00100 00100 00100 00100 01110",
    "2": "01110 10001 00001 00010 00100 01000 11111", "3": "11111 00010 00100 00010 00001 10001 01110",
    "4": "00010 00110 01010 10010 11111 00010 00010", "5": "11111 10000 11110 00001 00001 10001 01110",
    "6": "00110 01000 10000 11110 10001 10001 01110", "7": "11111 00001 00010 00100 01000 01000 01000",
    "8": "01110 10001 10001 01110 10001 10001 01110", "9": "01110 10001 10001 01111 00001 00010 01100",
    "-": "00000 00000 00000 11111 00000 00000 00000", "/": "00001 00001 00010 00100 01000 10000 10000",
    ":": "00000 01100 01100 00000 01100 01100 00000", ".": "00000 00000 00000 00000 00000 01100 01100",
    "(": "00010 00100 01000 01000 01000 00100 00010", ")": "01000 00100 00010 00010 00010 00100 01000",
    "%": "11000 11001 00010 00100 01000 10011 00011", "_": "00000 00000 00000 00000 00000 00000 11111",
    "+": "00000 00100 00100 11111 00100 00100 00000", "#": "01010 01010 11111 01010 11111 01010 01010",
    ARROW: "00000 00000 01010 11111 01010 00000 00000", " ": "00000 00000 00000 00000 00000 00000 00000",
    "?": "01110 10001 00001 00010 00100 00000 00100",
}


def _rgb(color: str) -> tuple[int, int, int]:
    c = color.lstrip("#")
    if len(c) == 3:
        c = "".join(ch * 2 for ch in c)
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


class _Canvas:
    def __init__(self, w: int, h: int, scale: int = 1):
        self.s, self.w, self.h = scale, w * scale, h * scale
        self.px = bytearray(self.w * self.h * 3)

    def fill(self, x0: float, y0: float, x1: float, y1: float, rgb) -> None:
        s = self.s
        xa, xb = max(0, int(x0 * s)), min(self.w, int(round(x1 * s)))
        ya, yb = max(0, int(y0 * s)), min(self.h, int(round(y1 * s)))
        if xa >= xb:
            return
        row = bytes(rgb) * (xb - xa)
        for y in range(ya, yb):
            i = (y * self.w + xa) * 3
            self.px[i:i + len(row)] = row

    def rect(self, x, y, w, h, fill, stroke) -> None:
        if fill:
            self.fill(x, y, x + w, y + h, _rgb(fill))
        if stroke:
            c, t = _rgb(stroke), 1 / self.s
            self.fill(x, y, x + w, y + t, c)
            self.fill(x, y + h - t, x + w, y + h, c)
            self.fill(x, y, x + t, y + h, c)
            self.fill(x + w - t, y, x + w, y + h, c)

    def line(self, pts, color, width) -> None:
        c, half = _rgb(color), max(0.5, width / 2)
        for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
            if x0 == x1 or y0 == y1:   # the cable channel draws only straight runs
                self.fill(min(x0, x1) - half, min(y0, y1) - half, max(x0, x1) + half, max(y0, y1) + half, c)
            else:
                n = int(max(abs(x1 - x0), abs(y1 - y0)) * self.s) + 1
                for i in range(n + 1):
                    x, y = x0 + (x1 - x0) * i / n, y0 + (y1 - y0) * i / n
                    self.fill(x - half, y - half, x + half, y + half, c)

    def circle(self, cx, cy, r, color) -> None:
        c = _rgb(color)
        s = self.s
        for py in range(int((cy - r) * s), int((cy + r) * s) + 1):
            for px in range(int((cx - r) * s), int((cx + r) * s) + 1):
                if (px / s - cx) ** 2 + (py / s - cy) ** 2 <= r * r and 0 <= px < self.w and 0 <= py < self.h:
                    i = (py * self.w + px) * 3
                    self.px[i:i + 3] = bytes(c)

    def text(self, x, y, text, size, color, anchor) -> None:
        """Bitmap text: the baseline at y, like SVG's; a pixel of the font is
        size/8 of a drawing unit (so 7-unit text is about 7 units tall)."""
        c = _rgb(color)
        dot = max(size / 8, 0.6)
        width = len(text) * 6 * dot
        x0 = x - width / 2 if anchor == "middle" else x - width if anchor == "end" else x
        top = y - 7 * dot
        for k, ch in enumerate(text.upper()):
            rows = (_FONT.get(ch) or _FONT["?"]).split()
            for r, bits in enumerate(rows):
                for col, b in enumerate(bits):
                    if b == "1":
                        gx, gy = x0 + (k * 6 + col) * dot, top + r * dot
                        self.fill(gx, gy, gx + dot, gy + dot, c)


def png(m: dict, scale: int = 2) -> bytes:
    """The same drawing as svg(), as a PNG (stdlib only)."""
    from .power import png as encode
    S, w, h = shapes(m)
    cv = _Canvas(w, h, scale)
    for s in S:
        if s[0] == "rect":
            cv.rect(s[1], s[2], s[3], s[4], s[5], s[6])
        elif s[0] == "line":
            cv.line(s[1], s[2], s[3])
        elif s[0] == "curve":
            cv.line(_bez(s[1]), s[2], s[3])
        elif s[0] == "text":
            cv.text(s[1], s[2], s[3], s[4], s[5], s[6])
        elif s[0] == "circle":
            cv.circle(s[1], s[2], s[3], s[4])
    return encode(cv.w, cv.h, bytes(cv.px))


# ------------------------------------------------------------------ the label sheet
# Code 39, the barcode on an asset tag: 9 elements per character, 3 wide.
_C39 = {
    "0": "nnnwwnwnn", "1": "wnnwnnnnw", "2": "nnwwnnnnw", "3": "wnwwnnnnn", "4": "nnnwwnnnw",
    "5": "wnnwwnnnn", "6": "nnwwwnnnn", "7": "nnnwnnwnw", "8": "wnnwnnwnn", "9": "nnwwnnwnn",
    "A": "wnnnnwnnw", "B": "nnwnnwnnw", "C": "wnwnnwnnn", "D": "nnnnwwnnw", "E": "wnnnwwnnn",
    "F": "nnwnwwnnn", "G": "nnnnnwwnw", "H": "wnnnnwwnn", "I": "nnwnnwwnn", "J": "nnnnwwwnn",
    "K": "wnnnnnnww", "L": "nnwnnnnww", "M": "wnwnnnnwn", "N": "nnnnwnnww", "O": "wnnnwnnwn",
    "P": "nnwnwnnwn", "Q": "nnnnnnwww", "R": "wnnnnnwwn", "S": "nnwnnnwwn", "T": "nnnnwnwwn",
    "U": "wwnnnnnnw", "V": "nwwnnnnnw", "W": "wwwnnnnnn", "X": "nwnnwnnnw", "Y": "wwnnwnnnn",
    "Z": "nwwnwnnnn", "-": "nwnnnnwnw", ".": "wwnnnnwnn", " ": "nwwnnnwnn", "*": "nwnnwnwnn",
}


def barcode_svg(text: str, height: int = 26, narrow: float = 1.2) -> str:
    """A Code 39 barcode of `text` (characters it cannot carry are left out)."""
    body = "".join(ch for ch in text.upper() if ch in _C39 and ch != "*")
    x, bars = 0.0, []
    for ch in f"*{body}*":
        for i, e in enumerate(_C39[ch]):
            w = narrow * (2.5 if e == "w" else 1)
            if i % 2 == 0:
                bars.append(f'<rect x="{x:.2f}" y="0" width="{w:.2f}" height="{height}"/>')
            x += w
        x += narrow
    return (f'<svg xmlns="http://www.w3.org/2000/svg" class="bc" viewBox="0 0 {x:.2f} {height}" '
            f'width="{x:.2f}" height="{height}" fill="#000">{"".join(bars)}</svg>')


def label_sheet(m: dict) -> str:
    """The printable label sheet: an asset tag for every device and a wrap
    label for every cable (its text printed twice, one for each end)."""
    esc = html.escape
    devs = sorted([*(i for i in m["items"]), *m["desk"]], key=lambda d: d["name"].lower())
    tag_cells = "".join(
        f'<div class="tag"><div class="own">PROPERTY OF {esc(m["lab"].upper())} IT</div>'
        f'<div class="at">{esc(d["tag"])}</div>{barcode_svg(d["tag"])}'
        f'<div class="sub">{esc(d["name"])} &middot; S/N {esc(d["serial"])}</div></div>' for d in devs)
    cab_cells = "".join(
        f'<div class="cab" style="--c:{esc(c["color"])}"><div class="end">{esc(c["label"])}</div>'
        f'<div class="wrap"></div><div class="end">{esc(c["label"])}</div>'
        f'<div class="meta">{esc(c["id"])}{" &middot; VLAN " + str(c["vlan"]) if c["vlan"] else ""}'
        f'{" &middot; via " + esc(c["panel"]) if c.get("panel") else ""}</div></div>'
        for c in m["cables"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Labels - {esc(m['lab'])}</title><style>
@page {{ size: A4; margin: 10mm }}
body {{ font: 11px "Segoe UI", system-ui, sans-serif; color: #111; background: #fff; margin: 14px }}
h1 {{ font-size: 15px; margin: 0 0 2px }} h2 {{ font-size: 12px; margin: 16px 0 6px; text-transform: uppercase; letter-spacing: .06em; color: #444 }}
.note {{ color: #555; margin-bottom: 8px }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fill, 63.5mm); gap: 3mm }}
.tag {{ border: 1px dashed #999; height: 29.6mm; padding: 2mm 3mm; box-sizing: border-box; display: flex; flex-direction: column; align-items: center; justify-content: space-between; break-inside: avoid }}
.tag .own {{ font-size: 7px; letter-spacing: .08em; color: #333 }} .tag .at {{ font: 600 15px Consolas, monospace }}
.tag .sub {{ font-size: 8px; color: #333 }} .tag .bc {{ height: 7mm; max-width: 56mm }}
.cabs {{ display: grid; grid-template-columns: repeat(auto-fill, 90mm); gap: 3mm }}
.cab {{ border: 1px dashed #999; border-left: 4mm solid var(--c); padding: 1.5mm 2mm; break-inside: avoid; box-sizing: border-box }}
.cab .end {{ font: 600 10px Consolas, monospace }} .cab .wrap {{ height: 5mm; background: repeating-linear-gradient(90deg, #eee 0 2mm, #fff 2mm 4mm); margin: 1mm 0 }}
.cab .meta {{ font-size: 8px; color: #555; margin-top: 1mm }}
@media print {{ .noprint {{ display: none }} body {{ margin: 0 }} }}
</style></head><body>
<h1>Rack labels &mdash; {esc(m['lab'])}</h1>
<div class="note">Print on plain paper or on label stock (63.5 &times; 29.6 mm asset tags; cable labels wrap round the cable, the text once on each side of the white band). Cut along the dashed lines.</div>
<h2>Asset tags ({len(devs)})</h2><div class="grid">{tag_cells}</div>
<h2>Cable labels ({len(m['cables'])})</h2><div class="cabs">{cab_cells}</div>
</body></html>"""


def labels_text(m: dict) -> str:
    """The label sheet as plain text, for the terminal."""
    lines = ["ASSET TAGS"]
    for d in sorted([*m["items"], *m["desk"]], key=lambda d: d["name"].lower()):
        lines.append(f"  {d['tag']:<12} {d['name']:<16} S/N {d['serial']}")
    lines += ["", "CABLE LABELS"]
    for c in m["cables"]:
        lines.append(f"  {c['label']:<44} {c['id']}" + (f"  via {c['panel']}" if c.get("panel") else ""))
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ cabling from the rack
# Two ports clicked one after the other plug one cable, as in a network
# simulator's physical view. The rack holds no cabling of its own: each
# cable goes through the action the Workbench (or the UPS's panel) uses for
# it, so the lab's real cabling changes, live while the machines run, with
# the Workbench's history and its cable faults following the cable.
def _end_kind(lab, end: dict) -> str:
    key, port = end["key"], end["port"]
    if key.startswith("sw:"):
        return "swgi1" if port == "Gi0/1" else "swgi" if port.startswith("Gi") else \
            "power" if port == "PSU" else "swport" if port.startswith("Fa") else "other"
    if key.startswith("pp"):
        return "panel"
    if key == "router":
        return "power" if port == "PSU" else "routerport" if port.startswith("Gi") else "other"
    if key == "ups":
        return "outlet" if port.startswith("OUT") else "upsusb" if port == "USB" else "upsnet" \
            if port == "NET" else "other"
    if key in lab.nodes:
        return "nic" if port.startswith("NIC") else "power" if port == "PSU" else "mgmt" if port == "MGMT" \
            else "usb" if port == "USB" else "other"
    return "other"


def _panel_switch(lab, plan, panel_key: str) -> str:
    """The switch a patch panel's back is punched down to: the one its
    cables already run into, else the lab's first switch."""
    from . import devcli
    for c in cables(lab, plan):
        if c.get("panel", "").lower().startswith(panel_key + "-") and c["b"]["key"].startswith("sw:"):
            return c["b"]["key"][3:]
    sws = devcli.switches(lab)
    if not sws:
        raise RackError("no switch in the lab for the patch panel to be punched down to: put one on the Workbench")
    return sws[0]


def plug_call(lab, plan, a: dict, b: dict) -> tuple[str, str, dict]:
    """(module, action, params) of the cable from port a to port b: which
    of the Workbench's (or the UPS's, or the management port's) actions
    plugs it. Raises RackError for two ports that take no cable together."""
    ka, kb = _end_kind(lab, a), _end_kind(lab, b)
    pairs = {(ka, kb): (a, b), (kb, ka): (b, a)}

    def pick(x: str, y: str):
        return pairs.get((x, y))
    if (hit := pick("nic", "swport") or pick("nic", "swgi") or pick("nic", "panel")):
        node, other = hit
        if other["key"].startswith("pp"):
            sw = _panel_switch(lab, plan, other["key"])
        else:
            sw = other["key"][3:]
        idx = int(node["port"][3:]) - 1
        nic = lab.nodes[node["key"]].nics[idx] if idx < len(lab.nodes[node["key"]].nics) else None
        if nic is None:
            raise RackError(f"{node['key']} has no network card {idx + 1}")
        cur = lab.networks.get(nic.network) if nic.plugged else None
        net = nic.network if cur is not None and cur.home == sw else sw  # a VLAN of that switch stays its VLAN
        call = {"node": node["key"], "nic": idx, "network": net}
        m = re.match(r"^Fa0/(\d+)$", str(other.get("port", "")))
        if other["key"].startswith("sw:") and m:
            call["port"] = int(m.group(1))  # the very port clicked
        return "workbench", "wb-cable", call
    if (hit := pick("swgi1", "routerport")):
        return "workbench", "wb-cable", {"node": "router", "network": hit[0]["key"][3:]}
    if (hit := pick("swgi1", "swgi")) or (hit := pick("swgi1", "swgi1")):
        sw, to = hit[0]["key"][3:], hit[1]["key"][3:]
        if sw == to:
            raise RackError("a switch is not cabled to itself")
        return "workbench", "wb-cable", {"node": "switch", "network": sw, "to": to}
    if (hit := pick("power", "outlet")):
        return "ups", "ups-plug", {"key": _plug_key(hit[0]["key"])}
    if (hit := pick("usb", "upsusb")):
        return "ups", "ups-usb", {"node": hit[0]["key"]}
    if (hit := pick("mgmt", "swport") or pick("mgmt", "panel")):
        node, other = hit
        sw = _panel_switch(lab, plan, other["key"]) if other["key"].startswith("pp") else other["key"][3:]
        return "power", "power-bmc", {"node": node["key"], "network": sw}
    if (hit := pick("upsnet", "swport") or pick("upsnet", "panel")):
        other = hit[1]
        sw = _panel_switch(lab, plan, other["key"]) if other["key"].startswith("pp") else other["key"][3:]
        return "ups", "ups-card", {"network": sw}
    raise RackError(f"{a['port']} and {b['port']} take no cable together: a network card goes into a switch "
                    f"or the patch panel, a switch's Gi0/1 uplink into the router or another switch's "
                    f"Gi0/2-4, a power inlet into a UPS outlet")


def unplug_call(lab, plan, cable_id: str) -> tuple[str, str, dict]:
    """(module, action, params) that pulls a cable out."""
    c = next((x for x in cables(lab, plan) if x["id"] == cable_id), None)
    if c is None:
        raise RackError(f"no cable {cable_id!r}")
    k = c["kind"]
    if k == "data":
        node, _, nic = c["id"].rpartition(":nic")
        return "workbench", "wb-unplug", {"node": node, "nic": int(nic)}
    if k == "ap":
        return "workbench", "wb-unplug", {"node": "ap:" + c["id"][3:]}
    if k == "trunk":
        sw = c["id"][3:]
        return "workbench", "wb-unplug", {"node": "switch" if lab.networks[sw].upstream else "router",
                                          "network": sw}
    if k == "power":
        return "ups", "ups-unplug", {"key": _plug_key(c["a"]["key"])}
    if k == "usb":
        return "ups", "ups-usb", {}
    if k == "mgmt":
        return "power", "power-bmc", {"node": c["a"]["key"], "op": "unplug"}
    if k == "card":
        return "ups", "ups-card", {}
    raise RackError("pull the console cable on the Workbench (its shelf)")


def _run_call(dash, call: tuple[str, str, dict]) -> dict:
    """Carries the action out through its own module, as the Workbench does."""
    import importlib
    mod, action, params = call
    r = importlib.import_module(f"winlab.{mod}").act(dash, action, dict(params))
    if hasattr(dash, "reload"):
        dash.reload()
    return r


def _end(params: dict, side: str) -> dict:
    e = params.get(side) or {}
    if not isinstance(e, dict) or not e.get("key") or not e.get("port"):
        raise RackError("click a port, then the port the other end of the cable goes into")
    return {"key": str(e["key"]), "port": str(e["port"])}


# ------------------------------------------------------------------ the desktop
def _save(dash) -> None:
    from . import editor
    prune(dash.lab)
    editor.save(dash.lab)
    if hasattr(dash, "reload"):
        dash.reload()


def act(dash, action: str, params: dict) -> dict:
    """The Rack window's rack-* actions."""
    lab, plan = dash.lab, dash.plan
    try:
        if action == "rack-view":
            return {"ok": True, **view(dash)}
        if action in ("rack-plug", "rack-unplug"):
            call = (plug_call(lab, plan, _end(params, "a"), _end(params, "b")) if action == "rack-plug"
                    else unplug_call(lab, plan, str(params.get("cable") or "")))
            r = _run_call(dash, call)
            return {**r, "call": call[1], **view(dash)} if r.get("ok") is not False else r
        if action == "rack-move":
            r, u = int(params.get("rack") or 1), int(params.get("u") or 0)
            msg = move(lab, resolve(lab, str(params.get("key") or "")), r, u)
        elif action == "rack-unrack":
            msg = unrack(lab, resolve(lab, str(params.get("key") or "")))
        elif action == "rack-unrack-all":
            msg = unrack_all(lab)
        elif action == "rack-label":
            msg = set_label(lab, plan, str(params.get("cable") or ""), str(params.get("text") or ""))
        elif action == "rack-tag":
            msg = set_tag(lab, resolve(lab, str(params.get("key") or "")), str(params.get("tag") or ""))
        elif action == "rack-serial":
            msg = set_serial(lab, resolve(lab, str(params.get("key") or "")), str(params.get("serial") or ""))
        elif action == "rack-racks":
            msg = set_racks(lab, int(params.get("count") or 1), int(params.get("units") or UNITS))
        elif action == "rack-panels":
            msg = set_panels(lab, int(params.get("count") or 0))
        elif action == "rack-audit-start":
            a = audit_start(lab, plan)
            _save(dash)
            n = len(a["faults"])
            return {"ok": True, "message": "Audit the rack: the auditor is coming. The documentation has "
                    f"{'an error' if n == 1 else 'errors'} somewhere: find and fix {'it' if n == 1 else 'them'} by hand."
                    + (f" (ticket {a['ticket']})" if a.get("ticket") else ""), **view(dash)}
        elif action == "rack-audit-check":
            return {**audit_check(lab, plan), **view(dash)}
        elif action == "rack-audit-hint":
            return {**audit_hint(lab, plan), **view(dash)}
        elif action == "rack-audit-end":
            return {**audit_end(lab, plan), **view(dash)}
        else:
            return {"ok": False, "message": f"unknown rack action {action!r}"}
    except (RackError, ValueError) as exc:
        return {"ok": False, "message": str(exc)}
    try:
        _save(dash)
    except Exception as exc:  # editor.EditError: the lab file would not load
        return {"ok": False, "message": str(exc)}
    return {"ok": True, "message": msg, **view(dash)}


# ------------------------------------------------------------------ the command line
def add_cli(sub) -> None:
    p = sub.add_parser("rack", help="the rack: where each device sits, cable labels, asset tags, the label sheet, "
                                    "the audit drill")
    p.add_argument("lab")
    p.add_argument("what", choices=["show", "move", "unrack", "plug", "unplug", "label", "tag", "serial", "labels",
                                    "export", "racks", "panels", "audit", "check", "hint", "end"])
    p.add_argument("args", nargs="*", default=[])


def _show(m: dict) -> str:
    lines = []
    for r in m["racks"]:
        lines.append(f"Rack {r['index']} ({r['units']}U)")
        for it in sorted((i for i in m["items"] if i["rack"] == r["index"]), key=lambda i: -i["u"]):
            span = f"U{it['u']}" + (f"-U{it['u'] + it['h'] - 1}" if it["h"] > 1 else "")
            lines.append(f"  {span:<8} {it['name']:<16} {it['kind']:<8} {it['tag']:<10} S/N {it['serial']}"
                         f"  {'on' if it['running'] else 'off'}")
    if m["unplaced"]:
        lines.append(f"No room: {', '.join(m['unplaced'])} (add a rack: winlab rack {m['lab']} racks 2)")
    waiting = [i for i in m["items"] if i.get("floor")]
    if waiting:
        lines.append("On the floor, to rack: " + ", ".join(f"{i['name']} ({i['h']}U)" for i in waiting)
                     + f" (winlab rack {m['lab']} move <device> <U>)")
    if m["desk"]:
        lines.append("Not racked: " + ", ".join(f"{d['name']} ({d['where']}, {d['tag']})" for d in m["desk"]))
    p = m["power"]
    lines.append(f"Power: the rack draws {p['now_w']} W now, {p['full_w']} W with everything on"
                 + (f"; {p['on_ups_w']} W on the {p['ups_title']} ({p['pct']}% of {p['ups_w']} W)" if p["ups"]
                    else "; no UPS"))
    lines.append("")
    lines.append("Cables (id, label, VLAN, patch panel)")
    for c in m["cables"]:
        lines.append(f"  {c['id']:<16} {c['label']:<44} {('VLAN ' + str(c['vlan'])) if c['vlan'] else c['kind']:<8}"
                     f" {c.get('panel') or ''}")
    if m["audit"].get("running"):
        lines.append("")
        lines.append(f"An audit is running: fix the documentation, then winlab rack {m['lab']} check")
    return "\n".join(lines)


def run_cli(args) -> int:
    import sys
    from . import editor, netplan, schema, state
    lab = schema.load(args.lab)
    plan = netplan.compile_topology(lab, check_ports=False)
    a = list(args.args)
    try:
        if args.what == "show":
            print(_show(model(lab, plan, state.running(lab.name))))
            return 0
        if args.what == "labels":
            m = model(lab, plan, state.running(lab.name))
            if a:
                Path(a[0]).write_text(label_sheet(m), encoding="utf-8")
                print(f"label sheet written to {a[0]}: open it in a browser and print it")
            else:
                print(labels_text(m), end="")
            return 0
        if args.what == "export":
            if not a:
                raise RackError("winlab rack <lab> export <file.svg|file.png>")
            m = model(lab, plan, state.running(lab.name))
            dest = Path(a[0])
            if dest.suffix.lower() == ".png":
                dest.write_bytes(png(m))
            elif dest.suffix.lower() == ".svg":
                dest.write_text(svg(m), encoding="utf-8")
            else:
                raise RackError("export to a .svg or a .png file")
            print(f"rack diagram written to {dest}")
            return 0
        if args.what in ("plug", "unplug"):
            return _cli_cable(lab, plan, args.what, a)
        if args.what in ("check", "hint", "end"):
            r = {"check": audit_check, "hint": audit_hint, "end": audit_end}[args.what](lab, plan)
            print(r["message"])
            return 0 if r["ok"] else 1
        if args.what == "audit":
            r = audit_start(lab, plan)
            msg = (f"Audit the rack: {len(r['faults'])} documentation error(s) are hidden in the labels and tags. "
                   f"Find and fix them (winlab rack {lab.name} label|tag ...), then winlab rack {lab.name} check")
        elif args.what == "move":
            if len(a) != 2:
                raise RackError("winlab rack <lab> move <device> <U | rack:U>")
            msg = move(lab, resolve(lab, a[0]), *parse_u(a[1]))
        elif args.what == "unrack":
            if len(a) != 1:
                raise RackError("winlab rack <lab> unrack <device | all>")
            msg = unrack_all(lab) if a[0].lower() == "all" else unrack(lab, resolve(lab, a[0]))
        elif args.what == "label":
            if not a:
                raise RackError("winlab rack <lab> label <cable> <text> (no text: the default label)")
            msg = set_label(lab, plan, a[0], " ".join(a[1:]))
        elif args.what == "tag":
            if len(a) != 2:
                raise RackError("winlab rack <lab> tag <device> <tag>")
            msg = set_tag(lab, resolve(lab, a[0]), a[1])
        elif args.what == "serial":
            if len(a) != 2:
                raise RackError("winlab rack <lab> serial <device> <serial>")
            msg = set_serial(lab, resolve(lab, a[0]), a[1])
        elif args.what == "racks":
            msg = set_racks(lab, int(a[0]) if a else 1, int(a[1]) if len(a) > 1 else UNITS)
        else:
            msg = set_panels(lab, int(a[0]) if a else 1)
    except (RackError, ValueError, editor.EditError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    prune(lab)
    editor.save(lab)
    print(msg)
    return 0


# ------------------------------------------------------------------ grading the rack
# The rack lesson's exercise is graded on the end state winlab keeps for the
# lab (the [rack] table, the cabling, the UPS's plugs, the audit's record):
# exercises.py asks these by name for a check whose node is "winlab". Each
# says what is still wrong, by device, so a failed check reads like a
# colleague's review of the rack.
WEIGHT = {"ups": 30, "san": 25, "nas": 15, "router": 4, "switch": 3, "panel": 1}
NETWORK = ("panel", "switch")
MACHINE_CABLES = ("data", "mgmt", "ap", "card")


def weight_of(it: dict) -> int:
    """A rough weight in kg: the UPS's batteries, the storage's drives."""
    return WEIGHT.get(it["kind"], 10 + 5 * (it["h"] - 1))


def _graded(lab):
    from .netplan import compile_topology
    plan = compile_topology(lab, check_ports=False)
    return plan, model(lab, plan, set())


def check_racked(lab) -> tuple[bool, str]:
    _, m = _graded(lab)
    out = [i["name"] for i in m["items"] if not i["rack"]]
    if out:
        return False, f"not in the rack yet: {', '.join(out)}"
    if not m["panels"]:
        return False, "no patch panel: fit one (Patch panels +) and rack it"
    if not any(i["kind"] == "ups" for i in m["items"]):
        return False, "no UPS: put one on from the Workbench's shelf and rack it"
    return True, f"{len(m['items'])} devices racked"


def check_top(lab) -> tuple[bool, str]:
    """The patch panel and the switches at the top of the rack."""
    _, m = _graded(lab)
    racked = [i for i in m["items"] if i["rack"]]
    nets = [i for i in racked if i["kind"] in NETWORK]
    if not nets:
        return False, "no patch panel or switch in the rack"
    for net in nets:
        under = [o for o in racked if o["rack"] == net["rack"] and o["kind"] not in NETWORK + ("router",)
                 and o["u"] + o["h"] - 1 > net["u"]]
        if under:
            return False, f"{under[0]['name']} sits above {net['name']}: the patch panel and the switches go at the top"
    for r in {i["rack"] for i in nets}:
        top = max((i for i in racked if i["rack"] == r), key=lambda i: i["u"] + i["h"])
        if top["kind"] not in NETWORK:
            return False, f"the top of rack {r} is {top['name']}: put the patch panel or the switch there"
    return True, "the patch panel and the switches are at the top"


def check_bottom(lab) -> tuple[bool, str]:
    """The UPS at the bottom, and heavier kit below lighter."""
    _, m = _graded(lab)
    racked = [i for i in m["items"] if i["rack"]]
    upses = [i for i in racked if i["kind"] == "ups"]
    if not upses:
        return False, "the UPS is not in the rack"
    for u in upses:
        lowest = min((i for i in racked if i["rack"] == u["rack"]), key=lambda i: i["u"])
        if lowest["key"] != u["key"]:
            return False, f"{lowest['name']} is under the UPS: the UPS, the heaviest, goes at the bottom"
    for r in {i["rack"] for i in racked}:
        kit = sorted((i for i in racked if i["rack"] == r and i["kind"] not in NETWORK + ("router",)),
                     key=lambda i: i["u"])
        for low, high in zip(kit, kit[1:]):
            if weight_of(high) > weight_of(low):
                return False, (f"{high['name']} (about {weight_of(high)} kg) is above {low['name']} "
                               f"(about {weight_of(low)} kg): heavy kit goes low")
    return True, "the UPS at the bottom, heavy kit low"


def check_panel(lab) -> tuple[bool, str]:
    """Every machine's cable through the patch panel."""
    _, m = _graded(lab)
    if not any(i["kind"] == "panel" and i["rack"] for i in m["items"]):
        return False, "no patch panel in the rack"
    direct = [c for c in m["cables"] if c["kind"] in MACHINE_CABLES and not c.get("panel")]
    if direct:
        return False, (f"{len(direct)} cable(s) go straight into the switch ({direct[0]['label']}): fit another "
                       f"patch panel")
    if not any(c.get("panel") for c in m["cables"]):
        return False, "no cable runs through the patch panel: cable the machines"
    return True, "every machine's cable runs through the patch panel"


def check_power(lab) -> tuple[bool, str]:
    """Every racked device's power cord in the UPS."""
    from . import ups
    _, m = _graded(lab)
    if not ups.load(lab.name).get("fitted"):
        return False, "no UPS"
    plugs = set(ups.load(lab.name).get("plugs") or [])
    wall = [i["name"] for i in m["items"] if i["rack"] and i["kind"] not in ("panel", "ups")
            and _plug_key(i["key"]) not in plugs]
    if wall:
        return False, f"on the wall, not the UPS: {', '.join(wall)}"
    return True, "everything in the rack is on the UPS"


def check_labels(lab) -> tuple[bool, str]:
    """Every network cable labelled by hand, naming the two ports it joins."""
    _, m = _graded(lab)
    want = [c for c in m["cables"] if c["kind"] in MACHINE_CABLES + ("trunk",)]
    if not want:
        return False, "no network cable to label"
    unlabelled = [c["default"] for c in want if not c["own"]]
    if unlabelled:
        return False, f"{len(unlabelled)} cable(s) carry no label of yours yet, such as {unlabelled[0]}"
    wrong = [c["label"] for c in want if not label_ok(lab, c)]
    if wrong:
        return False, f"{len(wrong)} label(s) do not name the two ports the cable joins, such as '{wrong[0]}'"
    return True, f"{len(want)} cables labelled"


def check_tags(lab) -> tuple[bool, str]:
    """Every racked device's asset tag written in the documentation, as
    purchasing's register has it for its serial number."""
    _, m = _graded(lab)
    own = table(lab)["tags"]
    bought = register_of(lab)
    racked = [i for i in m["items"] if i["rack"] and i["kind"] != "panel"]  # a patch panel is not an asset
    missing = [i["name"] for i in racked if i["key"] not in own]
    if missing:
        return False, f"no asset tag recorded yet on {', '.join(missing)}"
    wrong = [i["name"] for i in racked if own[i["key"]].upper() != bought[i["key"]].upper()]
    if wrong:
        return False, f"the tag on {wrong[0]} is not the one the asset register has for its serial number"
    return True, f"{len(racked)} asset tags recorded"


def check_audit(lab) -> tuple[bool, str]:
    a = audit_load(lab.name)
    if not a.get("faults"):
        return False, "no audit run yet: Audit the rack"
    if not a.get("ended"):
        return False, "the audit is still running: fix the documentation, then Check my fix"
    return (True, "the audit passed") if a.get("passed") else (False, "the last audit ended without passing: run another")


GRADES = {"rack-racked": check_racked, "rack-top": check_top, "rack-bottom": check_bottom,
          "rack-panel": check_panel, "rack-power": check_power, "rack-labels": check_labels,
          "rack-tags": check_tags, "rack-audit": check_audit}


def parse_end(lab, text: str) -> dict:
    """'SRV01-NIC1', 'sw1-Fa0/3', 'PP1-P5', 'UPS-OUT2' -> {key, port}."""
    dev, sep, port = text.strip().rpartition("-")
    if not sep or not dev or not port:
        raise RackError(f"{text!r} is not a port: write <device>-<port>, as on a cable label (SRV01-NIC1)")
    key = resolve(lab, dev)
    rackable, desk = inventory(lab)
    it = next((d for d in rackable if d["key"] == key), None)
    names = back_ports(it) if it else []
    hit = next((p for p in names if p.lower() == port.lower()), None)
    if hit is None:
        raise RackError(f"{dev} has no port {port!r}" + (f" (its ports: {', '.join(names)})" if names else ""))
    return {"key": key, "port": hit}


class _CliDash:
    """What the Workbench's actions need of the desktop, for the terminal."""

    def __init__(self, lab_name: str) -> None:
        self.name = lab_name
        self.reload()

    def reload(self) -> None:
        from . import netplan, schema
        self.lab = schema.load(self.name)
        self.plan = netplan.compile_topology(self.lab, check_ports=False)


def _cli_cable(lab, plan, what: str, a: list[str]) -> int:
    import sys
    try:
        if what == "plug":
            if len(a) != 2:
                raise RackError("winlab rack <lab> plug <device-port> <device-port> (SRV01-NIC1 sw1-Fa0/3)")
            call = plug_call(lab, plan, parse_end(lab, a[0]), parse_end(lab, a[1]))
        else:
            if len(a) != 1:
                raise RackError("winlab rack <lab> unplug <cable> (its id, its label or one of its ends)")
            call = unplug_call(lab, plan, find_cable(lab, plan, a[0])["id"])
        r = _run_call(_CliDash(lab.name), call)
    except RackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(r.get("message") or ("done" if r.get("ok") else "failed"))
    return 0 if r.get("ok") is not False else 1


def _ticket_check(lab, fault: dict, runner=None) -> tuple[bool, str]:
    ok = verify_fault(lab, fault)
    return ok, ("the labels and tags match the rack" if ok
                else "the auditor still finds labels or tags that do not match the rack")


# A rack audit ticket is resolved when the documentation is right again.
def _register() -> None:
    from . import exercises, helpdesk
    helpdesk.register_check("rack", _ticket_check)
    for name, fn in GRADES.items():  # the rack lesson's exercise grades these
        exercises.register_winlab_check(name, fn)


_register()
