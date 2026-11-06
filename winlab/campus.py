"""Wire a site: a client's existing buildings, cabled and set up by you.

A job (content/sites/<job>.toml) is a real-looking site drawn to scale in
metres: the buildings with their rooms, the wall jacks, ceiling and outdoor
mounting points, the cable tray along each corridor, the comms closets (the
main one, the MDF, and one per other building, IDFs), the ducts (conduits)
between the buildings, the spots the client's cameras must watch, and the
client's work order. The work order is what the client needs, the way an
installer gets it: the devices per room, Wi-Fi in every room, the VLAN plan,
the cameras, the servers, the domain, its users, groups, shares, GPOs.

The Site window shows the site from above with the backbone cables between
the buildings; a building opens to its own floor plan, where you put the
devices on their points and pull each point's cable along the tray to a
closet; a closet opens to its rack, where you fit switches and patch panels
and patch every cable into a switch port, the fibre between the closets
into the switches' gigabit ports, and the main switch into the router.

Nothing here is pretend. The lab under a job is a workbench lab: a switch
fitted in a closet is a real workbench switch with its own console, the
devices are real machines (Windows PCs and servers you install, OpenWrt
access points, the camera and printer appliances), and a cable that is
pulled, terminated and patched is a real cable in a real switch port (the
Workbench's own actions do it, so the Workbench, the Rack and the switch's
console see the same network). What this module adds is the physical layer
the client pays an installer for: cable lengths along the tray (a copper
run over 90 m fails), fibre between the buildings (multimode OM4 up to
400 m, singlemode OS2 beyond), patch panel ports, Power over Ethernet and
its budget (a PoE device on a plain switch stays dark), and the cable test.

"Hand over to the client" grades the work order: the physical and network
items from the lab (cabling, patching, tests, VLANs, the router's
sub-interfaces and DHCP pools, Wi-Fi, cameras, trunks), and the server and
desktop items inside the real machines, like an exercise's checks (the
domain, OUs, users, groups, shares and their permissions, GPOs, DHCP, DNS,
joined PCs). It gives a punch list; winlab never sets any of it up.

The job's state is the lab's additive [campus] table (parse_table/
emit_table), so a network file (.wlnet) carries the job with it.
"""

from __future__ import annotations

import math
import re
import time
from pathlib import Path

from . import content, paths

COPPER_MAX_M = 90          # a permanent link (TIA-568): 90 m, plus 10 m of patch cords
OM4_MAX_M = 400            # multimode at 10 Gb/s
SLACK_JACK_M = 3           # up the wall (or down from the ceiling) to the tray
SLACK_CLOSET_M = 5         # down the ladder, dressed into the rack, a service loop
CONDUIT_SLACK_M = 15       # risers and the run from the duct to each closet
PANEL_PORTS = 24
MAX_PANELS = 8
WIFI_RANGE_M = 18          # drawn only: the model below decides coverage
CAM_RANGE_M = {"ceiling": 15, "jack": 15, "outdoor": 35}
# An outdoor camera is a bullet camera: it looks one way (its aim, degrees
# clockwise from east as the map is drawn) over CAM_FOV degrees, and a
# building in between blocks its view. Indoor ones are domes: all round.
CAM_FOV = 90
ROUTER_PORT = "GigabitEthernet0/0/1"  # the router's LAN port, as its front in the rack says
# Wi-Fi as a site survey models it (2.4 GHz, indoor): the AP's transmit
# power, the loss over distance (log-distance, exponent 3 for an office),
# a fixed loss for every wall the signal goes through, and the signal a
# room needs for voice and video calls to work.
WIFI_MODEL = {"tx": 20, "pl1": 40, "exp": 3.0, "wall": 7, "good": -67, "edge": -80}
POE_W = {"ap": 25.5, "camera": 12.9, "camera-outdoor": 25.5, "phone": 6.5}
SWITCH_MODELS = {
    "poe": {"title": "24-port PoE+ switch, 370 W", "poe_w": 370},
    "poe-small": {"title": "24-port PoE switch, 124 W", "poe_w": 124},
    "plain": {"title": "24-port switch, no PoE", "poe_w": 0},
}
MEDIA = {
    "om4": {"title": "fibre, multimode OM4 (12 strands)", "fibre": True, "max": OM4_MAX_M},
    "os2": {"title": "fibre, singlemode OS2 (12 strands)", "fibre": True, "max": 10000},
    "cat6": {"title": "copper, Cat6", "fibre": False, "max": COPPER_MAX_M},
}
# What may go on which point, and which workbench shelf item it is.
KIT = {
    "pc": {"title": "Desktop PC", "shelf": "pc", "on": ("jack",), "prefix": "pc"},
    "phone": {"title": "IP desk phone", "shelf": "phone", "on": ("jack",), "prefix": "phone"},
    "printer": {"title": "Network printer", "shelf": "printer", "on": ("jack",), "prefix": "prn"},
    "ap": {"title": "Wi-Fi access point", "shelf": "ap", "on": ("ceiling",), "prefix": "ap"},
    "camera": {"title": "IP camera", "shelf": "camera", "on": ("ceiling", "outdoor"), "prefix": "cam"},
}
SERVER_KIT = {"server": "Windows Server", "linux": "Linux server", "nas": "NAS"}
FRONT_ROUTER = "RTR"       # the router's Gi0/0/1 on the MDF's patch side
# What the job costs the client, at trade prices (US dollars): cable by the
# metre, a fitted end for each fibre, an installer's time per cable run, and
# each piece of kit. A cable pulled out again is scrap: its metres stay on
# the bill.
PRICES = {"cat6_m": 0.9, "om4_m": 3.2, "os2_m": 2.6, "fibre_end": 90, "run": 25, "panel": 120,
          "switch:poe": 1800, "switch:poe-small": 950, "switch:plain": 420,
          "pc": 850, "phone": 160, "printer": 480, "ap": 340, "camera": 260, "camera-outdoor": 420,
          "server": 4200, "linux": 3100, "nas": 1500}


class CampusError(Exception):
    pass


# ------------------------------------------------------------------ jobs
def jobs_dir() -> Path:
    return paths.CONTENT / "sites"


def job_ids() -> list[str]:
    return sorted(p.stem for p in content.glob(jobs_dir()))


def load_job(job_id: str) -> dict:
    """A job's site and work order, checked and with every default filled."""
    path = jobs_dir() / f"{job_id}.toml"
    if not content.exists(path):
        raise CampusError(f"no job {job_id!r}")
    raw = content.load_toml(path)
    return _check_job(job_id, raw)


def _num(v, what: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise CampusError(f"{what} must be a number")
    return float(v)


def _pt(v, what: str) -> list[float]:
    if not isinstance(v, list) or len(v) != 2:
        raise CampusError(f"{what} must be [x, y]")
    return [_num(v[0], what), _num(v[1], what)]


def _check_job(job_id: str, raw: dict) -> dict:
    j = dict(raw.get("job") or {})
    if j.get("id") != job_id:
        raise CampusError(f"{job_id}: [job] id must be {job_id!r}")
    for k in ("title", "client", "brief"):
        if not str(j.get(k) or "").strip():
            raise CampusError(f"{job_id}: [job] needs {k}")
    j.setdefault("summary", "")
    j.setdefault("level", 1)
    j.setdefault("domain", "")
    j["width"], j["height"] = _num(j.get("width"), "width"), _num(j.get("height"), "height")
    j["budget"] = int(j.get("budget", 0) or 0)
    j["label_scheme"] = str(j.get("label_scheme", ""))
    if j["label_scheme"]:
        try:
            j["label_scheme"].format(closet="MDF", panel=1, port=1)
        except (KeyError, ValueError, IndexError) as exc:
            raise CampusError(f"{job_id}: label_scheme takes {{closet}}, {{panel}} and {{port}} ({exc})") from None
    out = {"job": j, "areas": [], "buildings": {}, "targets": {}, "conduits": {}, "needs": [], "checks": []}
    for a in raw.get("area", []):
        out["areas"].append({"kind": str(a.get("kind", "grass")), "name": str(a.get("name", "")),
                             "x": _num(a["x"], "area x"), "y": _num(a["y"], "area y"),
                             "w": _num(a["w"], "area w"), "h": _num(a["h"], "area h")})
    closets: dict[str, dict] = {}
    for b in raw.get("building", []):
        bid = str(b.get("id") or "")
        if not bid or bid in out["buildings"]:
            raise CampusError(f"{job_id}: a building needs a unique id")
        bd = {"id": bid, "name": str(b.get("name", bid)), "x": _num(b["x"], "x"), "y": _num(b["y"], "y"),
              "w": _num(b["w"], "w"), "h": _num(b["h"], "h"), "rooms": {}, "points": {}, "closets": {},
              "tray": [_pt(p, f"{bid} tray") for p in b.get("tray", [])], "doors": []}
        if len(bd["tray"]) < 2:
            raise CampusError(f"{job_id}: building {bid} needs a cable tray of two points or more")
        for r in b.get("room", []):
            rid = str(r["id"])
            bd["rooms"][rid] = {"id": rid, "name": str(r.get("name", rid)), "x": _num(r["x"], "x"),
                                "y": _num(r["y"], "y"), "w": _num(r["w"], "w"), "h": _num(r["h"], "h")}
        for d in b.get("door", []):
            bd["doors"].append(_pt(d, f"{bid} door"))
        for c in b.get("closet", []):
            cid = str(c["id"])
            if cid in closets:
                raise CampusError(f"{job_id}: closet {cid} twice")
            kind = str(c.get("kind", "idf"))
            if kind not in ("mdf", "idf"):
                raise CampusError(f"{job_id}: closet {cid} kind must be mdf or idf")
            cl = {"id": cid, "name": str(c.get("name", cid)), "kind": kind, "building": bid,
                  "x": _num(c["x"], "x"), "y": _num(c["y"], "y"), "room": str(c.get("room", ""))}
            bd["closets"][cid] = closets[cid] = cl
        for p in b.get("point", []):
            pid = str(p["id"])
            kind = str(p.get("kind", "jack"))
            if kind not in ("jack", "ceiling", "outdoor"):
                raise CampusError(f"{job_id}: point {pid} kind must be jack, ceiling or outdoor")
            room = str(p.get("room", ""))
            if room and room not in bd["rooms"]:
                raise CampusError(f"{job_id}: point {pid} is in no room {room!r}")
            if pid in out["buildings"] or any(pid in x["points"] for x in out["buildings"].values()):
                raise CampusError(f"{job_id}: point {pid} twice")
            bd["points"][pid] = {"id": pid, "kind": kind, "room": room, "building": bid,
                                 "x": _num(p["x"], "x"), "y": _num(p["y"], "y")}
        if not bd["closets"]:
            raise CampusError(f"{job_id}: building {bid} has no comms closet")
        out["buildings"][bid] = bd
    mdfs = [c for c in closets.values() if c["kind"] == "mdf"]
    if len(mdfs) != 1:
        raise CampusError(f"{job_id}: a site has exactly one main closet (kind = \"mdf\")")
    out["mdf"] = mdfs[0]["id"]
    out["closets"] = closets
    for t in raw.get("target", []):
        tid = str(t["id"])
        b = str(t.get("building", ""))
        if b and b not in out["buildings"]:
            raise CampusError(f"{job_id}: target {tid} in no building {b!r}")
        out["targets"][tid] = {"id": tid, "name": str(t.get("name", tid)), "building": b,
                               "x": _num(t["x"], "x"), "y": _num(t["y"], "y")}
    for c in raw.get("conduit", []):
        cid = str(c["id"])
        a, b = str(c.get("from", "")), str(c.get("to", ""))
        if a not in closets or b not in closets:
            raise CampusError(f"{job_id}: conduit {cid} must join two closets")
        path = [_pt(p, f"conduit {cid}") for p in c.get("path", [])]
        if len(path) < 2:
            raise CampusError(f"{job_id}: conduit {cid} needs a path")
        out["conduits"][cid] = {"id": cid, "from": a, "to": b, "path": path, "name": str(c.get("name", cid)),
                                "length": round(_polylen(path) + CONDUIT_SLACK_M)}
    for n in raw.get("need", []):
        if not n.get("id") or not n.get("kind") or not n.get("text"):
            raise CampusError(f"{job_id}: a [[need]] needs id, kind and text")
        if n["kind"] not in NEED_KINDS:
            raise CampusError(f"{job_id}: need {n['id']}: unknown kind {n['kind']!r}")
        out["needs"].append(dict(n))
    from .exercises import Check
    def check(c, section, where):
        if not c.get("name") or not c.get("node") or not c.get("script"):
            raise CampusError(f"{job_id}: a {where} needs name, node and script")
        return {"section": str(c.get("section", section)), "replaces": str(c.get("replaces", "")),
                "check": Check(name=str(c["name"]), node=str(c["node"]), script=str(c["script"]),
                               expect=str(c.get("expect", "True")), match=str(c.get("match", "exact")),
                               weight=int(c.get("weight", 1)), hint=str(c.get("hint", "")))}
    for c in raw.get("check", []):
        out["checks"].append(check(c, "Servers", "[[check]]"))
    base = {c["check"].name for c in out["checks"]}
    out["changes"] = []
    for c in raw.get("change", []):
        if not c.get("id") or not str(c.get("letter", "")).strip() or not (c.get("need") or c.get("check")):
            raise CampusError(f"{job_id}: a [[change]] needs id, letter and [[change.need]] or [[change.check]] items")
        checks = [check(x, "Change order", "[[change.check]]") for x in c.get("check", [])]
        for x in checks:
            if x["replaces"] and x["replaces"] not in base:
                raise CampusError(f"{job_id}: change {c['id']}: no check {x['replaces']!r} to replace")
        needs = []
        for n in c.get("need", []):
            if not n.get("id") or n.get("kind") not in NEED_KINDS or not n.get("text"):
                raise CampusError(f"{job_id}: change {c['id']}: each need takes id, a known kind and text")
            needs.append(dict(n, section=n.get("section", "Change order")))
        after = float(c.get("after", 0.5))
        if not 0 <= after <= 1:
            raise CampusError(f"{job_id}: change {c['id']}: after is the share of points cabled, 0 to 1")
        out["changes"].append({"id": str(c["id"]), "after": after, "from": str(c.get("from", "")),
                               "letter": str(c["letter"]).strip(), "needs": needs, "checks": checks})
    _check_refs(job_id, out)
    out["machines"] = [dict(m) for m in raw.get("machine", [])]
    out["people"] = [dict(p) for p in raw.get("person", [])]
    for p in out["people"]:
        if not p.get("first") or not p.get("last") or not p.get("account"):
            raise CampusError(f"{job_id}: a [[person]] needs first, last and account")
    return out


# ------------------------------------------------------------------ geometry
def _check_refs(job_id: str, job: dict) -> None:
    """What a job file says must fit together: points inside their rooms,
    closets in theirs, and every room, target, building and device a need
    names must exist (a typo would make a job no one can finish)."""
    rooms = {r for b in job["buildings"].values() for r in b["rooms"]}
    for b in job["buildings"].values():
        for p in b["points"].values():
            r = b["rooms"].get(p["room"])
            if r and not (r["x"] - 1 <= p["x"] <= r["x"] + r["w"] + 1 and r["y"] - 1 <= p["y"] <= r["y"] + r["h"] + 1):
                raise CampusError(f"{job_id}: point {p['id']} is not in its room {p['room']}")
        for c in b["closets"].values():
            if c["room"] and c["room"] not in b["rooms"]:
                raise CampusError(f"{job_id}: closet {c['id']} is in no room {c['room']!r}")
    for n in job["needs"] + [x for c in job.get("changes", []) for x in c["needs"]]:
        want = n.get("rooms")
        names = want if isinstance(want, list) else [n["room"]] if n.get("room") else []
        bad = [r for r in names if r not in rooms]
        if bad:
            raise CampusError(f"{job_id}: need {n['id']} names no room {', '.join(bad)}")
        bad = [t for t in n.get("targets") or [] if t not in job["targets"]]
        if bad:
            raise CampusError(f"{job_id}: need {n['id']} names no target {', '.join(bad)}")
        if n.get("building") and n["building"] not in job["buildings"]:
            raise CampusError(f"{job_id}: need {n['id']} names no building {n['building']}")
        if n["kind"] == "devices" and n.get("device") not in KIT:
            raise CampusError(f"{job_id}: need {n['id']}: no device {n.get('device')!r} in the kit")


def _polylen(pts) -> float:
    return sum(math.dist(pts[i], pts[i + 1]) for i in range(len(pts) - 1))


def _project(pts, p) -> tuple[list[float], float]:
    """The nearest point to p on the polyline, and its distance along it."""
    best, at, run = None, 0.0, 0.0
    for i in range(len(pts) - 1):
        a, b = pts[i], pts[i + 1]
        dx, dy = b[0] - a[0], b[1] - a[1]
        seg = math.hypot(dx, dy) or 1e-9
        t = max(0.0, min(1.0, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (seg * seg)))
        q = [a[0] + t * dx, a[1] + t * dy]
        d = math.dist(p, q)
        if best is None or d < best[0]:
            best, at = (d, q), run + t * seg
        run += seg
    return best[1], at


def _between(pts, s0: float, s1: float) -> list[list[float]]:
    """The polyline's vertices strictly between two distances along it, in
    the order of travel from s0 to s1."""
    out, run = [], 0.0
    for i in range(len(pts) - 1):
        if i:
            if min(s0, s1) < run < max(s0, s1):
                out.append(list(pts[i]))
        run += math.dist(pts[i], pts[i + 1])
    return out if s0 <= s1 else out[::-1]


def route(building: dict, point: dict, closet: dict) -> dict:
    """A horizontal cable from a point to a closet of its building: up to
    the tray, along it, down into the closet. Its path (building metres)
    and its length, with the slack an installer leaves."""
    tray = building["tray"]
    p, c = [point["x"], point["y"]], [closet["x"], closet["y"]]
    qp, sp = _project(tray, p)
    qc, sc = _project(tray, c)
    path = [p, qp, *_between(tray, sp, sc), qc, c]
    run = math.dist(p, qp) + abs(sc - sp) + math.dist(qc, c)
    length = round(run + SLACK_JACK_M + SLACK_CLOSET_M)
    return {"path": [[round(x, 2), round(y, 2)] for x, y in path], "length": length}


def site_xy(job: dict, building_id: str, x: float, y: float) -> tuple[float, float]:
    if not building_id:
        return x, y
    b = job["buildings"][building_id]
    return b["x"] + x, b["y"] + y


# ------------------------------------------------------------------ the [campus] table
TABLES = ("devices", "cables", "tested", "switches", "patches", "backbone", "servers", "panels", "damaged", "aims",
          "labels", "ledger", "changes", "portnets", "loops")


def parse_table(raw, fname: str = "lab") -> dict:
    from .schema import LabError
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise LabError(f"{fname}: [campus] must be a table")
    extra = sorted(set(raw) - set(TABLES) - {"job", "handed"})
    if extra:
        raise LabError(f"{fname}: [campus] has unknown key(s) {', '.join(extra)}")
    out: dict = {"job": str(raw.get("job", "")), "handed": str(raw.get("handed", ""))}
    for k in TABLES:
        t = raw.get(k, {})
        if not isinstance(t, dict) or not all(isinstance(v, str) for v in t.values()):
            raise LabError(f"{fname}: [campus.{k}] must be a table of name = \"text\"")
        out[k] = {str(a): str(b) for a, b in t.items()}
    return out


def emit_table(t: dict) -> list[str]:
    from .editor import _q
    if not t or not t.get("job"):
        return []
    out = ["[campus]", f"job = {_q(t['job'])}"]
    if t.get("handed"):
        out.append(f"handed = {_q(t['handed'])}")
    for k in TABLES:
        rows = t.get(k) or {}
        if rows:
            out.append(f"  [campus.{k}]")
            out += [f"  {_q(a)} = {_q(b)}" for a, b in sorted(rows.items())]
    out.append("")
    return out


def table(lab) -> dict:
    t = lab.campus
    for k in TABLES:
        t.setdefault(k, {})
    t.setdefault("job", "")
    t.setdefault("handed", "")
    return t


def job_of(lab) -> dict | None:
    jid = (lab.campus or {}).get("job")
    if not jid:
        return None
    try:
        return load_job(jid)
    except CampusError:
        return None


# ------------------------------------------------------------------ what is where
def _closet_switches(t: dict, closet: str) -> list[str]:
    return sorted(sw for sw, v in t["switches"].items() if v.split(":", 1)[0] == closet)


def _switch_model(t: dict, sw: str) -> str:
    v = t["switches"].get(sw, "")
    return v.split(":", 1)[1] if ":" in v else "plain"


def _front_of(t: dict, closet: str, front: str) -> str:
    return t["patches"].get(f"{closet}|{front}", "")


def _panel_port(t: dict, point: str) -> tuple[str, int] | None:
    v = t["cables"].get(point, "")
    if not v or "|" not in v:
        return None
    closet, port = v.split("|", 1)
    try:
        return closet, int(port)
    except ValueError:
        return None


def _free_panel_port(t: dict, closet: str) -> int:
    used = {pp[1] for p in t["cables"] if (pp := _panel_port(t, p)) and pp[0] == closet}
    for i in range(1, int(t["panels"].get(closet, "0") or 0) * PANEL_PORTS + 1):
        if i not in used:
            return i
    return 0


def _device_kind(lab, key: str) -> str:
    from . import appliance
    if key.startswith("ap:"):
        return "ap"
    node = lab.nodes.get(key)
    if node is None:
        return ""
    dev = appliance.device_of(node)
    if dev in ("printer", "phone", "camera"):
        return dev
    return "pc"


def _poe_need(job: dict, kind: str, point: dict) -> float:
    if kind == "camera":
        return POE_W["camera-outdoor"] if point["kind"] == "outdoor" else POE_W["camera"]
    return POE_W.get(kind, 0.0)


def _parse_sw_port(v: str) -> tuple[str, str]:
    if "|" not in v:
        return "", ""
    sw, port = v.split("|", 1)
    return sw, port


def links(lab, job: dict) -> dict[str, dict]:
    """Per installed point: what is there, its cable, the switch port it is
    patched to, whether it has power, and so whether it is connected."""
    t = table(lab)
    out = {}
    budget: dict[str, float] = {}
    for b in job["buildings"].values():
        for pid, p in b["points"].items():
            key = t["devices"].get(pid, "")
            kind = _device_kind(lab, key) if key else ""
            pp = _panel_port(t, pid)
            r = None
            if pp and pp[0] in job["closets"]:
                r = route(b, p, job["closets"][pp[0]])
            sw, port = _parse_sw_port(_front_of(t, pp[0], f"P{pp[1]}")) if pp else ("", "")
            need = _poe_need(job, kind, p) if kind else 0.0
            power, why = True, ""
            if need and sw:
                model = SWITCH_MODELS.get(_switch_model(t, sw), SWITCH_MODELS["plain"])
                if not model["poe_w"]:
                    power, why = False, f"{sw} has no PoE: the {KIT[kind]['title'].lower()} gets no power"
                elif budget.get(sw, 0.0) + need > model["poe_w"]:
                    power, why = False, f"{sw}'s PoE budget ({model['poe_w']} W) is used up"
                else:
                    budget[sw] = budget.get(sw, 0.0) + need
            too_long = bool(r and r["length"] > COPPER_MAX_M)
            damaged = bool(pp and t["damaged"].get(pid))
            out[pid] = {"device": key, "kind": kind, "closet": pp[0] if pp else "", "panel": pp[1] if pp else 0,
                        "length": r["length"] if r else 0, "path": r["path"] if r else [],
                        "tested": t["tested"].get(pid, ""), "switch": sw, "port": port, "poe_w": need,
                        "power": power, "power_why": why, "too_long": too_long,
                        "connected": bool(key and pp and sw and port and power and not too_long and not damaged)}
    for a, why in storm(lab, job, out).items():
        out[a]["storm"] = why
        out[a]["connected"] = False
    for a, v in t["loops"].items():
        b = v.split("|")[0]
        for x, y in ((a, b), (b, a)):
            if x in out:
                out[x]["loop"] = y
                out[x]["connected"] = False
    return out


def port_vlan(lab, t: dict, sw: str, port: str, key: str = "") -> int:
    """The VLAN a switch port is in: its device's, or what the port was set
    to before the device's cable came out (a switch keeps that on the port)."""
    tag = _vlan_of(lab, key) if key else 0
    if tag:
        return tag
    n = lab.networks.get(t["portnets"].get(f"{sw}|{port}", ""))
    return n.vlan_no if n is not None and n.home == sw else 1


def storm(lab, job: dict, lk: dict) -> dict[str, str]:
    """Point -> why it is down, for a loop someone made with a patch cord
    between two wall jacks: with spanning tree off in that VLAN the switch
    floods every broadcast round the loop forever, and everything on the
    VLAN on that switch drowns. With spanning tree on, it blocks one end."""
    from . import stp
    t = table(lab)
    out: dict[str, str] = {}
    for a, v in t["loops"].items():
        b = v.split("|")[0]
        la, lb = lk.get(a), lk.get(b)
        if not la or not lb or not la["switch"] or la["switch"] != lb["switch"] or la["too_long"] or lb["too_long"] \
                or t["damaged"].get(a) or t["damaged"].get(b):
            continue
        sw = la["switch"]
        tag = port_vlan(lab, t, sw, la["port"])
        if tag != port_vlan(lab, t, sw, lb["port"]) or stp.vlan_on(lab, sw, tag):
            continue
        for pid, l in lk.items():
            if l["switch"] == sw and l["device"] and port_vlan(lab, t, sw, l["port"], l["device"]) == tag:
                out[pid] = f"broadcast storm on {sw} VLAN {tag}: a loop between {sw} {la['port']} and {lb['port']}"
    return out


def backbone(lab, job: dict) -> dict[str, dict]:
    t = table(lab)
    out = {}
    for cid, c in job["conduits"].items():
        media = t["backbone"].get(cid, "")
        a = _parse_sw_port(_front_of(t, c["from"], f"F:{cid}"))
        b = _parse_sw_port(_front_of(t, c["to"], f"F:{cid}"))
        m = MEDIA.get(media)
        ok_len = bool(m) and c["length"] <= m["max"]
        out[cid] = {"media": media, "length": c["length"], "from": c["from"], "to": c["to"],
                    "a": {"switch": a[0], "port": a[1]}, "b": {"switch": b[0], "port": b[1]},
                    "too_long": bool(m) and not ok_len,
                    "linked": bool(m and ok_len and a[0] and b[0])}
    return out


# ------------------------------------------------------------------ the real network
def _wb(dash, action: str, params: dict) -> dict:
    from . import workbench
    try:
        res = workbench._act(dash, action, params)
    except Exception as exc:  # noqa: BLE001 - reported to the user, the job's record stands
        dash.reload()
        return {"ok": False, "message": str(exc).lstrip("% ")}
    return res


def sync(dash) -> list[str]:
    """Make the lab's real cables what the site's cabling says: a device
    whose cable is pulled, terminated, patched and powered is plugged into
    its switch port; any other device of the job is unplugged; the fibre
    between closets is a trunk between their switches; the main switch's
    patch to the router is its uplink. Returns what changed or failed."""
    from . import devcli, wifi
    said: list[str] = []
    job = job_of(dash.lab)
    if job is None:
        return said
    lk = links(dash.lab, job)
    for pid, l in lk.items():
        key = l["device"]
        if not key:
            continue
        lab = dash.lab
        want_sw, want_port = (l["switch"], l["port"]) if l["connected"] else ("", "")
        if key.startswith("ap:"):
            ap = wifi.aps(lab).get(key[3:])
            if ap is None:
                continue
            cur = lab.networks.get(ap["network"])
            cur_home = cur.home if cur else ""
            if want_sw and want_port.startswith("Fa0/"):
                devcli.pin_port(lab, want_sw, f"{key[3:]}:nic0", int(want_port[4:]))
            if want_sw and cur_home != want_sw:
                r = _wb(dash, "wb-cable", {"node": key, "network": want_sw})
            elif not want_sw and cur_home:
                r = _wb(dash, "wb-unplug", {"node": key})
            else:
                continue
            if not r.get("ok"):
                said.append(f"{key[3:]}: {r.get('message')}")
            continue
        node = lab.nodes.get(key)
        if node is None or not node.nics:
            continue
        said += _plug(dash, key, want_sw, want_port)
    # servers patched straight into a switch in their closet
    t = table(dash.lab)
    for node_id, closet in list(t["servers"].items()):
        sw, port = _parse_sw_port(_front_of(t, closet, f"SRV:{node_id}"))
        if node_id in dash.lab.nodes:
            said += _plug(dash, node_id, sw, port)
    # the backbone: a trunk from the switch patched on its Gi0/1 to the other end
    bb = backbone(dash.lab, job)
    want_up: dict[str, str] = {}
    for cid, b in bb.items():
        if not b["linked"]:
            continue
        ends = [(b["a"]["switch"], b["a"]["port"]), (b["b"]["switch"], b["b"]["port"])]
        down = [e for e in ends if e[1] == "Gi0/1"]
        if len(down) != 1:
            continue
        other = ends[1] if down[0] is ends[0] else ends[0]
        want_up[down[0][0]] = other[0]
    t = table(dash.lab)
    rsw, rport = _parse_sw_port(_front_of(t, job["mdf"], FRONT_ROUTER))
    for sw in sorted(t["switches"]):
        lab = dash.lab
        if sw not in lab.networks:
            continue
        net = lab.networks[sw]
        if sw == rsw and rport == "Gi0/1":
            if devcli.cabled_ports(lab).get(sw) != ROUTER_PORT:  # the port the rack's label names
                if devcli.uplinked(lab, sw):
                    _wb(dash, "wb-unplug", {"node": "router", "network": sw})
                r = _wb(dash, "wb-cable", {"node": "router", "network": sw, "port": ROUTER_PORT})
                if not r.get("ok"):
                    said.append(f"router to {sw}: {r.get('message')}")
            continue
        if devcli.uplinked(lab, sw):
            _wb(dash, "wb-unplug", {"node": "router", "network": sw})
        up = want_up.get(sw, "")
        if up and net.upstream != up:
            r = _wb(dash, "wb-cable", {"node": "switch", "network": sw, "to": up})
            if not r.get("ok"):
                said.append(f"{sw} to {up}: {r.get('message')}")
        elif not up and net.upstream:
            _wb(dash, "wb-unplug", {"node": "switch", "network": sw})
    return said


def _plug(dash, node_id: str, sw: str, port: str) -> list[str]:
    from . import devcli
    lab = dash.lab
    node = lab.nodes.get(node_id)
    if node is None or not node.nics:
        return []
    nic = node.nics[0]
    net = lab.networks.get(nic.network) if nic.plugged else None
    no = int(port[len("Fa0/"):]) if port.startswith("Fa0/") and port[4:].isdigit() else 0
    t = table(lab)
    here = devcli.port_no(lab, dash.plan, f"{node_id}:nic0") if net is not None else None
    if here and net.home == here[0]:
        t["portnets"][f"{here[0]}|Fa0/{here[1]}"] = net.id  # the port keeps its VLAN when the cable comes out
    if sw and no:
        if net is not None and net.home == sw and here == (sw, no):
            return []  # already there: its VLAN is the switch console's business
        kept = lab.networks.get(t["portnets"].get(f"{sw}|Fa0/{no}", ""))
        params = {"node": node_id, "nic": 0, "port": no,
                  "network": net.id if net is not None and net.home == sw and here and here[0] == sw
                  else kept.id if kept is not None and kept.home == sw else sw}
        r = _wb(dash, "wb-cable", params)
        return [] if r.get("ok") else [f"{node_id}: {r.get('message')}"]
    if net is not None:
        r = _wb(dash, "wb-unplug", {"node": node_id, "nic": 0})
        return [] if r.get("ok") else [f"{node_id}: {r.get('message')}"]
    return []


# ------------------------------------------------------------------ the window
def view(dash) -> dict:
    lab = dash.lab
    job = job_of(lab)
    out: dict = {"lab": lab.name, "jobs": [_job_card(j) for j in job_ids()]}
    if job is None:
        out["job"] = None
        return out
    t = table(lab)
    from . import devcli, wifi
    running = set()
    try:
        from . import state
        running = set(state.running(lab.name))
    except Exception:  # noqa: BLE001 - a view without run state
        pass
    lk = links(lab, job)
    bb = backbone(lab, job)
    rsw, rport = _parse_sw_port(_front_of(t, job["mdf"], FRONT_ROUTER))
    closets = {}
    for cid, c in job["closets"].items():
        sws = []
        for sw in _closet_switches(t, cid):
            if sw not in lab.networks:
                continue
            ports = devcli.switch_ports(lab, dash.plan).get(sw, [])
            fa = {}
            for f, v in t["patches"].items():
                if f.startswith(cid + "|"):
                    s, p = _parse_sw_port(v)
                    if s == sw:
                        fa[p] = f.split("|", 1)[1]
            vl = {}
            for i, link in enumerate(ports, 1):
                if link is not None:
                    n = lab.networks.get(link.network_id)
                    vl[f"Fa0/{i}"] = n.vlan_no if n else 1
            every = wifi.aps(lab)
            for no, ap_id in devcli.ap_slots(lab, dash.plan, sw, ports).items():
                n = lab.networks.get(every.get(ap_id, {}).get("network", ""))
                vl[f"Fa0/{no}"] = n.vlan_no if n else 1
            used_w = sum(l["poe_w"] for l in lk.values() if l["switch"] == sw and l["power"] and l["poe_w"])
            model = _switch_model(t, sw)
            sws.append({"id": sw, "name": devcli.hostname(lab, f"sw:{sw}"), "model": model,
                        "title": SWITCH_MODELS.get(model, SWITCH_MODELS["plain"])["title"],
                        "poe_w": SWITCH_MODELS.get(model, SWITCH_MODELS["plain"])["poe_w"], "poe_used": round(used_w, 1),
                        "patched": fa, "vlans": vl, "upstream": lab.networks[sw].upstream,
                        "router": devcli.uplinked(lab, sw), "off": devcli.switch_off(lab, sw)})
        fronts = []
        for pid, l in lk.items():
            if l["closet"] == cid:
                fronts.append({"front": f"P{l['panel']}", "point": pid, "panel": l["panel"], "device": l["device"]})
        fibres = [{"front": f"F:{k}", "conduit": k, "media": b["media"],
                   "to": b["to"] if b["from"] == cid else b["from"]}
                  for k, b in bb.items() if b["media"] and cid in (b["from"], b["to"])]
        servers = [{"front": f"SRV:{n}", "node": n, "kind": _device_kind(lab, n),
                    "running": n in running} for n, cl in t["servers"].items() if cl == cid and n in lab.nodes]
        closets[cid] = {**c, "panels": int(t["panels"].get(cid, "0") or 0), "switches": sws, "fronts": fronts,
                        "fibres": fibres, "servers": servers,
                        "patches": {k.split("|", 1)[1]: v for k, v in t["patches"].items() if k.startswith(cid + "|")},
                        "router": cid == job["mdf"]}
    aps = wifi.aps(lab)
    devices = {}
    for pid, l in lk.items():
        key = l["device"]
        if not key:
            continue
        d = {"id": key, "kind": l["kind"], "running": key in running}
        if key.startswith("ap:"):
            ap = aps.get(key[3:], {})
            d.update({"name": ap.get("name", key[3:]), "ssid": ap.get("ssid", ""), "radio": ap.get("radio", ""),
                      "running": l["connected"]})
        else:
            node = lab.nodes.get(key)
            if node is not None and node.nics and node.nics[0].plugged:
                n = lab.networks.get(node.nics[0].network)
                d["vlan"] = n.vlan_no if n else 0
        devices[pid] = d
    try:
        from . import labclock
        lt = time.localtime(labclock.load(lab.name).now())
        clock = {"hour": lt.tm_hour + lt.tm_min / 60, "text": time.strftime("%H:%M", lt)}
    except Exception:  # noqa: BLE001 - a view without the lab clock is daytime
        clock = {"hour": 12.0, "text": ""}
    aims = {pid: aim_of(lab, job, pid) for pid, l in lk.items()
            if l["kind"] == "camera" and l["device"]
            and next(b for b in job["buildings"].values() if pid in b["points"])["points"][pid]["kind"] == "outdoor"}
    out.update({"clock": clock, "aims": aims, "cam": {"fov": CAM_FOV, "range": CAM_RANGE_M}, "wifi_model": WIFI_MODEL,
                "wifi_overlap": overlap(lab, job, lk), "job": _public_job(job, lab), "links": lk, "backbone": bb, "closets": closets, "devices": devices,
                "router": {"switch": rsw, "port": rport, "running": "fabric" in running},
                "handed": t["handed"], "kit": {k: {"title": v["title"], "on": list(v["on"])} for k, v in KIT.items()},
                "switch_models": {k: v["title"] for k, v in SWITCH_MODELS.items()},
                "media": {k: v["title"] for k, v in MEDIA.items()}, "servers_kit": SERVER_KIT,
                "status": status(lab, job, lk, bb),
                "needs": [{"id": n["id"], "section": n.get("section", "Network"), "text": n["text"],
                           "hint": n.get("hint", ""), **dict(zip(("ok", "found"), need_result(lab, job, n, lk, bb)))}
                          for n in needs_of(lab, job)],
                "bill": bill(lab, job, lk, bb), "labels": table(lab).get("labels", {}),
                "label_scheme": job["job"].get("label_scheme", ""),
                "label_example": example_label(job) if job["job"].get("label_scheme") else "",
                "changes": [{"id": c["id"], "from": c["from"], "letter": c["letter"], "at": t["changes"][c["id"]]}
                            for c in job.get("changes", []) if c["id"] in t["changes"]],
                "routes": {pid: {cid: route(b, p, job["closets"][cid])["length"] for cid in b["closets"]}
                           for b in job["buildings"].values() for pid, p in b["points"].items()},
                "nodes": {n.id: {"kind": n.kind, "image": n.image, "running": n.id in running}
                          for n in lab.node_list() if not n.vars.get("devvm")}})
    return out


def _job_card(job_id: str) -> dict:
    try:
        j = load_job(job_id)
    except CampusError as exc:
        return {"id": job_id, "title": job_id, "error": str(exc)}
    return {"id": job_id, "title": j["job"]["title"], "client": j["job"]["client"], "summary": j["job"]["summary"],
            "level": j["job"]["level"], "buildings": len(j["buildings"]),
            "points": sum(len(b["points"]) for b in j["buildings"].values())}


def _public_job(job: dict, lab=None) -> dict:
    out = {k: v for k, v in job.items() if k not in ("checks", "changes")}
    out["checks"] = [{"section": c["section"], "name": c["check"].name, "node": c["check"].node}
                     for c in (checks_of(lab, job) if lab is not None else job["checks"])]
    out["changes"] = [{k: v for k, v in c.items() if k != "checks"} for c in job.get("changes", [])]
    return out


def status(lab, job, lk=None, bb=None) -> dict:
    lk = lk if lk is not None else links(lab, job)
    bb = bb if bb is not None else backbone(lab, job)
    pts = sum(len(b["points"]) for b in job["buildings"].values())
    return {"points": pts, "cabled": sum(1 for l in lk.values() if l["closet"]),
            "tested": sum(1 for l in lk.values() if l["tested"] == "pass"),
            "patched": sum(1 for l in lk.values() if l["switch"]),
            "devices": sum(1 for l in lk.values() if l["device"]),
            "connected": sum(1 for l in lk.values() if l["connected"]),
            "backbone": sum(1 for b in bb.values() if b["linked"]), "conduits": len(bb)}


# ------------------------------------------------------------------ actions
def act(dash, action: str, params: dict) -> dict:
    from . import editor
    try:
        return _act(dash, action, params)
    except (CampusError, editor.EditError) as exc:
        dash.reload()
        return {"ok": False, "message": str(exc)}


def _save(dash) -> None:
    from . import editor
    editor.save(dash.lab)
    dash.reload()


def _done(dash, message: str) -> dict:
    """Save, make the real cabling match, and say what happened."""
    job = job_of(dash.lab)
    news = arrive_changes(dash.lab, job) if job else []
    if news:
        message += ". " + " ".join(news)
    _save(dash)
    said = sync(dash)
    from . import workbench
    tail = workbench._sync(dash)
    if said:
        message += "; " + "; ".join(said)
    return {"ok": True, "message": message + tail}


def _need_job(dash) -> tuple[dict, dict]:
    job = job_of(dash.lab)
    if job is None:
        raise CampusError("this lab is not a client job: start one from the Site window")
    return job, table(dash.lab)


def _point(job: dict, pid: str) -> tuple[dict, dict]:
    for b in job["buildings"].values():
        if pid in b["points"]:
            return b, b["points"][pid]
    raise CampusError(f"no point {pid!r} on this site")


def _closet(job: dict, cid: str) -> dict:
    if cid not in job["closets"]:
        raise CampusError(f"no closet {cid!r} on this site")
    return job["closets"][cid]


def _sw_port_ok(dash, t: dict, closet: str, sw: str, port: str) -> None:
    from . import devcli
    if sw not in t["switches"] or t["switches"][sw].split(":", 1)[0] != closet:
        raise CampusError(f"no switch {sw!r} in this closet")
    ok = [f"Fa0/{i}" for i in range(1, devcli.SWITCH_PORTS + 1)] + [f"Gi0/{i}" for i in range(1, devcli.GIG_PORTS + 1)]
    if port not in ok:
        raise CampusError(f"{sw} has Fa0/1-{devcli.SWITCH_PORTS} and Gi0/1-{devcli.GIG_PORTS}")
    for f, v in t["patches"].items():
        if v == f"{sw}|{port}" and f.startswith(closet + "|"):
            raise CampusError(f"{sw} {port} already has a patch cord in it ({f.split('|', 1)[1]})")


def _act(dash, action: str, params: dict) -> dict:
    from . import editor
    if action == "campus-start":
        jid = str(params.get("job", ""))
        job = load_job(jid)
        name = str(params.get("name") or jid).strip().lower()
        dest = editor.new_workbench(name, f"{job['job']['client']}: {job['job']['title']} (a client job)")
        from . import schema
        lab = schema.load(dest)
        lab.campus = {"job": jid}
        if job["job"].get("domain"):
            lab.domain = str(job["job"]["domain"])
            lab.netbios = lab.domain.split(".")[0].upper()[:15]
        editor.save(lab, dest)
        staff = job_people(job, lab.domain)
        if staff:
            from . import people
            people.save(lab.name, staff)
        return {"ok": True, "lab": dest.stem, "message": f"{job['job']['title']}: the site is yours. Read the work order first."}

    job, t = _need_job(dash)
    if action == "campus-panel":
        cid = str(params.get("closet", ""))
        _closet(job, cid)
        n = int(params.get("count", 0))
        if not 0 <= n <= MAX_PANELS:
            raise CampusError(f"a closet's rack takes 0 to {MAX_PANELS} patch panels")
        used = max([pp[1] for p in t["cables"] if (pp := _panel_port(t, p)) and pp[0] == cid] or [0])
        if n * PANEL_PORTS < used:
            raise CampusError(f"port {used} of the patch panels has a cable in it: take the cable off first")
        t["panels"][cid] = str(n)
        if not n:
            t["panels"].pop(cid, None)
        return _done(dash, f"{job['closets'][cid]['name']}: {n} patch panel{'s' if n != 1 else ''} of {PANEL_PORTS} ports")

    if action == "campus-pull":
        pid = str(params.get("point", ""))
        b, p = _point(job, pid)
        cid = str(params.get("closet") or "") or next(iter(b["closets"]))
        if cid not in b["closets"]:
            raise CampusError(f"a horizontal cable stays in its building: pull it to a closet in {b['name']}")
        if pid in t["cables"]:
            raise CampusError(f"{pid} already has its cable")
        port = int(params.get("panel") or 0) or _free_panel_port(t, cid)
        if not port:
            raise CampusError(f"no free patch panel port in {job['closets'][cid]['name']}: fit a patch panel")
        if port > int(t["panels"].get(cid, "0") or 0) * PANEL_PORTS:
            raise CampusError(f"the closet has no panel port {port}")
        if any((pp := _panel_port(t, x)) and pp == (cid, port) for x in t["cables"]):
            raise CampusError(f"panel port {port} already has a cable")
        t["cables"][pid] = f"{cid}|{port}"
        t["tested"].pop(pid, None)
        r = route(b, p, job["closets"][cid])
        warn = (f"; {r['length']} m is over the {COPPER_MAX_M} m a copper run may be: it fails its test"
                if r["length"] > COPPER_MAX_M else "")
        return _done(dash, f"{pid}: Cat6 pulled to {job['closets'][cid]['name']}, {r['length']} m, "
                           f"punched down on panel port {port}{warn}")

    if action == "campus-unpull":
        pid = str(params.get("point", ""))
        _point(job, pid)
        pp = _panel_port(t, pid)
        if not pp:
            raise CampusError(f"{pid} has no cable")
        old = links(dash.lab, job)[pid]["length"]
        led = t.setdefault("ledger", {})
        led["scrap_m"] = str(round(float(led.get("scrap_m", "0") or 0) + old, 1))
        t["cables"].pop(pid, None)
        t["tested"].pop(pid, None)
        t["damaged"].pop(pid, None)
        t["patches"].pop(f"{pp[0]}|P{pp[1]}", None)
        return _done(dash, f"{pid}: cable pulled back out ({old} m of Cat6 scrapped)")

    if action == "campus-test":
        pids = [str(params["point"])] if params.get("point") else [p for p in t["cables"]]
        lk = links(dash.lab, job)
        res = []
        for pid in pids:
            l = lk.get(pid)
            if not l or not l["closet"]:
                raise CampusError(f"{pid} has no cable to test")
            cut = t["damaged"].get(pid, "")
            ok = l["length"] <= COPPER_MAX_M and not cut
            t["tested"][pid] = "pass" if ok else "fail"
            res.append(f"{pid} {'PASS' if ok else 'FAIL'} {l['length']} m"
                       + ("" if ok else f" (open pair 3-6 at {cut} m: the cable is damaged there)" if cut else
                          f" (over {COPPER_MAX_M} m: insertion loss too high)"))
        _save(dash)
        return {"ok": True, "message": "cable test: " + ", ".join(res[:12]) + (" ..." if len(res) > 12 else ""),
                "results": res}

    if action == "campus-switch":
        cid = str(params.get("closet", ""))
        _closet(job, cid)
        model = str(params.get("model", "poe"))
        if model not in SWITCH_MODELS:
            raise CampusError(f"switch model must be one of {', '.join(SWITCH_MODELS)}")
        r = _wb(dash, "wb-add", {"shelf": "switch", "id": str(params.get("id") or "")})
        if not r.get("ok"):
            raise CampusError(r.get("message", "the switch could not be fitted"))
        t = table(dash.lab)
        t["switches"][r["id"]] = f"{cid}:{model}"
        return _done(dash, f"{r['id']} ({SWITCH_MODELS[model]['title']}) fitted in {job['closets'][cid]['name']}: "
                           f"open its console to set it up")

    if action == "campus-unswitch":
        sw = str(params.get("switch", ""))
        if sw not in t["switches"]:
            raise CampusError(f"no switch {sw!r} on this site")
        for f, v in list(t["patches"].items()):
            if _parse_sw_port(v)[0] == sw:
                del t["patches"][f]
        _save(dash)
        sync(dash)
        r = _wb(dash, "wb-rm", {"id": f"net:{sw}"})
        if not r.get("ok"):
            raise CampusError(r.get("message", "the switch could not come out"))
        t = table(dash.lab)
        t["switches"].pop(sw, None)
        return _done(dash, f"{sw} taken out of the rack")

    if action == "campus-patch":
        cid = str(params.get("closet", ""))
        _closet(job, cid)
        front = str(params.get("front", ""))
        sw, port = str(params.get("switch", "")), str(params.get("port", ""))
        _front_ok(job, t, cid, front)
        if f"{cid}|{front}" in t["patches"]:
            raise CampusError(f"{front} already has a patch cord: take it out first")
        _sw_port_ok(dash, t, cid, sw, port)
        fibre = front.startswith("F:")
        if fibre and not port.startswith("Gi"):
            raise CampusError("fibre goes into a gigabit SFP port (Gi0/1 to Gi0/4), not a FastEthernet port")
        if front == FRONT_ROUTER and port != "Gi0/1":
            raise CampusError("the router's cable is the switch's uplink: Gi0/1")
        t["patches"][f"{cid}|{front}"] = f"{sw}|{port}"
        what = ("fibre patch lead" if fibre else "patch cord")
        return _done(dash, f"{what}: {front} to {sw} {port}")

    if action == "campus-unpatch":
        cid = str(params.get("closet", ""))
        front = str(params.get("front", ""))
        if t["patches"].pop(f"{cid}|{front}", None) is None:
            raise CampusError(f"{front} has no patch cord")
        return _done(dash, f"patch cord out of {front}")

    if action == "campus-backbone":
        cid = str(params.get("conduit", ""))
        if cid not in job["conduits"]:
            raise CampusError(f"no duct {cid!r}")
        media = str(params.get("media", ""))
        c = job["conduits"][cid]
        if not media:
            t["backbone"].pop(cid, None)
            for end in (c["from"], c["to"]):
                t["patches"].pop(f"{end}|F:{cid}", None)
            return _done(dash, f"{c['name']}: cable pulled back out of the duct")
        if media not in MEDIA:
            raise CampusError(f"media must be one of {', '.join(MEDIA)}")
        t["backbone"][cid] = media
        m = MEDIA[media]
        warn = ""
        if c["length"] > m["max"]:
            warn = f"; {c['length']} m is past what {media.upper()} carries ({m['max']} m): the link will not come up"
        elif not m["fibre"]:
            warn = "; copper between buildings carries ground differences and lightning: the client's spec may refuse it"
        return _done(dash, f"{c['name']}: {m['title']} pulled, {c['length']} m, terminated in both closets{warn}")

    if action == "campus-install":
        pid = str(params.get("point", ""))
        b, p = _point(job, pid)
        kind = str(params.get("kind", ""))
        if kind not in KIT:
            raise CampusError(f"no {kind!r} in the kit")
        if p["kind"] not in KIT[kind]["on"]:
            raise CampusError(f"a {KIT[kind]['title'].lower()} does not go on a {p['kind']} point")
        if t["devices"].get(pid):
            raise CampusError(f"{pid} already has {t['devices'][pid]}")
        wp = {"shelf": KIT[kind]["shelf"], "id": str(params.get("id") or "").strip().lower(),
              "how": str(params.get("how") or "hand"), "image": str(params.get("image") or "")}
        r = _wb(dash, "wb-add", wp)
        if not r.get("ok"):
            raise CampusError(r.get("message", "it could not be installed"))
        t = table(dash.lab)
        t["devices"][pid] = r["id"]
        if r["id"] in dash.lab.nodes and dash.lab.nodes[r["id"]].nics:
            from . import editor as ed
            if dash.lab.nodes[r["id"]].nics[0].plugged:
                ed.unplug(dash.lab, r["id"], 0)  # its cable is the site's to pull
        return _done(dash, f"{KIT[kind]['title']} {r['id'].removeprefix('ap:')} on {pid}: " + r.get("message", ""))

    if action == "campus-unloop":
        pid = str(params.get("point", ""))
        a = pid if pid in t["loops"] else next((k for k, v in t["loops"].items() if v.split("|")[0] == pid), "")
        if not a:
            raise CampusError(f"no patch cord joins {pid} to another jack")
        b = t["loops"].pop(a).split("|")[0]
        return _done(dash, f"The patch cord between {a} and {b} is out; the devices are plugged back into their jacks")

    if action == "campus-uninstall":
        pid = str(params.get("point", ""))
        key = t["devices"].get(pid, "")
        if not key:
            raise CampusError(f"nothing is installed on {pid}")
        r = _wb(dash, "wb-rm", {"id": key})
        if not r.get("ok"):
            raise CampusError(r.get("message", "it could not be taken down"))
        t = table(dash.lab)
        t["devices"].pop(pid, None)
        return _done(dash, f"{key} taken down from {pid}")

    if action == "campus-server":
        cid = str(params.get("closet", ""))
        _closet(job, cid)
        shelf = str(params.get("kind", "server"))
        if shelf not in SERVER_KIT:
            raise CampusError(f"a closet takes one of {', '.join(SERVER_KIT)}")
        r = _wb(dash, "wb-add", {"shelf": shelf, "id": str(params.get("id") or "").strip().lower(),
                                 "how": str(params.get("how") or "hand"), "image": str(params.get("image") or "")})
        if not r.get("ok"):
            raise CampusError(r.get("message", "the server could not be racked"))
        t = table(dash.lab)
        t["servers"][r["id"]] = cid
        node = dash.lab.nodes.get(r["id"])
        if node is not None and node.nics and node.nics[0].plugged:
            editor.unplug(dash.lab, r["id"], 0)
        return _done(dash, f"{r['id']} racked in {job['closets'][cid]['name']}: patch its network port into a switch; "
                           + r.get("message", ""))

    if action == "campus-unserver":
        nid = str(params.get("node", ""))
        if nid not in t["servers"]:
            raise CampusError(f"no server {nid!r} in a closet")
        r = _wb(dash, "wb-rm", {"id": nid})
        if not r.get("ok"):
            raise CampusError(r.get("message", "it could not come out"))
        t = table(dash.lab)
        cl = t["servers"].pop(nid)
        t["patches"].pop(f"{cl}|SRV:{nid}", None)
        return _done(dash, f"{nid} out of the rack")

    if action == "campus-label":
        pid = str(params.get("point", ""))
        _point(job, pid)
        text = re.sub(r"[^A-Za-z0-9 ._/-]", "", str(params.get("text", "")))[:24].strip()
        if text:
            t.setdefault("labels", {})[pid] = text
        else:
            t.setdefault("labels", {}).pop(pid, None)
        return _done(dash, f"{pid} labelled {text!r}" if text else f"{pid}'s label taken off")

    if action == "campus-aim":
        pid = str(params.get("point", ""))
        b, p = _point(job, pid)
        if p["kind"] != "outdoor" or _device_kind(dash.lab, t["devices"].get(pid, "")) != "camera":
            raise CampusError(f"no outdoor camera on {pid} to turn (indoor cameras are domes: they see all round)")
        try:
            deg = int(float(params.get("deg", 0))) % 360
        except ValueError:
            raise CampusError("turn it by a number of degrees") from None
        t.setdefault("aims", {})[pid] = str(deg)
        return _done(dash, f"{t['devices'][pid]} on {pid} now looks {_compass(deg)}")

    if action == "campus-handover":
        g = handover(dash.lab, job)
        t = table(dash.lab)
        t["handed"] = f"{g['earned']}/{g['total']} {time.strftime('%Y-%m-%d %H:%M')}"
        _save(dash)
        return {"ok": True, "message": f"hand-over: {g['earned']} of {g['total']} points"
                                       + (": the client signs it off" if g["passed"] else ": the client sends a punch list"),
                "grade": g}

    raise CampusError(f"unknown action {action!r}")


def _compass(deg: int) -> str:
    """Map degrees (clockwise from east, y down) as a compass word."""
    names = ["east", "south-east", "south", "south-west", "west", "north-west", "north", "north-east"]
    return names[round(deg / 45) % 8]


def _front_ok(job: dict, t: dict, cid: str, front: str) -> None:
    if front == FRONT_ROUTER:
        if cid != job["mdf"]:
            raise CampusError("the router is in the main closet")
        return
    if front.startswith("P") and front[1:].isdigit():
        no = int(front[1:])
        if not any((pp := _panel_port(t, p)) and pp == (cid, no) for p in t["cables"]):
            raise CampusError(f"panel port {no} has no cable behind it")
        return
    if front.startswith("F:"):
        c = job["conduits"].get(front[2:])
        if c is None or cid not in (c["from"], c["to"]) or not t["backbone"].get(front[2:]):
            raise CampusError(f"no fibre {front[2:]} ends in this closet")
        return
    if front.startswith("SRV:"):
        if t["servers"].get(front[4:]) != cid:
            raise CampusError(f"{front[4:]} is not racked here")
        return
    raise CampusError(f"nothing called {front!r} in the closet")


# ------------------------------------------------------------------ hand-over
NEED_KINDS = ("devices", "jacks", "wifi", "ssid", "cameras", "backbone", "uplink", "vlan", "routed",
              "dhcp-pool", "helper", "poe", "names", "budget", "labels")


def _rooms_of(job: dict, need: dict) -> list[tuple[dict, dict]]:
    want = need.get("rooms", "all")
    out = []
    for b in job["buildings"].values():
        if need.get("building") and b["id"] != need["building"]:
            continue
        for r in b["rooms"].values():
            if want == "all" or r["id"] in want:
                out.append((b, r))
    return out


def _devices_where(lab, job, lk, kinds) -> list[tuple[str, dict, dict]]:
    """(point, link, point) of every installed device of these kinds."""
    out = []
    for b in job["buildings"].values():
        for pid, p in b["points"].items():
            l = lk[pid]
            if l["kind"] in kinds:
                out.append((pid, l, p))
    return out


def wifi_net(lab, ap_id: str) -> str:
    """The network an access point's cable is in ('' when it has none)."""
    from . import wifi
    return wifi.aps(lab).get(ap_id, {}).get("network", "")


def _vlan_of(lab, key: str) -> int:
    from . import wifi
    if key.startswith("ap:"):
        ap = wifi.aps(lab).get(key[3:], {})
        n = lab.networks.get(ap.get("network", ""))
        return n.vlan_no if n else 0
    node = lab.nodes.get(key)
    if node is None or not node.nics or not node.nics[0].plugged:
        return 0
    n = lab.networks.get(node.nics[0].network)
    return n.vlan_no if n else 0


def _nets_of_tag(lab, t: dict, tag: int) -> list:
    return [n for n in lab.networks.values() if n.home in t["switches"] and n.vlan_no == tag]


def _rooms_at(job: dict) -> list[tuple[float, float, float, float, str]]:
    """Every room as a site rectangle (x, y, w, h, id)."""
    return [(b["x"] + r["x"], b["y"] + r["y"], r["w"], r["h"], f"{b['id']}/{r['id']}")
            for b in job["buildings"].values() for r in b["rooms"].values()]


def _room_of(rooms, x: float, y: float) -> str:
    for rx, ry, rw, rh, rid in rooms:
        if rx < x < rx + rw and ry < y < ry + rh:
            return rid
    return ""


def walls_between(job: dict, a, b, rooms=None) -> int:
    """How many walls a straight line from a to b (site metres) goes
    through: each change of room along it is one."""
    rooms = rooms if rooms is not None else _rooms_at(job)
    d = math.dist(a, b)
    n = max(1, int(d / 0.5))
    last, walls = _room_of(rooms, *a), 0
    for i in range(1, n + 1):
        x, y = a[0] + (b[0] - a[0]) * i / n, a[1] + (b[1] - a[1]) * i / n
        here = _room_of(rooms, x, y)
        if here != last:
            walls += 1
            last = here
    return walls


def signal(job: dict, ap, at, rooms=None) -> float:
    """The AP's signal at a spot (dBm), walls included."""
    m = WIFI_MODEL
    d = max(1.0, math.dist(ap, at))
    return m["tx"] - m["pl1"] - 10 * m["exp"] * math.log10(d) - m["wall"] * walls_between(job, ap, at, rooms)


def default_aim(job: dict, point: dict) -> int:
    """Where a camera on a wall looks before anyone turns it: straight out."""
    b = job["buildings"][point["building"]]
    x, y = point["x"], point["y"]
    away = min((abs(y), 270), (abs(y - b["h"]), 90), (abs(x), 180), (abs(x - b["w"]), 0))
    return away[1]


def aim_of(lab, job: dict, pid: str) -> int:
    t = table(lab)
    b = next(b for b in job["buildings"].values() if pid in b["points"])
    v = t.get("aims", {}).get(pid, "")
    return int(v) % 360 if v.lstrip("-").isdigit() else default_aim(job, b["points"][pid])


def _blocked(job: dict, a, b) -> bool:
    """A building stands between a and b (each may sit on a wall)."""
    d = math.dist(a, b)
    n = max(2, int(d / 0.5))
    for i in range(1, n):
        x, y = a[0] + (b[0] - a[0]) * i / n, a[1] + (b[1] - a[1]) * i / n
        if math.dist((x, y), a) < 1.2 or math.dist((x, y), b) < 1.2:
            continue
        for B in job["buildings"].values():
            if B["x"] + .6 < x < B["x"] + B["w"] - .6 and B["y"] + .6 < y < B["y"] + B["h"] - .6:
                return True
    return False


def camera_sees(job: dict, cam_xy, kind: str, aim: int, at) -> tuple[bool, str]:
    """(sees it, why not) for one camera and one spot."""
    d = math.dist(cam_xy, at)
    if d > CAM_RANGE_M[kind]:
        return False, "too far"
    if kind == "outdoor" and d > 0.5:
        ang = math.degrees(math.atan2(at[1] - cam_xy[1], at[0] - cam_xy[0]))
        off = (ang - aim + 180) % 360 - 180
        if abs(off) > CAM_FOV / 2:
            return False, "pointing away"
        if _blocked(job, cam_xy, at):
            return False, "a building is in the way"
    return True, ""


def overlap(lab, job: dict, lk=None) -> list[str]:
    """Pairs of live APs on the same 2.4 GHz channel that hear each other:
    they share the air and slow each other down."""
    from . import wifi
    lk = lk if lk is not None else links(lab, job)
    aps = wifi.aps(lab)
    live = [(l["device"][3:], site_xy(job, p["building"], p["x"], p["y"]))
            for pid, l, p in _devices_where(lab, job, lk, ("ap",)) if l["connected"]]
    rooms = _rooms_at(job)
    out = []
    for i, (a, axy) in enumerate(live):
        for b, bxy in live[i + 1:]:
            ca, cb = aps.get(a, {}).get("channel", ""), aps.get(b, {}).get("channel", "")
            if ca and ca == cb and signal(job, axy, bxy, rooms) >= WIFI_MODEL["edge"]:
                out.append(f"{a} and {b} share channel {ca}")
    return out


def needs_of(lab, job: dict) -> list[dict]:
    """The work order as it stands: the job's own items, the change orders
    the client has sent so far, the labels and the budget when it has them."""
    out = list(job["needs"])
    arrived = table(lab).get("changes", {})
    for c in job.get("changes", []):
        if c["id"] in arrived:
            out += c["needs"]
    j = job["job"]
    if j.get("label_scheme"):
        out.append({"id": "labels", "kind": "labels", "section": "Cabling", "weight": 2,
                    "text": f"Every cabled point labelled to the client's scheme, e.g. {example_label(job)}",
                    "hint": "Label the jack in its point's panel, by the closet, panel and port it is punched down on"})
    if j.get("budget"):
        out.append({"id": "budget", "kind": "budget", "section": "Budget", "weight": 2,
                    "text": f"The job comes in within the client's budget of ${j['budget']:,}",
                    "hint": "Pulled-out cable is scrap and stays on the bill; do not over-fit the closets"})
    return out


def checks_of(lab, job: dict) -> list[dict]:
    """The checks run inside the machines at hand-over, as the change orders
    that have arrived left them: a change can add checks or replace one (a
    PC the client has since asked to rename)."""
    arrived = table(lab).get("changes", {})
    extra = [x for c in job.get("changes", []) if c["id"] in arrived for x in c.get("checks", [])]
    gone = {x["replaces"] for x in extra if x["replaces"]}
    return [c for c in job["checks"] if c["check"].name not in gone] + extra


def example_label(job: dict) -> str:
    return job["job"]["label_scheme"].format(closet=job["mdf"].upper(), panel=1, port=7)


def label_for(job: dict, lk_entry: dict) -> str:
    """The label the client's scheme gives a cable: its closet, panel, port."""
    n = int(lk_entry["panel"] or 0)
    cid = lk_entry["closet"]
    code = job["closets"][cid].get("code") or cid.upper()
    return job["job"]["label_scheme"].format(closet=code, panel=(n - 1) // PANEL_PORTS + 1,
                                             port=(n - 1) % PANEL_PORTS + 1)


def bill(lab, job: dict, lk=None, bb=None) -> dict:
    """The invoice as the site stands: every cable, fitted end and piece
    of kit, and the scrap from cables pulled out again."""
    lk = lk if lk is not None else links(lab, job)
    bb = bb if bb is not None else backbone(lab, job)
    t = table(lab)
    P = PRICES
    lines = []

    def add(what, qty, unit):
        if qty:
            lines.append({"what": what, "qty": round(qty, 1), "unit": unit, "total": round(qty * unit, 2)})
    cabled = [l for l in lk.values() if l["closet"]]
    add("Cat6, metres (horizontal runs)", sum(l["length"] for l in cabled), P["cat6_m"])
    add("Cable runs pulled, terminated and tested (labour)", len(cabled), P["run"])
    for media in ("om4", "os2"):
        fib = [b for b in bb.values() if b["media"] == media]
        add(f"{media.upper()} fibre, metres", sum(b["length"] for b in fib), P[f"{media}_m"])
        add(f"{media.upper()} fibre ends fitted", 2 * len(fib), P["fibre_end"])
    cu = [b for b in bb.values() if b["media"] == "cat6"]
    add("Cat6 between buildings, metres", sum(b["length"] for b in cu), P["cat6_m"])
    add("Patch panels, 24-port", sum(int(v or 0) for v in t["panels"].values()), P["panel"])
    for model, title in SWITCH_MODELS.items():
        add(title["title"], sum(1 for sw in t["switches"] if _switch_model(t, sw) == model and sw in lab.networks),
            P[f"switch:{model}"])
    kinds: dict[str, int] = {}
    for pid, l in lk.items():
        if l["device"]:
            p = next(b for b in job["buildings"].values() if pid in b["points"])["points"][pid]
            k = "camera-outdoor" if l["kind"] == "camera" and p["kind"] == "outdoor" else l["kind"]
            kinds[k] = kinds.get(k, 0) + 1
    names = {"pc": "Desktop PCs", "phone": "IP desk phones", "printer": "Network printers", "ap": "Wi-Fi access points",
             "camera": "IP cameras, indoor dome", "camera-outdoor": "IP cameras, outdoor bullet"}
    for k, n in kinds.items():
        add(names.get(k, k), n, P.get(k, 0))
    for n in t["servers"]:
        if n in lab.nodes:
            k = _device_kind(lab, n)
            k = "server" if k == "pc" else k
            add(f"Server {n}", 1, P.get(k, P["server"]))
    add("Scrap: Cat6 pulled out again, metres", float(t.get("ledger", {}).get("scrap_m", "0") or 0), P["cat6_m"])
    total = round(sum(x["total"] for x in lines), 2)
    return {"lines": lines, "total": total, "budget": job["job"].get("budget", 0)}


def arrive_changes(lab, job: dict) -> list[str]:
    """Change orders whose moment has come (the share of points cabled):
    each arrives once, as the client's message."""
    t = table(lab)
    st = status(lab, job)
    share = st["cabled"] / max(1, st["points"])
    said = []
    for c in job.get("changes", []):
        if c["id"] not in t["changes"] and share >= c["after"]:
            t["changes"][c["id"]] = time.strftime("%Y-%m-%d %H:%M")
            said.append(f"New from {c['from'] or 'the client'}: {c['letter']}")
    return said


def need_result(lab, job: dict, need: dict, lk=None, bb=None) -> tuple[bool, str]:
    """One work-order item, graded from the lab: (done, what was found)."""
    from . import devcli, imaging, wifi
    lk = lk if lk is not None else links(lab, job)
    bb = bb if bb is not None else backbone(lab, job)
    t = table(lab)
    kind = need["kind"]
    if kind == "devices":
        dev = need["device"]
        rooms = need.get("rooms") or [need.get("room")]
        got = [(pid, l) for pid, l, p in _devices_where(lab, job, lk, (dev,)) if p["room"] in rooms]
        live = [pid for pid, l in got if l["connected"]]
        want = int(need.get("count", 1))
        ids = need.get("ids") or []
        missing = [i for i in ids if not any(l["device"] in (i, "ap:" + i) for _, l in got)]
        if missing:
            return False, f"no {', '.join(missing)} installed there (name them as the work order says)"
        if len(live) < want:
            off = [pid for pid, l in got if not l["connected"]]
            return False, (f"{len(live)} of {want} connected" + (f"; {', '.join(off)} not yet cabled, patched or powered"
                                                                 if off else ""))
        return True, f"{len(live)} connected"
    if kind == "jacks":
        rooms = need.get("rooms", "all")
        bad = []
        for b in job["buildings"].values():
            for pid, p in b["points"].items():
                if p["kind"] != "jack" or (rooms != "all" and p["room"] not in rooms):
                    continue
                l = lk[pid]
                if not l["closet"]:
                    bad.append(f"{pid} no cable")
                elif l["tested"] != "pass":
                    bad.append(f"{pid} {'failed its test' if l['tested'] == 'fail' else 'not tested'}")
                elif not l["switch"]:
                    bad.append(f"{pid} not patched")
        return (not bad), ("every jack cabled, tested and patched" if not bad else
                           f"{len(bad)} to do: " + ", ".join(bad[:6]) + (" ..." if len(bad) > 6 else ""))
    if kind == "wifi":
        aps = [(site_xy(job, p["building"], p["x"], p["y"]))
               for pid, l, p in _devices_where(lab, job, lk, ("ap",)) if l["connected"]]
        rooms = _rooms_at(job)
        dark = []
        for b, r in _rooms_of(job, need):
            cx, cy = site_xy(job, b["id"], r["x"] + r["w"] / 2, r["y"] + r["h"] / 2)
            best = max((signal(job, a, (cx, cy), rooms) for a in aps), default=-200)
            if best < WIFI_MODEL["good"]:
                dark.append(f"{r['name']} ({round(best)} dBm)" if aps else r["name"])
        return (not dark), (f"every room has {WIFI_MODEL['good']} dBm or better" if not dark
                            else "weak or no signal in " + ", ".join(dark[:8]))
    if kind == "ssid":
        aps = wifi.aps(lab)
        mine = [l["device"][3:] for pid, l, p in _devices_where(lab, job, lk, ("ap",))]
        if not mine:
            return False, "no access points installed"
        bad = []
        for a in mine:
            ap = aps.get(a, {})
            if ap.get("radio") != "on":
                bad.append(f"{a} radio off")
            elif ap.get("ssid") != need["ssid"]:
                bad.append(f"{a} broadcasts {ap.get('ssid')!r}")
            elif need.get("security") and ap.get("security") != need["security"]:
                bad.append(f"{a} security {ap.get('security')}")
        return (not bad), ("every AP broadcasts it" if not bad else "; ".join(bad) +
                           " (read each AP's settings after changing them in LuCI)")
    if kind == "cameras":
        cams = [(site_xy(job, p["building"], p["x"], p["y"]), p["kind"], aim_of(lab, job, pid))
                for pid, l, p in _devices_where(lab, job, lk, ("camera",)) if l["connected"]]
        blind = []
        for tid in need.get("targets") or list(job["targets"]):
            tg = job["targets"][tid]
            xy = site_xy(job, tg["building"], tg["x"], tg["y"]) if tg.get("building") else (tg["x"], tg["y"])
            if not any(camera_sees(job, c, k, a, xy)[0] for c, k, a in cams):
                why = {camera_sees(job, c, k, a, xy)[1] for c, k, a in cams if math.dist(c, xy) <= CAM_RANGE_M[k]}
                blind.append(tg["name"] + (f" ({', '.join(sorted(why))})" if why else ""))
        return (not blind), ("every spot is watched" if not blind else "nothing watches " + ", ".join(blind))
    if kind == "backbone":
        bad = []
        fibre_only = need.get("fibre", True)
        for cid, c in job["closets"].items():
            if cid == job["mdf"]:
                continue
            # the closet's switch must reach the main one up its trunks
            sws = _closet_switches(t, cid)
            if not sws:
                bad.append(f"{c['name']}: no switch")
                continue
            ok = False
            for sw in sws:
                hop, seen = sw, set()
                while hop and hop not in seen and hop in lab.networks:
                    seen.add(hop)
                    if t["switches"].get(hop, "").split(":", 1)[0] == job["mdf"]:
                        ok = True
                        break
                    hop = lab.networks[hop].upstream
            if not ok:
                bad.append(f"{c['name']}: no trunk to the main closet")
        for cid, b in bb.items():
            if b["media"] and fibre_only and not MEDIA[b["media"]]["fibre"]:
                bad.append(f"{job['conduits'][cid]['name']}: copper between buildings")
            if b["too_long"]:
                bad.append(f"{job['conduits'][cid]['name']}: {b['length']} m is past {b['media'].upper()}'s reach")
        return (not bad), ("every closet is on the backbone" if not bad else "; ".join(bad))
    if kind == "uplink":
        rsw, rport = _parse_sw_port(_front_of(t, job["mdf"], FRONT_ROUTER))
        if not rsw:
            return False, "the router is not patched into the main switch"
        return devcli.uplinked(lab, rsw), f"router to {rsw} {rport}"
    if kind == "vlan":
        tag = int(need["tag"])
        nets = _nets_of_tag(lab, t, tag)
        if not nets:
            return False, f"no switch has VLAN {tag}"
        if need.get("name") and not any(n.description.lower() == str(need["name"]).lower() for n in nets):
            return False, f"VLAN {tag} is not named {need['name']}"
        kinds = need.get("devices") or []
        ids = need.get("ids") or []
        wrong = [l["device"] for pid, l, p in _devices_where(lab, job, lk, tuple(kinds))
                 if l["connected"] and _vlan_of(lab, l["device"]) != tag]
        wrong += [i for i in ids if i in lab.nodes and _vlan_of(lab, i) != tag]
        return (not wrong), (f"VLAN {tag} in place" if not wrong else
                             f"not in VLAN {tag}: " + ", ".join(w.removeprefix("ap:") for w in wrong[:8]))
    if kind in ("routed", "dhcp-pool", "helper"):
        tag = int(need["tag"])
        segs = {lab.segment_id(n.id) for n in _nets_of_tag(lab, t, tag)}
        if not segs:
            return False, f"no switch has VLAN {tag}"
        bad = []
        own = lab.devices.get(devcli.ROUTER, {})
        for s in sorted(segs):
            net = lab.networks[s]
            if kind == "routed":
                import ipaddress
                gw = ipaddress.ip_interface(need["gateway"])
                if not net.routed:
                    bad.append(f"VLAN {tag} has no router interface")
                elif net.router_ip != str(gw.ip) or net.prefixlen != gw.network.prefixlen:
                    bad.append(f"VLAN {tag}'s gateway is {net.router_ip}/{net.prefixlen}")
            elif kind == "dhcp-pool":
                if not any(k.startswith("pool:") and v == s for k, v in own.items()):
                    bad.append(f"no DHCP pool on the router for VLAN {tag}")
            elif not imaging.helpers(lab, s):
                bad.append(f"no ip helper-address on VLAN {tag}'s interface")
        return (not bad), ("; ".join(bad) if bad else f"VLAN {tag} done")
    if kind == "poe":
        dark = [l["device"].removeprefix("ap:") for l in lk.values() if l["device"] and not l["power"]]
        return (not dark), ("every PoE device has power" if not dark else "no power: " + ", ".join(dark))
    if kind == "budget":
        b = bill(lab, job, lk, bb)
        over = b["total"] - b["budget"]
        return over <= 0, (f"${b['total']:,.0f} of ${b['budget']:,}" + (f": ${over:,.0f} over" if over > 0 else ""))
    if kind == "labels":
        lab_t = table(lab).get("labels", {})
        bad = [pid for pid, l in lk.items() if l["closet"]
               and lab_t.get(pid, "").strip().upper() != label_for(job, l).upper()]
        missing = [p for p in bad if not lab_t.get(p)]
        wrong = [p for p in bad if lab_t.get(p)]
        if not bad:
            return True, "every cable labelled"
        return False, ((f"{len(missing)} unlabelled: " + ", ".join(missing[:5]) + (" ..." if len(missing) > 5 else "")
                        if missing else "") + ("; " if missing and wrong else "")
                       + (f"{len(wrong)} wrong: " + ", ".join(wrong[:5]) if wrong else ""))
    if kind == "names":
        missing = [n for n in need.get("ids", []) if n not in lab.nodes and n not in wifi.aps(lab)]
        return (not missing), ("named to the client's standard" if not missing else "missing: " + ", ".join(missing))
    return False, f"unknown need {kind}"


def handover(lab, job: dict, runner=None) -> dict:
    """The work order graded: the site's items from the lab, the machines'
    inside the machines (an exercise's checks). runner(check) -> (ok, detail)
    replaces the guest channel in tests."""
    from . import exercises
    lk, bb = links(lab, job), backbone(lab, job)
    items = []
    for need in needs_of(lab, job):
        ok, found = need_result(lab, job, need, lk, bb)
        items.append({"section": need.get("section", "Network"), "text": need["text"], "ok": ok, "found": found,
                      "weight": int(need.get("weight", 1)), "hint": "" if ok else need.get("hint", "")})
    checks = checks_of(lab, job)
    if checks:
        if runner is None:
            ex = exercises.Exercise(id=job["job"]["id"], title=job["job"]["title"],
                                    checks=[c["check"] for c in checks])
            g = exercises.grade(ex, lab.name)
            got = [(r.passed, r.detail) for r in g.results]
        else:
            got = [runner(c["check"]) for c in checks]
        for c, (ok, detail) in zip(checks, got):
            items.append({"section": c["section"], "text": c["check"].name, "ok": ok, "found": detail,
                          "weight": c["check"].weight, "hint": ""})
    earned = sum(i["weight"] for i in items if i["ok"])
    total = sum(i["weight"] for i in items) or 1
    return {"items": items, "earned": earned, "total": total, "passed": earned == total, "invoice": bill(lab, job, lk, bb)}


# ------------------------------------------------------------------ day two: running the site
# After the hand-over the site goes on working, and its people call the help
# desk (winlab/helpdesk.py). Besides the queue's own faults (inside the
# machines, the cards and cables of winlab/physfaults.py) a site has its own:
# a patch cord pulled out in a closet (a cleaner, a curious visitor) and a
# cable damaged in the wall (a contractor's drill). Both are real: the device
# drops off the network, and the cable test finds the open pair. The fix is
# the student's: find which port, patch it back, or pull a new cable.
DAMAGE_AT = (6, 11, 17, 23)


def job_people(job: dict, domain: str) -> list[dict]:
    """The client's staff as the lab's directory (winlab/people.py), with
    the student as IT (the admin)."""
    if not job.get("people"):
        return []
    from . import people
    domain = (domain or "corp.lab").lower()
    out = [{"id": "admin", "first": "You", "last": "(IT)", "name": "You (IT)", "department": people.DEPARTMENTS[0][0],
            "title": "IT support (contractor)", "account": "itadmin", "mail": f"itadmin@{domain}",
            "ext": people.FIRST_EXT, "pc": "", "manager": False, "admin": True}]
    for i, p in enumerate(job["people"], 1):
        acc = str(p["account"])
        out.append({"id": acc, "first": str(p["first"]), "last": str(p["last"]),
                    "name": f"{p['first']} {p['last']}", "department": str(p.get("department", "Staff")),
                    "title": str(p.get("title", "")), "account": acc, "mail": f"{acc}@{domain}",
                    "ext": people.FIRST_EXT + i, "pc": str(p.get("pc", "")), "manager": bool(p.get("manager")),
                    "admin": False})
    return out


class _LabDash:
    """A dashboard stand-in for a lab object held by someone else (the
    desktop's): reloading refreshes that same object, so the caller's copy
    never writes an older lab back over a change made here."""

    def __init__(self, lab):
        from . import netplan
        self.lab = lab
        self.plan = netplan.compile_topology(lab, check_ports=False)

    def reload(self) -> None:
        from . import netplan, schema
        fresh = schema.load(self.lab.source_path or self.lab.name)
        self.lab.__dict__.update(fresh.__dict__)
        self.plan = netplan.compile_topology(self.lab, check_ports=False)


TICKET_TEXT = {
    "camera": ("Camera shows nothing", "The camera picture for {where} has been black since this morning. "
               "The others still work."),
    "ap": ("No Wi-Fi in {where}", "The Wi-Fi in {where} is gone: laptops and phones say no network. "
           "It was fine yesterday."),
    "pc": ("No network on my PC", "My PC says the network cable is unplugged, but nobody touched it."),
    "printer": ("Printer is offline", "The printer in {where} shows offline on every PC. It has paper and is switched on."),
    "phone": ("Desk phone dead", "My desk phone shows no network and cannot make calls."),
}


# Collisions: two things claiming one place on the network. Each is broken for
# real, inside the machines or on the site, and checked the same way.
# A PC given a fixed address that another PC already has: Windows finds the
# clash (ARP) and the newcomer's address goes unused, so it is the one that calls.
_NIC = "$ix = (Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Sort-Object ifIndex | Select-Object -First 1).ifIndex; "
DUPIP_ADDRESS = ("$a = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { "
                 "$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1; "
                 "if ($a) { \"$($a.IPAddress)/$($a.PrefixLength)\" }")
DUPIP_APPLY = (_NIC + "$gw = (Get-NetRoute -InterfaceIndex $ix -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue "
               "| Select-Object -First 1).NextHop; "
               "$dns = (Get-DnsClientServerAddress -InterfaceIndex $ix -AddressFamily IPv4).ServerAddresses; "
               "Set-NetIPInterface -InterfaceIndex $ix -Dhcp Disabled; "
               "Get-NetIPAddress -InterfaceIndex $ix -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false; "
               "Get-NetRoute -InterfaceIndex $ix -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false; "
               "if ($gw) { New-NetIPAddress -InterfaceIndex $ix -IPAddress '{ip}' -PrefixLength {prefix} -DefaultGateway $gw | Out-Null } "
               "else { New-NetIPAddress -InterfaceIndex $ix -IPAddress '{ip}' -PrefixLength {prefix} | Out-Null }; "
               "if ($dns) { Set-DnsClientServerAddress -InterfaceIndex $ix -ServerAddresses $dns }; 'True'")
DUPIP_VERIFY = ("$a = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' }); "
                "if ($a | Where-Object IPAddress -eq '{ip}') { 'it still has {ip}, which is {victim}''s address' } "
                "elseif (-not ($a | Where-Object { $_.PrefixOrigin -eq 'Dhcp' -and $_.AddressState -eq 'Preferred' })) "
                "{ 'no working address from DHCP yet' } else { 'True' }")
DUPIP_CLEAR = (_NIC + "Get-NetIPAddress -InterfaceIndex $ix -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false; "
               "Get-NetRoute -InterfaceIndex $ix -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false; "
               "Set-NetIPInterface -InterfaceIndex $ix -Dhcp Enabled; Set-DnsClientServerAddress -InterfaceIndex $ix -ResetServerAddresses; "
               "ipconfig /renew | Out-Null; 'True'")
# A record someone typed by hand with an address nothing has: the machine's own
# update cannot replace a record it does not own, so it stays wrong.
STALE_APPLY = ("$r = @(Get-DnsServerResourceRecord -ZoneName '{zone}' -Name '{name}' -RRType A -ErrorAction SilentlyContinue); "
               "if (-not $r) { 'NONE' } else { $ip = $r[0].RecordData.IPv4Address.IPAddressToString; "
               "$b = $ip.Split('.'); $b[3] = if ([int]$b[3] -eq 19) { '18' } else { '19' }; $old = $b -join '.'; "
               "$r | Remove-DnsServerResourceRecord -ZoneName '{zone}' -Force; "
               "Add-DnsServerResourceRecordA -ZoneName '{zone}' -Name '{name}' -IPv4Address $old; \"$ip $old\" }")
STALE_VERIFY = ("$a = @(Resolve-DnsName '{name}.{zone}' -Type A -DnsOnly -Server 127.0.0.1 -ErrorAction SilentlyContinue "
                "| Where-Object Type -eq 'A' | ForEach-Object IPAddress); "
                "if ($a -contains '{stale}') { '{name}.{zone} still answers {stale}, an address nothing has' } "
                "elseif (-not ($a -contains '{ip}')) { '{name}.{zone} does not answer {ip}' } else { 'True' }")
STALE_CLEAR = ("Get-DnsServerResourceRecord -ZoneName '{zone}' -Name '{name}' -RRType A -ErrorAction SilentlyContinue "
               "| Remove-DnsServerResourceRecord -ZoneName '{zone}' -Force; "
               "Add-DnsServerResourceRecordA -ZoneName '{zone}' -Name '{name}' -IPv4Address '{ip}'; 'True'")

COLLISION_TEXT = {
    "dupip": ("IP address conflict on my PC", "Windows says it has detected an IP address conflict, and since then "
              "nothing on the network works on my PC: no shared drives, no internet, no printer. Someone was fiddling "
              "with the network settings on it yesterday.", "P3"),
    "stale-printer": ("Cannot print to {name}", "Nobody can print to {name} since this morning. The printer itself "
                      "looks fine: it is on, it has paper, and its screen shows its address.", "P2"),
    "stale-server": ("Shared drives gone", "Every PC says 'the network path was not found' for the shared drives on "
                     "{name}. The server is on: we can see its screen in the comms room.", "P1"),
    "loop": ("Whole network down in {where}", "Everything in {where} stopped at once: PCs cannot load anything, the "
             "Wi-Fi and the phones drop. The switch lights in the comms room are flashing like mad.", "P1"),
}


def _dc_of(lab, job: dict) -> str:
    """The client's domain controller: the machine the work order says is one."""
    for m in job.get("machines", []):
        if "domain controller" in str(m.get("what", "")).lower() and m.get("id") in lab.nodes:
            return m["id"]
    return ""


def _collisions(lab, job: dict, running, lk: dict, staff) -> list[dict]:
    from . import people
    t = table(lab)
    out = []

    def spec(fault: dict, node: str, caller: str, key: str, **fill) -> dict:
        summary, body, pri = COLLISION_TEXT[key]
        return {"fault": {"kind": "campus", "id": "", "node": node, "params": fault, "by": "queue"}, "node": node,
                "caller": caller, "source": "phone", "summary": summary.format(**fill), "body": body.format(**fill),
                "priority": pri, "category": "Network", "department": ""}

    pcs = [(pid, l) for pid, l in lk.items() if l["kind"] == "pc" and l["connected"] and l["device"] in running]
    for pid, l in pcs:
        who = people.at_pc(staff, l["device"])
        victim = next((v["device"] for _, v in pcs if v["device"] != l["device"]
                       and _vlan_of(lab, v["device"]) == _vlan_of(lab, l["device"])), "")
        if who is not None and victim:
            out.append(spec({"fault": "dupip", "point": pid, "victim": victim}, l["device"], who["id"], "dupip"))
    dc = _dc_of(lab, job)
    if dc and dc in running:
        zone = job["job"].get("domain", "") or lab.domain
        for pid, l in lk.items():
            if l["kind"] == "printer" and l["connected"]:
                out.append(spec({"fault": "stale-dns", "point": pid, "name": l["device"], "dc": dc, "zone": zone},
                                l["device"], "", "stale-printer", name=l["device"].upper()))
        for srv in t["servers"]:
            if srv != dc and srv in running and _device_kind(lab, srv) in ("server", "pc"):
                out.append(spec({"fault": "stale-dns", "point": "", "name": srv, "dc": dc, "zone": zone},
                                srv, "", "stale-server", name=srv.upper()))
    if not t["loops"]:
        for b in job["buildings"].values():
            by_room: dict[str, list[str]] = {}
            for pid, p in b["points"].items():
                l = lk[pid]
                if p["kind"] == "jack" and l["switch"] and l["connected"] and l["kind"] in ("pc", "phone", "printer"):
                    by_room.setdefault(p["room"], []).append(pid)
            for room, pids in by_room.items():
                pairs = [(x, y) for i, x in enumerate(pids) for y in pids[i + 1:]
                         if lk[x]["switch"] == lk[y]["switch"]]
                if pairs:
                    a, c = pairs[0]
                    out.append(spec({"fault": "loop", "point": a, "other": c}, lk[a]["device"], "", "loop",
                                    where=b["name"]))
    return out


def ticket_candidates(lab, running) -> list[dict]:
    """The site faults the help desk queue could raise now: devices that are
    connected, and whose caller is somebody."""
    job = job_of(lab)
    if job is None:
        return []
    from . import people
    staff = people.load(lab)
    lk = links(lab, job)
    out = []
    for b in job["buildings"].values():
        for pid, p in b["points"].items():
            l = lk[pid]
            if not l["connected"] or l["kind"] not in TICKET_TEXT:
                continue
            key = l["device"]
            if l["kind"] in ("pc", "phone", "printer", "camera") and key not in running:
                continue
            where = b["rooms"].get(p["room"], {}).get("name", b["name"])
            who = people.at_pc(staff, key) if l["kind"] == "pc" else None
            if l["kind"] == "pc" and who is None:
                continue
            summary, body = TICKET_TEXT[l["kind"]]
            for kind in ("patch", "cable"):
                out.append({"fault": {"kind": "campus", "id": "", "node": key.removeprefix("ap:"),
                                      "params": {"fault": kind, "point": pid}, "by": "queue"},
                            "node": key.removeprefix("ap:"), "caller": who["id"] if who else "", "source": "phone",
                            "summary": summary.format(where=where), "body": body.format(where=where),
                            "priority": "P2" if l["kind"] in ("camera", "ap") else "P3",
                            "category": "Network", "department": ""})
    return out + _collisions(lab, job, running, lk, staff)


def _ps(runner, node: str, script: str, params: dict) -> tuple[bool, str]:
    from . import guestfaults as gf
    if runner is None:
        return False, "no guest channel"
    ok, out = runner(node, gf._fill(script, params), "powershell")
    lines = [ln.strip() for ln in (out or "").strip().splitlines() if ln.strip()]
    return ok, lines[-1] if lines else ""


def _break_collision(lab, job: dict, fault: dict, runner) -> tuple[bool, str]:
    t = table(lab)
    pr = fault["params"]
    kind = pr["fault"]
    if kind == "dupip":
        ok, got = _ps(runner, pr["victim"], DUPIP_ADDRESS, {})
        if not ok or "/" not in got:
            return False, f"{pr['victim']} has no address to take"
        pr["ip"], pr["prefix"] = got.split("/", 1)
        ok, out = _ps(runner, fault["node"], DUPIP_APPLY, pr)
        if not ok or out != "True":
            return False, out or "the address could not be set"
        fault["id"] = f"dupip:{fault['node']}"
        return True, ""
    if kind == "stale-dns":
        ok, out = _ps(runner, pr["dc"], STALE_APPLY, pr)
        if not ok or out == "NONE" or len(out.split()) != 2:
            return False, f"no A record for {pr['name']} to spoil"
        pr["ip"], pr["stale"] = out.split()
        fault["id"] = f"stale-dns:{pr['name']}"
        return True, ""
    if kind == "loop":
        from . import stp
        lk = links(lab, job)
        a, b = pr["point"], pr["other"]
        sw = lk[a]["switch"]
        if not sw or lk[b]["switch"] != sw:
            return False, "the jacks are not on one switch"
        tag = port_vlan(lab, t, sw, lk[a]["port"], lk[a]["device"])
        own = lab.devices.setdefault(f"sw:{sw}", {})
        pr["switch"], pr["tag"] = sw, str(tag)
        pr["stp_was"] = "off" if not stp.vlan_on(lab, sw, tag) else ""
        own[f"stp-off:{tag}"] = "yes"  # someone turned spanning tree off to "speed up" the ports
        t["loops"][a] = f"{b}|{tag}"
        fault["id"] = f"loop:{a}"
        dash = _LabDash(lab)
        _save(dash)
        sync(dash)
        return True, ""
    return False, f"unknown fault {kind}"


def break_fault(lab, fault: dict, runner=None) -> tuple[bool, str]:
    job = job_of(lab)
    if job is None:
        return False, "not a site job"
    if fault["params"].get("fault") in ("dupip", "stale-dns", "loop"):
        return _break_collision(lab, job, fault, runner)
    t = table(lab)
    pid = fault["params"].get("point", "")
    pp = _panel_port(t, pid)
    if not pp:
        return False, f"{pid} has no cable"
    if fault["params"]["fault"] == "patch":
        front = f"{pp[0]}|P{pp[1]}"
        was = t["patches"].pop(front, "")
        if not was:
            return False, "not patched"
        fault["params"]["was"] = was
    else:
        b, p = _point(job, pid)
        r = route(b, p, job["closets"][pp[0]])
        t["damaged"][pid] = str(min([d for d in DAMAGE_AT if d < r["length"]] or [1]))
        t["tested"].pop(pid, None)
    fault["id"] = f"{fault['params']['fault']}:{pid}"
    dash = _LabDash(lab)
    _save(dash)
    sync(dash)
    return True, ""


def fault_check(lab, fault: dict, runner=None) -> tuple[bool, str] | None:
    t = table(lab)
    pr = fault["params"]
    pid = pr.get("point", "")
    job = job_of(lab)
    if job is None:
        return True, "the site is gone"
    if pr["fault"] in ("dupip", "stale-dns"):
        node = fault["node"] if pr["fault"] == "dupip" else pr["dc"]
        if node not in lab.nodes:
            return True, f"{node} is gone"
        ok, out = _ps(runner, node, DUPIP_VERIFY if pr["fault"] == "dupip" else STALE_VERIFY, pr)
        if not ok:
            return None  # the machine did not answer: nothing can be said either way
        return out == "True", ("fixed" if out == "True" else out)
    if pr["fault"] == "loop":
        lk = links(lab, job)
        if pid in t["loops"]:
            hit = [p for p, l in lk.items() if l.get("storm")]
            if hit:
                return False, lk[hit[0]]["storm"]
            return False, f"spanning tree holds the loop, but the patch cord between {pid} and {pr['other']} is still in"
        return True, "the patch cord is out and the storm is over"
    l = links(lab, job).get(pid)
    if l is None or not l["device"]:
        return True, "the device is no longer there"
    if fault["params"]["fault"] == "cable" and t["damaged"].get(pid):
        return False, f"{pid}'s cable is still damaged (test it from the closet's tester)"
    if not l["connected"]:
        return False, f"{pid} is still not connected"
    return True, f"{pid} connected again ({l['switch']} {l['port']})"


def fault_undo(lab, fault: dict, runner=None) -> None:
    t = table(lab)
    pr = fault["params"]
    pid = pr.get("point", "")
    if pr["fault"] == "dupip":
        _ps(runner, fault["node"], DUPIP_CLEAR, pr)
        return
    if pr["fault"] == "stale-dns":
        if pr.get("ip"):
            _ps(runner, pr["dc"], STALE_CLEAR, pr)
        return
    if pr["fault"] == "loop":
        t["loops"].pop(pid, None)
        own = lab.devices.get(f"sw:{pr.get('switch', '')}")
        if own is not None and not pr.get("stp_was"):
            own.pop(f"stp-off:{pr.get('tag', '1')}", None)
        dash = _LabDash(lab)
        _save(dash)
        sync(dash)
        return
    pp = _panel_port(t, pid)
    if fault["params"]["fault"] == "cable":
        t["damaged"].pop(pid, None)
    elif pp and fault["params"].get("was") and f"{pp[0]}|P{pp[1]}" not in t["patches"]:
        t["patches"][f"{pp[0]}|P{pp[1]}"] = fault["params"]["was"]
    dash = _LabDash(lab)
    _save(dash)
    sync(dash)


def _register() -> None:
    from . import helpdesk
    helpdesk.register_check("campus", fault_check, fault_undo)


_register()
