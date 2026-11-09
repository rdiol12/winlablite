"""The change history of a lab's build, with undo and redo on the workbench.

Every physical change made on the bench is a line in the lab's history
(``var/labs/<lab>/changes.jsonl``): a device added, moved or taken away, a
cable plugged, pulled or moved, parts fitted or taken out of a case, a disc
or a stick put in, a disk pulled, the Wi-Fi, a WAN line, a switch's or the
router's settings typed on its console. Each line says when (and the lab
clock's time, when the lab has its own clock), who, what, and the settings
before and after. It is not a save: user-named versions stay in
winlab/netfile.py; this is the trail of how the network came to be.

Undo and redo cover the layout and the cabling (devices added, removed and
moved, cables, the parts in a case). Undo puts the lab file back as it was
before the change and saves it the way the workbench saves its own changes,
so a running network takes it live (winlab/livenet.py). It refuses where a
real bench would: a running machine taken away or opened up, a disk with
data on it pulled out. Nothing inside a machine is ever undone: that is the
student's work. Undo goes back as far as the last change it cannot undo (a
console setting, a disc, a change made outside the workbench).

The lab file before and after each change is kept by its hash beside the
history (``history/<hash>.toml``), so a long run of moves costs one copy per
distinct design.

This is the workbench's undo trail, not a configuration backup. A console
setting appears here as one line of who changed what, so the bench can tell
what it may undo; keeping the devices' configurations, their versions and
the diffs between them is the job of the open-source tool the lab gives the
student for it: in a lab with a Network operations server, Oxidized, which
logs in to the router and the switches over SSH (winlab/netops.py,
winlab/iosssh.py) and keeps each configuration in git.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import re
import threading
import time
import tomllib
from pathlib import Path

from . import paths

LOG = "changes.jsonl"
SNAPS = "history"
MAX_DIFF = 40
DATA_BYTES = 1 << 20  # a data disk file past this has had data written to it

# Actions whose change can be undone: the layout and the cabling.
UNDOABLE = {"wb-add", "wb-rm", "wb-move", "wb-cable", "wb-unplug", "wb-parts"}
# Never recorded: faults hidden for the student to find, and reads.
SECRET = {"wb-fault", "wb-drill", "wb-new", "wb-history", "wb-undo", "wb-redo", "wb-wpa-drill"}
# Physical changes that leave the lab file as it was (the media and the drive bays).
MEDIA_OPS = {"insert", "eject", "plug", "unplug", "boot"}
PHYSICAL = {"hw-pull", "hw-back", "hw-replace", "media-blank", "media-drivers", "media-plug",
            "media-unplug", "media-pack", "disk-add", "disk-rm", "disk-bus", "disk-pull",
            "disk-back", "disk-replace", "disk-fail"}
WATCHED = PHYSICAL | {"node-set", "nic-set"}  # outside the workbench, recorded from webui.py
HIDDEN_KEYS = ("password", "key", "psk", "secret")

KINDS = {"wb-add": "add", "wb-rm": "remove", "wb-move": "move", "wb-cable": "cable",
         "wb-unplug": "unplug", "wb-parts": "parts", "wb-hw": "parts", "wb-media": "media", "wb-burn": "media",
         "wb-wifi": "wifi", "wb-ap": "wifi", "wb-ap-read": "wifi", "wb-wan": "wan", "wb-cli": "console",
         "wb-switch": "switch", "node-set": "parts", "nic-set": "cable"}

_lock = threading.Lock()


class HistoryError(Exception):
    pass


# ------------------------------------------------------------------ storage
def log_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / LOG


def _snap_dir(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / SNAPS


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _keep(lab_name: str, text: str) -> str:
    h = _hash(text)
    f = _snap_dir(lab_name) / f"{h}.toml"
    if not f.exists():
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    return h


def _snap(lab_name: str, h: str) -> str:
    try:
        return (_snap_dir(lab_name) / f"{h}.toml").read_text(encoding="utf-8")
    except OSError:
        raise HistoryError("that version of the network is no longer kept") from None


def entries(lab_name: str) -> list[dict]:
    try:
        lines = log_file(lab_name).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _append(lab_name: str, entry: dict) -> dict:
    f = log_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    old = entries(lab_name)
    entry = {"seq": (old[-1]["seq"] + 1) if old else 1, **entry}
    with f.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
    return entry


def _who() -> str:
    try:
        return getpass.getuser()
    except (OSError, KeyError, ImportError):
        return "you"


def _when(lab_name: str) -> dict:
    out = {"t": time.strftime("%Y-%m-%d %H:%M:%S")}
    from . import labclock
    if labclock.clock_file(lab_name).exists():
        out["lab_time"] = labclock.stamp(labclock.load(lab_name).now())
    return out


def _read(path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, TypeError):
        return ""


# --------------------------------------------------------------------- diff
def _flat(raw, path: tuple = (), out: dict | None = None) -> dict:
    out = {} if out is None else out
    if isinstance(raw, dict):
        for k, v in raw.items():
            _flat(v, path + (str(k),), out)
    elif isinstance(raw, list) and raw and all(isinstance(x, dict) for x in raw):
        for i, x in enumerate(raw):
            name = str(x.get("id")) if "id" in x else f"{path[-1] if path else 'item'} {i + 1}"
            _flat({k: v for k, v in x.items() if k != "id"} | {"": True}, path[:-1] + (name,), out)
    else:
        out[path] = raw
    return out


def _label(path: tuple) -> str:
    return " › ".join(p for p in path if p) or "the lab"


def _shown(path: tuple, v):
    if v is None:
        return None
    if any(h in path[-1].lower() for h in HIDDEN_KEYS) and path[-1].lower() != "keyboard":
        return "••••"
    return v if isinstance(v, (str, int, float, bool)) else json.dumps(v)


def diff(before: str, after: str) -> list[list]:
    """[what, before, after] for every setting that differs (None: absent)."""
    try:
        a, b = _flat(tomllib.loads(before or "")), _flat(tomllib.loads(after or ""))
    except tomllib.TOMLDecodeError:
        return []
    out = []
    whole = {k[:-1] for k in set(a) ^ set(b) if k and k[-1] == ""}  # devices and cards that came or went
    for k in sorted(set(a) | set(b)):
        if any(k[:len(w)] == w and k[len(w):] != ("",) for w in whole):
            continue
        if k[-1] == "mac" and k not in a:
            continue  # a card's address written down the first time the file is saved
        if a.get(k) != b.get(k):
            if k[-1] == "":  # a whole device or card came or went
                out.append([_label(k[:-1]), "present" if k in a else None, "present" if k in b else None])
            else:
                out.append([_label(k), _shown(k, a.get(k)), _shown(k, b.get(k))])
    return out[:MAX_DIFF]


def _devices(rows: list[list], params: dict) -> list[str]:
    from . import wifi
    out = []
    for v in (params.get("node"), params.get("id"), params.get("network"), params.get("to"),
              params.get("device")):
        if isinstance(v, str) and v and v not in ("switch",):
            out.append(v)
    out += list((params.get("positions") or {}) if isinstance(params.get("positions"), dict) else [])
    for what, _, _ in rows:
        parts = what.split(" › ")
        head = parts[1] if parts[0] in ("layout", "devices") and len(parts) > 1 else \
            parts[0] if parts[0] not in ("lab", "layout", "devices") else ""
        if head:
            out.append(head)
    clean = []
    for d in out:
        for pre in ("net:", "sw:", "wan:", wifi.PREFIX):
            d = d[len(pre):] if d.startswith(pre) else d
        d = "router" if d == "fabric" else d
        if d and d not in clean:
            clean.append(d)
    return clean


# ---------------------------------------------------------------- recording
def _counts(action: str, params: dict) -> bool:
    if action == "wb-media":
        return str(params.get("op") or "") in MEDIA_OPS
    return action in PHYSICAL


def _what(action: str, params: dict, res: dict) -> str:
    if action == "wb-cli":
        line = re.sub(r"(?i)\b(password|secret|key-string|key|psk)\b.*$", r"\1 ••••", str(params.get("line") or ""))
        return f"{params.get('device', '')}: {line.strip()}"
    if action == "wb-move":
        names = list((params.get("positions") or {}) if isinstance(params.get("positions"), dict) else [])
        return "moved " + ", ".join(names[:4]) + (" …" if len(names) > 4 else "") if names else "moved"
    text = str(res.get("message") or action).split("; ")[0].replace(" (live)", "")
    if action in ("wb-add", "wb-rm") or (action == "wb-cable" and params.get("node") == "router"):
        text = text.split(": ")[0].split(" (")[0]
        text += " added" if action == "wb-add" and not text.endswith("added") else ""
    return text[:200]


def recorded(dash, action: str, params: dict, run) -> dict:
    """``run()`` the action and, if it changed the bench, put it in the
    history. The one place every recorded action goes through."""
    if action in SECRET:
        return run()
    lab_name, src = dash.lab.name, dash.lab.source_path
    before = _read(src)
    res = run()
    if not isinstance(res, dict) or not res.get("ok") or dash.lab.name != lab_name:
        return res
    after = _read(src)
    if before == after and not _counts(action, params):
        return res
    try:
        note(lab_name, action, params, res, before, after)
    except Exception:  # noqa: BLE001 - the history never stops a change
        pass
    return res


def note(lab_name: str, action: str, params: dict, res: dict, before: str, after: str) -> dict:
    rows = diff(before, after) if before != after else []
    entry = {**_when(lab_name), "who": _who(), "action": action,
             "kind": KINDS.get(action, "disk" if action.startswith(("hw-", "disk-")) else
                               "media" if action.startswith("media-") else "device"),
             "what": _what(action, params, res), "devices": _devices(rows, params),
             "undo": action in UNDOABLE and before != after, "changes": rows}
    with _lock:
        head = _head(lab_name)
        if before != after:
            entry["before"], entry["after"] = _keep(lab_name, before), _keep(lab_name, after)
            if head and head != entry["before"]:
                entry["gap"] = True  # changed outside the workbench in between
        return _append(lab_name, entry)


# ---------------------------------------------------------------- undo/redo
def _head(lab_name: str) -> str:
    for e in reversed(entries(lab_name)):
        if e.get("after"):
            return e["after"]
    return ""


def stacks(lab_name: str) -> tuple[list[dict], list[dict]]:
    """(what undo would take back, newest last; what redo would put back)."""
    undo, redo = [], []
    for e in entries(lab_name):
        if e["action"] == "undo" and undo and undo[-1]["seq"] == e.get("of"):
            redo.append(undo.pop())
        elif e["action"] == "redo" and redo and redo[-1]["seq"] == e.get("of"):
            undo.append(redo.pop())
        elif e["action"] in ("undo", "redo"):
            undo, redo = [], []
        elif e.get("gap"):  # what came before was changed outside: undo stops here
            undo, redo = ([e] if e.get("undo") else []), []
        elif e.get("undo"):
            undo.append(e)
            redo = []
        elif e.get("after"):
            undo, redo = [], []  # a change undo cannot take back: it stops there
    return undo, redo


def _hardware(node: dict) -> dict:
    """A machine's settings that need it off, as the lab file has them."""
    out = {k: v for k, v in node.items() if k != "nic"}
    out["nics"] = len(node.get("nic", []))
    return out


def _check(dash, target: str) -> None:
    """Refuse an undo a real bench could not do as it stands."""
    from . import naming, workbench
    lab = dash.lab
    running = workbench._running(lab.name)
    try:
        now_nodes = {n["id"]: n for n in tomllib.loads(_read(lab.source_path)).get("node", [])}
        new_nodes = {n["id"]: n for n in tomllib.loads(target).get("node", [])}
    except tomllib.TOMLDecodeError as exc:
        raise HistoryError(f"that version of the network does not read: {exc}") from None
    for nid in sorted(running & set(now_nodes)):
        if nid not in new_nodes:
            raise HistoryError(f"{naming.display(lab, nid)} is running and the undo takes it off the "
                               f"bench: shut it down first")
        if _hardware(now_nodes[nid]) != _hardware(new_nodes[nid]):
            raise HistoryError(f"the undo changes the parts in {naming.display(lab, nid)}: shut it "
                               f"down before you open its case")
    for nid, node in now_nodes.items():
        keep = len(new_nodes.get(nid, {}).get("data_disks_gb", [])) if nid in new_nodes else None
        if keep is None:
            continue  # a machine taken off the bench keeps its disks
        for i in range(keep, len(node.get("data_disks_gb", []))):
            f = paths.lab_dir(lab.name) / nid / f"data{i}.qcow2"
            if f.exists() and f.stat().st_size > DATA_BYTES:
                raise HistoryError(f"data disk {i + 1} of {naming.display(lab, nid)} has data on it: "
                                   f"undo will not pull it out; take it out in the case if you mean to")


def _apply(dash, text: str) -> str:
    """Put the lab file back to ``text`` the way the workbench saves, so a
    running network takes it. What it says about the running network."""
    from . import editor, schema, workbench
    cur = dash.lab
    try:
        lab = schema._build(tomllib.loads(text), Path(cur.source_path))
    except (schema.LabError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise HistoryError(f"that version of the network does not load: {exc}") from None
    lab.password_in_toml, lab.admin_password = cur.password_in_toml, cur.admin_password
    lab.source_path = cur.source_path
    had = set(cur.nodes)
    dash.lab = lab
    try:
        workbench._save(dash)
    except editor.EditError as exc:
        dash.reload()
        raise HistoryError(str(exc)) from None
    from . import mylabs  # a machine taken off the bench and put back: its disks too
    for nid in set(dash.lab.nodes) - had:
        mylabs.unpark_machine(dash.lab.name, nid)
    cons = dash.__dict__.get("dev_consoles", {})
    for key in [k for k in cons if k != "router" and k.removeprefix("sw:") not in dash.lab.networks]:
        cons.pop(key, None)
    return workbench._sync(dash)


def step(dash, back: bool = True) -> dict:
    """Undo (``back``) or redo the newest change there is to take back or
    put back. Raises HistoryError with the reason it cannot."""
    lab_name = dash.lab.name
    with _lock:
        undo, redo = stacks(lab_name)
        pile = undo if back else redo
        if not pile:
            raise HistoryError("nothing to undo" if back else "nothing to redo")
        e = pile[-1]
        current = _read(dash.lab.source_path)
        if _head(lab_name) and _hash(current) != _head(lab_name):
            raise HistoryError("the network was changed outside the workbench since; undo stops there")
        target = _snap(lab_name, e["before"] if back else e["after"])
        _check(dash, target)
        live = _apply(dash, target)
        after = _read(dash.lab.source_path)
        rec = {**_when(lab_name), "who": _who(), "action": "undo" if back else "redo",
               "kind": "undo" if back else "redo", "of": e["seq"],
               "what": ("Undo: " if back else "Redo: ") + e["what"], "devices": e.get("devices", []),
               "undo": False, "changes": diff(current, after),
               "before": _keep(lab_name, current), "after": _keep(lab_name, after)}
        _append(lab_name, rec)
    return {"ok": True, "message": rec["what"] + live}


def view(lab_name: str, device: str = "", limit: int = 500) -> dict:
    """The Change history window: newest first, and what undo and redo would do."""
    undo, redo = stacks(lab_name)
    rows = [e for e in entries(lab_name) if not device or device in e.get("devices", [])]
    devices = sorted({d for e in entries(lab_name) for d in e.get("devices", [])})
    keep = ("seq", "t", "lab_time", "who", "kind", "what", "devices", "changes", "undo", "of")
    return {"ok": True, "lab": lab_name, "devices": devices,
            "entries": [{k: e[k] for k in keep if k in e} for e in reversed(rows[-limit:])],
            "can_undo": undo[-1]["what"] if undo else "", "can_redo": redo[-1]["what"] if redo else "",
            "undone": [e["seq"] for e in redo]}


def since(lab_name: str, started: float) -> list[dict]:
    """Who changed what since ``started`` (the Activity window's trail)."""
    t0 = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started))
    return [{k: e.get(k, "") for k in ("t", "who", "what", "kind")}
            for e in entries(lab_name) if e.get("t", "") >= t0]


def act(dash, action: str, params: dict) -> dict:
    """wb-history, wb-undo, wb-redo (from workbench.act)."""
    if action == "wb-history" and params.get("brief"):
        undo, redo = stacks(dash.lab.name)
        return {"ok": True, "can_undo": undo[-1]["what"] if undo else "",
                "can_redo": redo[-1]["what"] if redo else ""}
    if action == "wb-history":
        return view(dash.lab.name, str(params.get("device") or ""))
    try:
        return step(dash, back=action == "wb-undo")
    except HistoryError as exc:
        return {"ok": False, "message": str(exc)}


# ---------------------------------------------------------------- the CLI
class Bench:
    """What undo needs of the desktop, for the command line."""

    def __init__(self, lab) -> None:
        self.lab = lab
        self.reload()

    def reload(self) -> None:
        from . import netplan, schema
        self.lab = schema.load(self.lab.source_path or self.lab.name)
        self.plan = netplan.compile_topology(self.lab, check_ports=False)


def _text(v) -> str:
    return "—" if v is None else "(none)" if v == "" else str(v)


def render(lab_name: str, device: str = "", limit: int = 40) -> str:
    v = view(lab_name, device, limit)
    if not v["entries"]:
        return f"{lab_name}: no changes recorded yet"
    out = []
    for e in v["entries"]:
        mark = " (undone)" if e["seq"] in v["undone"] else ""
        lt = f" [lab {e['lab_time']}]" if e.get("lab_time") else ""
        out.append(f"{e['seq']:>4}  {e['t']}{lt}  {e.get('who', ''):<10} {e['what']}{mark}")
        for what, a, b in e.get("changes", [])[:6]:
            out.append(f"        {what}: {_text(a)} -> {_text(b)}")
    out.append("")
    out.append(f"undo: {v['can_undo'] or 'nothing'}")
    if v["can_redo"]:
        out.append(f"redo: {v['can_redo']}")
    return "\n".join(out)
