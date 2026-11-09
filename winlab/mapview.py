"""The Network map's laid-out view: Cytoscape.js, fetched at bootstrap.

The Network map window draws the lab by VLAN in winlab's own SVG (router on
top, a column per switch, the machines under it). That works for the small
labs; on a large lab, or one with campus gear, access points and site
gateways, the student wants the whole graph laid out so cables do not cross,
with zoom and pan. Cytoscape.js (MIT, the Cytoscape Consortium) does that:
the page hands it the same /api/topology the SVG view draws (router,
switches, machines, every cable and tagged VLAN) and it computes the layout.
winlab still draws every device with its own glyphs and colours; Cytoscape
only places them and draws the cables between them.

Like xterm.js (termview.py) it is fetched onto the customer's PC from the
npm registry's published tarball, pinned by the tarball's SHA-256, with its
licence file kept beside it; only the one browser build and the licence are
kept. Nothing of it is in winlab's installer. Without it the map keeps its
VLAN view and the laid-out view offers to fetch it.
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import paths
from .termview import REGISTRY, TermError, _get, unpack

VERSION = "3.34.4"
LICENSE = "MIT"
STAMP = "VERSION"

# tarball -> (sha256 of the tarball, {path inside the tarball: path kept})
PACKAGES: dict[str, tuple[str, dict[str, str]]] = {
    f"cytoscape/-/cytoscape-{VERSION}.tgz": (
        "0d02363d99d805ce8d91fdecab7b2a8cb91ee280d67f309ce44c161d117b4679",
        {"package/dist/cytoscape.min.js": "cytoscape.min.js", "package/LICENSE": "LICENSE-cytoscape.txt"}),
}
FILES = tuple(dest for _, members in PACKAGES.values() for dest in members.values())
STAMP_TEXT = VERSION


class MapViewError(TermError):
    pass


def map_dir() -> Path:
    return paths.RUNTIME / "cytoscape"


def ready() -> bool:
    d = map_dir()
    try:
        return ((d / STAMP).read_text(encoding="ascii").strip() == STAMP_TEXT
                and all((d / f).exists() for f in FILES))
    except OSError:
        return False


def fetch(refresh: bool = False, progress=None, get=_get) -> Path:
    d = map_dir()
    say = progress or (lambda line: print(f"  {line}", file=sys.stderr))
    if ready() and not refresh:
        say(f"Cytoscape.js {VERSION} already fetched")
        return d
    d.mkdir(parents=True, exist_ok=True)
    (d / STAMP).unlink(missing_ok=True)
    for rel, (digest, members) in PACKAGES.items():
        name = rel.rsplit("/", 1)[-1]
        try:
            data = get(REGISTRY + rel)
            unpack(data, digest, members, d, name)
        except TermError as exc:
            raise MapViewError(str(exc)) from exc
        say(f"{name} ({len(data) // 1024} KiB)")
    (d / STAMP).write_text(STAMP_TEXT + "\n", encoding="ascii")
    say(f"Cytoscape.js {VERSION} ready in {d}")
    return d


def render_status() -> str:
    head = f"network map layout: Cytoscape.js {VERSION} ({LICENSE}), fetched from the npm registry at bootstrap"
    return head + ("\n  ready in " + str(map_dir()) if ready()
                   else "\n  not fetched: 'winlab bootstrap' or 'winlab viewer fetch' downloads it")


# ---------------------------------------------------------------- where the student put things
# The map is the student's drawing of the lab: they drag the router, a switch
# or a machine where it reads best, and it stays there. Positions live beside
# the lab's disks (var/labs/<lab>/map-layout.json), never in the lab file: a
# shipped lab stays untouched and a saved network file carries no drawing.
# One set per view: "vlan" (winlab's own drawing, top-left corners) and
# "graph" (the laid-out view, Cytoscape node centres).
LAYOUT_FILE = "map-layout.json"
VIEWS = ("vlan", "graph")
MAX_KEYS = 2000
_LIMIT = 100000


def layout_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / LAYOUT_FILE


def _known(lab, key: str) -> bool:
    kind, _, ident = key.partition(":")
    return ((kind == "router" and ident == "fabric") or (kind == "switch" and ident in lab.networks)
            or (kind == "machine" and ident in lab.nodes))


def positions(lab) -> dict[str, dict[str, list[float]]]:
    """{view: {"machine:dc01": [x, y], ...}} for the devices still in the lab."""
    import json
    try:
        data = json.loads(layout_file(lab.name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    out: dict[str, dict[str, list[float]]] = {}
    for view in VIEWS:
        got = data.get(view) if isinstance(data, dict) else None
        if not isinstance(got, dict):
            got = {}
        out[view] = {k: [float(v[0]), float(v[1])] for k, v in got.items()
                     if isinstance(k, str) and _known(lab, k) and isinstance(v, list) and len(v) == 2
                     and all(isinstance(c, (int, float)) and not isinstance(c, bool) for c in v)}
    return out


def move(lab, view: str, moved: dict | None, reset: bool = False) -> dict:
    """Keeps where devices were dragged to on one view; reset forgets that view's drawing."""
    from . import state
    if view not in VIEWS:
        return {"ok": False, "message": f"no such map view: {view}"}
    if moved is not None and not isinstance(moved, dict):
        return {"ok": False, "message": "positions must be {device: [x, y]}"}
    every = positions(lab)
    if reset:
        every[view] = {}
    for key, pos in (moved or {}).items():
        key = str(key)
        if not _known(lab, key):
            continue
        try:
            x, y = float(pos[0]), float(pos[1])
        except (TypeError, ValueError, IndexError):
            return {"ok": False, "message": f"{key} must be [x, y]"}
        if x != x or y != y:  # NaN
            continue
        every[view][key] = [round(max(-_LIMIT, min(x, _LIMIT)), 1), round(max(-_LIMIT, min(y, _LIMIT)), 1)]
        if len(every[view]) > MAX_KEYS:
            return {"ok": False, "message": "too many devices on the map"}
    state.save_json(layout_file(lab.name), every if any(every.values()) else None)
    return {"ok": True, "message": "map layout reset" if reset else "map layout kept", "map_layout": every}
