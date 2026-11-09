"""The Network map's Tidy layout: ELK (elkjs) and its Cytoscape adapter.

The Laid out view of the Network map (mapview.py, Cytoscape.js) places the
lab as a tree from the router by default (Cytoscape's own breadthfirst
layout). Tidy hands the same graph to the Eclipse Layout Kernel's layered
algorithm instead: devices in layers from the router down, crossings kept to
a minimum and the cables routed at right angles, the way a drawn network
diagram looks. elkjs is ELK compiled to JavaScript; cytoscape-elk lets
Cytoscape use it as a layout.

Licences, both verified from the files in the published tarballs:
  * elkjs: Eclipse Public License 2.0 (with GPL-3.0-or-later named as a
    secondary licence; winlab takes it under the EPL). The EPL is a weak,
    file-level copyleft: winlab fetches the published file onto the
    customer's PC and serves it to the browser unmodified, with its licence
    beside it, and never changes, bundles or ships it.
  * cytoscape-elk: MIT (the Cytoscape Consortium).

Like Cytoscape.js both are fetched from the npm registry's published
tarballs, pinned by SHA-256, and only the browser builds and the licences are
kept. Without them the Laid out view keeps its tree layout and Tidy offers to
fetch them.
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import paths
from .termview import REGISTRY, TermError, _get, unpack

VERSION = "0.12.0"            # elkjs
ADAPTER_VERSION = "2.3.0"     # cytoscape-elk
LICENSE = "EPL-2.0"
ADAPTER_LICENSE = "MIT"
STAMP = "VERSION"

# tarball -> (sha256 of the tarball, {path inside the tarball: path kept})
PACKAGES: dict[str, tuple[str, dict[str, str]]] = {
    f"elkjs/-/elkjs-{VERSION}.tgz": (
        "c1d7719723e020b10724e3ccbc935696a2884f1e78d361cdd03766309e8e8e2a",
        {"package/lib/elk.bundled.js": "elk.bundled.js", "package/LICENSE.md": "LICENSE-elkjs.md"}),
    f"cytoscape-elk/-/cytoscape-elk-{ADAPTER_VERSION}.tgz": (
        "c3f1b27e4a86fc2980a0a34a7addc1827bb216572f314046fde5dadd40b1775c",
        {"package/dist/cytoscape-elk.js": "cytoscape-elk.js", "package/LICENSE": "LICENSE-cytoscape-elk.txt"}),
}
FILES = tuple(dest for _, members in PACKAGES.values() for dest in members.values())
STAMP_TEXT = f"{VERSION} {ADAPTER_VERSION}"


class ElkViewError(TermError):
    pass


def elk_dir() -> Path:
    return paths.RUNTIME / "elk"


def ready() -> bool:
    d = elk_dir()
    try:
        return ((d / STAMP).read_text(encoding="ascii").strip() == STAMP_TEXT
                and all((d / f).exists() for f in FILES))
    except OSError:
        return False


def fetch(refresh: bool = False, progress=None, get=_get) -> Path:
    d = elk_dir()
    say = progress or (lambda line: print(f"  {line}", file=sys.stderr))
    if ready() and not refresh:
        say(f"ELK {VERSION} already fetched")
        return d
    d.mkdir(parents=True, exist_ok=True)
    (d / STAMP).unlink(missing_ok=True)
    for rel, (digest, members) in PACKAGES.items():
        name = rel.rsplit("/", 1)[-1]
        try:
            data = get(REGISTRY + rel)
            unpack(data, digest, members, d, name)
        except TermError as exc:
            raise ElkViewError(str(exc)) from exc
        say(f"{name} ({len(data) // 1024} KiB)")
    (d / STAMP).write_text(STAMP_TEXT + "\n", encoding="ascii")
    say(f"ELK {VERSION} and cytoscape-elk {ADAPTER_VERSION} ready in {d}")
    return d


def render_status() -> str:
    head = (f"network map Tidy layout: elkjs {VERSION} ({LICENSE}, served unmodified) and "
            f"cytoscape-elk {ADAPTER_VERSION} ({ADAPTER_LICENSE}), fetched from the npm registry at bootstrap")
    return head + ("\n  ready in " + str(elk_dir()) if ready()
                   else "\n  not fetched: 'winlab bootstrap' or 'winlab viewer fetch' downloads it")
