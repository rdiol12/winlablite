"""The Performance window's charts: uPlot, fetched at bootstrap.

The meters in the Performance window, a machine's Performance sheet and the
Alerts window are time series: CPU, memory, disk and network every few
seconds over the last minutes (winlab/perfmon.py keeps the history and the
time of each sample). uPlot (MIT, Leon Sorokin) draws them as real charts,
with a time axis, gridlines in the meter's own colour and a cursor that reads
the value under it, the way Task Manager's Performance tab and Performance
Monitor draw theirs. winlab picks the colours, fonts and layout from its own
theme; uPlot only draws the lines.

Like xterm.js (termview.py) and Cytoscape.js (mapview.py) it is fetched onto
the customer's PC from the npm registry's published tarball, pinned by the
tarball's SHA-256, with its licence file kept beside it; only the browser
build, its stylesheet and the licence are kept. Nothing of it is in winlab's
installer. Without it the meters keep winlab's own hand-drawn lines and the
Performance window offers to fetch it.
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import paths
from .termview import REGISTRY, TermError, _get, unpack

VERSION = "1.6.32"
LICENSE = "MIT"
STAMP = "VERSION"

# tarball -> (sha256 of the tarball, {path inside the tarball: path kept})
PACKAGES: dict[str, tuple[str, dict[str, str]]] = {
    f"uplot/-/uplot-{VERSION}.tgz": (
        "4b8a8191e425658e3ea8c8c1314b0fc679c861ee3a1af2b20c7b16ba50b5133d",
        {"package/dist/uPlot.iife.min.js": "uPlot.iife.min.js", "package/dist/uPlot.min.css": "uPlot.min.css",
         "package/LICENSE": "LICENSE-uplot.txt"}),
}
FILES = tuple(dest for _, members in PACKAGES.values() for dest in members.values())
STAMP_TEXT = VERSION


class ChartViewError(TermError):
    pass


def chart_dir() -> Path:
    return paths.RUNTIME / "uplot"


def ready() -> bool:
    d = chart_dir()
    try:
        return ((d / STAMP).read_text(encoding="ascii").strip() == STAMP_TEXT
                and all((d / f).exists() for f in FILES))
    except OSError:
        return False


def fetch(refresh: bool = False, progress=None, get=_get) -> Path:
    d = chart_dir()
    say = progress or (lambda line: print(f"  {line}", file=sys.stderr))
    if ready() and not refresh:
        say(f"uPlot {VERSION} already fetched")
        return d
    d.mkdir(parents=True, exist_ok=True)
    (d / STAMP).unlink(missing_ok=True)
    for rel, (digest, members) in PACKAGES.items():
        name = rel.rsplit("/", 1)[-1]
        try:
            data = get(REGISTRY + rel)
            unpack(data, digest, members, d, name)
        except TermError as exc:
            raise ChartViewError(str(exc)) from exc
        say(f"{name} ({len(data) // 1024} KiB)")
    (d / STAMP).write_text(STAMP_TEXT + "\n", encoding="ascii")
    say(f"uPlot {VERSION} ready in {d}")
    return d


def render_status() -> str:
    head = f"performance charts: uPlot {VERSION} ({LICENSE}), fetched from the npm registry at bootstrap"
    return head + ("\n  ready in " + str(chart_dir()) if ready()
                   else "\n  not fetched: 'winlab bootstrap' or 'winlab viewer fetch' downloads it")
