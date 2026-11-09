"""The network diagram as a diagrams.net (draw.io) drawing.

An admin documents a network in a diagram tool, and diagrams.net (draw.io,
Apache-2.0, JGraph Ltd) is the free one most of them use. So winlab does
not draw its own printable diagram any more: it writes the lab's topology
as a .drawio file (the mxGraph XML diagrams.net opens and saves) and shows
it with diagrams.net's own viewer. The student can download that file,
open it in diagrams.net and keep the documentation going there: move
boxes, add the rack, the floor, the notes.

What the file holds is plain data winlab writes itself: the router with
one interface per network, a box per network (VLAN, subnet, gateway) with
the machines cabled into it, each machine with its address and roles, and
the trunks dashed. Only diagrams.net's built-in shapes are used, so the
viewer needs no stencil or image from the internet.

The viewer (viewer-static.min.js) is fetched onto the customer's PC from
diagrams.net's own GitHub tag at bootstrap, pinned by SHA-256, with its
licence beside it, like noVNC and xterm.js; nothing of it is in winlab's
installer. Its page sets every diagrams.net address to winlab's own
server and a Content-Security-Policy that lets nothing leave the PC, so
showing a diagram never reaches diagrams.net. Without the viewer the
Viewer window offers the .drawio file and the fetch.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from xml.sax.saxutils import quoteattr

from . import paths
from .netplan import TRUNK, TopologyPlan
from .termview import TermError, _get

VERSION = "28.2.5"
LICENSE = "Apache-2.0"
SOURCE = f"https://raw.githubusercontent.com/jgraph/drawio/v{VERSION}/"
STAMP = "VERSION"
EXT = ".drawio"

# file kept -> (path at the tag, sha256)
FILES: dict[str, tuple[str, str]] = {
    "viewer-static.min.js": ("src/main/webapp/js/viewer-static.min.js",
                             "e77c093ad93b7f6f83a3e9f18e44ce49b8667c1f5da839b10b9ffc930c37eef1"),
    "LICENSE-drawio.txt": ("LICENSE", "43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1"),
}
STAMP_TEXT = VERSION

# One colour per network, the way a hand-made diagram would colour them.
PALETTE = [("#dae8fc", "#6c8ebf"), ("#d5e8d4", "#82b366"), ("#ffe6cc", "#d79b00"),
           ("#e1d5e7", "#9673a6"), ("#f8cecc", "#b85450"), ("#fff2cc", "#d6b656")]
KIND = {"windows-server": "Windows Server", "windows-client": "Windows PC",
        "linux": "Linux", "custom": "own ISO"}

COL_W = 260
BOX_W = 210
BOX_H = 64
GAP = 14
ROUTER_Y = 30
ROUTER_H = 70
NET_Y = 170
NET_HEAD = 46


class DrawioError(TermError):
    pass


def viewer_dir() -> Path:
    return paths.RUNTIME / "drawio"


def ready() -> bool:
    d = viewer_dir()
    try:
        return ((d / STAMP).read_text(encoding="ascii").strip() == STAMP_TEXT
                and all((d / f).exists() for f in FILES))
    except OSError:
        return False


def fetch(refresh: bool = False, progress=None, get=_get) -> Path:
    import hashlib

    d = viewer_dir()
    say = progress or (lambda line: print(f"  {line}", file=sys.stderr))
    if ready() and not refresh:
        say(f"diagrams.net viewer {VERSION} already fetched")
        return d
    d.mkdir(parents=True, exist_ok=True)
    (d / STAMP).unlink(missing_ok=True)
    for dest, (rel, digest) in FILES.items():
        try:
            data = get(SOURCE + rel)
        except TermError as exc:
            raise DrawioError(str(exc)) from exc
        got = hashlib.sha256(data).hexdigest()
        if got != digest:
            raise DrawioError(f"{dest}: checksum mismatch (got {got[:12]}, pinned {digest[:12]})")
        tmp = d / (dest + ".part")
        tmp.write_bytes(data)
        tmp.replace(d / dest)
        say(f"{dest} ({len(data) // 1024} KiB)")
    (d / STAMP).write_text(STAMP_TEXT + "\n", encoding="ascii")
    say(f"diagrams.net viewer {VERSION} ready in {d}")
    return d


def render_status() -> str:
    head = (f"network diagram: diagrams.net viewer {VERSION} ({LICENSE}), "
            "fetched from diagrams.net's GitHub tag at bootstrap")
    return head + ("\n  ready in " + str(viewer_dir()) if ready()
                   else "\n  not fetched: 'winlab bootstrap' or 'winlab viewer fetch' downloads it")


# ---------------------------------------------------------------- the drawing

def _cell(cells: list[str], cid: str, value: str, style: str, x: float, y: float,
          w: float, h: float, parent: str = "1") -> None:
    cells.append(f'<mxCell id={quoteattr(cid)} value={quoteattr(value)} style={quoteattr(style)} '
                 f'vertex="1" parent={quoteattr(parent)}><mxGeometry x="{x:g}" y="{y:g}" '
                 f'width="{w:g}" height="{h:g}" as="geometry"/></mxCell>')


def _edge(cells: list[str], cid: str, src: str, dst: str, style: str, value: str = "") -> None:
    cells.append(f'<mxCell id={quoteattr(cid)} value={quoteattr(value)} style={quoteattr(style)} '
                 f'edge="1" parent="1" source={quoteattr(src)} target={quoteattr(dst)}>'
                 f'<mxGeometry relative="1" as="geometry"/></mxCell>')


def _impair(net) -> str:
    bits = []
    if net.impair.delay_ms:
        bits.append(f"{net.impair.delay_ms} ms")
    if net.impair.loss_pct:
        bits.append(f"{net.impair.loss_pct}% loss")
    if net.impair.rate_mbit:
        bits.append(f"{net.impair.rate_mbit} Mbit/s")
    return " / ".join(bits)


def model(plan: TopologyPlan) -> str:
    """The lab as one mxGraphModel: what diagrams.net reads and writes."""
    lab = plan.lab
    segments = sorted(plan.segments.values(), key=lambda s: s.vid)
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    width = max(len(segments), 1) * COL_W
    font = "fontFamily=Segoe UI;"

    _cell(cells, "title", f"<b>{html.escape(lab.name)}</b><br>{html.escape(lab.domain)}"
          f" · {len(lab.nodes)} machines · {len(segments)} networks",
          f"text;html=1;align=left;verticalAlign=top;fontSize=14;{font}", 0, -40, width, 40)
    # The router spans the networks, each cabled straight up to its interface.
    rx, rw = 10, width - 20
    svis = " · ".join(f"{html.escape(s.svi)} {html.escape(s.network.router_ip)}" for s in segments)
    _cell(cells, "router", f"<b>Router</b><br><font style=\"font-size:10px\">{svis}</font>",
          f"rounded=1;whiteSpace=wrap;html=1;fillColor=#f5f5f5;strokeColor=#666666;{font}",
          rx, ROUTER_Y, rw, ROUTER_H)
    net_y = NET_Y

    col: dict[str, str] = {}
    for i, seg in enumerate(segments):
        fill, stroke = PALETTE[i % len(PALETTE)]
        net = seg.network
        nid = f"net-{net.id}"
        col[net.id] = nid
        x = i * COL_W + (COL_W - BOX_W - 20) / 2
        h = NET_HEAD + len(seg.members) * (BOX_H + GAP) + GAP
        head = (f"<b>{html.escape(net.id)}</b> · VLAN {seg.vid}<br>"
                f"{html.escape(net.cidr)} · gateway {html.escape(net.router_ip)}")
        imp = _impair(net) if net.impair.active else ""
        if imp:
            head += f"<br><i>{html.escape(imp)}</i>"
        _cell(cells, nid, head,
              f"swimlane;html=1;startSize={NET_HEAD};rounded=1;whiteSpace=wrap;fillColor={fill};"
              f"strokeColor={stroke};swimlaneFillColor=#ffffff;fontSize=11;collapsible=0;{font}",
              x, net_y, BOX_W + 20, h)
        # Straight up from the network to its own interface along the router's foot.
        _edge(cells, f"up-{net.id}", nid, "router",
              f"endArrow=none;html=1;strokeWidth=2;strokeColor={stroke};edgeStyle=orthogonalEdgeStyle;"
              f"exitX=0.5;exitY=0;entryX={(i * COL_W + COL_W / 2 - rx) / rw:.4f};entryY=1;"
              "labelBackgroundColor=#ffffff;fontSize=10;",
              f"{seg.svi}")
        for j, link in enumerate(seg.members):
            node = lab.nodes[link.node_id]
            nic = node.nics[link.nic_index]
            roles = ", ".join(node.roles) or "no roles"
            label = (f"<b>{html.escape(node.id)}</b> · {KIND.get(node.kind, node.kind)}<br>"
                     f"<font face=\"Consolas\">{html.escape(nic.ip or 'DHCP')}</font><br>"
                     f"<font style=\"font-size:9px\">{html.escape(roles[:40])}</font>")
            if link.mode == TRUNK:
                label += f"<br><font style=\"font-size:9px\">trunk + {len(link.trunk_vlans)} VLANs</font>"
            _cell(cells, f"node-{link.label}", label,
                  f"rounded=1;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor={stroke};"
                  f"align=left;spacingLeft=8;fontSize=11;{font}",
                  10, NET_HEAD + GAP + j * (BOX_H + GAP), BOX_W, BOX_H, parent=nid)

    # Trunks: a machine whose port carries other networks too, dashed to them.
    for seg in segments:
        for link in seg.members:
            if link.mode != TRUNK:
                continue
            for other in link.trunk_vlans:
                if other in col:
                    _edge(cells, f"trunk-{link.label}-{other}", f"node-{link.label}", col[other],
                          "endArrow=none;html=1;dashed=1;strokeColor=#666666;labelBackgroundColor=#ffffff;fontSize=9;", "tagged")

    note_y = net_y + max((NET_HEAD + len(s.members) * (BOX_H + GAP) + GAP for s in segments),
                         default=NET_HEAD) + 30
    _cell(cells, "note", "Isolated lab: no path to the host or the internet. "
          "One router routes between the networks; every machine port is a switch port on it.",
          f"text;html=1;align=left;verticalAlign=top;whiteSpace=wrap;fontSize=10;fontColor=#666666;{font}",
          0, note_y, width, 30)
    return ('<mxGraphModel dx="0" dy="0" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" '
            'arrows="1" fold="1" page="1" pageScale="1" math="0" shadow="0"><root>'
            + "".join(cells) + "</root></mxGraphModel>")


def dumps(plan: TopologyPlan) -> str:
    """The .drawio file: an mxfile with one page, uncompressed so it diffs."""
    return ('<mxfile host="winlab" agent="winlab" version="' + VERSION + '">'
            f'<diagram id="network" name={quoteattr(plan.lab.name)}>{model(plan)}</diagram></mxfile>\n')


# The viewer's page. Every diagrams.net address points at this server, and the
# CSP lets nothing load from anywhere else.
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
       "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; "
       "connect-src 'self'; frame-src 'none'; form-action 'none'")
URLS = ("PROXY_URL", "STYLE_PATH", "SHAPES_PATH", "STENCIL_PATH", "DRAW_MATH_URL", "GRAPH_IMAGE_PATH",
        "mxImageBasePath", "mxBasePath", "DRAWIO_BASE_URL", "DRAWIO_SERVER_URL", "DRAWIO_LIGHTBOX_URL",
        "DRAWIO_VIEWER_URL", "EXPORT_URL", "PLANT_URL", "VSS_CONVERT_URL", "EMF_CONVERT_URL")


def page(plan: TopologyPlan, base: str = "/drawio/", download: str = "/api/diagram.drawio") -> str:
    lab = plan.lab
    head = (f'<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
            f'content="{CSP}"><title>{html.escape(lab.name)} network diagram</title>'
            '<style>body{margin:0;background:#fff;color:#1b1b1b;font:13px "Segoe UI",system-ui,sans-serif}'
            '.bar{display:flex;gap:12px;align-items:center;padding:8px 14px;border-bottom:1px solid #e5e5e5}'
            '.bar a{color:#0067c0}.dia{padding:16px}@media print{.bar{display:none}}</style>')
    bar = (f'<div class="bar"><span>Drawn with diagrams.net; open the file there to edit it.</span>'
           f'<a href="{download}" download="{html.escape(lab.name)}{EXT}">Download .drawio</a></div>')
    if not ready():
        return (head + bar + '<div class="dia"><p>The diagram viewer (diagrams.net, Apache-2.0) is not on '
                'this PC yet. Download the .drawio file and open it in diagrams.net, or fetch the viewer '
                'with <code>winlab viewer fetch</code> (Settings &gt; Viewer).</p></div>')
    cfg = json.dumps({"xml": dumps(plan), "toolbar": "zoom layers", "nav": True, "lightbox": False,
                      "highlight": "#0067c0", "resize": True, "auto-fit": True})
    local = "".join(f"window.{k}={json.dumps(base)};" for k in URLS)
    return (head + bar + f'<div class="dia"><div class="mxgraph" data-mxgraph={quoteattr(cfg)}></div></div>'
            f'<script>{local}window.mxLoadStylesheets=false;window.DRAWIO_LOG_URL="";</script>'
            f'<script src="{base}viewer-static.min.js"></script>')
