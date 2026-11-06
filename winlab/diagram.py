"""Render a compiled topology as an SVG network diagram inside an HTML page."""

from __future__ import annotations

import html

from .netplan import TRUNK, TopologyPlan

PALETTE = [
    ("#2563eb", "#60a5fa"),
    ("#0d9488", "#2dd4bf"),
    ("#b45309", "#fbbf24"),
    ("#7c3aed", "#a78bfa"),
    ("#be123c", "#fb7185"),
    ("#4d7c0f", "#a3e635"),
]

COL_W = 268
NODE_W = 214
NODE_H = 62
NODE_GAP = 14
TOP = 122
FABRIC_H = 78
PAD = 28


def _kind_glyph(kind: str) -> str:
    return {
        "windows-server": "SRV",
        "windows-client": "PC",
        "linux": "LNX",
        "custom": "ISO",
    }.get(kind, "VM")


def render(plan: TopologyPlan) -> str:
    lab = plan.lab
    segments = sorted(plan.segments.values(), key=lambda s: s.vid)
    colors = {s.network.id: PALETTE[i % len(PALETTE)] for i, s in enumerate(segments)}

    max_nodes = max((len(s.members) for s in segments), default=1)
    width = PAD * 2 + COL_W * max(len(segments), 1)
    stack_h = max_nodes * (NODE_H + NODE_GAP)
    fabric_y = TOP + stack_h + 54
    height = fabric_y + FABRIC_H + 92

    svg: list[str] = [
        f'<svg class="winlab-topo" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" '
        f'role="img" aria-label="network topology for {html.escape(lab.name)}">',
        # The styles travel inside the SVG so the diagram looks the same
        # inlined in the dashboard, in the standalone page, or saved to a file.
        f"<style>{SVG_CSS}</style>",
        "<defs>",
        '<marker id="dot" markerWidth="6" markerHeight="6" refX="3" refY="3">'
        '<circle cx="3" cy="3" r="2.4" fill="currentColor"/></marker>',
        "</defs>",
    ]

    svg.append(
        f'<text x="{PAD}" y="34" class="title">{html.escape(lab.name)}</text>'
    )
    svg.append(
        f'<text x="{PAD}" y="58" class="sub">{html.escape(lab.domain)} &#183; '
        f"{len(lab.nodes)} machines &#183; {len(segments)} vlans &#183; "
        f"isolated from host</text>"
    )

    col_x: dict[str, float] = {}
    for i, seg in enumerate(segments):
        cx = PAD + COL_W * i + COL_W / 2
        col_x[seg.network.id] = cx
        dark, light = colors[seg.network.id]

        svg.append(
            f'<line x1="{cx}" y1="{TOP - 18}" x2="{cx}" y2="{fabric_y}" '
            f'class="wire" stroke="{dark}"/>'
        )

        net = seg.network
        tag = f"vlan {seg.vid}"
        svg.append(
            f'<rect x="{cx - 104}" y="{TOP - 44}" width="208" height="30" rx="15" '
            f'class="seg-pill" fill="{dark}"/>'
        )
        svg.append(
            f'<text x="{cx}" y="{TOP - 24}" class="seg-label">'
            f"{html.escape(net.id)} &#183; {tag}</text>"
        )

        for j, link in enumerate(seg.members):
            node = lab.nodes[link.node_id]
            ny = TOP + j * (NODE_H + NODE_GAP)
            nx = cx - NODE_W / 2
            nic = node.nics[link.nic_index]
            addr = nic.ip or "dhcp"
            is_trunk = link.mode == TRUNK

            svg.append(
                f'<line x1="{cx}" y1="{ny + NODE_H / 2}" x2="{cx}" '
                f'y2="{ny + NODE_H / 2}" class="stub" stroke="{dark}"/>'
            )
            svg.append(
                f'<rect x="{nx}" y="{ny}" width="{NODE_W}" height="{NODE_H}" rx="10" '
                f'class="node" stroke="{dark}"/>'
            )
            svg.append(
                f'<text x="{nx + 14}" y="{ny + 24}" class="node-id">'
                f"{html.escape(node.id)}</text>"
            )
            svg.append(
                f'<text x="{nx + NODE_W - 14}" y="{ny + 24}" class="badge" '
                f'text-anchor="end" fill="{dark}">{_kind_glyph(node.kind)}</text>'
            )
            svg.append(
                f'<text x="{nx + 14}" y="{ny + 43}" class="node-meta">'
                f"{html.escape(addr)}</text>"
            )
            roles = ",".join(node.roles)[:30] or "-"
            svg.append(
                f'<text x="{nx + 14}" y="{ny + 56}" class="node-roles">'
                f"{html.escape(roles)}</text>"
            )
            if is_trunk:
                svg.append(
                    f'<text x="{nx + NODE_W - 14}" y="{ny + 43}" class="trunk-tag" '
                    f'text-anchor="end" fill="{dark}">trunk +{len(link.trunk_vlans)}</text>'
                )

        if net.impair.active:
            bits = []
            if net.impair.delay_ms:
                bits.append(f"{net.impair.delay_ms}ms")
            if net.impair.loss_pct:
                bits.append(f"{net.impair.loss_pct}% loss")
            if net.impair.rate_mbit:
                bits.append(f"{net.impair.rate_mbit}mbit")
            svg.append(
                f'<text x="{cx}" y="{fabric_y - 12}" class="impair" '
                f'text-anchor="middle">{html.escape(" / ".join(bits))}</text>'
            )

    # trunk cross-links
    for seg in segments:
        for link in seg.members:
            if link.mode != TRUNK:
                continue
            src = col_x[link.network_id]
            for other in link.trunk_vlans:
                dst = col_x.get(other)
                if dst is None:
                    continue
                dark, _ = colors[other]
                mid = fabric_y - 30
                svg.append(
                    f'<path d="M {src} {mid} C {src} {mid - 26}, {dst} {mid - 26}, '
                    f'{dst} {mid}" class="trunk-link" stroke="{dark}"/>'
                )

    fx = PAD
    fw = width - PAD * 2
    svg.append(
        f'<rect x="{fx}" y="{fabric_y}" width="{fw}" height="{FABRIC_H}" rx="12" '
        f'class="fabric"/>'
    )
    svg.append(
        f'<text x="{fx + 18}" y="{fabric_y + 28}" class="fabric-title">'
        f"fabric &#183; vlan-aware bridge lab0</text>"
    )
    svg.append(
        f'<text x="{fx + 18}" y="{fabric_y + 50}" class="fabric-sub">'
        f"{plan.fabric_link_count} ports &#183; one svi per vlan &#183; routing, "
        f"nftables, dhcp relay, netem</text>"
    )
    svg.append(
        f'<text x="{fx + 18}" y="{fabric_y + 68}" class="fabric-sub">'
        f"no tap driver &#183; no user-mode nic &#183; no path to host or internet</text>"
    )

    for seg in segments:
        cx = col_x[seg.network.id]
        dark, _ = colors[seg.network.id]
        svg.append(
            f'<text x="{cx}" y="{fabric_y + FABRIC_H + 22}" class="svi" '
            f'text-anchor="middle" fill="{dark}">{seg.svi}</text>'
        )
        svg.append(
            f'<text x="{cx}" y="{fabric_y + FABRIC_H + 38}" class="svi-sub" '
            f'text-anchor="middle">{html.escape(seg.network.cidr)}</text>'
        )
        svg.append(
            f'<text x="{cx}" y="{fabric_y + FABRIC_H + 54}" class="svi-sub" '
            f'text-anchor="middle">gw {html.escape(seg.network.router_ip)}</text>'
        )

    svg.append("</svg>")
    return "\n".join(svg)


SVG_CSS = """
svg.winlab-topo{display:block;max-width:100%;height:auto;
--topo-fabric:#eaeef6;--topo-fabric-line:#bcc5d4}
@media (prefers-color-scheme:dark){svg.winlab-topo{--topo-fabric:#111621;--topo-fabric-line:#2c3443}}
:root[data-theme=dark] svg.winlab-topo{--topo-fabric:#111621;--topo-fabric-line:#2c3443}
:root[data-theme=light] svg.winlab-topo{--topo-fabric:#eaeef6;--topo-fabric-line:#bcc5d4}
svg.winlab-topo text{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;fill:var(--fg,#141821)}
svg.winlab-topo .title{font-size:20px;font-weight:650}
svg.winlab-topo .sub{font-size:12.5px;fill:var(--muted,#596273)}
svg.winlab-topo .wire{stroke-width:2.5;opacity:.5}
svg.winlab-topo .stub{stroke-width:2}
svg.winlab-topo .node{fill:var(--card,#fff);stroke-width:1.6}
svg.winlab-topo .node-id{font-size:14px;font-weight:620}
svg.winlab-topo .node-meta{font-size:11.5px;fill:var(--muted,#596273);font-family:ui-monospace,monospace;
font-variant-numeric:tabular-nums}
svg.winlab-topo .node-roles{font-size:10.5px;fill:var(--muted,#596273)}
svg.winlab-topo .badge{font-size:10px;font-weight:700;letter-spacing:.06em}
svg.winlab-topo .trunk-tag{font-size:9.5px;font-weight:600}
svg.winlab-topo .seg-pill{opacity:.92}
svg.winlab-topo .seg-label{font-size:12px;font-weight:620;fill:#fff;text-anchor:middle}
svg.winlab-topo .fabric{fill:var(--topo-fabric);stroke:var(--topo-fabric-line);stroke-width:1.4}
svg.winlab-topo .fabric-title{font-size:14px;font-weight:650}
svg.winlab-topo .fabric-sub{font-size:11.5px;fill:var(--muted,#596273)}
svg.winlab-topo .svi{font-size:11.5px;font-weight:650;font-family:ui-monospace,monospace}
svg.winlab-topo .svi-sub{font-size:10.5px;fill:var(--muted,#596273);font-family:ui-monospace,monospace;
font-variant-numeric:tabular-nums}
svg.winlab-topo .impair{font-size:10.5px;fill:var(--muted,#596273);font-style:italic}
svg.winlab-topo .trunk-link{fill:none;stroke-width:1.6;stroke-dasharray:5 4;opacity:.75}
"""

CSS = """
:root{--bg:#f7f8fb;--fg:#141821;--muted:#596273;--card:#ffffff;--line:#d5dae4}
@media (prefers-color-scheme:dark){:root{--bg:#0b0e14;--fg:#e6e9f0;--muted:#8f99ad;
--card:#141822;--line:#262d3b}}
:root[data-theme=dark]{--bg:#0b0e14;--fg:#e6e9f0;--muted:#8f99ad;--card:#141822;--line:#262d3b}
:root[data-theme=light]{--bg:#f7f8fb;--fg:#141821;--muted:#596273;--card:#ffffff;--line:#d5dae4}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 56px}
h1{font-size:1.5rem;margin:0 0 4px;letter-spacing:-.012em;text-wrap:balance;
font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
p.lead{color:var(--muted);margin:0 0 28px;max-width:62ch}
.canvas{overflow-x:auto;background:var(--card);border:1px solid var(--line);
border-radius:14px;padding:18px}
.legend{display:flex;gap:22px;flex-wrap:wrap;margin-top:22px;color:var(--muted);
font-size:12.5px}
.legend b{color:var(--fg);font-weight:600}
"""


def render_page(plan: TopologyPlan, title: str = "") -> str:
    lab = plan.lab
    name = title or f"winlab topology: {lab.name}"
    return f"""<title>{html.escape(name)}</title>
<style>{CSS}</style>
<div class="wrap">
  <h1>{html.escape(lab.name)}</h1>
  <p class="lead">{html.escape(lab.description)}</p>
  <div class="canvas">{render(plan)}</div>
  <div class="legend">
    <span><b>SRV</b> Windows Server</span>
    <span><b>PC</b> Windows client</span>
    <span><b>LNX</b> Linux</span>
    <span><b>solid</b> access port</span>
    <span><b>dashed</b> trunked vlan</span>
  </div>
</div>"""
