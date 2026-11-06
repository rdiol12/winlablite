"""Sites: an office and a cloud region that only meet through the WAN.

A lab with [[site]] entries puts each segment in a site. The lab router keeps
routing freely inside a site, but a packet for another site is handed to the
site's gateway machine (policy routing by ingress interface, one table per
site), and that machine carries it over the WAN in a tunnel it builds with
the other site's gateway: Windows RRAS on the office side, strongSwan on the
cloud side. Without a gateway, the other sites are unreachable, which is
the honest state of two networks with nothing between them.

The WAN segments (`wan = true`) belong to no site: they are the Internet
between the gateways' outside interfaces.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Lab, Network, Node


@dataclass
class Gateway:
    node: Node
    site: str
    inside_ip: str
    inside_network: str
    outside_ip: str
    outside_network: str


@dataclass
class Tunnel:
    """What one site's gateway needs to reach the other site."""

    site: str
    local_outside_ip: str
    local_inside_ip: str
    local_prefixes: list[str]
    peer_site: str
    peer_node: str
    peer_outside_ip: str
    remote_prefixes: list[str]
    psk: str = ""
    notes: list[str] = field(default_factory=list)


def site_of(lab: Lab, network_id: str) -> str:
    net = lab.networks.get(network_id)
    return net.site if net else ""


def site_of_node(lab: Lab, node_id: str) -> str:
    """The site a machine sits in: that of its first adapter on a site
    segment (a gateway's inside adapter comes first by convention)."""
    node = lab.nodes.get(node_id)
    for nic in (node.nics if node else []):
        s = site_of(lab, nic.network)
        if s:
            return s
    return ""


def networks_of(lab: Lab, site: str) -> list[Network]:
    """The site's segments in address order (the WAN belongs to no site)."""
    return [n for n in sorted(lab.networks.values(), key=lambda x: (x.net, x.id))
            if n.site == site and not n.wan]


def prefixes_of(lab: Lab, site: str) -> list[str]:
    return [n.cidr for n in networks_of(lab, site)]


def gateway_of(lab: Lab, site: str) -> Gateway | None:
    s = lab.sites.get(site)
    if not s or not s.gateway or s.gateway not in lab.nodes:
        return None
    node = lab.nodes[s.gateway]
    inside = outside = None
    for nic in node.nics:
        net = lab.networks.get(nic.network)
        if not net or not nic.ip:
            continue
        if net.wan and outside is None:
            outside = (nic.ip, net.id)
        elif net.site == site and inside is None:
            inside = (nic.ip, net.id)
    if not inside or not outside:
        return None
    return Gateway(node, site, inside[0], inside[1], outside[0], outside[1])


def tunnel_for(lab: Lab, node_id: str) -> Tunnel | None:
    """The site-to-site tunnel a gateway machine terminates, or None when
    the node is no site's gateway or no other site has a gateway yet."""
    mine = [s for s in lab.sites.values() if s.gateway == node_id]
    if not mine:
        return None
    gw = gateway_of(lab, mine[0].id)
    if not gw:
        return None
    others = [gateway_of(lab, s.id) for s in sorted(lab.sites.values(), key=lambda x: x.id)
              if s.id != gw.site]
    others = [o for o in others if o]
    if not others:
        return None
    peer = others[0]
    t = Tunnel(site=gw.site, local_outside_ip=gw.outside_ip, local_inside_ip=gw.inside_ip,
               local_prefixes=prefixes_of(lab, gw.site), peer_site=peer.site,
               peer_node=peer.node.id, peer_outside_ip=peer.outside_ip,
               remote_prefixes=prefixes_of(lab, peer.site), psk=lab.admin_password)
    if len(others) > 1:
        t.notes.append("more than two sites: only the first other site is tunnelled")
    return t


def validate(lab: Lab) -> list[str]:
    errs: list[str] = []
    for net in lab.networks.values():
        if net.site and net.site not in lab.sites:
            errs.append(f"network '{net.id}': site {net.site!r} is not a [[site]] of the lab")
        if net.site and net.wan:
            errs.append(f"network '{net.id}': a wan segment is the Internet between sites "
                        f"and belongs to none; drop 'site'")
    for site in lab.sites.values():
        if not networks_of(lab, site.id):
            errs.append(f"site '{site.id}': no network names it (site = {site.id!r})")
        if site.gateway:
            if site.gateway not in lab.nodes:
                errs.append(f"site '{site.id}': gateway {site.gateway!r} is not a machine of the lab")
            elif gateway_of(lab, site.id) is None:
                errs.append(f"site '{site.id}': gateway {site.gateway} needs a static address "
                            f"on a segment of the site and one on a wan segment")
    if lab.sites and not any(n.wan for n in lab.networks.values()):
        errs.append("the lab has sites but no wan segment for their gateways to meet on")
    return errs


def describe(lab: Lab) -> list[str]:
    if not lab.sites:
        return []
    out = ["sites (the router routes within a site; other sites only through the gateway)"]
    for site in sorted(lab.sites.values(), key=lambda x: x.id):
        gw = gateway_of(lab, site.id)
        via = (f"gateway {gw.node.id} ({gw.inside_ip} inside, {gw.outside_ip} on {gw.outside_network})"
               if gw else "no gateway: other sites unreachable")
        out.append(f"  {site.id:<10} {', '.join(prefixes_of(lab, site.id)):<40} {via}")
        if site.description:
            out.append(f"  {'':<10} {site.description}")
    return out
