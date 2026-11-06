"""Zone firewall on the lab router, in the Azure network security group model.

Every segment (VLAN) gets a rule table per direction, the way an NSG attached
to a subnet does: rules carry a priority from 100 to 4096, the lowest number
is evaluated first, and the first match decides. Below every table sit the
same default rules Azure puts there: traffic between the lab's own subnets is
allowed, anything from the edge is denied inbound and allowed outbound, and
the rest is denied. The rules render into nftables on the fabric, one chain
per table with a counter on every rule, so a student can read hit counts,
and a Python evaluator answers "would this flow pass, and by which rule"
the way Azure's IP flow verify does.

What the model does not pretend: the router only sees routed traffic. Two
machines on one VLAN talk through the switch and never meet these rules, as
on a physical network; the Windows firewall on the machine is the layer for
that. Azure's AllowAzureLoadBalancerInBound default is left out, because the
lab has no load balancer.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from . import naming
from .model import FirewallRule, Lab, Network

INBOUND = "inbound"
OUTBOUND = "outbound"
DIRECTIONS = (INBOUND, OUTBOUND)
ALLOW = "Allow"
DENY = "Deny"
ACTIONS = (ALLOW, DENY)
PROTOCOLS = ("Any", "Tcp", "Udp", "Icmp")
TAG_ANY = "Any"
TAG_VNET = "VirtualNetwork"
TAG_INTERNET = "Internet"
TAGS = (TAG_ANY, TAG_VNET, TAG_INTERNET)
PRIORITY_MIN = 100
PRIORITY_MAX = 4096
TABLE = "inet winlab"
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


class FirewallError(Exception):
    pass


# --------------------------------------------------------------------------
# Rule tables
# --------------------------------------------------------------------------


def default_rules(segment: str) -> list[FirewallRule]:
    """The rules every segment's tables end with, Azure's numbers kept so a
    student who has seen an NSG recognises them."""
    mk = lambda name, prio, direction, src, dst, action, why: FirewallRule(  # noqa: E731
        name=name, priority=prio, direction=direction, segment=segment, source=src,
        destination=dst, ports="*", protocol="Any", action=action, description=why,
        builtin=True)
    return [
        mk("AllowVnetInBound", 65000, INBOUND, TAG_VNET, TAG_VNET, ALLOW,
           "traffic from the lab's own subnets"),
        mk("DenyAllInBound", 65500, INBOUND, TAG_ANY, TAG_ANY, DENY,
           "everything else, the edge included"),
        mk("AllowVnetOutBound", 65000, OUTBOUND, TAG_VNET, TAG_VNET, ALLOW,
           "traffic to the lab's own subnets"),
        mk("AllowInternetOutBound", 65001, OUTBOUND, TAG_ANY, TAG_INTERNET, ALLOW,
           "traffic towards the edge"),
        mk("DenyAllOutBound", 65500, OUTBOUND, TAG_ANY, TAG_ANY, DENY,
           "everything else"),
    ]


def normalise(rule: FirewallRule) -> FirewallRule:
    """Case-insensitive input, canonical spelling out."""
    rule.direction = rule.direction.strip().lower()
    rule.action = rule.action.strip().capitalize()
    proto = rule.protocol.strip().lower()
    rule.protocol = {"*": "Any", "any": "Any", "tcp": "Tcp", "udp": "Udp", "icmp": "Icmp",
                     "icmpv4": "Icmp"}.get(proto, rule.protocol.strip())
    rule.ports = rule.ports.strip().replace(" ", "") or "*"
    for attr in ("source", "destination"):
        v = getattr(rule, attr).strip().replace(" ", "")
        low = v.lower()
        if low in ("*", "any"):
            v = TAG_ANY
        elif low == "virtualnetwork":
            v = TAG_VNET
        elif low == "internet":
            v = TAG_INTERNET
        setattr(rule, attr, v)
    return rule


def has_tables(net: Network) -> bool:
    """The edge (wan) segment plays the Internet, which has no NSG: traffic
    from and to it is filtered by the tables of the lab segments it reaches."""
    return not net.wan


def filtered_segments(lab: Lab) -> list[Network]:
    return [n for n in sorted(lab.networks.values(), key=lambda x: x.id) if has_tables(n)]


def rules_for(lab: Lab, segment: str, direction: str, defaults: bool = True) -> list[FirewallRule]:
    """A segment's table for one direction, in evaluation order."""
    net = lab.networks.get(segment)
    if net is not None and not has_tables(net):
        return []
    out = [r for r in lab.firewall.rules if r.segment == segment and r.direction == direction]
    if defaults:
        out += [r for r in default_rules(segment) if r.direction == direction]
    return sorted(out, key=lambda r: (r.priority, r.name))


def find_rule(lab: Lab, name: str, segment: str = "") -> FirewallRule | None:
    for r in lab.firewall.rules:
        if r.name == name and (not segment or r.segment == segment):
            return r
    return None


def add_rule(lab: Lab, **fields) -> FirewallRule:
    """Adds a rule to the lab, validated against the whole table it joins."""
    rule = normalise(FirewallRule(**fields))
    # A machine named by its computer name is stored by its id, so the rule
    # survives the next rename.
    for attr in ("source", "destination"):
        parts = [p.strip() for p in getattr(rule, attr).split(",")]
        setattr(rule, attr, ",".join(p if p in lab.networks else naming.resolve(lab, p)
                                     for p in parts))
    errs = _rule_errors(lab, rule, lab.firewall.rules)
    if errs:
        raise FirewallError("; ".join(errs))
    lab.firewall.rules.append(rule)
    return rule


def remove_rule(lab: Lab, name: str, segment: str = "") -> FirewallRule:
    rule = find_rule(lab, name, segment)
    if not rule:
        where = f" on {segment}" if segment else ""
        raise FirewallError(f"no rule named '{name}'{where} in the lab definition")
    lab.firewall.rules.remove(rule)
    return rule


# --------------------------------------------------------------------------
# Endpoints, ports, protocols
# --------------------------------------------------------------------------


@dataclass
class Endpoint:
    """What a rule's source or destination resolves to."""

    text: str
    kind: str                     # any | cidrs | not-vnet
    cidrs: list[str] = field(default_factory=list)

    def contains(self, ip: str, vnet: list[str]) -> bool:
        addr = ipaddress.ip_address(ip)
        if self.kind == "any":
            return True
        if self.kind == "not-vnet":
            return not any(addr in ipaddress.ip_network(c) for c in vnet)
        return any(addr in ipaddress.ip_network(c) for c in self.cidrs)


def vnet_cidrs(lab: Lab) -> list[str]:
    """The VirtualNetwork tag: every segment that is not the edge."""
    return [n.cidr for n in sorted(lab.networks.values(), key=lambda x: x.id) if not n.wan]


def resolve(lab: Lab, text: str) -> Endpoint:
    """An address, a CIDR, a segment id, a machine id, a tag, or a comma-separated
    mix of those."""
    text = (text or TAG_ANY).strip().replace(" ", "")
    if text in (TAG_ANY, "*"):
        return Endpoint(TAG_ANY, "any")
    if text == TAG_VNET:
        return Endpoint(TAG_VNET, "cidrs", vnet_cidrs(lab))
    if text == TAG_INTERNET:
        return Endpoint(TAG_INTERNET, "not-vnet")
    cidrs: list[str] = []
    for part in text.split(","):
        if not part:
            continue
        if part in lab.networks:
            cidrs.append(lab.networks[part].cidr)
            continue
        part = naming.resolve(lab, part)
        if part in lab.nodes:
            ips = [nic.ip for nic in lab.nodes[part].nics if nic.ip]
            if not ips:
                raise FirewallError(
                    f"machine '{part}' takes its address from DHCP, so a rule cannot name it; "
                    f"use its segment or an address")
            cidrs.extend(f"{ip}/32" for ip in ips)
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            raise FirewallError(
                f"'{part}' is not an address, a CIDR, a segment, a machine, or one of "
                f"{', '.join(TAGS)}") from None
        cidrs.append(str(net))
    if not cidrs:
        raise FirewallError("an empty source or destination")
    return Endpoint(text, "cidrs", cidrs)


def parse_ports(text: str) -> list[tuple[int, int]]:
    """'*' -> [], '80,443' -> [(80,80),(443,443)], '1000-2000' -> [(1000,2000)]."""
    text = (text or "*").strip().replace(" ", "")
    if text in ("*", "any", "Any"):
        return []
    out = []
    for part in text.split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        try:
            a = int(lo)
            b = int(hi) if hi else a
        except ValueError:
            raise FirewallError(f"'{part}' is not a port or a range like 1000-2000") from None
        if not (1 <= a <= 65535 and 1 <= b <= 65535 and a <= b):
            raise FirewallError(f"port range '{part}' is outside 1-65535")
        out.append((a, b))
    if not out:
        raise FirewallError("an empty port list")
    return out


def _port_in(port: int, ranges: list[tuple[int, int]]) -> bool:
    return not ranges or any(lo <= port <= hi for lo, hi in ranges)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def _rule_errors(lab: Lab, rule: FirewallRule, others: list[FirewallRule]) -> list[str]:
    errs: list[str] = []
    tag = f"rule '{rule.name}'"
    if not NAME.match(rule.name or ""):
        errs.append(f"firewall rule name {rule.name!r}: letters, digits, '.', '_' and '-', "
                    f"starting with a letter, at most 64")
    if not PRIORITY_MIN <= rule.priority <= PRIORITY_MAX:
        errs.append(f"{tag}: priority is {PRIORITY_MIN} to {PRIORITY_MAX}, got {rule.priority}")
    if rule.direction not in DIRECTIONS:
        errs.append(f"{tag}: direction is inbound or outbound, got {rule.direction!r}")
    if rule.action not in ACTIONS:
        errs.append(f"{tag}: action is Allow or Deny, got {rule.action!r}")
    if rule.protocol not in PROTOCOLS:
        errs.append(f"{tag}: protocol is Any, Tcp, Udp or Icmp, got {rule.protocol!r}")
    if not rule.segment:
        errs.append(f"{tag}: names no segment; a rule attaches to one segment's table")
    elif rule.segment not in lab.networks:
        errs.append(f"{tag}: segment {rule.segment!r} is not in the lab")
    elif not has_tables(lab.networks[rule.segment]):
        errs.append(f"{tag}: {rule.segment} is the edge, which has no table (it plays the "
                    f"Internet); put the rule on the segment the traffic reaches, with "
                    f"source or destination Internet")
    for attr in ("source", "destination"):
        try:
            resolve(lab, getattr(rule, attr))
        except FirewallError as exc:
            errs.append(f"{tag}: {attr}: {exc}")
    try:
        parse_ports(rule.ports)
    except FirewallError as exc:
        errs.append(f"{tag}: ports: {exc}")
    for o in others:
        if o is rule:
            continue
        if o.name == rule.name and o.segment == rule.segment:
            errs.append(f"{tag}: a rule of that name is already on {rule.segment}")
            break
        if (o.segment == rule.segment and o.direction == rule.direction
                and o.priority == rule.priority):
            errs.append(f"{tag}: priority {rule.priority} is taken by '{o.name}' in the "
                        f"{rule.direction} table of {rule.segment}")
            break
    return errs


def validate(lab: Lab) -> list[str]:
    errs: list[str] = []
    seen: list[FirewallRule] = []
    for rule in lab.firewall.rules:
        normalise(rule)
        errs.extend(_rule_errors(lab, rule, seen))
        seen.append(rule)
    return errs


# --------------------------------------------------------------------------
# nftables rendering
# --------------------------------------------------------------------------


def chain_name(segment: str, direction: str) -> str:
    seg = re.sub(r"[^A-Za-z0-9_]", "_", segment)
    return f"nsg_{seg}_{'in' if direction == INBOUND else 'out'}"


def counter_name(rule: FirewallRule) -> str:
    return f"c_{chain_name(rule.segment, rule.direction)[4:]}_{rule.priority}"


def _nft_set(cidrs: list[str]) -> str:
    return "{ " + ", ".join(cidrs) + " }"


def _nft_match(lab: Lab, rule: FirewallRule) -> str:
    """The match part of one nft rule."""
    parts: list[str] = []
    vnet = vnet_cidrs(lab)
    for attr, key in (("source", "saddr"), ("destination", "daddr")):
        ep = resolve(lab, getattr(rule, attr))
        if ep.kind == "cidrs":
            parts.append(f"ip {key} {_nft_set(ep.cidrs)}")
        elif ep.kind == "not-vnet":
            if vnet:
                parts.append(f"ip {key} != {_nft_set(vnet)}")
    ranges = parse_ports(rule.ports)
    ports = ", ".join(f"{lo}-{hi}" if lo != hi else str(lo) for lo, hi in ranges)
    proto = rule.protocol
    if proto == "Icmp":
        parts.append("meta l4proto icmp")
    elif proto in ("Tcp", "Udp"):
        parts.append(f"{proto.lower()} dport {{ {ports} }}" if ports else f"meta l4proto {proto.lower()}")
    elif ports:
        parts.append(f"meta l4proto {{ tcp, udp }} th dport {{ {ports} }}")
    return " ".join(parts)


def nft_rule(lab: Lab, rule: FirewallRule) -> str:
    verdict = "accept" if rule.action == ALLOW else "drop"
    match = _nft_match(lab, rule)
    return (f"{match + ' ' if match else ''}counter name \"{counter_name(rule)}\" {verdict} "
            f"comment \"{rule.priority} {rule.name}\"")


def render_nft(lab: Lab, svi_of: dict[str, str]) -> list[str]:
    """The `nft -f` text for the whole table. `svi_of` maps a segment id to
    the router interface that serves it (lab0.<vid>)."""
    segs = [n for n in filtered_segments(lab) if n.id in svi_of]
    out = [f"table {TABLE} {{"]
    for net in segs:
        for direction in DIRECTIONS:
            for rule in rules_for(lab, net.id, direction):
                out.append(f"  counter {counter_name(rule)} {{ }}")
    out.append("  chain forward {")
    out.append("    type filter hook forward priority 0; policy accept;")
    out.append("    ct state established,related accept comment \"replies to allowed flows\"")
    for net in segs:
        out.append(f"    iifname \"{svi_of[net.id]}\" jump {chain_name(net.id, OUTBOUND)}"
                   f" comment \"leaving {net.id}\"")
    for net in segs:
        out.append(f"    oifname \"{svi_of[net.id]}\" jump {chain_name(net.id, INBOUND)}"
                   f" comment \"entering {net.id}\"")
    out.append("  }")
    for net in segs:
        for direction in DIRECTIONS:
            out.append(f"  chain {chain_name(net.id, direction)} {{")
            for rule in rules_for(lab, net.id, direction):
                out.append("    " + nft_rule(lab, rule))
            out.append("  }")
    out.append("}")
    return out


def live_script(lab: Lab, svi_of: dict[str, str], legacy: list[str]) -> str:
    """Replaces the running router's table in one go: what the fabric script
    would have rendered at boot, applied to a router that is already up.
    `legacy` is the firewall-off rendering (netplan._render_firewall)."""
    lines = [f"nft delete table {TABLE} 2>/dev/null || true"]
    if lab.firewall.enabled:
        lines += ["nft -f - <<'EOF'"] + render_nft(lab, svi_of) + ["EOF"]
    else:
        lines += [l for l in legacy if l and not l.startswith("#")]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Reading the running router
# --------------------------------------------------------------------------

_COUNTER = re.compile(r"counter\s+(\S+)\s*\{\s*packets\s+(\d+)\s+bytes\s+(\d+)", re.S)
_LIVE_RULE = re.compile(
    r"^\s*(?P<match>.*?)\s*counter(?: name \"(?P<cname>[^\"]*)\"| packets (?P<pk>\d+) bytes (?P<by>\d+))?"
    r"\s+(?P<verdict>accept|drop|reject)(?:\s+comment \"(?P<comment>[^\"]*)\")?"
    r"\s*(?:#\s*handle\s+(?P<handle>\d+))?\s*$")


def parse_counters(text: str) -> dict[str, tuple[int, int]]:
    """`nft list counters table inet winlab` -> {counter: (packets, bytes)}."""
    return {m.group(1): (int(m.group(2)), int(m.group(3))) for m in _COUNTER.finditer(text)}


def parse_live_chain(text: str) -> list[dict]:
    """`nft -a list chain inet winlab <chain>` -> the rules as the router has
    them, in evaluation order: what Azure calls the effective rules. Lines
    that are not rules (the chain header, braces) are skipped."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("table ", "chain ", "}", "type ")):
            continue
        m = _LIVE_RULE.match(s)
        if not m:
            continue
        comment = m.group("comment") or ""
        prio, _, name = comment.partition(" ")
        out.append({"match": m.group("match").strip() or "any", "verdict": m.group("verdict"),
                    "priority": int(prio) if prio.isdigit() else None, "name": name or comment,
                    "counter": m.group("cname") or "",
                    "packets": int(m.group("pk")) if m.group("pk") else None,
                    "handle": int(m.group("handle")) if m.group("handle") else None})
    return out


def read_live(run, lab: Lab) -> dict:
    """What the running router actually enforces. `run(cmd)` executes a shell
    command on the fabric and returns its output. Chains the lab defines but
    the router lacks come back as None (the firewall was off when it
    booted); rules the router has but the lab does not define (a fault, a
    hand edit) show up in `chains` and nowhere else, which is the point."""
    counters = parse_counters(run(f"nft list counters table {TABLE} 2>/dev/null") or "")
    chains: dict[str, list | None] = {}
    tables: list[dict] = []
    for net in filtered_segments(lab):
        for direction in DIRECTIONS:
            ch = chain_name(net.id, direction)
            out = run(f"nft -a list chain {TABLE} {ch} 2>/dev/null") or ""
            rules = parse_live_chain(out) if out.strip() else None
            chains[ch] = rules
            if rules is not None:
                defined = {(r.priority, r.name) for r in rules_for(lab, net.id, direction)}
                for r in rules:
                    r["defined"] = (r["priority"], r["name"]) in defined
                    if r["packets"] is None and r["counter"] in counters:
                        r["packets"] = counters[r["counter"]][0]
                tables.append({"segment": net.id, "direction": direction, "chain": ch,
                               "rules": rules})
    return {"present": bool(tables), "counters": counters, "hits": hits(lab, counters),
            "tables": tables}


def remove_live(run, lab: Lab, name: str) -> int:
    """Deletes every rule of that name from the running router's tables, by
    handle. Returns how many went."""
    n = 0
    for net in filtered_segments(lab):
        for direction in DIRECTIONS:
            ch = chain_name(net.id, direction)
            out = run(f"nft -a list chain {TABLE} {ch} 2>/dev/null") or ""
            for r in parse_live_chain(out):
                if r["name"] == name and r["handle"] is not None:
                    run(f"nft delete rule {TABLE} {ch} handle {r['handle']}")
                    n += 1
    return n


def hits(lab: Lab, counters: dict[str, tuple[int, int]]) -> list[dict]:
    """Every rule in every table with its packet and byte counts."""
    out = []
    for net in filtered_segments(lab):
        for direction in DIRECTIONS:
            for rule in rules_for(lab, net.id, direction):
                pk, by = counters.get(counter_name(rule), (0, 0))
                out.append({"segment": net.id, "direction": direction, "priority": rule.priority,
                            "name": rule.name, "action": rule.action, "builtin": rule.builtin,
                            "packets": pk, "bytes": by})
    return out


# --------------------------------------------------------------------------
# IP flow verify
# --------------------------------------------------------------------------


@dataclass
class Hop:
    segment: str
    direction: str
    rule: FirewallRule | None

    @property
    def allowed(self) -> bool:
        return self.rule is None or self.rule.action == ALLOW


@dataclass
class Verdict:
    allowed: bool
    reason: str
    source: str
    destination: str
    port: int
    protocol: str
    source_segment: str = ""
    destination_segment: str = ""
    via: str = ""             # the site-to-site tunnel the flow crosses, if any
    hops: list[Hop] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "reason": self.reason, "source": self.source,
                "destination": self.destination, "port": self.port, "protocol": self.protocol,
                "source_segment": self.source_segment,
                "destination_segment": self.destination_segment, "via": self.via,
                "hops": [{"segment": h.segment, "direction": h.direction,
                          "rule": h.rule.name if h.rule else "", "priority": h.rule.priority if h.rule else None,
                          "action": h.rule.action if h.rule else ALLOW, "allowed": h.allowed}
                         for h in self.hops]}


def address_of(lab: Lab, text: str) -> str:
    """A machine id (its first static address) or an address."""
    text = naming.resolve(lab, (text or "").strip())
    if text in lab.nodes:
        node = lab.nodes[text]
        for nic in node.nics:
            if nic.ip:
                return nic.ip
        # A DHCP client: stand in with the first address of its segment's
        # pool, which sits in the same subnet, so the same rules apply.
        if node.nics and node.nics[0].network in lab.networks:
            hosts = list(lab.networks[node.nics[0].network].net.hosts())
            return str(hosts[min(49, len(hosts) - 2)])
        raise FirewallError(f"'{text}' has no network adapter")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise FirewallError(f"'{text}' is neither a machine in the lab nor an address") from None


def segment_of(lab: Lab, ip: str) -> Network | None:
    addr = ipaddress.ip_address(ip)
    for net in lab.networks.values():
        if addr in net.net:
            return net
    return None


def _matches(lab: Lab, rule: FirewallRule, src: str, dst: str, port: int, proto: str) -> bool:
    vnet = vnet_cidrs(lab)
    if not resolve(lab, rule.source).contains(src, vnet):
        return False
    if not resolve(lab, rule.destination).contains(dst, vnet):
        return False
    if rule.protocol != "Any" and rule.protocol != proto:
        return False
    if proto == "Icmp":
        return True
    return _port_in(port, parse_ports(rule.ports))


def evaluate(lab: Lab, source: str, destination: str, port: int = 0, protocol: str = "Tcp") -> Verdict:
    """Would a new flow from `source` to `destination` pass the router, and
    which rule decides? Azure's IP flow verify, for the lab."""
    proto = normalise(FirewallRule("x", 100, protocol=protocol)).protocol
    if proto not in PROTOCOLS or proto == "Any":
        proto = "Tcp"
    src = address_of(lab, source)
    dst = address_of(lab, destination)
    s_net = segment_of(lab, src)
    d_net = segment_of(lab, dst)
    v = Verdict(True, "", src, dst, port, proto,
                s_net.id if s_net else TAG_INTERNET, d_net.id if d_net else TAG_INTERNET)
    if s_net and d_net and s_net.id == d_net.id:
        v.reason = (f"switched within {s_net.id}: both addresses share the VLAN, so the "
                    f"router never sees this flow; only the Windows firewall on "
                    f"{dst} applies")
        return v
    if s_net and d_net and s_net.site and d_net.site and s_net.site != d_net.site:
        from . import sites
        a, b = sites.gateway_of(lab, s_net.site), sites.gateway_of(lab, d_net.site)
        if a and b:
            v.via = (f"crosses the site-to-site tunnel {a.node.id} to {b.node.id} "
                     f"({s_net.site} to {d_net.site})")
        else:
            v.allowed = False
            v.reason = (f"unreachable: {s_net.site} and {d_net.site} are different sites and "
                        f"{'both' if not a and not b else (d_net.site if not b else s_net.site)} "
                        f"ha{'ve' if not a and not b else 's'} no gateway")
            return v
    if not lab.firewall.enabled:
        v.reason = "the zone firewall is off: the router forwards everything between segments"
        if v.via:
            v.reason += f"; {v.via}"
        return v
    if s_net and has_tables(s_net):
        v.hops.append(_decide(lab, s_net.id, OUTBOUND, src, dst, port, proto))
    if v.via:
        # Between sites the packet also enters the near gateway's segment
        # and, decapsulated, leaves the far gateway's segment, each with its
        # own tables (an NSG on a GatewaySubnet is unusual, but the router
        # enforces what the lab says, so Verify shows it).
        from . import sites
        a, b = sites.gateway_of(lab, s_net.site), sites.gateway_of(lab, d_net.site)
        for seg, direction in ((a.inside_network, INBOUND), (b.inside_network, OUTBOUND)):
            net = lab.networks[seg]
            if has_tables(net) and seg not in (s_net.id, d_net.id):
                v.hops.append(_decide(lab, seg, direction, src, dst, port, proto))
    if d_net and has_tables(d_net):
        v.hops.append(_decide(lab, d_net.id, INBOUND, src, dst, port, proto))
    for hop in v.hops:
        if not hop.allowed:
            v.allowed = False
            v.reason = (f"denied by {hop.rule.priority} {hop.rule.name} in the {hop.direction} "
                        f"table of {hop.segment}")
            if v.via:
                v.reason += f"; {v.via}"
            return v
    last = v.hops[-1] if v.hops else None
    if last and last.rule:
        v.reason = (f"allowed by {last.rule.priority} {last.rule.name} in the {last.direction} "
                    f"table of {last.segment}")
    else:
        v.reason = "allowed: no table applies"
    if v.via:
        v.reason += f"; {v.via}"
    return v


def _decide(lab: Lab, segment: str, direction: str, src: str, dst: str, port: int, proto: str) -> Hop:
    for rule in rules_for(lab, segment, direction):
        if _matches(lab, rule, src, dst, port, proto):
            return Hop(segment, direction, rule)
    return Hop(segment, direction, None)


# --------------------------------------------------------------------------
# Text
# --------------------------------------------------------------------------


def describe(lab: Lab) -> str:
    fw = lab.firewall
    lines = [f"zone firewall on the lab router: {'on' if fw.enabled else 'off'}"]
    if not fw.enabled:
        lines.append("  the router forwards everything between segments; "
                     f"'winlab fw {lab.name} on' turns the tables on")
    lines.append(f"  tags: Any = everything; VirtualNetwork = {', '.join(vnet_cidrs(lab)) or 'nothing'}; "
                 f"Internet = outside those")
    for net in filtered_segments(lab):
        for direction in DIRECTIONS:
            lines.append("")
            lines.append(f"{net.id} ({net.cidr}) {direction}")
            lines.append(f"  {'prio':<6}{'name':<26}{'source':<20}{'destination':<20}{'ports':<12}"
                         f"{'proto':<6}action")
            for r in rules_for(lab, net.id, direction):
                mark = "*" if r.builtin else " "
                lines.append(f" {mark}{r.priority:<6}{r.name:<26}{r.source:<20}{r.destination:<20}"
                             f"{r.ports:<12}{r.protocol:<6}{r.action}")
    lines.append("")
    edge = [n.id for n in lab.networks.values() if not has_tables(n)]
    if edge:
        lines.append(f"{', '.join(edge)}: the edge plays the Internet and has no table of its own")
    lines.append("* default rule; intra-VLAN traffic is switched and never reaches these tables")
    return "\n".join(lines)


def describe_verdict(v: Verdict) -> str:
    lines = [f"{v.source} ({v.source_segment}) -> {v.destination} ({v.destination_segment}) "
             f"{v.protocol}/{v.port if v.port else '*'}: {'ALLOWED' if v.allowed else 'DENIED'}"]
    for h in v.hops:
        if h.rule:
            lines.append(f"  {h.segment} {h.direction:<9} {h.rule.priority:<6} {h.rule.name:<26} {h.rule.action}")
        else:
            lines.append(f"  {h.segment} {h.direction:<9} no rule matched")
    lines.append(f"  {v.reason}")
    return "\n".join(lines)
