"""A branch office over a WAN link: the cable from a switch to the router
becomes a circuit with the delay, jitter, loss and bandwidth of a real one.

The switch (with every VLAN on it and every switch trunked below it) is
then a site of its own. Traffic between that site and the rest of the
network crosses the WAN in both directions: a ping from head office to the
branch over satellite takes 600 ms and loses some replies, a file copy is
held to the line's speed, while machines inside one site still talk at
full speed. Two branches reach each other over both their lines.

The router does it with Linux traffic control: on each gateway interface
(SVI) a prio qdisc whose extra bands hold netem, with u32 filters sending
the packets that come from another site through the band for that pair of
sites. The settings live in the lab's ``[devices."wan:<switch>"]`` table.
"""

from __future__ import annotations

from dataclasses import dataclass

PREFIX = "wan:"


@dataclass(frozen=True)
class Line:
    """One way across the circuit: what netem adds to each packet."""
    delay_ms: int = 0
    jitter_ms: int = 0
    loss_pct: float = 0.0
    rate_mbit: float = 0.0

    @property
    def active(self) -> bool:
        return bool(self.delay_ms or self.jitter_ms or self.loss_pct or self.rate_mbit)

    def plus(self, other: "Line") -> "Line":
        """Two circuits in a row: delays add, losses compound, the slower sets the speed."""
        rates = [r for r in (self.rate_mbit, other.rate_mbit) if r]
        return Line(self.delay_ms + other.delay_ms, self.jitter_ms + other.jitter_ms,
                    round(100 * (1 - (1 - self.loss_pct / 100) * (1 - other.loss_pct / 100)), 3),
                    min(rates) if rates else 0.0)

    def text(self) -> str:
        bits = []
        if self.delay_ms:
            bits.append(f"{self.delay_ms * 2} ms round trip" + (f" ±{self.jitter_ms}" if self.jitter_ms else ""))
        if self.loss_pct:
            bits.append(f"{self.loss_pct:g}% loss")
        if self.rate_mbit:
            bits.append(f"{self.rate_mbit:g} Mbit/s")
        return ", ".join(bits) or "no delay"


# One-way figures for the circuits an office meets.
PRESETS: dict[str, tuple[str, Line]] = {
    "fibre": ("Fibre (leased line)", Line(3, 0, 0.0, 100)),
    "dsl": ("Business DSL", Line(15, 3, 0.1, 20)),
    "4g": ("4G router", Line(35, 15, 0.5, 30)),
    "satellite": ("Satellite", Line(300, 10, 1.0, 10)),
    "poor": ("A bad line", Line(60, 30, 5.0, 2)),
}


class WanError(Exception):
    pass


def links(lab) -> dict[str, Line]:
    """Switch id -> its WAN line, for every switch on one."""
    out = {}
    for key, own in lab.devices.items():
        if key.startswith(PREFIX) and key[len(PREFIX):] in lab.networks:
            out[key[len(PREFIX):]] = Line(int(own.get("delay_ms") or 0), int(own.get("jitter_ms") or 0),
                                          float(own.get("loss_pct") or 0), float(own.get("rate_mbit") or 0))
    return out


def preset_of(lab, sw: str) -> str:
    return lab.devices.get(PREFIX + sw, {}).get("preset", "")


def set_link(lab, sw: str, preset: str = "", delay_ms=None, jitter_ms=None, loss_pct=None,
             rate_mbit=None) -> Line | None:
    """Put the switch's uplink on a WAN circuit (a preset, or the figures
    given), or back on a plain cable (preset "none")."""
    net = lab.networks.get(sw)
    if net is None or net.switch:
        raise WanError(f"no switch {sw!r} on the canvas")
    if preset == "none":
        lab.devices.pop(PREFIX + sw, None)
        return None
    if net.upstream:
        raise WanError(f"{sw} hangs off {net.upstream} by a trunk; a WAN circuit runs from a switch to the router")
    if preset:
        if preset not in PRESETS:
            raise WanError(f"no such circuit {preset!r}: one of {', '.join(PRESETS)}")
        line = PRESETS[preset][1]
    else:
        try:
            line = Line(int(delay_ms or 0), int(jitter_ms or 0), float(loss_pct or 0), float(rate_mbit or 0))
        except (TypeError, ValueError):
            raise WanError("delay and jitter are whole milliseconds, loss a percentage, speed Mbit/s") from None
    if not 0 <= line.delay_ms <= 2000 or not 0 <= line.jitter_ms <= 1000:
        raise WanError("a one-way delay is 0 to 2000 ms, jitter 0 to 1000 ms")
    if not 0 <= line.loss_pct <= 50:
        raise WanError("loss is 0 to 50%")
    if line.rate_mbit and not 0.064 <= line.rate_mbit <= 1000:
        raise WanError("a line's speed is 0.064 to 1000 Mbit/s (0 for no limit)")
    lab.devices[PREFIX + sw] = {"preset": preset, "delay_ms": str(line.delay_ms), "jitter_ms": str(line.jitter_ms),
                                "loss_pct": f"{line.loss_pct:g}", "rate_mbit": f"{line.rate_mbit:g}"}
    return line


def drop_switch(lab, sw: str) -> None:
    lab.devices.pop(PREFIX + sw, None)


def site_of(lab, net_id: str) -> str:
    """The switch on a WAN line that a network sits behind, or "" (head office)."""
    net = lab.networks.get(net_id)
    if net is None:
        return ""
    sw, seen = net.home, set()
    while lab.networks.get(sw) is not None and lab.networks[sw].upstream and sw not in seen:
        seen.add(sw)
        sw = lab.networks[sw].upstream
    return sw if sw in links(lab) else ""


def render(plan, reset: bool = False) -> list[str]:
    """The router's traffic-control script for the WAN lines: empty when
    there are none, unless ``reset`` (a running router whose last line was
    just taken away) asks for the gateways to be cleared."""
    lab = plan.lab
    lines = links(lab)
    if not lines and not reset:
        return []
    segs = [s for s in sorted(plan.segments.values(), key=lambda s: s.vid)
            if s.network.routed and not s.network.impair.active]  # a lab's own impairment stays
    if not segs:
        return []
    out = ["### WAN lines between sites (netem on the gateways, by source site)"]
    for seg in segs:
        out.append(f"tc qdisc del dev {seg.svi} root 2>/dev/null || true")
    if not lines:
        return out + [""]
    place = {s.network.id: site_of(lab, s.network.id) for s in segs}
    for seg in segs:
        here = place[seg.network.id]
        bands = []
        for there in sorted(set(place.values()) - {here}):
            line = lines.get(here, Line()).plus(lines.get(there, Line()))
            cidrs = [s.network.cidr for s in segs if place[s.network.id] == there]
            if line.active and cidrs:
                bands.append((there, line, cidrs))
        if not bands:
            continue
        dev = seg.svi
        # Bands 1-3 carry the site's own traffic as prio does by default;
        # the WAN bands after them take only what the filters send there.
        out.append(f"tc qdisc add dev {dev} root handle 1: prio bands {3 + len(bands)} "
                   "priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1")
        for k, (there, line, cidrs) in enumerate(bands, 4):
            netem = f"tc qdisc add dev {dev} parent 1:{k} handle {k}0: netem limit 10000"
            if line.delay_ms:
                netem += f" delay {line.delay_ms}ms"
                if line.jitter_ms:
                    netem += f" {line.jitter_ms}ms distribution normal"
            if line.loss_pct:
                netem += f" loss {line.loss_pct:g}%"
            if line.rate_mbit:
                netem += f" rate {line.rate_mbit:g}mbit"
            out.append(f"# into {seg.network.id} from {there or 'head office'}: {line.text()}")
            out.append(netem + " || true")
            for cidr in cidrs:
                out.append(f"tc filter add dev {dev} parent 1: protocol ip prio 1 u32 "
                           f"match ip src {cidr} flowid 1:{k} || true")
    return out + [""]
