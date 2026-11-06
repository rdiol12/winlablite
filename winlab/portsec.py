"""Port security and err-disabled ports on the workbench's switches.

A switch port normally takes frames from any address. Port security limits
a port to the addresses it knows: typed in (switchport port-security
mac-address <mac>), learnt from the first frames and written into the
configuration (sticky), or learnt and forgotten again (dynamic), up to a
maximum. A frame from any other address is a violation: dropped silently
(protect), dropped and counted and logged (restrict), or the port is
err-disabled (shutdown, the default), and stays so until shutdown / no
shutdown, or the errdisable recovery timer.

How it is real. Every machine's cable is a port of the router's bridge
(winlab/netplan.py, eth<N>). The rules are nftables' bridge family, the
switch's own layer, in one table (TABLE): per port a set of the addresses
it allows, sized to the maximum, which the kernel itself fills from the
frames that come in while there is room (that is learning), and a rule
that drops, counts and remembers what comes from any other. A port whose
addresses are all known also gets them as static entries in the bridge's
forwarding table, with learning off. Shutdown is the router's own watcher
(WATCH_SH): the moment a port's violation counter moves it sets the bridge
port disabled; the app then takes the machine's link down (QEMU's
set_link), as a real err-disabled port drops the link light, and writes it
in the switch's log (show logging). Sticky addresses the kernel learnt are
read back into the switch's configuration (show running-config).

Without the router running nothing moves: with no frames there is nothing
to learn or to violate. While it runs and cannot be read, the same verdicts
are worked out here (settle()) from what is plugged in and powered on.

A visitor's laptop is the rogue device: plugged into a desk port next to a
machine, through a desk switch, on the canvas. On the router it is a small
network namespace whose frames tc puts into the machine's port as if they
came up that cable (mirred ingress redirect), and that sends DHCP requests
like any laptop; the port's frames are copied back to it.

802.1X (winlab/dot1x.py) shares the table: until a RADIUS server says yes,
a port that runs it passes nothing but EAPOL.

The console's settings live with the switch's others in the lab file
([devices."sw:<id>"]): psec, psec-max, psec-sticky, psec-mac (typed),
psec-stuck (sticky), psec-viol, keyed by the cable in the port (as the
port's other settings are) or, for an empty port, by its name; psec-err and
visitor by the cable; errdis-cause and errdis-interval for the switch.
Counters, the log and what the kernel was last seen to say are runtime
state, in the lab's folder (portsec.json).
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
from dataclasses import dataclass, field

from . import devcli, dot1x, paths, state

TABLE = "winlab_port"
RUN = "/run/winlab-port"
VIOLATIONS = ("shutdown", "restrict", "protect")
MAX_ADDRS = 132           # a 2950's secure addresses on one port
RECOVERY = 300            # errdisable recovery interval, seconds
CAUSE = "psecure-violation"
CONF_FIELDS = ("psec", "psec-max", "psec-sticky", "psec-mac", "psec-stuck", "psec-viol", "dx-ctl", "dx-pae")
LOG_KEEP = 200
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_IF = re.compile(r"^[A-Za-z0-9]{1,12}$")


class PortSecError(Exception):
    pass


def norm_mac(text: str) -> str:
    """0050.5600.0101, 00:50:56:00:01:01 or 00-50-56-00-01-01 -> 00:50:56:00:01:01."""
    h = re.sub(r"[.:-]", "", text.strip().lower())
    if not re.fullmatch(r"[0-9a-f]{12}", h) or int(h[1], 16) & 1:
        raise devcli.CliError(f"% Invalid MAC address {text.strip()}: a unicast address, as 0050.5600.0101")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def _macs(v: str | None) -> list[str]:
    return [m for m in (v or "").split() if _MAC.match(m)]


def _own(lab, sw: str) -> dict:
    return lab.devices.get(f"sw:{sw}", {})


# ------------------------------------------------------------------ ports
@dataclass
class Port:
    sw: str
    no: int
    link: object
    key: str                  # where its settings are: the cable's label, or FastEthernet0/<no>
    on: bool = False
    maximum: int = 1
    sticky: bool = False
    macs: list[str] = field(default_factory=list)
    stuck: list[str] = field(default_factory=list)
    violation: str = "shutdown"
    err: str = ""             # the address that err-disabled it
    err_at: float = 0
    visitors: list[str] = field(default_factory=list)
    dx: str = ""              # 802.1X: "auto", "closed" or ""

    @property
    def name(self) -> str:
        return f"FastEthernet0/{self.no}"

    @property
    def short(self) -> str:
        return f"Fa0/{self.no}"

    @property
    def label(self) -> str:
        return self.link.label

    @property
    def iface(self) -> str:
        i = self.link.fabric_iface or ""
        return i if _IF.match(i) else ""

    @property
    def allowed(self) -> list[str]:
        return list(dict.fromkeys(self.macs + self.stuck))

    @property
    def secured(self) -> bool:
        return self.on or bool(self.dx)


def conf_key(own: dict, label: str, no: int) -> str:
    if any(f"{f}:{label}" in own for f in CONF_FIELDS):
        return label
    return f"FastEthernet0/{no}"


def _port(lab, sw: str, no: int, link) -> Port:
    own = _own(lab, sw)
    key = conf_key(own, link.label, no)
    try:
        mx = max(1, min(MAX_ADDRS, int(own.get(f"psec-max:{key}") or 1)))
    except ValueError:
        mx = 1
    err = own.get(f"psec-err:{link.label}", "").split()
    p = Port(sw, no, link, key, on=bool(own.get(f"psec:{key}")), maximum=mx,
             sticky=bool(own.get(f"psec-sticky:{key}")), macs=_macs(own.get(f"psec-mac:{key}")),
             stuck=_macs(own.get(f"psec-stuck:{key}")), violation=own.get(f"psec-viol:{key}") or "shutdown",
             err=err[0] if err else "", visitors=_macs(own.get(f"visitor:{link.label}")),
             dx=dot1x.enforced(lab, sw, key))
    if len(err) > 1:
        try:
            p.err_at = float(err[1])
        except ValueError:
            pass
    return p


def ports_of(lab, plan, sw: str) -> list[Port]:
    """Every machine port plugged into a switch, by its number there."""
    links = devcli.switch_ports(lab, plan).get(sw, [])
    return [_port(lab, sw, i, l) for i, l in enumerate(links, 1) if l is not None]


def all_ports(lab, plan) -> list[Port]:
    by = devcli.switch_ports(lab, plan)
    return [_port(lab, sw, i, l) for sw in sorted(by) for i, l in enumerate(by[sw], 1) if l is not None]


# ------------------------------------------------------------------ runtime state and the log
def _rt_path(lab_name: str):
    return paths.lab_dir(lab_name) / "portsec.json"


def runtime(lab_name: str) -> dict:
    try:
        d = json.loads(_rt_path(lab_name).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _rt_save(lab_name: str, d: dict) -> None:
    state.save_json(_rt_path(lab_name), d)


def _stamp(now: float | None = None) -> str:
    t = time.localtime(now or time.time())
    return time.strftime("*%b %d %H:%M:%S", t) + f".{int(((now or time.time()) % 1) * 1000):03d}"


def log(lab_name: str, device: str, lines: list[str], rt: dict | None = None, now: float | None = None,
        lab=None) -> None:
    """Into a device's log buffer, and with the lab at hand to its syslog
    servers too (winlab/nms.py: show logging, logging host)."""
    if not lines:
        return
    if lab is not None:
        from . import nms
        for text in lines:
            for x in text.split("\n"):
                if x.startswith("%"):
                    nms.device_log(lab, device, x)
    d = rt if rt is not None else runtime(lab_name)
    buf = d.setdefault("log", {}).setdefault(device, [])
    for text in lines:
        buf += [f"{_stamp(now)}: {x}" for x in text.split("\n") if x.startswith("%")]
    d["log"][device] = buf[-LOG_KEEP:]
    if rt is None:
        _rt_save(lab_name, d)


def _counts(rt: dict, label: str) -> int:
    return int(rt.get("count", {}).get(label, 0))


# ------------------------------------------------------------------ the verdicts
def _violation_lines(p: Port, mac: str) -> list[str]:
    s = p.short
    out = [f"%PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address "
           f"{devcli.dotted_mac(mac)} on port {p.name}."]
    if p.violation == "shutdown":
        out = [f"%PM-4-ERR_DISABLE: psecure-violation error detected on {s}, putting {s} in err-disable state"] + out
        out += [f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {p.name}, changed state to down",
                f"%LINK-3-UPDOWN: Interface {p.name}, changed state to down"]
    return out


def _err(lab, p: Port, mac: str, now: float, rt: dict, said: dict, links: list) -> None:
    own = lab.devices.setdefault(f"sw:{p.sw}", {})
    if own.get(f"psec-err:{p.label}"):
        return
    own[f"psec-err:{p.label}"] = f"{mac} {int(now)}"
    rt.setdefault("last", {})[p.label] = mac
    said.setdefault(p.sw, []).append("\n".join(_violation_lines(p, mac)))
    links.append((p.link, False))


def settle(lab, plan, running: set, live: dict | None = None, now: float | None = None) -> tuple[list[str], list, bool]:
    """What port security does with what reaches the ports, and the
    errdisable recovery timer: (what the switches say, [(link, up)] for the
    machines' links, whether the lab file changed). From the kernel's own
    sets and counters when `live` has them, else worked out here."""
    now = now or time.time()
    rt = runtime(lab.name)
    said: dict[str, list[str]] = {}
    links: list = []
    before = json.dumps({k: v for k, v in sorted(lab.devices.items())}, sort_keys=True)
    if "fabric" not in running:
        return [], [], False
    psec = (live or {}).get("psec")
    for p in all_ports(lab, plan):
        own = lab.devices.setdefault(f"sw:{p.sw}", {})
        # errdisable recovery: the port tries again after the interval
        if p.err and own.get(f"errdis-cause:{CAUSE}"):
            iv = int(own.get("errdis-interval") or RECOVERY)
            if now - (p.err_at or now) >= iv:
                own.pop(f"psec-err:{p.label}", None)
                for k in ("noted", "dyn"):
                    rt.get(k, {}).pop(p.label, None)
                said.setdefault(p.sw, []).append(
                    f"%PM-4-ERR_RECOVER: Attempting to recover from {CAUSE} err-disable state on {p.short}")
                links.append((p.link, True))
                p.err = ""
        if not p.on or p.err or own.get(f"shut:{p.label}"):
            continue
        if psec is not None and p.iface in psec.get("allowed", {}):
            _from_kernel(lab, p, psec, rt, now, said, links)
            continue
        if psec is not None and p.iface and p.iface in psec.get("err", {}):
            continue
        # Worked out: the machine speaks first (Windows chatters from boot),
        # then whatever came in with it, in the order it was plugged in.
        seen = ([p.link.mac.lower()] if p.link.node_id in running else []) + p.visitors
        known = p.allowed + [m for m in rt.get("dyn", {}).get(p.label, []) if m not in p.allowed]
        noted = rt.setdefault("noted", {}).setdefault(p.label, [])
        for mac in seen:
            if mac in known:
                continue
            if len(known) < p.maximum:
                known.append(mac)
                if p.sticky:
                    own[f"psec-stuck:{p.key}"] = " ".join(p.stuck + [mac])
                    p.stuck.append(mac)
                else:
                    rt.setdefault("dyn", {}).setdefault(p.label, []).append(mac)
                continue
            if p.violation == "protect" or (mac in noted and p.violation == "restrict"):
                continue
            noted.append(mac)
            rt.setdefault("count", {})[p.label] = _counts(rt, p.label) + 1
            rt.setdefault("last", {})[p.label] = mac
            if p.violation == "shutdown":
                _err(lab, p, mac, now, rt, said, links)
                break
            said.setdefault(p.sw, []).append(_violation_lines(p, mac)[0])
    if live is not None:
        _events(lab, plan, live.get("events", []), rt, said)
    for sw, lines in said.items():
        log(lab.name, f"sw:{sw}", lines, rt, now, lab=lab)
    _rt_save(lab.name, rt)
    after = json.dumps({k: v for k, v in sorted(lab.devices.items())}, sort_keys=True)
    flat = [f"{devcli.hostname(lab, 'sw:' + sw)}: {x}" for sw, xs in said.items() for x in xs]
    return flat, links, before != after


def _from_kernel(lab, p: Port, psec: dict, rt: dict, now: float, said: dict, links: list) -> None:
    """The kernel's set of the port's addresses, its violation counter and
    the router's watcher: the truth while the router runs."""
    own = lab.devices.setdefault(f"sw:{p.sw}", {})
    i = p.iface
    have = psec["allowed"].get(i, [])
    new = [m for m in have if m not in p.allowed]
    if p.sticky and new:
        own[f"psec-stuck:{p.key}"] = " ".join(p.stuck + new)
    else:
        rt.setdefault("dyn", {})[p.label] = new
    c = int(psec.get("count", {}).get(i, 0))
    gen = psec.get("gen", "")
    kc = rt.setdefault("kc", {})
    base = kc.get(p.label, [gen, 0])
    was = int(base[1]) if base[0] == gen else 0
    kc[p.label] = [gen, c]
    bad = [m for m in psec.get("bad", {}).get(i, []) if m not in have]
    if c > was and p.violation != "protect":
        rt.setdefault("count", {})[p.label] = _counts(rt, p.label) + c - was
        if bad:
            rt.setdefault("last", {})[p.label] = bad[0]
        if p.violation == "restrict":
            said.setdefault(p.sw, []).append(_violation_lines(p, bad[0] if bad else "00:00:00:00:00:00")[0])
    if i in psec.get("err", {}) or (c > was and p.violation == "shutdown"):
        _err(lab, p, psec.get("err", {}).get(i) or (bad[0] if bad else "00:00:00:00:00:00"), now, rt, said, links)


_EVENT_TEXT = {
    "CTRL-EVENT-EAP-SUCCESS2": "%DOT1X-5-SUCCESS: Authentication successful for client ({mac}) on Interface {port}",
    "AP-STA-CONNECTED": "%AUTHMGR-5-SUCCESS: Authorization succeeded for client ({mac}) on Interface {port}",
    "CTRL-EVENT-EAP-FAILURE2": "%DOT1X-5-FAIL: Authentication failed for client ({mac}) on Interface {port}",
    "AP-STA-DISCONNECTED": "%AUTHMGR-7-STOPPING: Stopping 'dot1x' for client ({mac}) on Interface {port}",
}


def _events(lab, plan, events: list[str], rt: dict, said: dict) -> None:
    """hostapd's events on the router (dot1x.ACT_SH) into the switches' logs,
    each once."""
    if not events:
        return
    last = rt.get("event", "")
    start = 0
    if last in events:
        start = len(events) - events[::-1].index(last)
    else:
        try:
            t0 = int(last.split()[0]) if last else 0
        except ValueError:
            t0 = 0
        start = next((k for k, e in enumerate(events) if int((e.split() or ["0"])[0] or 0) > t0), len(events))
    where = {p.iface: p for p in all_ports(lab, plan) if p.iface}
    for e in events[start:]:
        parts = e.split()
        if len(parts) < 3:
            continue
        if parts[2] == "hostapd-missing":
            for sw in sorted({p.sw for p in where.values() if p.dx}):
                said.setdefault(sw, []).append(f"%WINLAB-3-NO_AUTHENTICATOR: {dot1x.MISSING}")
            continue
        p = where.get(parts[1])
        fmt = _EVENT_TEXT.get(parts[2])
        if p is None or fmt is None or len(parts) < 4:
            continue
        said.setdefault(p.sw, []).append(fmt.format(mac=devcli.dotted_mac(parts[3]), port=p.short))
    rt["event"] = events[-1]


# ------------------------------------------------------------------ the router
WATCH_SH = """#!/bin/sh
# Port security's shutdown (winlab/portsec.py): the moment a port's
# violation counter moves, its bridge port is disabled: err-disabled.
R={run}
while :; do
  for p in {ports}; do
    [ -e $R/$p.err ] && continue
    n=$(nft list counter bridge {table} viol_$p 2>/dev/null | sed -n 's/.*packets \\([0-9]*\\).*/\\1/p')
    if [ "${{n:-0}}" -gt 0 ]; then
      bridge link set dev $p state 0
      nft list set bridge {table} bad_$p 2>/dev/null | tr -d '\\n\\t' | sed -n 's/.*elements = {{ *\\([0-9a-f:]*\\).*/\\1/p' > $R/$p.err
      echo "$(date +%s) $p psecure-violation $(cat $R/$p.err)" >> $R/events
    fi
  done
  sleep 1
done
"""


def render(plan, reset: bool = False) -> list[str]:
    """The ports' rules on the router: shell for its start script, or to
    build them again while it runs (reset)."""
    lab = plan.lab
    ps = [p for p in all_ports(lab, plan) if p.iface and (p.secured or p.visitors or p.err)]
    if not ps and not reset:
        return []
    out = ["### port security and 802.1X on the switches' access ports (winlab/portsec.py, winlab/dot1x.py)",
           f"mkdir -p {RUN}",
           f"[ -f {RUN}/watch.pid ] && kill $(cat {RUN}/watch.pid) 2>/dev/null; rm -f {RUN}/*.err {RUN}/watch.pid"]
    pre, post = dot1x.render(plan, ps, RUN, TABLE)
    out += pre
    out += [f"nft delete table bridge {TABLE} 2>/dev/null; true",
            "for n in $(ip netns list 2>/dev/null | grep -o '^wv[0-9]*'); do kill $(ip netns pids $n) 2>/dev/null; ip netns del $n; done; "
            "for i in $(ls /sys/class/net 2>/dev/null | grep '^wv'); do ip link del $i 2>/dev/null; done; true",
            "wl_port() { bridge link set dev $1 learning on state 3 2>/dev/null; tc qdisc del dev $1 clsact 2>/dev/null; "
            "bridge fdb show dev $1 2>/dev/null | awk '/ static/{print $1, $3}' | while read m v; do "
            "bridge fdb del $m dev $1 master vlan $v 2>/dev/null; done; true; }"]
    out += [f"wl_port {l.fabric_iface}" for l in plan.ports if _IF.match(l.fabric_iface or "")]
    sets, rules = [], []
    for p in ps:
        i, tag = p.iface, f"   # {devcli.hostname(lab, 'sw:' + p.sw)} {p.short} ({p.label})"
        if p.dx:
            sets.append(f"  set dx_{i} {{ type ether_addr; }}{tag}: let in by 802.1X")
            rules.append(f"    iifname \"{i}\" ether type 0x888e accept")
        if p.on:
            known = p.allowed[:p.maximum]
            el = f" elements = {{ {', '.join(known)} }};" if known else ""
            sets += [f"  set ok_{i} {{ type ether_addr; size {p.maximum}; flags dynamic;{el} }}{tag}: allowed",
                     f"  set bad_{i} {{ type ether_addr; size 16; flags dynamic; }}",
                     f"  counter viol_{i} {{ }}"]
            if len(known) < p.maximum:
                rules.append(f"    iifname \"{i}\" ether saddr != @ok_{i} add @ok_{i} {{ ether saddr }}")
            if p.violation == "protect":
                rules.append(f"    iifname \"{i}\" ether saddr != @ok_{i} drop")
            else:
                rules.append(f"    iifname \"{i}\" ether saddr != @ok_{i} add @bad_{i} {{ ether saddr }} "
                             f"counter name viol_{i} drop")
        if p.dx:
            rules.append(f"    iifname \"{i}\" ether saddr != @dx_{i} drop")
    if sets:
        out += [f"nft -f - <<'WINLAB_EOF'", f"table bridge {TABLE} {{", *sets, "  chain ports {",
                "    type filter hook prerouting priority -200; policy accept;", *rules, "  }", "}", "WINLAB_EOF"]
    for p in ps:
        i = p.iface
        if p.err:
            out.append(f"bridge link set dev {i} state 0   # {p.short} err-disabled ({CAUSE})")
        elif p.on and not p.dx and len(p.allowed) >= p.maximum:
            vid = plan.vid_of(p.link)
            out += [f"bridge fdb replace {m} dev {i} master static vlan {vid}" for m in p.allowed[:p.maximum]]
            out.append(f"bridge link set dev {i} learning off   # {p.short}: every address it allows is known")
    for k, (p, mac) in enumerate(((p, m) for p in ps for m in p.visitors), 1):
        n, i = f"wv{k}", p.iface
        out += [f"# a visitor's laptop on {p.short}, through a desk switch next to {p.link.node_id}: "
                f"{devcli.dotted_mac(mac)}",
                f"ip netns add {n}", f"ip link add {n}h type veth peer name {n}l netns {n}",
                f"ip netns exec {n} ip link set {n}l address {mac}", f"ip netns exec {n} ip link set lo up",
                f"ip netns exec {n} ip link set {n}l up", f"ip link set {n}h up",
                f"tc qdisc add dev {n}h ingress",
                f"tc filter add dev {n}h parent ffff: protocol all u32 match u32 0 0 action mirred ingress redirect dev {i}",
                f"tc qdisc add dev {i} clsact 2>/dev/null; true",
                f"tc filter add dev {i} egress protocol all u32 match u32 0 0 action mirred egress mirror dev {n}h",
                f"ip netns exec {n} setsid sh -c 'while :; do udhcpc -i {n}l -n -q -t 2 -T 2 -s /bin/true "
                f"-x hostname:visitor >/dev/null 2>&1; sleep 8; done' >/dev/null 2>&1 </dev/null &"]
    watch = [p.iface for p in ps if p.on and p.violation == "shutdown" and not p.err]
    if watch:
        out += [f"cat > {RUN}/watch.sh <<'WINLAB_EOF'",
                WATCH_SH.format(run=RUN, ports=" ".join(watch), table=TABLE).rstrip("\n"), "WINLAB_EOF",
                f"chmod +x {RUN}/watch.sh",
                f"setsid {RUN}/watch.sh >/dev/null 2>&1 </dev/null & echo $! > {RUN}/watch.pid"]
    out += post
    gen = hashlib.sha256("\n".join(out).encode()).hexdigest()[:12]
    out += [f"echo {gen} > {RUN}/gen", ""]
    return out


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


def live_cmd(plan) -> str:
    dx = [p.iface for p in all_ports(plan.lab, plan) if p.iface and p.dx]
    return (f"echo '#gen'; cat {RUN}/gen 2>/dev/null; echo '#nft'; nft list table bridge {TABLE} 2>/dev/null; "
            f"echo '#err'; for f in {RUN}/*.err; do [ -e \"$f\" ] && echo \"$(basename $f .err) $(cat $f)\"; done; "
            f"echo '#events'; tail -n 60 {RUN}/events 2>/dev/null; " + dot1x.live_cmd(dx) + "echo '#end'")


def parse_live(text: str) -> dict:
    """live_cmd's answer: {"psec": {"gen", "allowed": {iface: [mac]}, "bad",
    "count": {iface: n}, "err": {iface: mac}}, "events": [...], "dot1x": {...}}."""
    sec, buf = "", {"gen": [], "nft": [], "err": [], "events": [], "dx": []}
    for line in (text or "").splitlines():
        m = re.match(r"^#(gen|nft|err|events|end)$", line.strip())
        if m:
            sec = m.group(1)
            continue
        if line.startswith("#sta ") or line.startswith("#mib "):
            sec = "dx"
        if sec in buf:
            buf[sec].append(line)
    nft = "\n".join(buf["nft"])
    allowed, bad, count = {}, {}, {}
    for m in re.finditer(r"set (ok|bad)_(\w+) \{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", nft):
        macs = re.findall(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", m.group(3))
        (allowed if m.group(1) == "ok" else bad)[m.group(2)] = macs
    for m in re.finditer(r"counter viol_(\w+) \{\s*packets (\d+)", nft):
        count[m.group(1)] = int(m.group(2))
    err = {}
    for line in buf["err"]:
        parts = line.split()
        if parts:
            err[parts[0]] = parts[1] if len(parts) > 1 and _MAC.match(parts[1]) else "00:00:00:00:00:00"
    out = {"events": [e.strip() for e in buf["events"] if e.strip()], "dot1x": dot1x.parse("\n".join(buf["dx"]))}
    if nft.strip() or err:
        out["psec"] = {"gen": "".join(buf["gen"]).strip(), "allowed": allowed, "bad": bad, "count": count, "err": err}
    return out


# ------------------------------------------------------------------ the machines' links
def _set_link(lab, link, up: bool) -> None:
    from . import physfaults, state
    if up and any(r["kind"] == "nic" for r in physfaults.active(lab.name, link=link.label)):
        return
    st = state.load(lab.name)
    ns = st.nodes.get(link.node_id) if st else None
    if ns and ns.qmp_port and ns.pid and state.pid_alive(ns.pid):
        from . import livenet
        livenet.set_link(ns.qmp_port, link.nic_index, up)


def _apply(lab, links: list, setter=None) -> None:
    for link, up in links:
        if up and devcli.held_down(lab, link):
            continue
        (setter or (lambda l, u: _set_link(lab, l, u)))(link, up)


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    E = ("enable",)
    add("switchport port-security", lambda a: _on(con, True), "Security related command", I)
    add("no switchport port-security", lambda a: _on(con, False), "Negate a command or set its defaults", I)
    add("switchport port-security maximum <num>", lambda a: _maximum(con, a[0]), "Max secure addresses", I)
    add("no switchport port-security maximum", lambda a: _maximum(con, ""), "Negate a command or set its defaults", I)
    add("switchport port-security mac-address <line>", lambda a: _mac(con, a[0], True), "Secure mac address", I)
    add("no switchport port-security mac-address <line>", lambda a: _mac(con, a[0], False),
        "Negate a command or set its defaults", I)
    add("switchport port-security violation <line>", lambda a: _violation(con, a[0]), "Security violation mode", I)
    add("no switchport port-security violation", lambda a: _violation(con, ""), "Negate a command or set its defaults", I)
    add("errdisable recovery cause <line>", lambda a: _cause(con, a[0], True), "Enable error disable recovery for application", C)
    add("no errdisable recovery cause <line>", lambda a: _cause(con, a[0], False), "Negate a command or set its defaults", C)
    add("errdisable recovery interval <num>", lambda a: _interval(con, a[0]), "Error disable recovery timer value", C)
    add("no errdisable recovery interval", lambda a: _interval(con, ""), "Negate a command or set its defaults", C)
    add("show port-security", lambda a: show(con), "Show secure port information", U)
    add("show port-security interface <line>", lambda a: show_iface(con, a[0]), "Show secure interface", U)
    add("show port-security address", lambda a: show_address(con), "Show secure address", U)
    add("show errdisable recovery", lambda a: show_recovery(con), "Error disable recovery", U)
    add("clear port-security <line>", lambda a: clear(con, a[0]), "Clear secure address", E)
    dot1x.add_specs(con, add, U, C, I)


def _sw(con) -> str:
    return devcli.switch_id(con.device)


def _mine(con) -> dict:
    return devcli.settings(con.lab, con.device)


def write_key(con) -> str:
    """The interface being configured, as its settings are kept: the cable
    in it (settings typed while it was empty come along), or its name."""
    ctx = con.s.ctx
    if not ctx.startswith("FastEthernet"):
        raise devcli.CliError("% Port security is for the ports machines are in (Fa0/1 to Fa0/24); the "
                              "gigabit ports are trunks")
    link = con._port_link()
    if link is None:
        return ctx
    own = _mine(con)
    for f in CONF_FIELDS:
        if f"{f}:{ctx}" in own and f"{f}:{link.label}" not in own:
            own[f"{f}:{link.label}"] = own.pop(f"{f}:{ctx}")
    return link.label


def _here(con) -> Port:
    key = write_key(con)
    no = int(con.s.ctx.rsplit("/", 1)[1])
    link = con._port_link()
    if link is not None:
        return _port(con.lab, _sw(con), no, link)

    class _Empty:
        label, node_id, fabric_iface, mac, nic_index = key, "", "", "", 0
    p = _port(con.lab, _sw(con), no, _Empty())
    p.key = key
    return p


def live_of(con) -> dict:
    """The running router's port rules and hostapd's sessions ({} when it is
    off or cannot be read)."""
    if not con.powered():
        return {}
    try:
        return parse_live(con._on_router(live_cmd(con.plan), timeout=20))
    except devcli.CliError:
        return {}


def done(con, live: bool = True) -> str:
    """Saves a change (and pushes it into the running router), after the
    kernel's learnt addresses are read back; what the switches log about it."""
    data = live_of(con) if live else {}
    said, links, _ = settle(con.lab, con.plan, con._running(), data or None)
    note = con._save(live=live)
    _apply(con.lab, links, con._set_link)
    return "\n".join(said + ([note.strip()] if note.strip() else []))


def on_shutdown(con, link) -> str:
    """no shutdown on an access port: what brings an err-disabled port back
    (and what a rogue device still plugged in sends it straight back to)."""
    own = _mine(con)
    if not own.pop(f"psec-err:{link.label}", None):
        return ""
    rt = runtime(con.lab.name)
    for k in ("noted", "dyn"):
        rt.get(k, {}).pop(link.label, None)
    _rt_save(con.lab.name, rt)
    log(con.lab.name, con.device, [f"%LINK-3-UPDOWN: Interface {con.s.ctx}, changed state to up"])  # winlab/nms.py logs the link coming up itself
    out = done(con)
    return "\n" + out if out else ""


def _int(n: str) -> int:
    try:
        return int(n)
    except ValueError:
        raise devcli.CliError(f"% Invalid input: {n} is not a number") from None


def _on(con, on: bool) -> str:
    key = write_key(con)
    if on:
        _mine(con)[f"psec:{key}"] = "yes"
    else:
        _mine(con).pop(f"psec:{key}", None)
    return done(con)


def _maximum(con, n: str) -> str:
    p = _here(con)
    own = _mine(con)
    if not n:
        own.pop(f"psec-max:{p.key}", None)
        return done(con)
    v = _int(n)
    if not 1 <= v <= MAX_ADDRS:
        raise devcli.CliError(f"% Maximum secure addresses: 1 to {MAX_ADDRS}")
    if v < len(p.allowed):
        raise devcli.CliError(f"Maximum is less than number of currently secured mac-addresses on {p.name}")
    own[f"psec-max:{p.key}"] = str(v)
    return done(con)


def _mac(con, text: str, add: bool) -> str:
    p = _here(con)
    own = _mine(con)
    w = text.split()
    if not w:
        raise devcli.CliError("% Incomplete command.")
    sticky = w[0].lower() == "sticky" or (len(w[0]) > 1 and "sticky".startswith(w[0].lower()) and not
                                          re.fullmatch(r"[0-9a-fA-F.:-]+", w[0]))
    if sticky and len(w) == 1:
        if add:
            own[f"psec-sticky:{p.key}"] = "yes"
            # what the port learnt so far becomes sticky, as on IOS
            rt = runtime(con.lab.name)
            dyn = [m for m in rt.get("dyn", {}).pop(p.label, []) if m not in p.allowed]
            if dyn:
                own[f"psec-stuck:{p.key}"] = " ".join(p.stuck + dyn)
                _rt_save(con.lab.name, rt)
        else:
            own.pop(f"psec-sticky:{p.key}", None)
            own.pop(f"psec-stuck:{p.key}", None)   # sticky addresses become dynamic ones, and go with the link
        return done(con)
    mac = norm_mac(w[-1])
    field_ = "psec-stuck" if sticky else "psec-mac"
    have = _macs(own.get(f"{field_}:{p.key}"))
    if add:
        if mac in p.allowed:
            return ""
        if len(p.allowed) >= p.maximum:
            raise devcli.CliError(f"Total secure mac-addresses on interface {p.name} has reached maximum limit.")
        if sticky and not p.sticky:
            raise devcli.CliError("% Turn sticky learning on first: switchport port-security mac-address sticky")
        own[f"{field_}:{p.key}"] = " ".join(have + [mac])
    else:
        if mac not in have:
            raise devcli.CliError(f"% {devcli.dotted_mac(mac)} is not a {'sticky' if sticky else 'configured'} "
                                  f"address on {p.short}")
        have.remove(mac)
        if have:
            own[f"{field_}:{p.key}"] = " ".join(have)
        else:
            own.pop(f"{field_}:{p.key}", None)
    return done(con)


def _violation(con, how: str) -> str:
    p = _here(con)
    own = _mine(con)
    how = how.strip().lower()
    if not how:
        own.pop(f"psec-viol:{p.key}", None)
        return done(con)
    hit = [v for v in VIOLATIONS if v.startswith(how)]
    if len(hit) != 1:
        raise devcli.CliError("% Invalid input: switchport port-security violation protect | restrict | shutdown")
    if hit[0] == "shutdown":
        own.pop(f"psec-viol:{p.key}", None)
    else:
        own[f"psec-viol:{p.key}"] = hit[0]
    return done(con)


def _cause(con, what: str, on: bool) -> str:
    w = what.strip().lower()
    if w == "bpduguard":
        raise devcli.CliError("% Only psecure-violation recovers on a timer in this switch; a BPDU guard "
                              "port comes back with shutdown, then no shutdown")
    if w not in (CAUSE, "all"):
        raise devcli.CliError(f"% Invalid input: errdisable recovery cause {CAUSE} | all")
    if on:
        _mine(con)[f"errdis-cause:{CAUSE}"] = "yes"
    else:
        _mine(con).pop(f"errdis-cause:{CAUSE}", None)
    out = done(con)
    if w == "all":
        out = (out + "\n" if out else "") + f"% Recovery on for {CAUSE}, the only cause with a timer in this switch"
    return out


def _interval(con, n: str) -> str:
    if not n:
        _mine(con).pop("errdis-interval", None)
        return done(con)
    v = _int(n)
    if not 30 <= v <= 86400:
        raise devcli.CliError("% Recovery interval: 30 to 86400 seconds")
    _mine(con)["errdis-interval"] = str(v)
    return done(con)


# ---- show
def _status(p: Port, con) -> str:
    if p.err:
        return "Secure-shutdown"
    if con.powered() and p.link.node_id in con._running():
        return "Secure-up"
    return "Secure-down"


def _sync_live(con) -> list[Port]:
    """Reads the router, settles what it says into the lab file, and gives
    the switch's ports as they are now."""
    data = live_of(con)
    _, links, changed = settle(con.lab, con.plan, con._running(), data or None)
    if changed:
        con._save()
        _apply(con.lab, links, con._set_link)
    return ports_of(con.lab, con.plan, _sw(con))


def show(con) -> str:
    rt_ports = [p for p in _sync_live(con) if p.on]
    rt = runtime(con.lab.name)
    out = ["Secure Port  MaxSecureAddr  CurrentAddr  SecurityViolation  Security Action",
           "                (Count)       (Count)          (Count)",
           "---------------------------------------------------------------------------"]
    for p in rt_ports:
        cur = len(p.allowed) + len(rt.get("dyn", {}).get(p.label, []))
        out.append(f"{p.short:>10}{p.maximum:>15}{min(cur, p.maximum):>13}{_counts(rt, p.label):>19}"
                   f"{p.violation.capitalize():>17}")
    out += ["---------------------------------------------------------------------------",
            f"Total Addresses in System (excluding one mac per port)     : "
            f"{sum(max(0, len(p.allowed) - 1) for p in rt_ports)}",
            "Max Addresses limit in System (excluding one mac per port) : 1024"]
    return "\n".join(out)


def show_iface(con, text: str) -> str:
    name = devcli.parse_if(text, con._if_names())
    ports = {p.name: p for p in _sync_live(con)}
    p = ports.get(name)
    rt = runtime(con.lab.name)
    if p is None or not p.on:
        return "\n".join([f"Port Security              : Disabled", f"Port Status                : Secure-down",
                          "Violation Mode             : Shutdown", "Maximum MAC Addresses      : 1",
                          "Total MAC Addresses        : 0", "Security Violation Count   : 0"])
    dyn = rt.get("dyn", {}).get(p.label, [])
    last = rt.get("last", {}).get(p.label) or (dyn[-1] if dyn else p.allowed[-1] if p.allowed else "")
    vlan = con.lab.networks[p.link.network_id].vlan_no if p.link.network_id in con.lab.networks else 1
    out = [f"Port Security              : Enabled", f"Port Status                : {_status(p, con)}",
           f"Violation Mode             : {p.violation.capitalize()}", "Aging Time                 : 0 mins",
           "Aging Type                 : Absolute", "SecureStatic Address Aging : Disabled",
           f"Maximum MAC Addresses      : {p.maximum}",
           f"Total MAC Addresses        : {min(p.maximum, len(p.allowed) + len(dyn))}",
           f"Configured MAC Addresses   : {len(p.macs)}", f"Sticky MAC Addresses       : {len(p.stuck)}",
           f"Last Source Address:Vlan   : {devcli.dotted_mac(last) + ':' + str(vlan) if last else '0000.0000.0000:0'}",
           f"Security Violation Count   : {_counts(rt, p.label)}"]
    if p.err:
        out.append(f"% err-disabled by {devcli.dotted_mac(p.err)}: shutdown, then no shutdown, brings it back"
                   + (" (or the errdisable recovery timer)" if _own(con.lab, p.sw).get(f"errdis-cause:{CAUSE}") else ""))
    return "\n".join(out)


def show_address(con) -> str:
    rt = runtime(con.lab.name)
    out = ["               Secure Mac Address Table",
           "-----------------------------------------------------------------------------",
           f"{'Vlan':<8}{'Mac Address':<18}{'Type':<30}{'Ports':<8}Remaining Age",
           f"{'':<67}(mins)", f"{'----':<8}{'-----------':<18}{'----':<30}{'-----':<8}-------------"]
    n = 0
    for p in _sync_live(con):
        if not p.on:
            continue
        vlan = con.lab.networks[p.link.network_id].vlan_no if p.link.network_id in con.lab.networks else 1
        rows = ([(m, "SecureConfigured") for m in p.macs] + [(m, "SecureSticky") for m in p.stuck if m not in p.macs]
                + [(m, "SecureDynamic") for m in rt.get("dyn", {}).get(p.label, []) if m not in p.allowed])
        for m, kind in rows[:p.maximum]:
            out.append(f"{vlan:>4}    {devcli.dotted_mac(m):<18}{kind:<30}{p.short:<8}-")
            n += 1
    out += ["-----------------------------------------------------------------------------",
            f"Total Addresses in System (excluding one mac per port)     : {max(0, n - 1)}",
            "Max Addresses limit in System (excluding one mac per port) : 1024"]
    return "\n".join(out)


def show_recovery(con) -> str:
    own = _mine(con)
    on = bool(own.get(f"errdis-cause:{CAUSE}"))
    iv = int(own.get("errdis-interval") or RECOVERY)
    out = ["ErrDisable Reason            Timer Status", "-----------------            --------------"]
    for cause in ("arp-inspection", "bpduguard", "dhcp-rate-limit", "link-flap", CAUSE, "security-violation"):
        out.append(f"{cause:<29}{'Enabled' if cause == CAUSE and on else 'Disabled'}")
    out += ["", f"Timer interval: {iv} seconds", "", "Interfaces that will be enabled at the next timeout:", ""]
    errs = [p for p in _sync_live(con) if p.err]
    if errs and on:
        out += ["Interface       Errdisable reason       Time left(sec)",
                "---------       -----------------       --------------"]
        now = time.time()
        out += [f"{p.short:<16}{CAUSE:<24}{max(0, int(iv - (now - (p.err_at or now)))):>14}" for p in errs]
    return "\n".join(out)


def show_logging(con) -> str:
    if con.powered():
        _sync_live(con)
    buf = runtime(con.lab.name).get("log", {}).get(con.device, [])
    return "\n".join(["Syslog logging: enabled (0 messages dropped, 0 messages rate-limited, 0 flushes, 0 overruns)",
                      "    Console logging: level debugging", f"    Buffer logging:  level debugging, {len(buf)} messages logged",
                      "", f"Log Buffer (4096 bytes):"] + buf)


def clear(con, text: str) -> str:
    """clear port-security {all | configured | dynamic | sticky} [interface <if>]."""
    w = text.split()
    kinds = ("all", "configured", "dynamic", "sticky")
    hit = [k for k in kinds if w and k.startswith(w[0].lower())]
    if len(hit) != 1:
        raise devcli.CliError("% Invalid input: clear port-security all | configured | dynamic | sticky "
                              "[interface <if>]")
    want = ""
    if len(w) > 1:
        if not "interface".startswith(w[1].lower()) or len(w) < 3:
            raise devcli.CliError("% Invalid input: clear port-security sticky interface fa0/1")
        want = devcli.parse_if(" ".join(w[2:]), con._if_names())
    own, rt = _mine(con), runtime(con.lab.name)
    for p in ports_of(con.lab, con.plan, _sw(con)):
        if want and p.name != want:
            continue
        if hit[0] in ("all", "configured"):
            own.pop(f"psec-mac:{p.key}", None)
        if hit[0] in ("all", "sticky"):
            own.pop(f"psec-stuck:{p.key}", None)
        if hit[0] in ("all", "dynamic"):
            rt.get("dyn", {}).pop(p.label, None)
        rt.get("noted", {}).pop(p.label, None)
    _rt_save(con.lab.name, rt)
    return done(con)


def run_lines(lab, sw: str) -> list[str]:
    own = _own(lab, sw)
    out = []
    if own.get(f"errdis-cause:{CAUSE}"):
        out.append(f"errdisable recovery cause {CAUSE}")
    if own.get("errdis-interval"):
        out.append(f"errdisable recovery interval {own['errdis-interval']}")
    return (out + ["!"] if out else []) + dot1x.run_lines(lab, sw)


def iface_lines(lab, sw: str, key: str) -> list[str]:
    """Port security and 802.1X lines under an access port in show
    running-config."""
    own, out = _own(lab, sw), []
    if own.get(f"psec-max:{key}"):
        out.append(f" switchport port-security maximum {own[f'psec-max:{key}']}")
    if own.get(f"psec-viol:{key}"):
        out.append(f" switchport port-security violation {own[f'psec-viol:{key}']}")
    if own.get(f"psec-sticky:{key}"):
        out.append(" switchport port-security mac-address sticky")
    out += [f" switchport port-security mac-address sticky {devcli.dotted_mac(m)}"
            for m in _macs(own.get(f"psec-stuck:{key}"))]
    out += [f" switchport port-security mac-address {devcli.dotted_mac(m)}" for m in _macs(own.get(f"psec-mac:{key}"))]
    if own.get(f"psec:{key}"):
        out.append(" switchport port-security")
    return out + dot1x.iface_lines(lab, sw, key)


# ------------------------------------------------------------------ the canvas
def view(lab, plan) -> dict:
    """Per switch, its ports that port security or 802.1X guard, or that a
    visitor's laptop is plugged into: what the canvas marks and the port
    panel lists."""
    rt = runtime(lab.name)
    rows = []
    for p in all_ports(lab, plan):
        if not (p.secured or p.visitors or p.err):
            continue
        rows.append({"sw": p.sw, "port": p.short, "slot": p.no - 1, "label": p.label, "node": p.link.node_id,
                     "on": p.on, "max": p.maximum, "sticky": p.sticky, "violation": p.violation,
                     "macs": [devcli.dotted_mac(m) for m in p.macs],
                     "stuck": [devcli.dotted_mac(m) for m in p.stuck],
                     "count": _counts(rt, p.label), "err": devcli.dotted_mac(p.err) if p.err else "",
                     "last": devcli.dotted_mac(rt["last"][p.label]) if rt.get("last", {}).get(p.label) else "",
                     "dot1x": p.dx, "iface": p.iface,
                     "visitors": [devcli.dotted_mac(m) for m in p.visitors]})
    d = drill_state(lab.name)
    drill = None
    if d:
        k = DRILLS[d["id"]]
        drill = {"id": k.id, "shown": int(d.get("hints", 0)), "of": len(k.hints),
                 "hints": [h.format(**_words(lab, d)) for h in k.hints[:int(d.get("hints", 0))]],
                 "symptom": k.symptom.format(**_words(lab, d)), "done": bool(d.get("done")),
                 "title": k.title if d.get("done") else "", "fix": k.fix if d.get("done") else ""}
    return {"ports": rows, "drill": drill}


# ------------------------------------------------------------------ actions
def act(dash, action: str, params: dict) -> dict:
    try:
        if action == "wb-psec-visitor":
            return visitor(dash, str(params.get("node", "")), int(params.get("nic", 0) or 0),
                           str(params.get("op", "plug")))
        if action == "wb-psec-live":
            return live(dash)
        if action == "wb-psec-drill":
            return drill(dash, str(params.get("op", "")), params)
    except PortSecError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown port-security action {action!r}"}


def _link_of(dash, node: str, nic: int):
    for l in dash.plan.ports_for(node):
        if l.nic_index == nic:
            if not l.plugged:
                raise PortSecError(f"{node}'s port {nic + 1} has no cable to a switch")
            return l
    raise PortSecError(f"no machine port {node}:{nic}")


def _settle_save(dash, data: dict | None = None) -> list[str]:
    from .workbench import _running, _save
    said, links, changed = settle(dash.lab, dash.plan, _running(dash.lab.name), data)
    if changed:
        _save(dash)
    _apply(dash.lab, links)
    return said


def visitor(dash, node: str, nic: int, op: str) -> dict:
    """A visitor's laptop into the desk port next to a machine (through a
    desk switch), or out of it again."""
    from .workbench import _save, _sync
    lab = dash.lab
    link = _link_of(dash, node, nic)
    sw = lab.networks[link.network_id].home
    own = lab.devices.setdefault(f"sw:{sw}", {})
    have = _macs(own.get(f"visitor:{link.label}"))
    if op == "pull":
        if not have:
            raise PortSecError("no visitor's laptop on that port")
        own.pop(f"visitor:{link.label}", None)
        _save(dash)
        return {"ok": True, "message": f"the visitor's laptop is out of {node}'s desk port{_sync(dash)}"}
    if len(have) >= 2:
        raise PortSecError("two visitors' laptops on one desk port is enough")
    mac = "0a:%02x:%02x:%02x:%02x:%02x" % tuple(random.randrange(256) for _ in range(5))
    own[f"visitor:{link.label}"] = " ".join(have + [mac])
    _save(dash)
    said = _settle_save(dash)
    no = next((i for i, l in enumerate(devcli.switch_ports(dash.lab, dash.plan).get(sw, []), 1)
               if l is not None and l.label == link.label), 0)
    return {"ok": True, "message": f"a visitor's laptop ({devcli.dotted_mac(mac)}) is in {node}'s desk port, "
                                   f"through a desk switch: {devcli.hostname(lab, 'sw:' + sw)} Fa0/{no}"
                                   + "".join("; " + x.split("\n")[0] for x in said) + _sync(dash)}


def live(dash) -> dict:
    """The router's port rules and sessions, settled into the lab file: the
    canvas polls this while the router runs."""
    from .workbench import _running
    lab = dash.lab
    if "fabric" not in _running(lab.name):
        return {"ok": False, "message": "the router is off"}
    from .cli import _fabric_runner
    run, why = _fabric_runner(lab.name)
    if not run:
        return {"ok": False, "message": why}
    try:
        text = run(live_cmd(dash.plan), timeout=20)
    except Exception as exc:  # the serial channel: any failure is "not now"
        return {"ok": False, "message": str(exc)}
    finally:
        close = getattr(run, "close", None)
        if close:
            close()
    data = parse_live(text)
    before = json.dumps(view(dash.lab, dash.plan)["ports"], sort_keys=True)
    said = _settle_save(dash, data)
    sessions = {}
    for iface, d in data.get("dot1x", {}).items():
        sessions[iface] = [{"mac": devcli.dotted_mac(m), "state": dot1x.session_state(s)[0],
                            "why": dot1x.session_state(s)[1], "user": s.get("dot1xAuthSessionUserName", "")}
                           for m, s in sorted(d.get("sta", {}).items())]
    after = json.dumps(view(dash.lab, dash.plan)["ports"], sort_keys=True)
    return {"ok": True, "t": time.time(), "sessions": sessions, "said": said, "changed": before != after}


# ------------------------------------------------------------------ drills
# Graded faults in the manner of winlab/stp.py: put into the user's own
# network without a word, a hint ladder, Check my fix, Give up.
@dataclass(frozen=True)
class Drill:
    id: str
    title: str
    teaches: str
    symptom: str
    hints: tuple[str, ...]
    fix: str


DRILLS: dict[str, Drill] = {}


def _d(d: Drill) -> None:
    DRILLS[d.id] = d


_d(Drill("rogue", "A rogue device on a secured port",
         "what a port security violation looks like from the desk and from the console, finding the device "
         "by its address, and bringing an err-disabled port back without giving the port away",
         "{node} on {sw} has lost the network (or something else on its desk port is in the switch's log)",
         ("Start at the switch: show interfaces status and show port-security on {sw}. A port that is "
          "err-disabled, or a violation count that is not 0, is where to look.",
          "show port-security interface {port_long} names the last address that came in on it, and show "
          "logging has the PSECURE_VIOLATION line. That address is not {node}'s: something else is plugged "
          "in at that desk (on the canvas, next to {node}'s cable).",
          "Pull the visitor's laptop out (its menu on the canvas), check the sticky address on {port} is still "
          "{node}'s (show port-security address; clear port-security sticky interface {port} if the stranger "
          "got there first), then interface {port_long}, shutdown, no shutdown."),
         "the rogue device out, the port's sticky address the machine's own, then shutdown and no shutdown"))
_d(Drill("radius-key", "The switch's RADIUS key does not match the server's",
         "how a wrong shared key looks (no answer at all, rather than a reject), where each side records it, "
         "and why the switch retries",
         "{node} cannot get on the network: its port on {sw} never authorizes",
         ("show authentication sessions on {sw}: a session that stays Running, never Auth or Unauth, means "
          "the switch asks and nobody answers.",
          "show radius server-group all counts requests and timeouts and no challenges. On the server, the "
          "event log says why it dropped them: NPS logs event 18 (a Message-Authenticator that is not valid), "
          "FreeRADIUS says the shared secret is incorrect.",
          "The key under radius server {server} on {sw} is not the one the server has for this RADIUS client. "
          "configure terminal, radius server {server}, key <the server's key>."),
         "the switch's key back to the one the RADIUS server has for it"))


def _drill_path(lab_name: str):
    return paths.lab_dir(lab_name) / "portsec-drill.json"


def drill_state(lab_name: str) -> dict | None:
    try:
        return json.loads(_drill_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _drill_save(lab_name: str, data: dict | None) -> None:
    state.save_json(_drill_path(lab_name), data)


def _words(lab, d: dict) -> dict:
    from . import naming
    return {"sw": devcli.hostname(lab, f"sw:{d['sw']}"), "node": naming.display(lab, d.get("node", "")),
            "port": d.get("port", ""), "port_long": d.get("port", "").replace("Fa", "FastEthernet"),
            "server": d.get("server", "")}


def drill(dash, op: str, params: dict) -> dict:
    from .workbench import _save, _sync
    lab = dash.lab
    d = drill_state(lab.name)
    if op == "start":
        if d and not d.get("done"):
            raise PortSecError("a fault is already hidden in this network: find it, or give up")
        return _drill_start(dash, str(params.get("id") or "") or random.choice(sorted(DRILLS)))
    if not d:
        raise PortSecError("no port-security fault in this network")
    k = DRILLS[d["id"]]
    if op == "hint":
        d["hints"] = min(len(k.hints), int(d.get("hints", 0)) + 1)
        _drill_save(lab.name, d)
        return {"ok": True, "message": k.hints[d["hints"] - 1].format(**_words(lab, d))}
    if op == "check":
        res = check(dash, d)
        if res["passed"]:
            d["done"] = True
            _drill_save(lab.name, d)
        return res
    if op in ("undo", "close"):
        if op == "undo" and not d.get("done"):
            for k_, v in d.get("was", {}).items():
                sw, key = k_.split("|", 1)
                own = lab.devices.setdefault(f"sw:{sw}", {})
                if v is None:
                    own.pop(key, None)
                else:
                    own[key] = v
            _save(dash)
            _drill_save(lab.name, None)
            return {"ok": True, "message": f"put back: it was {k.title.lower()}{_sync(dash)}"}
        _drill_save(lab.name, None)
        return {"ok": True, "message": ""}
    raise PortSecError(f"unknown drill step {op!r}")


def _drill_start(dash, did: str) -> dict:
    from .workbench import _save, _sync
    lab, plan = dash.lab, dash.plan
    if did not in DRILLS:
        raise PortSecError(f"no drill {did!r}")
    was: dict = {}

    def put(sw, key, val):
        own = lab.devices.setdefault(f"sw:{sw}", {})
        was.setdefault(f"{sw}|{key}", own.get(key))
        if val is None:
            own.pop(key, None)
        else:
            own[key] = val
    if did == "rogue":
        cands = [p for p in all_ports(lab, plan) if p.on and not p.err and not p.visitors]
        if not cands:
            raise PortSecError("secure a port first: on a switch's console, interface fa0/1, switchport "
                               "port-security (and mac-address sticky)")
        p = random.choice(cands)
        mac = "0a:%02x:%02x:%02x:%02x:%02x" % tuple(random.randrange(256) for _ in range(5))
        put(p.sw, f"visitor:{p.label}", mac)
        put(p.sw, f"psec-err:{p.label}", None)   # the port as it was: whatever it is now is the drill's
        put(p.sw, f"psec-stuck:{p.key}", lab.devices[f"sw:{p.sw}"].get(f"psec-stuck:{p.key}"))
        info = {"sw": p.sw, "node": p.link.node_id, "port": p.short, "label": p.label, "key": p.key,
                "mac": mac, "own": p.link.mac.lower()}
    else:
        cands = [p for p in all_ports(lab, plan) if p.dx == "auto"]
        srv = [(p, s) for p in cands for s in dot1x.servers(lab, p.sw) if s["key"]]
        if not srv:
            raise PortSecError("set 802.1X up first: a RADIUS server with its key on the switch, and a port "
                               "with authentication port-control auto")
        p, s = random.choice(srv)
        bad = s["key"][:-1] + ("x" if not s["key"].endswith("x") else "y")
        put(p.sw, f"radius-key:{s['name']}", bad)
        info = {"sw": p.sw, "node": p.link.node_id, "port": p.short, "label": p.label, "server": s["name"],
                "key_sum": hashlib.sha256(s["key"].encode()).hexdigest()}
    _save(dash)
    _drill_save(lab.name, {"id": did, **info, "was": was, "hints": 0, "at": int(time.time())})
    _settle_save(dash)
    return {"ok": True, "message": "something on the switches' ports is broken; find it with the canvas and "
                                   "the consoles, then Check my fix" + _sync(dash)}


def check(dash, d: dict) -> dict:
    """Check my fix, from the lab file and, while the router runs, its
    hostapd sessions."""
    lab, plan = dash.lab, dash.plan
    w = _words(lab, d)
    rows = []
    if d["id"] == "rogue":
        own = _own(lab, d["sw"])
        p = next((x for x in all_ports(lab, plan) if x.label == d["label"]), None)
        rows.append(("the rogue device is out of the port", not own.get(f"visitor:{d['label']}")))
        rows.append((f"port security is still on on {w['port']}", bool(p and p.on)))
        rows.append((f"{w['port']} is no longer err-disabled", bool(p and not p.err)))
        rows.append((f"the stranger's address is not one {w['port']} allows",
                     bool(p and d["mac"] not in p.allowed)))
    else:
        s = next((x for x in dot1x.servers(lab, d["sw"]) if x["name"] == d["server"]), None)
        same = bool(s and hashlib.sha256(s["key"].encode()).hexdigest() == d["key_sum"])
        authed = False
        from .workbench import _running
        if "fabric" in _running(lab.name) and not same:
            r = live(dash)
            authed = any(x["state"] == "Auth" for xs in r.get("sessions", {}).values() for x in xs)
        rows.append((f"the switch's key for {w['server']} is the server's again (or the server took the new one "
                     f"and a port authorizes)", same or authed))
    passed = all(ok for _, ok in rows)
    k = DRILLS[d["id"]]
    msg = (f"fixed: it was {k.title.lower()}. The fix: {k.fix}." if passed else
           "not yet: " + "; ".join(t for t, ok in rows if not ok))
    return {"ok": True, "passed": passed, "message": msg, "results": [{"check": t, "passed": ok} for t, ok in rows]}
