"""QoS on the lab router, as typed at its console: IOS's Modular QoS CLI.

* ``class-map match-any|match-all <name>`` with ``match dscp``, ``match
  precedence``, ``match access-group``, ``match protocol`` or ``match any``
  says which packets (winlab/mqc.py);
* ``policy-map <name>`` with ``class <class>`` and ``priority``,
  ``bandwidth``, ``shape average``, ``police``, ``set dscp``,
  ``fair-queue``, ``drop`` or a child ``service-policy`` says what each
  class gets;
* ``service-policy output|input <policy>`` on an interface applies it.

These are not the zone firewall's ``class-map type inspect`` and
``policy-map type inspect`` (winlab/zbf.py): IOS keeps the two apart by the
word ``type``, and so does this console; they share only the way a class
is matched.

How the router does it (Linux traffic control, beside nftables):

* classifying and marking is an nftables table (``table ip wlqos``): on the
  way out of an interface the first class that matches counts the packet,
  polices it (``limit rate over ... drop``), rewrites its DSCP (``ip dscp
  set``) and gives it its queue (``meta priority set 1:<class>``); on the
  way in (``service-policy input``) only counting, policing and marking
  happen, as on IOS;
* queueing is an HTB tree on the interface (``tc qdisc ... htb``): one
  class per policy class. ``priority`` is a class served first (HTB prio 0)
  and held to its rate; ``bandwidth`` a guaranteed rate that may borrow up
  to the parent's; ``shape average`` a ceiling (rate and ceil the same);
  a child ``service-policy`` under a shaped class is the classic
  hierarchical policy (shape the line, then share it out). Each queue is
  fq_codel with ``fair-queue``, else a FIFO of 64 packets.

What differs from an ISR, said in the lessons: a real router's LLQ polices
the priority class only when the line is congested, HTB always holds it to
its rate; ``match protocol`` is by well-known port, not NBAR's look inside
the packet; the interface's own speed is taken as 1 Gbit/s, so a policy
only bites under a ``shape average``. An interface whose segment already
carries the lab's WAN lines or an impairment (netem, winlab/wan.py) keeps
those; a service-policy there is refused at render with a comment.

Settings: ``cmap:<name>``, ``pmap:<name>`` (JSON); ``qos-out:<if>`` /
``qos-in:<if>`` = policy.
"""

from __future__ import annotations

import hashlib
import json
import re

from . import iosl3, mqc

TABLE = "wlqos"
LINK_KBIT = 1_000_000
DEVS_FILE = "/run/winlab-qos-devs"
QUEUEING = ("priority", "bandwidth", "shape", "fair-queue", "child")


class QosError(ValueError):
    pass


# ------------------------------------------------------------------ settings
def cmaps(own: dict) -> list[str]:
    return sorted(k[5:] for k in own if k.startswith("cmap:"))


def pmaps(own: dict) -> list[str]:
    return sorted(k[5:] for k in own if k.startswith("pmap:"))


def pmap(own: dict, name: str) -> list[list]:
    """[[class, {action: value}], ...] in the order typed; class-default last."""
    try:
        rows = json.loads(own.get(f"pmap:{name}", "") or "[]")
    except ValueError:
        rows = []
    rows = [r for r in rows if isinstance(r, list) and len(r) == 2 and isinstance(r[1], dict)]
    return [r for r in rows if r[0] != "class-default"] + [r for r in rows if r[0] == "class-default"]


def store_pmap(own: dict, name: str, rows: list[list]) -> None:
    own[f"pmap:{name}"] = json.dumps(rows, separators=(",", ":"))


def with_default(rows: list[list]) -> list[list]:
    return rows if any(r[0] == "class-default" for r in rows) else rows + [["class-default", {}]]


def attached(own: dict) -> list[tuple[str, str, str]]:
    """(interface, out | in, policy) for every service-policy on an interface."""
    out = []
    for k, v in sorted(own.items()):
        if k.startswith(("qos-out:", "qos-in:")):
            way, ifname = k.split(":", 1)
            out.append((ifname, way[4:], v))
    return out


def parse_rate(text: str, unit: int = 1) -> int:
    """'20000000', '20m', '512k' -> a number (of `unit`)."""
    m = re.match(r"^(\d+)([kmg]?)$", text.lower())
    if not m:
        raise QosError("% Invalid input detected at '^' marker.")
    return int(m.group(1)) * {"": 1, "k": 1000, "m": 1000000, "g": 1000000000}[m.group(2)] // unit


def police_of(words: list[str]) -> dict:
    """police <bps> [<bc>] | police cir <bps> [bc <bytes>], then optional
    conform-action transmit and exceed-action drop | transmit |
    set-dscp-transmit <dscp>."""
    w = [x.lower() for x in words]
    if not w:
        raise QosError("% Incomplete command.")
    i = 0
    if w[0] == "cir":
        i = 1
    if i >= len(w):
        raise QosError("% Incomplete command.")
    cir = parse_rate(w[i])
    if not 8000 <= cir <= 10_000_000_000:
        raise QosError("% Rate must be between 8000 and 10000000000 bits per second")
    i += 1
    bc = max(1500, cir // 8 // 40)   # IOS's default: 25 ms of the rate in bytes
    if i < len(w) and w[i] == "bc":
        i += 1
    if i < len(w) and w[i].isdigit():
        bc = int(w[i])
        i += 1
    exceed = "drop"
    while i < len(w):
        if w[i] == "conform-action" and i + 1 < len(w) and w[i + 1] == "transmit":
            i += 2
        elif w[i] == "exceed-action" and i + 1 < len(w) and w[i + 1] in ("drop", "transmit"):
            exceed = w[i + 1]
            i += 2
        elif w[i] == "exceed-action" and i + 2 < len(w) and w[i + 1] == "set-dscp-transmit":
            exceed = f"set-dscp-transmit {mqc.dscp_value(w[i + 2])}"
            i += 3
        else:
            raise QosError("% Invalid input detected at '^' marker.")
    return {"cir": cir, "bc": bc, "exceed": exceed}


def check_input(own: dict, name: str) -> str:
    """'' when the policy may go on an interface's input, else why not."""
    for cls, acts in pmap(own, name):
        if any(k in acts for k in QUEUEING):
            return ("% A policy with queueing actions (priority, bandwidth, shape, fair-queue or a child "
                    "service-policy) can only be attached in the output direction")
    return ""


def guaranteed(own: dict, name: str, parent_kbit: int) -> int:
    """What a policy's priority and bandwidth classes take, in kbit/s."""
    total = 0
    for cls, acts in pmap(own, name):
        for k in ("priority", "bandwidth"):
            v = acts.get(k, "")
            if v.startswith("kbps "):
                total += int(v.split()[1])
            elif v.startswith("percent "):
                total += parent_kbit * int(v.split()[1]) // 100
    return total


def check_fit(own: dict, name: str, parent_kbit: int, ifname: str) -> str:
    """'' when what a policy guarantees fits under its parent, else IOS's complaint."""
    total = guaranteed(own, name, parent_kbit)
    if total > parent_kbit:
        return (f"I/f {ifname} class bandwidth {total} (kbps) exceeds available bandwidth "
                f"{parent_kbit} (kbps)\n% service-policy not attached")
    for cls, acts in pmap(own, name):
        if acts.get("child"):
            sub = int(acts["shape"].split()[1]) // 1000 if acts.get("shape") else parent_kbit
            why = check_fit(own, acts["child"], sub, ifname)
            if why:
                return why
    return ""


# ------------------------------------------------------------------ rendering
def _blocked(plan, ifname: str) -> str:
    """Why an interface cannot take a queueing policy here, or ''."""
    from . import devcli, wan
    lab = plan.lab
    if ifname.startswith("Tunnel"):
        return ""
    net = devcli.iface_net(lab, ifname)
    if net is not None and net.impair.active:
        return "its segment carries an impairment (netem) already"
    if wan.links(lab):
        return "the lab's WAN lines (netem) hold the router's interfaces' queues"
    return ""


class _Tree:
    def __init__(self, own, dev, way, ifname):
        self.own, self.dev, self.way, self.ifname = own, dev, way, ifname
        self.tc: list[str] = []
        self.chains: dict[str, list[str]] = {}
        self.minor = 0x10
        self.default = 0

    def next_minor(self) -> int:
        m = self.minor
        self.minor += 1
        return m

    def policy(self, name: str, parent: str, parent_kbit: int, path: str) -> str:
        """The chain of a policy (and its tc classes under `parent`)."""
        rows = with_default(pmap(self.own, name))
        ch = mqc._chain_name("qp", self.dev, self.way, path)
        body: list[str] = []
        fixed = guaranteed(self.own, name, parent_kbit)
        left = max(8, parent_kbit - fixed)
        for k, (cls, acts) in enumerate(rows):
            minor = self.next_minor() if self.way == "out" else 0
            if self.way == "out":
                self._class(cls, acts, minor, parent, parent_kbit, left, path)
                if cls == "class-default" and parent == "1:1":
                    self.default = minor
            cc = mqc._chain_name("qc", self.dev, self.way, path, str(k))
            self.chains[cc] = self._actions(name, cls, acts, minor, path)
            tail = f"jump {cc}"
            if cls == "class-default":
                body.append(tail)
            elif f"cmap:{cls}" in self.own:
                body += mqc.class_rules(self.own, mqc.load(self.own, f"cmap:{cls}"), tail,
                                        mqc._chain_name("qm", self.dev, self.way, path, cls), self.chains)
        self.chains[ch] = body
        return ch

    def _class(self, cls, acts, minor, parent, parent_kbit, left, path):
        prio, ceil = 2, parent_kbit
        pr, bw = acts.get("priority", ""), acts.get("bandwidth", "")
        if pr:
            rate = int(pr.split()[1]) if pr.startswith("kbps") else parent_kbit * int(pr.split()[1]) // 100
            prio, ceil = 0, rate
        elif bw:
            n = int(bw.split()[1])
            rate = n if bw.startswith("kbps") else parent_kbit * n // 100 if bw.startswith("percent") \
                else left * n // 100
            prio = 1
        else:
            rate = left if cls == "class-default" else max(8, parent_kbit // 100)
        if acts.get("shape"):
            ceil = max(8, int(acts["shape"].split()[1]) // 1000)
            rate = min(rate, ceil) if (pr or bw) else ceil
        rate, ceil = max(8, min(rate, parent_kbit)), max(8, min(ceil, parent_kbit))
        rate = min(rate, ceil)
        cid = f"1:{minor:x}"
        self.tc.append(f"tc class add dev {self.dev} parent {parent} classid {cid} htb rate {rate}kbit "
                       f"ceil {ceil}kbit prio {prio} quantum 1514 || true   # {path} {cls}")
        if acts.get("child"):
            self.policy(acts["child"], cid, ceil, f"{path}-{acts['child']}")
        elif acts.get("fair-queue") or (cls == "class-default" and not pr):
            self.tc.append(f"tc qdisc add dev {self.dev} parent {cid} handle {minor:x}: fq_codel || true")
        else:
            self.tc.append(f"tc qdisc add dev {self.dev} parent {cid} handle {minor:x}: pfifo limit 64 || true")

    def _actions(self, policy, cls, acts, minor, path) -> list[str]:
        tag = f"qos {self.ifname} {self.way} {path} {cls}"
        out = [f'counter comment "{tag}"']
        if acts.get("police"):
            p = acts["police"]
            over = f"limit rate over {max(1, p['cir'] // 8)} bytes/second burst {p['bc']} bytes counter"
            if p["exceed"] == "drop":
                out.append(f'{over} drop comment "{tag} exceeded"')
            elif p["exceed"].startswith("set-dscp-transmit"):
                out.append(f'{over} ip dscp set {p["exceed"].split()[1]} comment "{tag} exceeded"')
        if acts.get("drop"):
            out.append("drop")
            return out
        last = f"ip dscp set {acts['set']} " if "set" in acts else ""
        if acts.get("child") and self.way == "out":
            child = mqc._chain_name("qp", self.dev, self.way, f"{path}-{acts['child']}")
            out.append(f"{last}meta priority set 1:{minor:x} counter jump {child}")
        elif self.way == "out":
            out.append(f"{last}meta priority set 1:{minor:x} counter accept")
        else:
            out.append(f"{last}counter accept")
        return out


def render(plan, reset: bool = False) -> list[str]:
    lab = plan.lab
    own = lab.devices.get("router", {})
    pols = [(i, w, p) for i, w, p in attached(own) if f"pmap:{p}" in own]
    if not pols and not reset:
        return []
    out = ["### QoS typed at the router's console (winlab/qos.py)",
           f"nft delete table ip {TABLE} 2>/dev/null || true"]
    devs, post, pre, chains, tcs = [], [], [], {}, []
    for ifname, way, name in pols:
        dev = iosl3.svi_for(lab, plan, ifname)
        if not dev:
            out.append(f"# service-policy {way}put {name} on {ifname}: the interface is down, not applied")
            continue
        if way == "out":
            why = _blocked(plan, ifname)
            if why:
                out.append(f"# service-policy output {name} on {ifname} not applied: {why}")
                continue
            if check_fit(own, name, LINK_KBIT, ifname):
                out.append(f"# service-policy output {name} on {ifname} not applied: bandwidth exceeds the line")
                continue
        elif check_input(own, name):
            out.append(f"# service-policy input {name} on {ifname} not applied: queueing on input")
            continue
        t = _Tree(own, dev, way, ifname)
        top = t.policy(name, "1:1", LINK_KBIT, name)
        if way == "out":
            t.tc[:0] = [f"tc qdisc del dev {dev} root 2>/dev/null || true",
                        f"tc qdisc add dev {dev} root handle 1: htb default {t.default:x} r2q 10 || true",
                        f"tc class add dev {dev} parent 1: classid 1:1 htb rate {LINK_KBIT}kbit "
                        f"ceil {LINK_KBIT}kbit quantum 1514 || true"]
            post.append(f'oifname "{dev}" jump {top}')
            devs.append(dev)
        else:
            pre.append(f'iifname "{dev}" jump {top}')
        chains.update(t.chains)
        tcs += [f"# {ifname} ({dev}) service-policy {way}put {name}"] + t.tc
    # Queues this render no longer wants come off (only ones it put there).
    keep = " ".join(devs)
    out.append(f"for d in $(cat {DEVS_FILE} 2>/dev/null); do case \" {keep} \" in *\" $d \"*) ;; "
               f"*) tc qdisc del dev $d root 2>/dev/null ;; esac; done; echo {keep} > {DEVS_FILE}")
    out += tcs
    if post or pre:
        out += ["nft -f - <<'EOF' || true", f"table ip {TABLE} {{"]
        for ch, body in sorted(chains.items()):
            out += [f"  chain {ch} {{"] + [f"    {r}" for r in body] + ["  }"]
        out += ["  chain post {", "    type filter hook postrouting priority 10; policy accept;"]
        out += [f"    {r}" for r in post] + ["  }"]
        out += ["  chain pre {", "    type filter hook prerouting priority -160; policy accept;"]
        out += [f"    {r}" for r in pre] + ["  }", "}", "EOF"]
    out.append("")
    return out


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


# ------------------------------------------------------------------ reading
def live_cmd(devs: list[str]) -> str:
    return (f"nft list table ip {TABLE} 2>/dev/null; "
            + "; ".join(f"echo '#dev {d}'; tc -s class show dev {d} 2>/dev/null" for d in devs))


def parse_tc(text: str) -> dict[str, dict[str, tuple[int, int, int]]]:
    """'#dev X' sections of tc -s class show -> {dev: {classid: (bytes, packets, dropped)}}."""
    out: dict[str, dict] = {}
    dev, cid = "", ""
    for line in text.splitlines():
        if line.startswith("#dev "):
            dev = line[5:].strip()
            out.setdefault(dev, {})
            continue
        m = re.match(r"^class htb (\S+) ", line)
        if m:
            cid = m.group(1)
            continue
        m = re.match(r"^\s*Sent (\d+) bytes (\d+) pkt \(dropped (\d+)", line)
        if m and dev and cid:
            out[dev][cid] = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return out


# ------------------------------------------------------------------ the console
def _acts_lines(acts: dict, ind: str) -> list[str]:
    out = []
    pr, bw = acts.get("priority", ""), acts.get("bandwidth", "")
    if pr:
        out.append(f"{ind}priority {pr.split()[1]}" if pr.startswith("kbps") else f"{ind}priority percent {pr.split()[1]}")
    if bw:
        n = bw.split()[1]
        out.append(f"{ind}bandwidth {n}" if bw.startswith("kbps") else f"{ind}bandwidth percent {n}"
                   if bw.startswith("percent") else f"{ind}bandwidth remaining percent {n}")
    if acts.get("shape"):
        out.append(f"{ind}shape average {acts['shape'].split()[1]}")
    if acts.get("police"):
        p = acts["police"]
        out.append(f"{ind}police {p['cir']} {p['bc']} conform-action transmit  exceed-action "
                   + (f"set-dscp-transmit {mqc.dscp_show(int(p['exceed'].split()[1]))}"
                      if p["exceed"].startswith("set-dscp") else p["exceed"]))
    if "set" in acts:
        out.append(f"{ind}set dscp {mqc.dscp_show(int(acts['set']))}")
    if acts.get("fair-queue"):
        out.append(f"{ind}fair-queue")
    if acts.get("drop"):
        out.append(f"{ind}drop")
    if acts.get("child"):
        out.append(f"{ind}service-policy {acts['child']}")
    return out


def run_lines(own: dict) -> list[str]:
    out = []
    for name in cmaps(own):
        cm = mqc.load(own, f"cmap:{name}")
        out.append(f"class-map {cm['how']} {name}")
        out += [f" description {cm['desc']}"] if cm["desc"] else []
        out += [f" match {mqc.run_match(m)}" for m in cm["m"]]
        out.append("!")
    for name in pmaps(own):
        out.append(f"policy-map {name}")
        for cls, acts in pmap(own, name):
            out.append(f" class {cls}")
            out += _acts_lines(acts, "  ")
        out.append("!")
    return out


def iface_lines(own: dict, ifname: str) -> list[str]:
    out = []
    for way, word in (("in", "input"), ("out", "output")):
        if own.get(f"qos-{way}:{ifname}"):
            out.append(f" service-policy {word} {own[f'qos-{way}:{ifname}']}")
    return out


def add_specs(con, add, U, E, C, IF, sub) -> None:
    CM, PM, PC = ("config-cmap",), ("config-pmap",), ("config-pmap-c",)
    sub(CM + PM + PC)
    for how in ("match-any", "match-all"):
        add(f"class-map {how} <name>", lambda a, h=how: _cmap(con, a[0], h),
            "Logical-OR (any) / Logical-AND (all) of the match criteria", C + CM)
        add(f"no class-map {how} <name>", lambda a: _no(con, f"cmap:{a[0]}"), "Negate a command or set its defaults", C)
    add("class-map <name>", lambda a: _cmap(con, a[0], "match-all"), "Configure Class Map", C + CM)
    add("no class-map <name>", lambda a: _no(con, f"cmap:{a[0]}"), "Negate a command or set its defaults", C)
    add("description <line>", lambda a: _desc(con, a[0]), "Class-Map description", CM)
    add("no description", lambda a: _desc(con, ""), "Negate a command or set its defaults", CM)
    for words, help_ in (("match dscp <line>", "Match DSCP in IPv4 and IPv6 packets"),
                         ("match ip dscp <line>", "Match IP DSCP (DiffServ CodePoints)"),
                         ("match precedence <line>", "Match Precedence in IPv4 and IPv6 packets"),
                         ("match protocol <name>", "Protocol"),
                         ("match access-group <num>", "Access group"),
                         ("match access-group name <name>", "Named Access List"),
                         ("match any", "Any packets")):
        add(words, lambda a, w=words: _match(con, w.split()[1:], a, True), help_, CM)
    add("no match <line>", lambda a: _match(con, [], a, False), "Negate a command or set its defaults", CM)
    add("policy-map <name>", lambda a: _pmap(con, a[0]), "Configure QoS Policy Map", C + PM)
    add("no policy-map <name>", lambda a: _no(con, f"pmap:{a[0]}"), "Negate a command or set its defaults", C)
    add("class <name>", lambda a: _class(con, a[0]), "policy criteria", PM + PC)
    add("no class <name>", lambda a: _no_class(con, a[0]), "Negate a command or set its defaults", PM)
    add("priority <num>", lambda a: _act(con, "priority", f"kbps {a[0]}"), "Strict Scheduling Priority for this Class", PC)
    add("priority percent <num>", lambda a: _act(con, "priority", f"percent {a[0]}"), "% of total bandwidth", PC)
    add("bandwidth <num>", lambda a: _act(con, "bandwidth", f"kbps {a[0]}"), "Bandwidth", PC)
    add("bandwidth percent <num>", lambda a: _act(con, "bandwidth", f"percent {a[0]}"), "% of total Bandwidth", PC)
    add("bandwidth remaining percent <num>", lambda a: _act(con, "bandwidth", f"remaining {a[0]}"),
        "% of the remaining bandwidth", PC)
    add("shape average <line>", lambda a: _act(con, "shape", a[0]), "configure token bucket: CIR (bps)", PC)
    add("police <line>", lambda a: _act(con, "police", a[0]), "Police", PC)
    add("set dscp <name>", lambda a: _act(con, "set", a[0]), "Set DSCP in IP(v4) and IPv6 packets", PC)
    add("set ip dscp <name>", lambda a: _act(con, "set", a[0]), "Set IP DSCP (DiffServ CodePoints)", PC)
    add("fair-queue", lambda a: _act(con, "fair-queue", True), "Enable Flow-based Fair Queuing in this Class", PC)
    add("drop", lambda a: _act(con, "drop", True), "Drop all packets", PC)
    add("service-policy <name>", lambda a: _act(con, "child", a[0]), "Configure Flow Next", PC)
    for w in ("priority", "bandwidth", "police", "set", "fair-queue", "drop", "service-policy"):
        key = {"set": "set", "service-policy": "child"}.get(w, w)
        add(f"no {w}", lambda a, k=key: _act(con, k, None), "Negate a command or set its defaults", PC)
        add(f"no {w} <line>", lambda a, k=key: _act(con, k, None), "Negate a command or set its defaults", PC)
    add("no shape average", lambda a: _act(con, "shape", None), "Negate a command or set its defaults", PC)
    add("no shape average <line>", lambda a: _act(con, "shape", None), "Negate a command or set its defaults", PC)
    add("service-policy output <name>", lambda a: _attach(con, "out", a[0]), "Assign policy-map to the output of an interface", IF)
    add("service-policy input <name>", lambda a: _attach(con, "in", a[0]), "Assign policy-map to the input of an interface", IF)
    for way, w in (("out", "output"), ("in", "input")):
        add(f"no service-policy {w}", lambda a, x=way: _attach(con, x, ""), "Negate a command or set its defaults", IF)
        add(f"no service-policy {w} <name>", lambda a, x=way: _attach(con, x, ""), "Negate a command or set its defaults", IF)
    add("show class-map", lambda a: show_cmaps(con, ""), "Show QoS Class Map", U)
    add("show class-map <name>", lambda a: show_cmaps(con, a[0]), "Show QoS Class Map", U)
    add("show policy-map", lambda a: show_pmaps(con, ""), "Show QoS Policy Map", U)
    add("show policy-map <name>", lambda a: show_pmaps(con, a[0]), "Show QoS Policy Map", U)
    add("show policy-map interface", lambda a: show_iface(con, ""), "Show Qos Policy Map", U)
    add("show policy-map interface <line>", lambda a: show_iface(con, a[0]), "Show Qos Policy Map", U)


def _own(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _err(text: str) -> Exception:
    from . import devcli
    return devcli.CliError(text)


def _done(con) -> str:
    return con._save().strip()


def _name_ok(name: str) -> str:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$", name) or name.lower() in ("type", "interface",
                                                                                    "match-any", "match-all"):
        raise _err("% Invalid input detected at '^' marker.")
    return name


def _cmap(con, name: str, how: str) -> str:
    _name_ok(name)
    if name == "class-default":
        raise _err("% class-default is a system class; it cannot be configured")
    own = _own(con)
    key = f"cmap:{name}"
    cm = mqc.load(own, key)
    if key in own and cm["how"] != how:
        raise _err(f"% class-map {name} is already {cm['how']}; remove it to change that")
    cm["how"] = how
    mqc.store(own, key, cm)
    con.s.mode, con.s.ctx = "config-cmap", name
    return _done(con)


def _desc(con, text: str) -> str:
    own = _own(con)
    cm = mqc.load(own, f"cmap:{con.s.ctx}")
    cm["desc"] = text
    mqc.store(own, f"cmap:{con.s.ctx}", cm)
    return _done(con)


def _match(con, words: list[str], args: list[str], on: bool) -> str:
    own = _own(con)
    key = f"cmap:{con.s.ctx}"
    cm = mqc.load(own, key)
    typed: list[str] = []
    args = list(args)
    for w in words:
        typed += args.pop(0).split() if w.startswith("<") else [w]
    if not words:   # no match <what was matched>
        typed = args[0].split() if args else []
    try:
        line = mqc.match_line(typed, qos=True)
    except mqc.MqcError as exc:
        raise _err(str(exc)) from None
    if on and line not in cm["m"]:
        cm["m"].append(line)
    elif not on:
        if line not in cm["m"]:
            return "% Match statement not found"
        cm["m"].remove(line)
    mqc.store(own, key, cm)
    return _done(con)


def _pmap(con, name: str) -> str:
    _name_ok(name)
    own = _own(con)
    if f"pmap:{name}" not in own:
        store_pmap(own, name, [])
    con.s.mode, con.s.ctx = "config-pmap", name
    return _done(con)


def _class(con, cls: str) -> str:
    own = _own(con)
    pm = con.s.ctx.split("|")[0]
    if cls != "class-default" and f"cmap:{cls}" not in own:
        raise _err(f"% class-map {cls} not configured")
    rows = pmap(own, pm)
    if not any(r[0] == cls for r in rows):
        rows.append([cls, {}])
        store_pmap(own, pm, rows)
    con.s.mode, con.s.ctx = "config-pmap-c", f"{pm}|{cls}"
    return _done(con)


def _no_class(con, cls: str) -> str:
    own = _own(con)
    store_pmap(own, con.s.ctx, [r for r in pmap(own, con.s.ctx) if r[0] != cls])
    return _done(con)


def _in_use(own: dict, name: str) -> str:
    for ifname, way, p in attached(own):
        if p == name:
            return f"% Policy map {name} is in use on {ifname}; remove the service-policy there first"
    for other in pmaps(own):
        for cls, acts in pmap(own, other):
            if acts.get("child") == name:
                return f"% Policy map {name} is a child of {other}; remove it there first"
    return ""


def _no(con, key: str) -> str:
    own = _own(con)
    name = key.split(":", 1)[1]
    if key.startswith("pmap:") and _in_use(own, name):
        return _in_use(own, name)
    if own.pop(key, None) is None:
        return f"% {name} does not exist"
    return _done(con)


def _act(con, key: str, value) -> str:
    own = _own(con)
    pm, cls = con.s.ctx.split("|", 1)
    rows = pmap(own, pm)
    row = next(r for r in rows if r[0] == cls)
    acts = row[1]
    if value is None:
        acts.pop(key, None)
    else:
        try:
            if key == "shape":
                w = str(value).split()
                bps = parse_rate(w[0])
                if not 8000 <= bps <= 10_000_000_000:
                    raise QosError("% Rate must be between 8000 and 10000000000 bits per second")
                value = f"bps {bps}"
            elif key == "police":
                value = police_of(str(value).split())
            elif key == "set":
                value = mqc.dscp_value(str(value))
            elif key in ("priority", "bandwidth"):
                n = int(str(value).split()[1])
                if str(value).startswith(("percent", "remaining")) and not 1 <= n <= 100:
                    raise QosError("% Invalid input detected at '^' marker.")
                if str(value).startswith("kbps") and not 8 <= n <= 10_000_000:
                    raise QosError("% Invalid input detected at '^' marker.")
                other = "bandwidth" if key == "priority" else "priority"
                if other in acts:
                    raise QosError(f"% {other.capitalize()} is configured in this class already: "
                                   "a class takes either priority or bandwidth")
                if cls == "class-default" and key == "priority":
                    raise QosError("% priority is not allowed in class-default")
            elif key == "child":
                if f"pmap:{value}" not in own or value == pm:
                    raise QosError(f"% policy-map {value} not configured")
            elif key == "drop" and any(k in acts for k in ("priority", "bandwidth", "shape", "police", "set")):
                raise QosError("% drop cannot be configured with other actions in a class")
        except QosError as exc:
            raise _err(str(exc)) from None
        before = own.get(f"pmap:{pm}")
        acts[key] = value
        store_pmap(own, pm, rows)
        # A policy already on an interface must still fit its line (IOS refuses the change).
        for ifname, way, name in attached(own):
            why = check_fit(own, name, LINK_KBIT, ifname) if way == "out" else check_input(own, name)
            if why:
                own[f"pmap:{pm}"] = before
                raise _err(why.replace("% service-policy not attached", "% the change is refused"))
        return _done(con)
    store_pmap(own, pm, rows)
    return _done(con)


def _attach(con, way: str, name: str) -> str:
    own = _own(con)
    key = f"qos-{way}:{con.s.ctx}"
    if not name:
        own.pop(key, None)
        return _done(con)
    if f"pmap:{name}" not in own:
        raise _err(f"policy map {name} not configured")
    if way == "in" and check_input(own, name):
        raise _err(check_input(own, name))
    if way == "out":
        why = check_fit(own, name, LINK_KBIT, con.s.ctx)
        if why:
            raise _err(why)
    own[key] = name
    return _done(con)


def show_cmaps(con, only: str) -> str:
    own = con.lab.devices.get("router", {})
    out = []
    for name in cmaps(own):
        if only and name != only:
            continue
        cm = mqc.load(own, f"cmap:{name}")
        out.append(f" Class Map {cm['how']} {name} (id {cmaps(own).index(name) + 1})")
        out += [f"   Description: {cm['desc']}"] if cm["desc"] else []
        out += [f"   Match {mqc.show_match(m)} " for m in cm["m"]] + [""]
    if not only:
        out.insert(0, " Class Map match-any class-default (id 0)\n   Match any \n")
    return "\n".join(out).rstrip()


def show_pmaps(con, only: str) -> str:
    own = con.lab.devices.get("router", {})
    out = []
    for name in pmaps(own):
        if only and name != only:
            continue
        out.append(f"  Policy Map {name}")
        for cls, acts in pmap(own, name):
            out.append(f"    Class {cls}")
            out += _acts_lines(acts, "      ")
    if only and not out:
        return f"% policy-map {only} not configured"
    return "\n".join(out)


def show_iface(con, only: str) -> str:
    from . import devcli
    lab = con.lab
    own = lab.devices.get("router", {})
    want = ""
    if only.strip():
        want = _ifname(con, only)
    rows = [r for r in attached(own) if not want or r[0] == want]
    devs = {}
    for ifname, way, name in rows:
        devs[ifname] = iosl3.svi_for(lab, con.plan, ifname)
    counts, tcs = {}, {}
    if con.powered() and rows:
        try:
            text = con._on_router(live_cmd(sorted({d for d in devs.values() if d})), timeout=15)
            counts, tcs = mqc.counters(text, "qos"), parse_tc(text)
        except Exception:  # noqa: BLE001 - the policy shows without the router's numbers
            counts, tcs = {}, {}
    out = []
    for ifname in sorted({r[0] for r in rows}):
        out += [f" {ifname} ", ""]
        for _, way, name in [r for r in rows if r[0] == ifname]:
            out += [f"  Service-policy {way}put: {name}", ""]
            dev = devs.get(ifname, "")
            minor = [0x10]
            out += _show_policy(own, ifname, way, name, name, counts, tcs.get(dev, {}), minor, "    ",
                                devcli.ROUTER)
    if not out:
        return "" if not want else ""
    return "\n".join(out).rstrip()


def _ifname(con, text: str) -> str:
    from . import devcli
    from . import vti
    t = vti.tunnel_name(text)
    return t or devcli.parse_if(text, con._if_names(), sub=True)


def _show_policy(own, ifname, way, name, path, counts, tcs, minor, ind, _r) -> list[str]:
    out = []
    for cls, acts in with_default(pmap(own, name)):
        m = minor[0]
        minor[0] += 1
        cm = mqc.load(own, f"cmap:{cls}") if cls != "class-default" else {"how": "match-any", "m": ["any"]}
        pk, by = counts.get(f"{ifname} {way} {path} {cls}", (0, 0))
        out += [f"{ind}Class-map: {cls} ({cm['how']})  ", f"{ind}  {pk} packets, {by} bytes",
                f"{ind}  5 minute offered rate 0000 bps, drop rate 0000 bps"]
        out += [f"{ind}  Match: {mqc.show_match(x)} " for x in cm["m"]]
        if way == "out":
            sent = tcs.get(f"1:{m:x}", (0, 0, 0))
            if any(k in acts for k in ("priority", "bandwidth", "shape", "fair-queue")) or cls == "class-default":
                out += [f"{ind}  Queueing", f"{ind}  queue limit 64 packets",
                        f"{ind}  (queue depth/total drops/no-buffer drops) 0/{sent[2]}/0",
                        f"{ind}  (pkts output/bytes output) {sent[1]}/{sent[0]}"]
            pr, bw = acts.get("priority", ""), acts.get("bandwidth", "")
            if pr:
                out.append(f"{ind}  Priority: {pr.split()[1]}" + (" kbps" if pr.startswith("kbps") else "%")
                           + f", burst bytes 1500, b/w exceed drops: {sent[2]}")
            if bw:
                n = bw.split()[1]
                out.append(f"{ind}  bandwidth " + (f"{n} kbps" if bw.startswith("kbps") else f"{n}%"
                                                    if bw.startswith("percent") else f"remaining {n}%"))
            if acts.get("shape"):
                bps = acts["shape"].split()[1]
                out += [f"{ind}  shape (average) cir {bps}, bc {int(bps) // 250}, be {int(bps) // 250}",
                        f"{ind}  target shape rate {bps}"]
            if acts.get("fair-queue"):
                out.append(f"{ind}  Fair-queue: per-flow queue limit 16 packets")
        if acts.get("police"):
            p = acts["police"]
            xp, xb = counts.get(f"{ifname} {way} {path} {cls} exceeded", (0, 0))
            out += [f"{ind}  police:", f"{ind}      cir {p['cir']} bps, bc {p['bc']} bytes",
                    f"{ind}    conformed {max(0, pk - xp)} packets, {max(0, by - xb)} bytes; actions:",
                    f"{ind}      transmit ", f"{ind}    exceeded {xp} packets, {xb} bytes; actions:",
                    f"{ind}      {p['exceed']} "]
        if "set" in acts:
            out += [f"{ind}  QoS Set", f"{ind}    dscp {mqc.dscp_show(int(acts['set']))}",
                    f"{ind}      Packets marked {pk}"]
        if acts.get("drop"):
            out.append(f"{ind}  drop")
        if acts.get("child"):
            out += ["", f"{ind}  Service-policy : {acts['child']}", ""]
            out += _show_policy(own, ifname, way, acts["child"], f"{path}-{acts['child']}", counts, tcs,
                                minor, ind + "    ", _r)
        out.append("")
    return out
