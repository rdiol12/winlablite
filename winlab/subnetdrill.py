"""Subnetting and VLSM practice: fresh questions every time, graded by winlab.

Subnetting is a skill of speed and accuracy, so it is drilled, not read:
each question is made from a seed (random addresses, prefixes, host counts)
and graded here, from Python's own ipaddress arithmetic. Six kinds:

  facts      an address and prefix: its network, broadcast, usable range or host count
  hosts      a number of hosts: the smallest prefix that holds them, as a mask
  vlsm       a block and the LANs it must hold: the subnet one LAN gets when the
             plan is laid out largest first from the start of the block
  summary    contiguous networks: the single route that covers exactly them
  wildcard   a subnet: the wildcard mask an ACL or an OSPF network line takes
  member     an address and prefix: which of four addresses shares its subnet

``winlab drill subnet`` asks them in the terminal with typed answers (an
address, a prefix or a mask, a range) and keeps each run's score in
var/drills/subnet.json; the subnetting lesson's check reads that file. The
practice exams take the same questions as multiple choice: a bank question
with ``generator = "<kind>"`` is made fresh for each exam from a seed the
session keeps (winlab/practice_exam.py).

The vlsm-address-plan lesson then puts a plan on the lab: VLANs on the
office switch, router sub-interfaces sized by VLSM out of 172.20.8.0/22,
and one summary route on rtr-edge; check_vlsm_plan grades it from the lab
file.
"""

from __future__ import annotations

import ipaddress
import json
import random
import re
import time
from typing import Callable

from . import paths

KINDS = ("facts", "hosts", "vlsm", "summary", "wildcard", "member")
MAX_HISTORY = 100
PASS = 80          # percent a drill run needs to count for the lesson
MIN_QUESTIONS = 10


def prefix_for(hosts: int) -> int:
    """The longest prefix whose subnet holds this many hosts (network and
    broadcast taken off)."""
    for p in range(30, 0, -1):
        if 2 ** (32 - p) - 2 >= hosts:
            return p
    return 1


def mask(p: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{p}").netmask)


def wildcard(p: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{p}").hostmask)


def _private(rng: random.Random) -> ipaddress.IPv4Address:
    pick = rng.choice(("10", "172", "192"))
    if pick == "10":
        return ipaddress.IPv4Address(f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}")
    if pick == "172":
        return ipaddress.IPv4Address(f"172.{rng.randrange(16, 32)}.{rng.randrange(256)}.{rng.randrange(1, 255)}")
    return ipaddress.IPv4Address(f"192.168.{rng.randrange(256)}.{rng.randrange(1, 255)}")


def _options(rng: random.Random, right: str, wrong: list[str], n: int = 4) -> list[str]:
    seen, out = {right}, [right]
    for w in wrong:
        if w not in seen and len(out) < n:
            seen.add(w)
            out.append(w)
    rng.shuffle(out)
    return out


# ------------------------------------------------------------------ the kinds
def q_facts(rng: random.Random) -> dict:
    p = rng.randrange(18, 31)
    ip = _private(rng)
    net = ipaddress.IPv4Network(f"{ip}/{p}", strict=False)
    if net.network_address == ip or net.broadcast_address == ip:
        ip = net.network_address + 1
    block = net.num_addresses
    hosts = block - 2
    first, last = net.network_address + 1, net.broadcast_address - 1
    ask = rng.choice(("network", "broadcast", "range", "hosts"))
    where = f"{ip}/{p}"
    prev = ipaddress.IPv4Network((max(0, int(net.network_address) - block), p))
    if ask == "network":
        right = str(net.network_address)
        wrong = [str(prev.network_address), str(net.broadcast_address), str(ip - 1 if ip != first else ip),
                 str(ipaddress.IPv4Network(f"{ip}/{p + 1}", strict=False).network_address)]
        text, accept = f"Host {where}: what is the address of its subnet?", {right, f"{right}/{p}"}
    elif ask == "broadcast":
        right = str(net.broadcast_address)
        wrong = [str(net.broadcast_address - 1), str(prev.broadcast_address), str(net.network_address + block),
                 str(ipaddress.IPv4Network(f"{ip}/{p + 1}", strict=False).broadcast_address)]
        text, accept = f"Host {where}: what is its subnet's broadcast address?", {right}
    elif ask == "range":
        right = f"{first} - {last}"
        wrong = [f"{net.network_address} - {net.broadcast_address}", f"{first} - {net.broadcast_address}",
                 f"{prev.network_address + 1} - {prev.broadcast_address - 1}", f"{first + 1} - {last + 1}"]
        text, accept = f"Host {where}: what is the usable host range of its subnet?", {right, f"{first}-{last}"}
    else:
        right = str(hosts)
        wrong = [str(block), str(hosts // 2), str(hosts * 2 + 2), str(hosts - 1)]
        text, accept = f"How many usable host addresses does a /{p} subnet such as {where} have?", {right}
    why = (f"{where}: /{p} is mask {mask(p)}, a block of {block} addresses. The subnet is {net}: network "
           f"{net.network_address}, broadcast {net.broadcast_address}, hosts {first} to {last} ({hosts}).")
    return {"text": text, "answer": right, "options": _options(rng, right, wrong), "accept": accept, "why": why}


def q_hosts(rng: random.Random) -> dict:
    hosts = rng.choice((rng.randrange(3, 15), rng.randrange(15, 63), rng.randrange(63, 255), rng.randrange(255, 1023),
                        rng.randrange(1023, 4000)))
    p = prefix_for(hosts)
    right = f"/{p} ({mask(p)})"
    wrong = [f"/{q} ({mask(q)})" for q in (p + 1, p - 1, p + 2, p - 2) if 1 <= q <= 30]
    return {"text": f"A LAN needs {hosts} host addresses. What is the smallest subnet that holds them?",
            "answer": right, "options": _options(rng, right, wrong), "accept": {f"/{p}", str(p), mask(p), right},
            "why": f"/{p} gives 2^{32 - p} - 2 = {2 ** (32 - p) - 2} hosts; /{p + 1} would give only "
                   f"{2 ** (32 - p - 1) - 2}."}


def plan(block: ipaddress.IPv4Network, needs: list[tuple[str, int]]) -> dict[str, ipaddress.IPv4Network]:
    """VLSM laid out largest first from the start of the block (ties in
    the order given). ValueError when the block is too small."""
    out: dict[str, ipaddress.IPv4Network] = {}
    at = int(block.network_address)
    for name, hosts in sorted(needs, key=lambda nh: -2 ** (32 - prefix_for(nh[1]))):
        p = prefix_for(hosts)
        size = 2 ** (32 - p)
        at = (at + size - 1) // size * size
        net = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(at)}/{p}")
        if not net.subnet_of(block):
            raise ValueError(f"{block} is too small")
        out[name] = net
        at += size
    return out


NAMES = ("Sales", "Staff", "Lab", "Voice", "Printers", "Cameras", "Guests", "Servers", "Management")


def q_vlsm(rng: random.Random) -> dict:
    while True:
        p = rng.choice((22, 23, 24))
        base = ipaddress.IPv4Network(f"{_private(rng)}/{p}", strict=False)
        names = rng.sample(NAMES, rng.choice((3, 4)))
        room = 2 ** (32 - p)
        needs = [(n, rng.randrange(2, max(3, room // 5))) for n in names]
        if len({prefix_for(h) for _, h in needs}) < len(needs) - 1:
            continue
        try:
            got = plan(base, needs)
        except ValueError:
            continue
        break
    target = rng.choice(names)
    right = str(got[target])
    others = [str(v) for k, v in got.items() if k != target]
    tp = got[target].prefixlen
    wrong = others + [f"{got[target].network_address}/{tp - 1}", f"{got[target].network_address}/{tp + 1}",
                      f"{base.network_address}/{tp}"]
    listing = ", ".join(f"{n} {h} hosts" for n, h in needs)
    return {"text": f"Plan {base} with VLSM, largest LAN first from the start of the block: {listing}. "
                    f"Which subnet does {target} get?",
            "answer": right, "options": _options(rng, right, wrong),
            "accept": {right, f"{got[target].network_address} {got[target].netmask}"},
            "why": "Largest first: " + ", ".join(f"{n} {got[n]}" for n in sorted(got, key=lambda n: got[n].network_address))
                   + ". Each subnet is the smallest prefix that holds its hosts, starting on a multiple of its size."}


def q_summary(rng: random.Random) -> dict:
    while True:
        p = rng.randrange(20, 28)
        k = rng.choice((2, 4, 8))
        big = p - {2: 1, 4: 2, 8: 3}[k]
        summ = ipaddress.IPv4Network(f"{_private(rng)}/{big}", strict=False)
        if summ.prefixlen == big:
            break
    nets = list(summ.subnets(new_prefix=p))
    right = str(summ)
    wrong = [str(summ.supernet()), f"{summ.network_address}/{p}", f"{summ.network_address}/{big + 1}",
             str(ipaddress.IPv4Network(f"{nets[-1].network_address}/{big}", strict=False).supernet())]
    return {"text": "What single route summarises exactly these networks: " + ", ".join(map(str, nets)) + "?",
            "answer": right, "options": _options(rng, right, wrong),
            "accept": {right, f"{summ.network_address} {summ.netmask}"},
            "why": f"{k} networks of /{p} are {k} times the block, so the summary is {k.bit_length() - 1} bits "
                   f"shorter: /{big}. {summ.network_address} is a multiple of that block, so {summ} covers them "
                   f"and nothing else."}


def q_wildcard(rng: random.Random) -> dict:
    p = rng.randrange(16, 31)
    net = ipaddress.IPv4Network(f"{_private(rng)}/{p}", strict=False)
    right = wildcard(p)
    wrong = [mask(p), wildcard(p + 1), wildcard(p - 1), "0.0.0.255" if right != "0.0.0.255" else "0.0.0.127"]
    return {"text": f"An access list entry or an OSPF network line must match all of {net}. "
                    f"Which wildcard mask goes with {net.network_address}?",
            "answer": right, "options": _options(rng, right, wrong), "accept": {right},
            "why": f"The wildcard is the mask turned over: 255.255.255.255 minus {mask(p)} is {right}."}


def q_member(rng: random.Random) -> dict:
    p = rng.randrange(20, 30)
    ip = _private(rng)
    net = ipaddress.IPv4Network(f"{ip}/{p}", strict=False)
    if ip in (net.network_address, net.broadcast_address):
        ip = net.network_address + 1
    hosts = list(range(int(net.network_address) + 1, int(net.broadcast_address)))
    same = ipaddress.IPv4Address(rng.choice([h for h in hosts if h != int(ip)] or hosts))
    size = net.num_addresses
    wrong = [str(net.broadcast_address + 1 + rng.randrange(max(1, size - 2))),
             str(net.network_address - 1 - rng.randrange(max(1, size - 2))) if int(net.network_address) > size else
             str(net.broadcast_address + size + 1),
             str(net.broadcast_address + size + 2)]
    right = str(same)
    return {"text": f"Host {ip}/{p}: which of these addresses is in the same subnet?",
            "answer": right, "options": _options(rng, right, wrong), "accept": {right},
            "why": f"{ip}/{p} is in {net} (hosts {net.network_address + 1} to {net.broadcast_address - 1}); "
                   f"{right} is the only one inside it."}


GENERATORS: dict[str, Callable[[random.Random], dict]] = {
    "facts": q_facts, "hosts": q_hosts, "vlsm": q_vlsm, "summary": q_summary, "wildcard": q_wildcard,
    "member": q_member,
}


def make(kind: str, seed: int) -> dict:
    """One question of a kind from a seed: the same seed, the same question."""
    if kind not in GENERATORS:
        raise KeyError(kind)
    q = GENERATORS[kind](random.Random(f"winlab-subnet/{kind}/{seed}"))
    q["kind"] = kind
    return q


def materialize(kind: str, seed: int) -> dict:
    """For a practice exam: text, options, answer and why."""
    q = make(kind, seed)
    return {k: q[k] for k in ("text", "options", "answer", "why")}


# ------------------------------------------------------------------ grading typed answers
def _norm(text: str) -> str:
    t = " ".join((text or "").replace("\u2013", "-").lower().split())
    return re.sub(r"\s*-\s*", "-", t)


def grade(q: dict, typed: str) -> bool:
    got = _norm(typed)
    if not got:
        return False
    return got in {_norm(a) for a in q.get("accept", {q["answer"]})}


# ------------------------------------------------------------------ the drill and its record
def _file():
    return paths.VAR / "drills" / "subnet.json"


def history() -> list[dict]:
    try:
        rows = json.loads(_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return rows if isinstance(rows, list) else []


def record(right: int, total: int, kinds: list[str], seconds: int) -> dict:
    from . import progress
    row = {"t": int(time.time()), "student": progress.student(), "right": right, "total": total,
           "percent": round(100 * right / total) if total else 0, "kinds": sorted(set(kinds)), "seconds": seconds}
    rows = (history() + [row])[-MAX_HISTORY:]
    f = _file()
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    tmp.replace(f)
    return row


def run_terminal(n: int, kinds: list[str], ask: Callable[[str], str], say: Callable[[str], None],
                 seed: int | None = None) -> dict:
    rng = random.Random(seed)
    right, used = 0, []
    t0 = time.time()
    say(f"Subnetting drill: {n} questions. Type the answer (an address, /prefix or mask, or a range a.b.c.d - "
        f"e.f.g.h); an empty line skips.\n")
    for i in range(1, n + 1):
        kind = rng.choice(kinds)
        q = make(kind, rng.randrange(1, 2 ** 31))
        used.append(kind)
        try:
            typed = ask(f"{i}/{n}  {q['text']}\n> ")
        except EOFError:
            break
        if grade(q, typed):
            right += 1
            say("  right.")
        else:
            say(f"  no: {q['answer']}. {q['why']}")
    row = record(right, n, used, int(time.time() - t0))
    say(f"\n{right} of {n} right ({row['percent']}%) in {row['seconds']} s."
        + (" That counts for the subnetting lesson." if n >= MIN_QUESTIONS and row["percent"] >= PASS else
           f" The lesson counts a run of at least {MIN_QUESTIONS} questions at {PASS}% or better."))
    return row


def add_cli(sub) -> None:
    p = sub.add_parser("drill", help="practice drills graded by winlab: subnetting and VLSM, fresh every time")
    p.add_argument("what", choices=("subnet", "history"), help="subnet: run a drill; history: past runs")
    p.add_argument("--count", type=int, default=MIN_QUESTIONS, help="how many questions")
    p.add_argument("--kind", action="append", choices=KINDS, default=[], help="only these kinds (repeatable)")
    p.add_argument("--seed", type=int, default=None, help="the same seed asks the same questions")


def run_cli(args, ask=input, say=print) -> int:
    if args.what == "history":
        rows = history()
        if not rows:
            say("no drills yet: winlab drill subnet")
        for r in rows[-20:]:
            say(f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(r['t']))}  {r['right']}/{r['total']} "
                f"({r['percent']}%)  {', '.join(r['kinds'])}")
        return 0
    n = max(1, min(100, int(args.count)))
    run_terminal(n, list(args.kind) or list(KINDS), ask, say, args.seed)
    return 0


# ------------------------------------------------------------------ graded checks
VLSM_BLOCK = ipaddress.IPv4Network("172.20.8.0/22")
VLSM_LANS = ((110, "STAFF", 200), (120, "LAB", 100), (130, "VOICE", 50), (140, "PRINTERS", 12))
VLSM_SWITCH = "office"


def check_drill(lab) -> tuple[bool, str]:
    rows = [r for r in history() if r.get("total", 0) >= MIN_QUESTIONS]
    if not rows:
        return False, f"no drill of {MIN_QUESTIONS} questions or more yet: winlab drill subnet"
    best = max(rows, key=lambda r: r.get("percent", 0))
    if best.get("percent", 0) < PASS:
        return False, f"best run {best['right']}/{best['total']} ({best['percent']}%): {PASS}% is the mark"
    return True, f"a drill of {best['total']} at {best['percent']}%"


def check_vlsm_plan(lab) -> tuple[bool, str]:
    from . import devcli
    nets = []
    for tag, name, hosts in VLSM_LANS:
        net = devcli.vlan_net(lab, VLSM_SWITCH, tag)
        if net is None:
            return False, f"the office switch has no VLAN {tag} ({name})"
        if not net.routed:
            return False, (f"VLAN {tag} is not routed: a router sub-interface with encapsulation dot1q {tag}, "
                           f"an address and no shutdown")
        try:
            n = ipaddress.IPv4Network(net.cidr, strict=False)
        except ValueError:
            return False, f"VLAN {tag} has no subnet"
        if not n.subnet_of(VLSM_BLOCK):
            return False, f"VLAN {tag} is {n}, outside {VLSM_BLOCK}"
        need = prefix_for(hosts)
        if n.prefixlen != need:
            return False, f"VLAN {tag} ({hosts} hosts) is a /{n.prefixlen}: the smallest that holds them is /{need}"
        nets.append((tag, n))
    for i, (ta, a) in enumerate(nets):
        for tb, b in nets[i + 1:]:
            if a.overlaps(b):
                return False, f"VLAN {ta} ({a}) and VLAN {tb} ({b}) overlap"
    return True, "four VLANs, each the smallest subnet that holds it, inside 172.20.8.0/22 and apart"


def _register() -> None:
    from . import exercises
    exercises.register_winlab_check("subnet-drill-passed", check_drill)
    exercises.register_winlab_check("subnet-vlsm-plan", check_vlsm_plan)


_register()
