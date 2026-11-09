"""Faults of the hardware and the cabling, on a running workbench network.

Two ways in. From a cable's or a machine's menu on the canvas the user
breaks something on purpose, the way it breaks on a desk: a dead network
card, a bad cable that drops and mangles frames, a link that flaps, a port
that came up at 10 Mbit, a duplex mismatch, a cable in a port of the wrong
VLAN, a full disk. Each shows on the canvas and is listed, so it can be put
right again. Or "Break something for me" hides one to three of them in the
user's own network and says nothing: the user finds them with the lab's own
tools (ipconfig and ping on the machines, the switch's console), fixes them
the way one would (reseat or replace the cable, set the port back to auto),
and "Check my fix" proves each one gone and says what it was, with a hint
ladder for each on the way (the pattern of winlab/guestfaults.py).

Everything is real. The router's switch port (the machine's cable, seen
from the switch) gets netem, a policer, a VLAN it should not carry, or a
loop taking it down and up; a card goes down over QMP, which Windows shows
as "Network cable unplugged"; a disk fills inside the machine with the
guest scenario of winlab/guestfaults.py. What is broken is kept beside the
lab's machines (faults.json), never in the lab file, so a network saved or
shared does not carry it and the desktop restarting forgets nothing. A
fault the router or the machine took with it when it restarted is "lost".
"""

from __future__ import annotations

import json
import random
import re
import time
from dataclasses import dataclass

from . import paths, state

FILE = "faults.json"
FLAP_PID = "/run/winlab-flap-{iface}.pid"
FLAP_DOWN, FLAP_UP = 4, 7      # seconds the flapping port is down, then up
CHECK = "Check my fix"

# Seams for the tests: the router's runner, QMP, a machine's agent channel.
fabric_runner = None   # lab_name -> (run(cmd, timeout) -> str, why)
qmp_class = None       # livenet.set_link's qmp
guest_channel = None   # (lab_name, node_id) -> channel with .run(cmd, shell, timeout) and .close()


class FaultError(Exception):
    pass


def _pt(text: str) -> str:
    """A drill text in the desktop's language (content/i18n/content/<lang>/problems.json)."""
    from .content import problem_text
    return problem_text(text)


@dataclass(frozen=True)
class Kind:
    id: str
    title: str        # what it is, in the menu and when revealed
    on: str           # "port": a machine's cable; "machine"
    side: str         # "router" (its switch port), "card" (QMP), "guest" (inside)
    menu: str         # the canvas menu's words
    symptom: str
    fix: str          # how it is put right by hand
    by: str = "cable"  # "cable": reseating or replacing the cable fixes it; "console"; "" (undo only)
    drill: bool = True
    hints: tuple[str, ...] = ()


KINDS: dict[str, Kind] = {}


def _k(k: Kind) -> None:
    KINDS[k.id] = k


_k(Kind("nic", "Dead network card", "port", "card", "Kill the network card",
        "Windows says 'Network cable unplugged'; the switch port is notconnect while the machine runs",
        "reseat the cable (pull it and plug it back in)",
        hints=("Start at each machine: does its network icon show a cable? On a switch's console, "
               "show interfaces status says which ports have a link.",
               "{machine} says 'Network cable unplugged', and {switch} lists {sw_port} as notconnect "
               "although {machine} runs: the link is down at the card or the plug.",
               "Reseat it: pull {machine}'s cable out of port {nic} and plug it into {switch} again "
               "(drag it off the switch and back on).")))
_k(Kind("bad", "Bad cable", "port", "router", "Make it a bad cable",
        "the link is up, but about one frame in ten is lost or damaged: pings drop, copies crawl",
        "replace the cable",
        hints=("Every machine has a link, yet something is unreliable. Ping each machine's gateway 50 "
               "times (ping -n 50 <gateway>) and compare the losses.",
               "{machine} loses replies, about one in ten, and large copies to or from it stall; the "
               "others are clean. Errors on one link while its light is on: that is the cable.",
               "Replace {machine}'s cable: pull it out of port {nic} and plug a new one into {switch} "
               "(drag it off and on again).")))
_k(Kind("flap", "Flapping link", "port", "router", "Make the link flap",
        f"the port goes down for {FLAP_DOWN} seconds every {FLAP_DOWN + FLAP_UP}: runs of 'Request timed out'",
        "replace the cable",
        hints=("Something drops off and comes back. Leave a ping running (ping -t <gateway>) on each "
               "machine and watch for runs of 'Request timed out'.",
               "{machine} loses everything for a few seconds, again and again. Run show interfaces "
               "status on {switch} a few times: {sw_port} goes notconnect and back.",
               "A port that bounces is a loose or damaged cable: replace {machine}'s cable (pull it "
               "out and plug it in again).")))
_k(Kind("slow", "Port at 10 Mbit", "port", "router", "Run it at 10 Mbit",
        "everything answers, but transfers to and from this machine run at about 1 MB/s",
        "replace the cable (a broken pair makes the ports fall back to 10 Mbit)",
        hints=("Everything answers, but one machine is slow. Copy a large file to and from each "
               "machine and compare the speeds.",
               "{switch}'s show interfaces status lists {sw_port} ({machine}) at a-10 where the "
               "others are a-100: the port negotiated 10 Mbit/s. Ports fall back to it when a pair "
               "of the cable is broken.",
               "Replace {machine}'s cable: pull it and plug a new one in; the port comes back at 100.")))
_k(Kind("duplex", "Duplex mismatch", "port", "router", "Hard-set the port (duplex mismatch)",
        "small pings are fine, but the busier the link the worse it gets: copies crawl and lose packets",
        "set the switch port back to auto: interface <port>, duplex auto, speed auto", by="console",
        hints=("One machine is slow, and worse the busier it is: small pings are fine, big copies "
               "crawl and lose packets. Compare the ports on the switch's console.",
               "On {switch}, show interfaces status: {sw_port} ({machine}) reads full / 100 without "
               "the a- of the others: hard-set, while the card negotiates and, hearing no "
               "negotiation, falls back to half duplex. A duplex mismatch.",
               "Set the port back to auto on {switch}'s console: enable, configure terminal, "
               "interface {sw_port_long}, duplex auto, speed auto, end.")))
_k(Kind("vlan", "Cable in the wrong port", "port", "router", "Plug it into a port of another VLAN",
        "the machine is on another network than the diagram shows: an address of the wrong subnet, "
        "or no way to its gateway",
        "re-patch the cable into the right port (pull it and plug it in again)",
        hints=("One machine cannot reach its gateway, or has an address of another network. Run "
               "ipconfig on each machine and compare it with the subnet of the switch it is drawn on.",
               "{machine}'s cable is not in the port the diagram shows: it is in a port of "
               "{wrong_place}, so {machine} is on that network. The router's "
               "show arp lists it on the wrong interface.",
               "Re-patch it: pull {machine}'s cable out and plug it into {switch} again (drag it "
               "off the switch and back on).")))
# The wiring faults a cable tester names (winlab/cabletest.py reads them
# back as a wire map): a pair split across two twisted pairs (the link comes
# up, crosstalk wrecks what crosses it), a wire cut (open), two wires
# touching (short), and two pairs crossed at one end (a mispunched jack).
# The last three take the link down at the card, as the real ones do on a
# 10/100 link that needs both of its pairs.
_k(Kind("split", "Split pair", "port", "router", "Wire it with a split pair",
        "the link lights are on and the port is up at 100, but almost nothing gets through: half the pings "
        "lost, logons and DHCP time out",
        "replace the cable (or re-terminate it, keeping each pair on its own pins)",
        hints=("One desk has link lights and no network. Ping its gateway 20 times (ping -n 20 <gateway>) and "
               "look at the switch's port: up, at a-100, error-free on the switch's side.",
               "{machine} loses about half of everything although {switch} shows {sw_port} connected at a-100: "
               "the link is up and the signal is garbage. Put a cable tester on {machine}'s cable (its menu, "
               "Test the cable): the wire map shows what is wrong inside it.",
               "The tester says split pair: the wires go pin to pin, but two of them are twisted with the wrong "
               "partner, so the pair picks up crosstalk. Replace {machine}'s cable (pull it and plug a new one "
               "into {switch}).")))
_k(Kind("open", "Open wire", "port", "card", "Cut a wire in it (open)",
        "no link at either end: Windows says 'Network cable unplugged' and the switch port is notconnect",
        "replace the cable (or re-terminate the end with the cut wire)",
        hints=("Start at each machine: does its network icon show a cable? show interfaces status on the "
               "switch says which ports have a link.",
               "{machine} says 'Network cable unplugged' and {switch} lists {sw_port} as notconnect while "
               "{machine} runs. Is it the card or the cable? Test the cable (its menu, Test the cable).",
               "The tester shows a wire open part way along: replace {machine}'s cable (pull it and plug a new one "
               "into {switch}).")))
_k(Kind("short", "Shorted pair", "port", "card", "Short two wires in it",
        "no link at either end: Windows says 'Network cable unplugged' and the switch port is notconnect",
        "replace the cable (a crushed cable or a bad crimp shorts two wires together)",
        hints=("Start at each machine: does its network icon show a cable? show interfaces status on the "
               "switch says which ports have a link.",
               "{machine} has no link and {switch} lists {sw_port} as notconnect. Test the cable before you "
               "suspect the card (its menu, Test the cable).",
               "The tester shows two wires shorted together at a distance: a crushed cable or a bad crimp. "
               "Replace {machine}'s cable.")))
_k(Kind("crossed", "Crossed pairs (mispunched)", "port", "card", "Punch it down with two pairs crossed",
        "no link at either end: Windows says 'Network cable unplugged' and the switch port is notconnect",
        "re-terminate the miswired end to T568B (or replace the cable)",
        hints=("Start at each machine: does its network icon show a cable? show interfaces status on the "
               "switch says which ports have a link.",
               "{machine} has no link and {switch} lists {sw_port} as notconnect: a new jack was punched down "
               "here recently. Test the cable (its menu, Test the cable).",
               "The wire map shows the green and the blue pairs swapped at one end: the receive pair lands on "
               "pins the card does not listen on. Re-terminate (here: replace {machine}'s cable).")))
_k(Kind("disk", "Disk full", "machine", "guest", "Fill its disk",
        "'low disk space', services fail to write, logons slow", "find the file that ate the disk and delete it",
        by="", drill=False))


# ------------------------------------------------------------------ records
def _path(lab_name: str):
    return paths.lab_dir(lab_name) / FILE


def load(lab_name: str) -> dict:
    try:
        data = json.loads(_path(lab_name).read_text(encoding="utf-8"))
        if isinstance(data.get("faults"), list):
            data.setdefault("drill", None)
            data.setdefault("seq", 0)
            return data
    except (OSError, ValueError, AttributeError):
        pass
    return {"faults": [], "drill": None, "seq": 0}


def _write(lab_name: str, data: dict) -> None:
    state.write_json(_path(lab_name), data)


def _pid(lab_name: str, node_id: str) -> int:
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    return ns.pid if ns and ns.pid and state.pid_alive(ns.pid) else 0


def card_side(kind: str) -> bool:
    """A fault that takes the link down at the machine's card (a dead card,
    or a cable with no working pair to carry the link)."""
    k = KINDS.get(kind)
    return bool(k and k.side == "card")


def _holder(rec: dict) -> str:
    return "fabric" if KINDS[rec["kind"]].side == "router" else rec["node"]


def refresh(lab_name: str, data: dict | None = None) -> dict:
    """The records, with a fault whose router or machine restarted since it
    was made marked lost (the restart took it: tc and links start clean; a
    full disk stays full)."""
    data = data or load(lab_name)
    changed = False
    for rec in data["faults"]:
        if rec["state"] == "on" and KINDS[rec["kind"]].side != "guest" \
                and _pid(lab_name, _holder(rec)) != rec.get("pid"):
            rec["state"], rec["how"] = "lost", (
                "the router restarted" if _holder(rec) == "fabric" else f"{rec['node']} restarted")
            changed = True
    if changed:
        _write(lab_name, data)
    return data


def active(lab_name: str, link: str = "", node: str = "") -> list[dict]:
    return [r for r in refresh(lab_name)["faults"] if r["state"] == "on"
            and (not link or r.get("link") == link) and (not node or r["node"] == node)]


# ------------------------------------------------------------------ the router's side
def _tc_off(i: str) -> list[str]:
    return [f"tc qdisc del dev {i} root 2>/dev/null || true", f"tc qdisc del dev {i} ingress 2>/dev/null || true"]


# The cable's two directions: towards the machine (the port's egress
# qdisc) and from it (a filter on the port's ingress).
_TC = {"bad": ("netem loss 8% 25% corrupt 2%", "action gact ok random netrand drop 12"),  # 1 in 12
       "split": ("netem loss 45% 25% corrupt 6%", "action gact ok random netrand drop 2"),  # 1 in 2
       "slow": ("tbf rate 10mbit burst 16kb latency 60ms", "police rate 10mbit burst 16k drop"),
       "duplex": ("netem rate 10mbit loss 3%", "police rate 10mbit burst 16k drop")}


def router_script(rec: dict, clear: bool, vid: int | None = None) -> list[str]:
    """The commands that break (or mend) the switch port of one cable.
    `vid` is the port's right VLAN now, for mending a wrong-port fault."""
    i, k = rec["iface"], rec["kind"]
    out = [f"# {'mend' if clear else 'break'} {rec['link']}: {KINDS[k].title}"]
    if k in _TC:
        if clear:
            return out + _tc_off(i)
        root, ingress = _TC[k]
        return out + _tc_off(i) + [f"tc qdisc add dev {i} root {root}",
                                   f"tc qdisc add dev {i} handle ffff: ingress",
                                   f"tc filter add dev {i} parent ffff: protocol all prio 1 u32 match u32 0 0 {ingress}"]
    if k == "flap":
        pid = FLAP_PID.format(iface=i)
        stop = f"kill $(cat {pid} 2>/dev/null) 2>/dev/null || true"
        if clear:
            return out + [stop, f"rm -f {pid}", f"ip link set {i} up"]
        # Its own fds, or the agent would wait for it to finish.
        return out + [stop, f"(while :; do ip link set {i} down; sleep {FLAP_DOWN}; ip link set {i} up; "
                            f"sleep {FLAP_UP}; done) </dev/null >/dev/null 2>&1 & echo $! > {pid}"]
    if k == "vlan":
        right = rec["vid"] if vid is None else vid
        if clear:
            return out + [f"bridge vlan del dev {i} vid {rec['wrong']} 2>/dev/null || true",
                          f"bridge vlan add dev {i} vid {right} pvid untagged"]
        return out + [f"bridge vlan del dev {i} vid {rec['vid']} 2>/dev/null || true",
                      f"bridge vlan add dev {i} vid {rec['wrong']} pvid untagged"]
    return out


def probe_cmd(recs: list[dict]) -> str:
    """What the router's switch ports hold now, per fault: their qdiscs and
    filters, a flapping loop, the VLANs they carry."""
    parts = []
    for r in recs:
        i = r["iface"]
        parts.append(f"echo '#{r['id']}'; echo '@tc'; tc qdisc show dev {i} 2>/dev/null; "
                     f"tc filter show dev {i} parent ffff: 2>/dev/null; echo '@flap'; "
                     f"kill -0 $(cat {FLAP_PID.format(iface=i)} 2>/dev/null) 2>/dev/null && echo FLAPPING; "
                     f"echo '@vlan'; bridge vlan show dev {i} 2>/dev/null")
    return "; ".join(parts)


def parse_probe(text: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    cur, sub = None, ""
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith("#") and len(s) > 1 and " " not in s:
            cur, sub = out.setdefault(s[1:], {"tc": "", "flap": "", "vlan": ""}), ""
        elif s.startswith("@") and cur is not None:
            sub = s[1:]
        elif cur is not None and sub in cur:
            cur[sub] += line + "\n"
    return out


def still_there(rec: dict, seen: dict[str, str]) -> bool:
    """Whether the router's port still shows the fault."""
    k, tc = rec["kind"], seen.get("tc", "")
    if k in ("bad", "split"):
        return "netem" in tc or "gact" in tc
    if k == "slow":
        return "tbf" in tc or "police" in tc
    if k == "duplex":
        return "netem" in tc or "police" in tc
    if k == "flap":
        return "FLAPPING" in seen.get("flap", "")
    if k == "vlan":
        vids = {int(t) for line in seen.get("vlan", "").splitlines() for t in line.split() if t.isdigit()}
        return int(rec["wrong"]) in vids
    return True


def _router(lab_name: str):
    factory = fabric_runner
    if factory is None:
        from .cli import _fabric_runner as factory
    run, why = factory(lab_name)
    if not run:
        raise FaultError(f"cannot reach the router: {why}")
    return run


def _on_router(lab_name: str, lines: list[str], timeout: float = 40) -> str:
    run = _router(lab_name)
    try:
        return run("\n".join(lines), timeout=timeout) or ""
    finally:
        close = getattr(run, "close", None)
        if close:
            close()


# ------------------------------------------------------------------ the machines' side
def _card(lab_name: str, node_id: str, nic: int, up: bool) -> None:
    from . import livenet
    port = state.qmp_port(lab_name, node_id)
    if not port or not livenet.set_link(port, nic, up, qmp=qmp_class, tries=3):
        raise FaultError(f"{node_id}'s network card did not answer (QMP)")


def _guest(lab_name: str, node_id: str, cmd: str, shell: str) -> None:
    if guest_channel is not None:
        ch = guest_channel(lab_name, node_id)
    else:
        from .guestctl import GuestChannel, GuestError
        st = state.load(lab_name)
        ns = st.nodes.get(node_id) if st else None
        try:
            ch = GuestChannel(ns.serial_port).connect(retries=4, delay=2)
        except (GuestError, OSError, AttributeError) as exc:
            raise FaultError(f"{node_id}'s agent does not answer ({exc}); it needs its operating "
                             f"system installed and running") from None
    from .guestctl import GuestError
    try:
        # A machine still in its firmware or Setup has no agent: say so in
        # seconds rather than wait out the command.
        if not ch.run("echo ok", shell=shell, timeout=15).ok:
            raise FaultError(f"{node_id}'s agent does not answer yet; it needs its operating system running")
        res = ch.run(cmd, shell=shell, timeout=180)
    except GuestError as exc:
        raise FaultError(f"{node_id}'s agent does not answer ({exc}); it needs its operating system "
                         f"installed and running") from None
    finally:
        ch.close()
    if not res.ok:
        raise FaultError(f"{node_id}: {(res.err or res.out or 'failed').strip()[:200]}")


def _disk_scenario(node) -> str:
    from .model import LINUX
    if node.is_windows:
        return "disk-full"
    if node.kind == LINUX:
        return "linux-disk-full"
    raise FaultError(f"winlab cannot reach inside {node.id} (its own disc's operating system)")


# ------------------------------------------------------------------ making and mending
def _plan(lab):
    from . import netplan
    return netplan.compile_topology(lab, check_ports=False)


def _link(lab, plan, node_id: str, nic: int):
    from . import wifi
    node = lab.nodes.get(node_id)
    if node is None:
        raise FaultError(f"no machine {node_id!r} on the canvas")
    link = next((l for l in plan.ports_for(node_id) if l.nic_index == nic), None)
    if link is None:
        raise FaultError(f"{node_id} has no network card {nic + 1}")
    if nic in wifi.wireless(node):
        raise FaultError("that is the Wi-Fi card: it has no cable")
    if not link.plugged:
        raise FaultError(f"{node_id} port {nic + 1} has no cable in")
    return link


def _wrong_vid(lab, plan, link, rng) -> tuple[int, str, str] | None:
    """A port of another VLAN for the cable: of the same switch when it has
    more VLANs (the wrong VLAN port), else of another switch."""
    right = plan.vid_of(link)
    home = lab.networks[link.network_id].home
    others = [(seg.vid, sid) for sid, seg in sorted(plan.segments.items()) if seg.vid != right]
    if not others:
        return None
    same = [o for o in others if lab.networks[o[1]].home == home]
    from . import devcli
    vid, sid = rng.choice(same or others)
    net = lab.networks[sid]
    place = (f"VLAN {net.vlan_no} ({sid})" if net.home == home else
             f"switch {devcli.hostname(lab, 'sw:' + net.home)}" + (f" (VLAN {net.vlan_no})" if net.vlan_no > 1 else ""))
    return vid, sid, place


def add(lab, kind: str, node_id: str, nic: int = 0, hidden: bool = False, rng=None) -> dict:
    """Breaks it: a record kept in faults.json."""
    from . import livenet
    k = KINDS.get(kind)
    if k is None:
        raise FaultError(f"no fault {kind!r} (one of {', '.join(KINDS)})")
    rng = rng or random.Random()
    dr = load(lab.name)["drill"]
    if not hidden and dr and not dr.get("done"):
        raise FaultError(f"faults are hidden in this network: find them first (or Show me), then break more")
    node = lab.nodes.get(node_id)
    if node is None:
        raise FaultError(f"no machine {node_id!r} on the canvas")
    rec = {"kind": kind, "node": node_id, "nic": nic, "link": "", "hidden": hidden,
           "state": "on", "how": "", "at": int(time.time())}
    # Where along the cable it is (as a fraction of its length): what the
    # tester's TDR reads back (winlab/cabletest.py).
    rec["along"] = round(rng.uniform(0.2, 0.85), 3)
    if k.on == "port":
        plan = _plan(lab)
        link = _link(lab, plan, node_id, nic)
        rec["link"] = link.label
        if active(lab.name, link=link.label):
            raise FaultError(f"{link.label}'s cable already has a fault; undo it first")
    elif active(lab.name, node=node_id) and any(r["kind"] == kind for r in active(lab.name, node=node_id)):
        raise FaultError(f"{node_id} already has that fault")
    if k.side == "router":
        fab = livenet._router(lab.name)
        if fab is None or not livenet.pinned_ports(lab.name):
            raise FaultError("power the network on first: these faults happen to a running network")
        rec["pid"], rec["iface"] = fab.pid, link.fabric_iface
        if not rec["iface"]:
            raise FaultError(f"the router has no port for {link.label} yet; try again in a moment")
        if kind == "vlan":
            got = _wrong_vid(lab, plan, link, rng)
            if got is None:
                raise FaultError("there is no other VLAN to plug it into: add another switch first")
            rec["vid"] = plan.vid_of(link)
            rec["wrong"], rec["wrong_net"], rec["wrong_place"] = got
        _on_router(lab.name, router_script(rec, clear=False))
    elif k.side == "card":
        rec["pid"] = _pid(lab.name, node_id)
        if not rec["pid"]:
            raise FaultError(f"power {node_id} on first: its card dies while it runs")
        _card(lab.name, node_id, nic, False)
    else:
        from . import guestfaults
        if not _pid(lab.name, node_id):
            raise FaultError(f"power {node_id} on first")
        sc = _disk_scenario(node)
        cmd, shell = guestfaults.build_command(sc, guestfaults.lab_params(lab), clear=False)
        rec["scenario"] = sc
        _guest(lab.name, node_id, cmd, shell)
    data = refresh(lab.name)
    data["seq"] += 1
    rec["id"] = f"f{data['seq']}"
    data["faults"].append(rec)
    _write(lab.name, data)
    return rec


def _mend(lab, rec: dict) -> None:
    """Undoes the fault on the router or the machine (nothing to undo for
    one a restart already took)."""
    from . import devcli
    k = KINDS[rec["kind"]]
    if k.side == "router":
        if _pid(lab.name, "fabric") == rec.get("pid"):
            vid = None
            if rec["kind"] == "vlan":
                plan = _plan(lab)
                link = next((l for l in plan.ports if l.label == rec["link"]), None)
                vid = plan.vid_of(link) if link else rec["vid"]
            _on_router(lab.name, router_script(rec, clear=True, vid=vid))
    elif k.side == "card":
        if _pid(lab.name, rec["node"]) == rec.get("pid"):
            plan = _plan(lab)
            link = next((l for l in plan.ports if l.label == rec["link"]), None)
            if link is not None and link.plugged and not devcli.held_down(lab, link):
                _card(lab.name, rec["node"], rec["nic"], True)
    else:
        from . import guestfaults
        if _pid(lab.name, rec["node"]):
            cmd, shell = guestfaults.build_command(rec["scenario"], guestfaults.lab_params(lab), clear=True)
            _guest(lab.name, rec["node"], cmd, shell)


def clear(lab, fault_id: str, how: str = "undone") -> dict:
    data = refresh(lab.name)
    rec = next((r for r in data["faults"] if r["id"] == fault_id), None)
    if rec is None:
        raise FaultError(f"no fault {fault_id}")
    if rec["state"] == "on":
        _mend(lab, rec)
        rec["state"], rec["how"] = "fixed", how
    if not rec["hidden"]:
        data["faults"].remove(rec)
    _write(lab.name, data)
    return rec


def clear_all(lab) -> list[dict]:
    """Every fault broken on purpose, mended (the hidden ones stay hidden);
    one that cannot be undone now (its machine's agent is down) stays listed."""
    done, why = [], []
    for r in list(refresh(lab.name)["faults"]):
        if not r["hidden"]:
            try:
                done.append(clear(lab, r["id"]))
            except FaultError as exc:
                why.append(str(exc))
    if why and not done:
        raise FaultError("; ".join(why))
    return done


def recabled(lab, node_id: str, nic: int) -> list[str]:
    """A cable pulled out or moved: a fault in that cable (or its plug, or
    its port) goes with it. Called before the workbench changes the cable;
    never raises, the cable moves either way."""
    from . import naming
    try:
        node_id = naming.resolve(lab, node_id)
        label = f"{node_id}:nic{nic}"
        node = lab.nodes.get(node_id)
        if node is None or nic >= len(node.nics) or not node.nics[nic].plugged:
            return []
        data = refresh(lab.name)
        if data["drill"] and not data["drill"].get("done") and label not in data["drill"]["touched"]:
            data["drill"]["touched"].append(label)
            _write(lab.name, data)
        done = []
        for rec in active(lab.name, link=label):
            if KINDS[rec["kind"]].by == "cable":
                clear(lab, rec["id"], how="cable")
                done.append(rec["id"])
        return done
    except Exception:  # noqa: BLE001 - a fault must never stop a cable moving
        return []


def port_auto(lab, link) -> bool:
    """`duplex auto` on the switch port: a hard-set port negotiates again.
    True when that mended a mismatch."""
    hit = [r for r in active(lab.name, link=link.label) if r["kind"] == "duplex"]
    for rec in hit:
        clear(lab, rec["id"], how="console")
    return bool(hit)


def port_look(lab, link) -> dict:
    """How the switch shows the port: its duplex, speed and link."""
    out = {"duplex": "a-full", "speed": "a-100", "down": False}
    for rec in active(lab.name, link=link.label):
        k = rec["kind"]
        if card_side(k):
            out["down"] = True
        elif k == "flap":
            out["down"] = (time.time() - rec["at"]) % (FLAP_DOWN + FLAP_UP) < FLAP_DOWN
        elif k == "slow":
            out["speed"] = "a-10"
        elif k == "duplex":
            out["duplex"], out["speed"] = "full", "100"
    return out


# ------------------------------------------------------------------ break something for me
def candidates(lab, plan) -> list:
    """The machine cables a hidden fault may go into: plugged, access ports
    (not Wi-Fi, not a trunk to a hypervisor)."""
    from . import wifi
    return [l for l in plan.ports if l.plugged and not l.trunk_vlans
            and l.nic_index not in wifi.wireless(lab.nodes[l.node_id])]


def drill_start(lab, count: int = 0, rng=None) -> dict:
    from . import livenet
    rng = rng or random.Random()
    data = refresh(lab.name)
    if data["drill"] and not data["drill"].get("done"):
        raise FaultError(f"faults are already hidden in this network: find them, then {CHECK}")
    if livenet._router(lab.name) is None:
        raise FaultError("power the network on first: the faults go into a running network")
    plan = _plan(lab)
    links = [l for l in candidates(lab, plan) if not active(lab.name, link=l.label)]
    if not links:
        raise FaultError("cable a machine to a switch first: the faults hide in your cabling")
    count = max(1, min(int(count or rng.randint(1, 3)), 3, len(links)))
    picked = rng.sample(links, count)
    used: list[str] = []
    made = []
    for link in picked:
        kinds = [k.id for k in KINDS.values() if k.drill and k.on == "port"]
        if not _pid(lab.name, link.node_id):
            kinds = [x for x in kinds if not card_side(x)]
        if _wrong_vid(lab, plan, link, rng) is None:
            kinds.remove("vlan")
        fresh = [k for k in kinds if k not in used] or kinds
        kind = rng.choice(fresh)
        used.append(kind)
        made.append(add(lab, kind, link.node_id, link.nic_index, hidden=True, rng=rng))
    data = refresh(lab.name)
    data["faults"] = [r for r in data["faults"] if not r["hidden"] or r["id"] in {m["id"] for m in made}]
    data["drill"] = {"ids": [m["id"] for m in made], "hints": {}, "touched": [], "checks": 0,
                     "started": int(time.time()), "done": False, "gave_up": False}
    _write(lab.name, data)
    n = len(made)
    return {"count": n, "message": f"{n} fault{'s are' if n != 1 else ' is'} hidden in your network. "
                                   f"Find {'them' if n != 1 else 'it'} with the machines' own tools, "
                                   f"fix {'them' if n != 1 else 'it'}, then press {CHECK}."}


def _hidden(data: dict) -> list[dict]:
    ids = (data["drill"] or {}).get("ids", [])
    by = {r["id"]: r for r in data["faults"]}
    return [by[i] for i in ids if i in by]


def _where(lab, rec: dict, plan=None) -> dict:
    """The words a hint or a reveal names the fault's place with."""
    from . import devcli, naming
    plan = plan or _plan(lab)
    out = {"machine": naming.display(lab, rec["node"]), "nic": rec["nic"] + 1, "switch": "the switch",
           "sw_port": "its port", "sw_port_long": "FastEthernet0/<n>",
           "wrong_place": rec.get("wrong_place", "")}
    for sw, links in devcli.switch_ports(lab, plan).items():
        for i, l in enumerate(links):
            if l is not None and l.label == rec.get("link"):
                out.update(switch=devcli.hostname(lab, f"sw:{sw}"), sw_port=f"Fa0/{i + 1}",
                           sw_port_long=f"FastEthernet0/{i + 1}")
    return out


def _fill(text: str, words: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: str(words.get(m.group(1), m.group(0))), text)


def _reveal(lab, rec: dict, plan=None) -> dict:
    k, w = KINDS[rec["kind"]], _where(lab, rec, plan)
    place = f"{w['machine']} port {w['nic']}" + (f" ({w['switch']} {w['sw_port']})" if k.on == "port" else "")
    if rec["kind"] == "vlan":
        place += f", in a port of {w['wrong_place']}"
    how = {"cable": "you reseated or replaced the cable", "console": "you set the port back to auto",
           "gone": "it is gone from the router", "shown": "shown to you and mended",
           "undone": "undone"}.get(rec["how"], rec["how"] or "")
    return {"id": rec["id"], "kind": rec["kind"], "title": _pt(k.title), "where": place, "link": rec.get("link", ""),
            "node": rec["node"], "symptom": _pt(k.symptom), "fix": _pt(k.fix), "state": rec["state"], "how": how}


def drill_check(lab) -> dict:
    """Check my fix: each hidden fault proved gone on the router (or by the
    record, for a card), and the ones gone revealed."""
    data = refresh(lab.name)
    dr = data["drill"]
    if not dr:
        raise FaultError("nothing is hidden: press Break something for me first")
    recs = _hidden(data)
    on_router = [r for r in recs if KINDS[r["kind"]].side == "router" and r["state"] != "lost"
                 and _pid(lab.name, "fabric") == r.get("pid")]
    if on_router:
        try:
            seen = parse_probe(_on_router(lab.name, [probe_cmd(on_router)]))
        except FaultError:
            seen = {}
        for r in on_router:
            if r["id"] not in seen:
                continue
            there = still_there(r, seen[r["id"]])
            if r["state"] == "on" and not there:
                r["state"], r["how"] = "fixed", "gone"   # mended some other way
            elif r["state"] == "fixed" and there:
                r["state"] = "on"                        # the mending did not hold
    dr["checks"] += 1
    left = [r for r in recs if r["state"] == "on"]
    dr["done"] = not left
    _write(lab.name, data)
    plan = _plan(lab)
    gone = [_reveal(lab, r, plan) for r in recs if r["state"] != "on"]
    if left:
        msg = (f"{len(gone)} of {len(recs)} fixed; {len(left)} still there. "
               f"Keep looking, or ask for a hint.")
    else:
        extra = len(dr["touched"]) - sum(1 for r in recs if r["how"] == "cable")
        msg = f"All {len(recs)} fixed." + (f" You handled {extra} cable{'s' if extra != 1 else ''} that "
                                           f"had nothing wrong." if extra > 0 else "")
    return {"fixed": not left, "left": len(left), "total": len(recs), "revealed": gone, "message": msg}


def drill_hint(lab) -> dict:
    data = refresh(lab.name)
    dr = data["drill"]
    left = [r for r in _hidden(data) if r["state"] == "on"] if dr else []
    if not left:
        raise FaultError("nothing left to find" if dr else "nothing is hidden")
    rec = left[0]
    k = KINDS[rec["kind"]]
    n = min(int(dr["hints"].get(rec["id"], 0)) + 1, len(k.hints))
    dr["hints"][rec["id"]] = n
    _write(lab.name, data)
    pos = dr["ids"].index(rec["id"]) + 1
    return {"n": n, "of": len(k.hints), "fault": pos, "total": len(dr["ids"]),
            "text": _fill(_pt(k.hints[n - 1]), _where(lab, rec)),
            "message": f"fault {pos} of {len(dr['ids'])}, hint {n} of {len(k.hints)}"}


def drill_reveal(lab) -> dict:
    """Give up: every hidden fault shown and mended."""
    data = refresh(lab.name)
    if not data["drill"]:
        raise FaultError("nothing is hidden")
    for rec in _hidden(data):
        if rec["state"] == "on":
            clear(lab, rec["id"], how="shown")
    data = refresh(lab.name)
    data["drill"].update(done=True, gave_up=True)
    _write(lab.name, data)
    plan = _plan(lab)
    return {"revealed": [_reveal(lab, r, plan) for r in _hidden(data)], "message": "here is what was broken"}


def drill_end(lab) -> None:
    """Puts the finished drill away (mending what is still hidden)."""
    data = refresh(lab.name)
    for rec in _hidden(data):
        if rec["state"] == "on":
            clear(lab, rec["id"], how="shown")
    data = refresh(lab.name)
    data["faults"] = [r for r in data["faults"] if not r["hidden"]]
    data["drill"] = None
    _write(lab.name, data)


# ------------------------------------------------------------------ the canvas
def _pub(lab, rec: dict, plan) -> dict:
    k, w = KINDS[rec["kind"]], _where(lab, rec, plan)
    return {"id": rec["id"], "kind": rec["kind"], "title": _pt(k.title), "node": rec["node"], "nic": rec["nic"],
            "link": rec.get("link", ""), "where": f"{w['machine']}" + (f" port {w['nic']}" if k.on == "port" else ""),
            "symptom": _pt(k.symptom), "fix": _pt(k.fix)}


def view(lab, plan=None) -> dict:
    """What the canvas shows: the faults broken on purpose (never the
    hidden ones), and the drill's count, checks and what it revealed."""
    data = refresh(lab.name)
    plan = plan or _plan(lab)
    out = {"faults": [_pub(lab, r, plan) for r in data["faults"] if r["state"] == "on" and not r["hidden"]],
           "kinds": [{"id": k.id, "title": _pt(k.title), "on": k.on, "menu": k.menu, "symptom": _pt(k.symptom)}
                     for k in KINDS.values()],
           "drill": None}
    dr = data["drill"]
    if dr:
        recs = _hidden(data)
        shown = dr.get("done") or dr.get("gave_up")
        out["drill"] = {"total": len(recs), "left": sum(r["state"] == "on" for r in recs),
                        "done": bool(dr.get("done")), "gave_up": bool(dr.get("gave_up")),
                        "checks": dr["checks"], "hints": sum(dr["hints"].values()),
                        "touched": len(dr["touched"]),
                        # What a check proved gone is shown; the rest only once it is over.
                        "revealed": [_reveal(lab, r, plan) for r in recs
                                     if shown or (r["state"] != "on" and dr["checks"])]}
    return out


def act(dash, action: str, params: dict) -> dict:
    """The workbench's wb-fault and wb-drill actions."""
    from . import naming
    lab = dash.lab
    op = str(params.get("op") or "")
    try:
        if action == "wb-fault":
            if op == "add":
                node = naming.resolve(lab, str(params.get("node") or ""))
                rec = add(lab, str(params.get("kind") or ""), node, int(params.get("nic") or 0))
                k = KINDS[rec["kind"]]
                return {"ok": True, "id": rec["id"], "message": f"{_pt(k.title)}: {naming.display(lab, node)}"
                        f"{' port ' + str(rec['nic'] + 1) if k.on == 'port' else ''} — {_pt(k.symptom)}"}
            if op == "clear":
                if params.get("id") == "all":
                    n = len(clear_all(lab))
                    return {"ok": True, "message": f"{n} fault{'s' if n != 1 else ''} undone"}
                rec = clear(lab, str(params.get("id") or ""))
                return {"ok": True, "message": f"{_pt(KINDS[rec['kind']].title)} undone"}
            return {"ok": True, **view(lab, dash.plan)}
        if op == "start":
            return {"ok": True, **drill_start(lab, int(params.get("count") or 0))}
        if op == "check":
            return {"ok": True, **drill_check(lab)}
        if op == "hint":
            return {"ok": True, **drill_hint(lab)}
        if op == "reveal":
            return {"ok": True, **drill_reveal(lab)}
        if op == "end":
            drill_end(lab)
            return {"ok": True, "message": "back to your network as you built it"}
        raise FaultError(f"no such step {op!r}")
    except (FaultError, ValueError) as exc:
        return {"ok": False, "message": str(exc)}


# ------------------------------------------------------------------ winlab fault
def run_cli(args) -> int:
    """winlab fault <lab> ...: the same faults from the command line."""
    import sys

    from . import naming, schema
    try:
        lab = schema.load(args.lab)
    except Exception as exc:  # noqa: BLE001 - the CLI reports it
        print(f"{exc}", file=sys.stderr)
        return 2
    op = args.faultcmd or "list"
    try:
        if op == "kinds":
            for k in KINDS.values():
                print(f"  {k.id:<8} {k.title:<24} {k.symptom}")
            return 0
        if op == "list":
            v = view(lab)
            for f in v["faults"]:
                print(f"  {f['id']:<5} {f['title']:<24} {f['where']}")
            if not v["faults"]:
                print("  nothing broken on purpose")
            d = v["drill"]
            if d:
                print(f"hidden: {d['total']} ({d['left']} left, {d['checks']} checks, {d['hints']} hints)")
                for r in d["revealed"]:
                    print(f"  found: {r['title']} — {r['where']}")
            return 0
        if op == "add":
            rec = add(lab, args.kind, naming.resolve(lab, args.node), max(0, args.nic - 1))
            print(f"{rec['id']}: {KINDS[rec['kind']].title} — {KINDS[rec['kind']].symptom}")
            return 0
        if op == "clear":
            if args.id == "all":
                print(f"{len(clear_all(lab))} undone")
            else:
                print(f"{KINDS[clear(lab, args.id)['kind']].title} undone")
            return 0
        if op == "drill":
            print(drill_start(lab, args.count)["message"])
            return 0
        if op == "check":
            r = drill_check(lab)
            for x in r["revealed"]:
                print(f"  {x['title']}: {x['where']} ({x['how']})")
            print(r["message"])
            return 0 if r["fixed"] else 1
        if op == "hint":
            r = drill_hint(lab)
            print(f"{r['message']}: {r['text']}")
            return 0
        if op == "reveal":
            for x in drill_reveal(lab)["revealed"]:
                print(f"  {x['title']}: {x['where']} — {x['symptom']}")
            return 0
        if op == "end":
            drill_end(lab)
            return 0
    except FaultError as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    return 2


def add_cli(sub) -> None:
    """The `winlab fault` parser."""
    fp = sub.add_parser("fault", help="break a running network's cables and cards, or hide faults to find")
    fp.add_argument("lab")
    fs = fp.add_subparsers(dest="faultcmd", metavar="<op>")
    fs.add_parser("kinds", help="the faults there are")
    fs.add_parser("list", help="what is broken, and the hidden faults' progress")
    fa = fs.add_parser("add", help="break a machine's cable, card or disk")
    fa.add_argument("kind", choices=list(KINDS))
    fa.add_argument("node")
    fa.add_argument("--nic", type=int, default=1, help="its network port (1 = the first)")
    fc = fs.add_parser("clear", help="undo a fault (its id, or all)")
    fc.add_argument("id")
    fd = fs.add_parser("drill", help="break something for me: hide 1-3 cabling faults")
    fd.add_argument("--count", type=int, default=0, help="how many (default: 1 to 3)")
    fs.add_parser("check", help="check my fix")
    fs.add_parser("hint", help="the next hint for the first fault not found")
    fs.add_parser("reveal", help="give up: show and mend what is still hidden")
    fs.add_parser("end", help="put the finished drill away")
