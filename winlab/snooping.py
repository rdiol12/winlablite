"""DHCP snooping and Dynamic ARP Inspection on the workbench's switches.

DHCP snooping sorts a switch's ports into trusted (where a real DHCP server,
or the uplink towards one, is) and untrusted (everything else). On an
untrusted port a DHCP server's messages (OFFER, ACK, NAK: UDP from port 67)
are dropped, so a box someone plugged in with its own DHCP server switched on
cannot hand out addresses; the switch learns, from the ACKs it lets through,
which address each client was given on which port: the binding table.
``ip dhcp snooping limit rate <pps>`` err-disables a port that sends more
DHCP than that (a client flooding DISCOVERs). Dynamic ARP Inspection checks
every ARP that comes in on an untrusted port of its VLANs against that table:
an ARP whose sender address and MAC are not a binding is dropped, which is
what stops a machine from claiming the gateway's address.

How it is real. Every machine's cable is a port of the router's bridge
(winlab/netplan.py), and the rules are nftables' bridge family in the table
port security and 802.1X already use (portsec.TABLE), built by the same
render and pushed by the same live path (winlab/livenet.py, "psec"):

* an untrusted port in a snooped VLAN gets a rule that drops UDP from port
  67 coming in on it, counts it and remembers the sender's MAC (sdrop_<port>,
  sbad_<port>): what show ip dhcp snooping statistics and the switch's log
  report;
* the router's own DHCP (dnsmasq on its VLAN interface, a pool typed at its
  console, or its relay of another server's answers) reaches the ports
  through the switch's uplink, GigabitEthernet0/1: unless that is trusted,
  the bridge's output hook drops those answers on their way to the switch's
  ports, as a real switch drops them coming in on an untrusted uplink;
* the binding table is the router's own: tcpdump watches every DHCP answer
  that leaves the bridge through a machine's port (so only what snooping
  let through), and a small awk program reads the ACKs in it (the address in
  yiaddr, the client's MAC in chaddr, the lease time in option 51) and puts
  them into an nftables set of address . MAC with the lease as its timeout,
  so a binding expires when its lease does, in the kernel; a file beside it
  (snoop.bind) keeps them with their port across the table being rebuilt;
* DAI drops ARP that comes in on an untrusted port of an inspected VLAN when
  its sender address . sender MAC is not in that set (dai_<port>), and ARP
  from the router itself on its way through an untrusted uplink (the
  router's address is no DHCP client's). ARP probes (sender 0.0.0.0) pass.
  ``ip arp inspection validate src-mac`` also checks the frame's own source
  MAC against the binding, and ``ip`` drops ARP for broadcast or multicast
  addresses;
* the rate limit is an nftables limit on DHCP coming in on the port; what
  goes over it is counted, and a watcher on the router disables the bridge
  port the moment that counter moves. The switch then err-disables the port
  as port security does (the same psec-err state, show interfaces status,
  shutdown / no shutdown, errdisable recovery cause dhcp-rate-limit).

What it does not do, and says so: option 82 is never inserted (the bridge
cannot rewrite a DHCP packet; ``no ip dhcp snooping information option``
is kept and shown, and is what to type on a real switch with a server that
is not a relay); ``validate dst-mac`` is kept but not enforced (nftables
cannot compare two fields of one frame); DAI has no rate limit and no ARP
ACLs (a machine with a static address on an untrusted port is dropped, so
trust its port); bindings are not removed on DHCPRELEASE, only when their
lease runs out; the binding table is one for all switches. Tested here by
unit tests of the rules (and nft -c on them where nft is installed) and of
the awk reader on tcpdump's -x output; not on a booted router.

Settings ([devices."sw:<id>"]): snoop, snoop-vlans, snoop-opt82 ("off"),
dai-vlans, dai-validate; per port (the cable's label, as port security keys
them, or the port's name) snoop-trust:, snoop-rate:, dai-trust:.
"""

from __future__ import annotations

import ipaddress
import re
import time

from . import devcli

TRUST, RATE, DTRUST = "snoop-trust", "snoop-rate", "dai-trust"
FIELDS = (TRUST, RATE, DTRUST)
UPLINK = "GigabitEthernet0/1"
RL_CAUSE = "dhcp-rate-limit"
VALIDATE = ("src-mac", "dst-mac", "ip")
INFINITE = 31536000


def _own(lab, sw: str) -> dict:
    return lab.devices.get(f"sw:{sw}", {})


def _vlans(own: dict, key: str) -> set[int]:
    try:
        return devcli.vlan_set(own.get(key, "")) or set()
    except ValueError:
        return set()


def snooped(lab, sw: str) -> set[int]:
    """The VLANs DHCP snooping runs in: ip dhcp snooping and the VLAN listed."""
    own = _own(lab, sw)
    return _vlans(own, "snoop-vlans") if own.get("snoop") else set()


def inspected(lab, sw: str) -> set[int]:
    return _vlans(_own(lab, sw), "dai-vlans")


def _vlan(lab, link) -> int:
    net = lab.networks.get(link.network_id)
    return net.vlan_no if net is not None else 1


def _name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


def trusted(lab, sw: str, key: str, what: str = TRUST) -> bool:
    return bool(_own(lab, sw).get(f"{what}:{key}"))


def rate(lab, sw: str, key: str) -> int:
    try:
        return int(_own(lab, sw).get(f"{RATE}:{key}") or 0)
    except ValueError:
        return 0


def active(lab) -> bool:
    return any(snooped(lab, sw) or inspected(lab, sw) for sw in devcli.switches(lab))


# ------------------------------------------------------------------ the router
SNOOP_AWK = r"""# DHCP snooping's binding table (winlab/snooping.py): tcpdump -tt -x of the
# DHCP answers leaving the bridge; an ACK that went out of a client's port is a
# binding, put into the nftables set with its lease as the timeout.
function hv(s,   i, n) { n = 0; for (i = 1; i <= length(s); i++) n = n * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return n }
function b(o) { return hv(substr(h, o * 2 + 1, 2)) }
function bind(   ihl, bo, i, t, l, mt, lease, yi, mac) {
  ihl = (b(0) % 16) * 4; bo = ihl + 8
  if (b(bo) != 2 || substr(h, (bo + 236) * 2 + 1, 8) != "63825363") return
  yi = b(bo + 16) "." b(bo + 17) "." b(bo + 18) "." b(bo + 19)
  mac = ""; for (i = 0; i < 6; i++) mac = mac (i ? ":" : "") substr(h, (bo + 28 + i) * 2 + 1, 2)
  i = bo + 240; mt = 0; lease = 0
  while (i * 2 < length(h)) {
    t = b(i); if (t == 255) break; if (t == 0) { i++; continue }
    l = b(i + 1)
    if (t == 53) mt = b(i + 2)
    if (t == 51) lease = b(i + 2) * 16777216 + b(i + 3) * 65536 + b(i + 4) * 256 + b(i + 5)
    i += 2 + l
  }
  if (mt != 5 || yi == "0.0.0.0") return
  if (lease <= 0 || lease >= 4294967295) lease = INF
  if (old[yi] != "" && old[yi] != mac) system(NFT " delete element bridge " T " snoop_bind '{ " yi " . " old[yi] " }' 2>/dev/null")
  system(NFT " delete element bridge " T " snoop_bind '{ " yi " . " mac " }' 2>/dev/null; " NFT " add element bridge " T " snoop_bind '{ " yi " . " mac " timeout " lease "s }' 2>/dev/null")
  old[yi] = mac
  print (ts + lease), ifc, mac, yi >> BIND; close(BIND)
  print ts, ifc, "dhcp-binding", mac, yi >> EVENTS; close(EVENTS)
}
/^[0-9]/ { ts = int($1); ifc = $2; want = (index(" " PORTS " ", " " $2 " ") > 0 && $3 == "Out"); h = ""; need = 0; next }
/^[ \t]+0x[0-9a-f]+:/ {
  if (!want) next
  for (k = 2; k <= NF; k++) if ($k ~ /^[0-9a-f]+$/) h = h $k
  if (need == 0 && length(h) >= 8) need = b(2) * 256 + b(3)
  if (need > 0 && length(h) >= need * 2) { bind(); want = 0 }
}
"""

WATCH_SH = """#!/bin/sh
# DHCP snooping's rate limit (winlab/snooping.py): the moment a port's
# over-the-limit counter moves, its bridge port is disabled: err-disabled.
R={run}
while :; do
  for p in {ports}; do
    [ -e $R/$p.rl ] && continue
    n=$(nft list counter bridge {table} srl_$p 2>/dev/null | sed -n 's/.*packets \\([0-9]*\\).*/\\1/p')
    if [ "${{n:-0}}" -gt 0 ]; then
      bridge link set dev $p state 0
      date +%s > $R/$p.rl
      echo "$(date +%s) $p {cause} -" >> $R/events
    fi
  done
  sleep 1
done
"""


def _plan_ports(lab, plan) -> list:
    from . import portsec
    return [(p.sw, p, _vlan(lab, p.link)) for p in portsec.all_ports(lab, plan) if p.iface]


def render(plan, run: str, table: str) -> dict:
    """The rules for the port table, as parts portsec.render puts in place:
    {"pre": shell before the table, "sets", "rules" (the ports chain),
    "local" (the output chain), "post": shell after it}. Empty lists when no
    switch snoops or inspects."""
    lab = plan.lab
    stop = (f"for f in {run}/snoop-*.pid; do [ -e \"$f\" ] && kill $(cat \"$f\") 2>/dev/null; done; "
            f"rm -f {run}/snoop-*.pid {run}/snoop.fifo {run}/*.rl; true")
    parts = {"pre": [stop], "sets": [], "rules": [], "local": [], "post": []}
    if not active(lab):
        return parts
    ports = _plan_ports(lab, plan)
    sets, rules, local = parts["sets"], parts["rules"], parts["local"]
    sets.append("  set snoop_bind { type ipv4_addr . ether_addr; flags timeout; }   # DHCP snooping's bindings")
    listen, limited = [], []
    for sw, p, vlan in ports:
        snoop, dai = vlan in snooped(lab, sw), vlan in inspected(lab, sw)
        if not (snoop or dai):
            continue
        i, k = p.iface, p.key
        tag = f"   # {devcli.hostname(lab, 'sw:' + sw)} {p.short} ({p.label}) vlan {vlan}"
        if snoop and rate(lab, sw, k):
            n = rate(lab, sw, k)
            sets.append(f"  counter srl_{i} {{ }}{tag}: DHCP over {n} pps")
            rules.append(f"    iifname \"{i}\" ether type ip udp dport 67 limit rate over {n}/second burst {n} packets "
                         f"counter name srl_{i} drop")
            limited.append(i)
        if snoop and not trusted(lab, sw, k):
            sets += [f"  counter sdrop_{i} {{ }}{tag}: untrusted, DHCP server messages dropped",
                     f"  set sbad_{i} {{ type ether_addr; size 8; flags dynamic; }}"]
            rules.append(f"    iifname \"{i}\" ether type ip udp sport 67 add @sbad_{i} {{ ether saddr }} "
                         f"counter name sdrop_{i} drop")
            listen.append(i)
        if dai and not trusted(lab, sw, k, DTRUST):
            val = set(_own(lab, sw).get("dai-validate", "").split())
            sets += [f"  counter dai_{i} {{ }}{tag}: ARP inspected", f"  counter daiok_{i} {{ }}"]
            rules.append(f"    iifname \"{i}\" ether type arp arp saddr ip 0.0.0.0 counter name daiok_{i} accept")
            if "ip" in val:
                rules += [f"    iifname \"{i}\" ether type arp arp saddr ip {{ 255.255.255.255, 224.0.0.0/4 }} "
                          f"counter name dai_{i} drop",
                          f"    iifname \"{i}\" ether type arp arp operation reply arp daddr ip {{ 0.0.0.0, "
                          f"255.255.255.255, 224.0.0.0/4 }} counter name dai_{i} drop"]
            rules.append(f"    iifname \"{i}\" ether type arp arp saddr ip . arp saddr ether != @snoop_bind "
                         f"counter name dai_{i} drop")
            if "src-mac" in val:
                rules.append(f"    iifname \"{i}\" ether type arp arp saddr ip . ether saddr != @snoop_bind "
                             f"counter name dai_{i} drop")
            rules.append(f"    iifname \"{i}\" ether type arp counter name daiok_{i}")
    for sw in devcli.switches(lab):
        mine = [(p, v) for s, p, v in ports if s == sw]
        n = _name(sw)
        sv = [p.iface for p, v in mine if v in snooped(lab, sw)]
        if sv and not trusted(lab, sw, UPLINK):
            sets.append(f"  counter sup_{n} {{ }}   # {devcli.hostname(lab, 'sw:' + sw)}: the router's DHCP "
                        f"answers through an untrusted Gi0/1")
            local.append(f"    oifname {{ {', '.join(chr(34) + i + chr(34) for i in sv)} }} ether type ip udp sport 67 "
                         f"counter name sup_{n} drop")
        dv = [p.iface for p, v in mine if v in inspected(lab, sw)]
        if dv and not trusted(lab, sw, UPLINK, DTRUST):
            sets.append(f"  counter daiup_{n} {{ }}   # {devcli.hostname(lab, 'sw:' + sw)}: the router's ARP "
                        f"through an untrusted Gi0/1")
            local.append(f"    oifname {{ {', '.join(chr(34) + i + chr(34) for i in dv)} }} ether type arp "
                         f"arp saddr ip . arp saddr ether != @snoop_bind counter name daiup_{n} drop")
    post = parts["post"]
    # the bindings learnt before the table was built again, with what is left of their leases
    post += [f"if [ -s {run}/snoop.bind ]; then now=$(date +%s); "
             f"awk -v now=$now '$1 > now {{ last[$4] = $0 }} END {{ for (k in last) print last[k] }}' "
             f"{run}/snoop.bind > {run}/snoop.bind.new; mv {run}/snoop.bind.new {run}/snoop.bind; "
             f"while read e i m a; do nft add element bridge {table} snoop_bind \"{{ $a . $m timeout $((e - now))s }}\" "
             f"2>/dev/null; done < {run}/snoop.bind; fi"]
    if listen:
        awk = SNOOP_AWK.replace("INF", str(INFINITE))
        post += [f"cat > {run}/snoop.awk <<'WINLAB_EOF'", awk.rstrip("\n"), "WINLAB_EOF",
                 f"mkfifo {run}/snoop.fifo",
                 f"setsid awk -v PORTS='{' '.join(listen)}' -v T={table} -v NFT=nft -v BIND={run}/snoop.bind "
                 f"-v EVENTS={run}/events -f {run}/snoop.awk < {run}/snoop.fifo >/dev/null 2>&1 & "
                 f"echo $! > {run}/snoop-awk.pid",
                 f"setsid tcpdump -i any -l -nn -tt -x 'udp src port 67 and udp dst port 68' > {run}/snoop.fifo "
                 f"2>/dev/null </dev/null & echo $! > {run}/snoop-dump.pid"]
    if limited:
        post += [f"cat > {run}/snoop-watch.sh <<'WINLAB_EOF'",
                 WATCH_SH.format(run=run, ports=" ".join(limited), table=table, cause=RL_CAUSE).rstrip("\n"),
                 "WINLAB_EOF", f"chmod +x {run}/snoop-watch.sh",
                 f"setsid {run}/snoop-watch.sh >/dev/null 2>&1 </dev/null & echo $! > {run}/snoop-watch.pid"]
    return parts


def live_cmd(run: str) -> str:
    return (f"echo '#snoop'; date +%s; cat {run}/snoop.bind 2>/dev/null; "
            f"echo '#rl'; for f in {run}/*.rl; do [ -e \"$f\" ] && echo \"$(basename $f .rl) $(cat $f)\"; done; ")


def parse(snoop: list[str], rl: list[str], nft: str) -> dict:
    """The router's word: {"now", "bind": [{exp, iface, mac, ip}], "rl":
    {iface: when}, "count": {name: packets}, "bad": {iface: [mac]}, "set":
    [(ip, mac)]}."""
    now, binds = 0, []
    for line in snoop:
        w = line.split()
        if len(w) == 1 and w[0].isdigit() and not now:
            now = int(w[0])
        elif len(w) == 4 and w[0].isdigit():
            binds.append({"exp": int(w[0]), "iface": w[1], "mac": w[2].lower(), "ip": w[3]})
    last: dict[str, dict] = {}
    for b in binds:
        last[b["ip"]] = b
    rlm = {}
    for line in rl:
        w = line.split()
        if w:
            rlm[w[0]] = int(w[1]) if len(w) > 1 and w[1].isdigit() else 0
    count = {m.group(1): int(m.group(2)) for m in
             re.finditer(r"counter ((?:sdrop|srl|dai|daiok|sup|daiup)_\w+) \{\s*packets (\d+)", nft or "")}
    bad = {}
    for m in re.finditer(r"set sbad_(\w+) \{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", nft or ""):
        bad[m.group(1)] = re.findall(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", m.group(2))
    kset = []
    m = re.search(r"set snoop_bind \{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", nft or "")
    if m:
        kset = re.findall(r"(\d+\.\d+\.\d+\.\d+) \. ([0-9a-f]{2}(?::[0-9a-f]{2}){5})", m.group(1))
    return {"now": now, "bind": sorted(last.values(), key=lambda b: b["ip"]), "rl": rlm, "count": count,
            "bad": bad, "set": kset, "table": bool((nft or "").strip())}


# ------------------------------------------------------------------ settling what the router says
def settle(lab, plan, live: dict | None, rt: dict, now: float, said: dict, links: list) -> None:
    """A port the rate-limit watcher disabled is err-disabled (dhcp-rate-limit);
    dropped DHCP and ARP since the last look go into the switch's log."""
    from . import portsec
    data = (live or {}).get("snoop")
    if not data:
        return
    seen = rt.setdefault("snoopc", {})
    for p in portsec.all_ports(lab, plan):
        i = p.iface
        if not i:
            continue
        own = lab.devices.setdefault(f"sw:{p.sw}", {})
        handled = rt.setdefault("rlseen", {})
        if i in data["rl"] and handled.get(i) == data["rl"][i]:
            pass   # what the watcher said before the port came back (no shutdown), not yet rebuilt
        elif i in data["rl"] and not p.err and not own.get(f"shut:{p.label}"):
            handled[i] = data["rl"][i]
            own[f"psec-err:{p.label}"] = f"00:00:00:00:00:00 {int(now)} {RL_CAUSE}"
            s = p.short
            said.setdefault(p.sw, []).append("\n".join([
                f"%DHCP_SNOOPING-4-DHCP_SNOOPING_ERRDISABLE_WARNING: DHCP Snooping received {rate(lab, p.sw, p.key)} "
                f"DHCP packets on interface {s}",
                f"%DHCP_SNOOPING-4-DHCP_SNOOPING_RATE_LIMIT_EXCEEDED: The interface {s} is receiving more than the "
                f"threshold set",
                f"%PM-4-ERR_DISABLE: {RL_CAUSE} error detected on {s}, putting {s} in err-disable state",
                f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {p.name}, changed state to down",
                f"%LINK-3-UPDOWN: Interface {p.name}, changed state to down"]))
            links.append((p.link, False))
        gen = (live or {}).get("psec", {}).get("gen", "")
        for kind in ("sdrop", "dai"):
            c = data["count"].get(f"{kind}_{i}")
            if c is None:
                continue
            was = seen.get(f"{kind}_{i}", [gen, 0])
            base = int(was[1]) if was[0] == gen else 0
            seen[f"{kind}_{i}"] = [gen, c]
            if c <= base:
                continue
            vlan = _vlan(lab, p.link)
            if kind == "sdrop":
                macs = data["bad"].get(i, [])
                rt.setdefault("snoopbad", {})[p.label] = macs
                said.setdefault(p.sw, []).append(
                    f"%DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: DHCP_SNOOPING drop message on untrusted port, "
                    f"message type: DHCPOFFER/DHCPACK, MAC sa: {devcli.dotted_mac(macs[0]) if macs else 'unknown'}, "
                    f"{c - base} on {p.short}")
            else:
                said.setdefault(p.sw, []).append(
                    f"%SW_DAI-4-DHCP_SNOOPING_DENY: {c - base} Invalid ARPs on {p.short}, vlan {vlan}.")


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    add("ip dhcp snooping", lambda a: _flag(con, "snoop", True), "DHCP Snooping", C)
    add("no ip dhcp snooping", lambda a: _flag(con, "snoop", False), "Negate a command or set its defaults", C)
    add("ip dhcp snooping vlan <line>", lambda a: _vlan_cmd(con, "snoop-vlans", a[0], True), "DHCP Snooping vlan", C)
    add("no ip dhcp snooping vlan <line>", lambda a: _vlan_cmd(con, "snoop-vlans", a[0], False),
        "Negate a command or set its defaults", C)
    add("ip dhcp snooping information option", lambda a: _opt82(con, True), "DHCP Snooping information", C)
    add("no ip dhcp snooping information option", lambda a: _opt82(con, False), "Negate a command or set its defaults", C)
    add("ip dhcp snooping trust", lambda a: _port_flag(con, TRUST, True), "DHCP Snooping trust config", I)
    add("no ip dhcp snooping trust", lambda a: _port_flag(con, TRUST, False), "Negate a command or set its defaults", I)
    add("ip dhcp snooping limit rate <num>", lambda a: _rate(con, a[0]), "DHCP Snooping rate limit", I)
    add("no ip dhcp snooping limit rate", lambda a: _rate(con, ""), "Negate a command or set its defaults", I)
    add("ip arp inspection vlan <line>", lambda a: _vlan_cmd(con, "dai-vlans", a[0], True), "Enable/Disable ARP Inspection on vlans", C)
    add("no ip arp inspection vlan <line>", lambda a: _vlan_cmd(con, "dai-vlans", a[0], False),
        "Negate a command or set its defaults", C)
    add("ip arp inspection validate <line>", lambda a: _validate(con, a[0]), "Validate addresses", C)
    add("no ip arp inspection validate", lambda a: _validate(con, ""), "Negate a command or set its defaults", C)
    add("no ip arp inspection validate <line>", lambda a: _validate(con, ""), "Negate a command or set its defaults", C)
    add("ip arp inspection trust", lambda a: _port_flag(con, DTRUST, True), "Configure Trust state", I)
    add("no ip arp inspection trust", lambda a: _port_flag(con, DTRUST, False), "Negate a command or set its defaults", I)
    add("show ip dhcp snooping", lambda a: show(con), "DHCP snooping", U)
    add("show ip dhcp snooping binding", lambda a: show_binding(con), "DHCP snooping binding", U)
    add("show ip dhcp snooping statistics", lambda a: show_stats(con), "DHCP snooping statistics", U)
    add("show ip arp inspection", lambda a: show_dai(con, ""), "Show ARP Inspection", U)
    add("show ip arp inspection vlan <line>", lambda a: show_dai(con, a[0]), "Show ARP Inspection for vlans", U)
    add("show ip arp inspection statistics", lambda a: show_dai(con, "", stats_only=True), "ARP Inspection statistics", U)
    add("show ip arp inspection interfaces", lambda a: show_dai_ifaces(con), "ARP Inspection interfaces", U)


def _mine(con) -> dict:
    return devcli.settings(con.lab, con.device)


def _sw(con) -> str:
    return devcli.switch_id(con.device)


def _done(con) -> str:
    from . import portsec
    return portsec.done(con)


def _flag(con, key: str, on: bool) -> str:
    if on:
        _mine(con)[key] = "yes"
    else:
        _mine(con).pop(key, None)
    return _done(con)


def _vlan_cmd(con, key: str, text: str, add: bool) -> str:
    try:
        tags = devcli.vlan_set(text)
    except ValueError:
        raise devcli.CliError("% Invalid input: a VLAN list, as 1 or 10,20-22") from None
    if tags is None or not tags:
        raise devcli.CliError("% Invalid input: a VLAN list, as 1 or 10,20-22")
    own = _mine(con)
    have = _vlans(own, key)
    have = have | tags if add else have - tags
    if have:
        own[key] = devcli.vlan_text(have)
    else:
        own.pop(key, None)
    out = _done(con)
    notes = []
    if add and key == "snoop-vlans" and not own.get("snoop"):
        notes.append("% Snooping on these VLANs starts with the global switch: ip dhcp snooping")
    if add and key == "dai-vlans" and not snooped(con.lab, _sw(con)):
        notes.append("% ARP inspection checks against DHCP snooping's bindings: with snooping off there are "
                     "none, and every ARP on an untrusted port is dropped")
    return "\n".join(x for x in [out] + notes if x)


def _opt82(con, on: bool) -> str:
    own = _mine(con)
    if on:
        own.pop("snoop-opt82", None)
    else:
        own["snoop-opt82"] = "off"
    con._save(live=False)
    if on:
        return ("% Kept: a real switch would now insert option 82 into clients' requests. This one cannot "
                "rewrite a DHCP packet, so nothing is inserted (no ip dhcp snooping information option is the "
                "usual setting with a server that is not a relay)")
    return ""


def _key(con) -> str:
    ctx = con.s.ctx
    if ctx.startswith("FastEthernet"):
        from . import portsec
        return portsec.write_key(con)
    if ctx.startswith("GigabitEthernet"):
        return ctx
    raise devcli.CliError("% DHCP snooping and ARP inspection are set on the switch's ports, not on a VLAN "
                          "interface")


def _port_flag(con, what: str, on: bool) -> str:
    key = _key(con)
    if on:
        _mine(con)[f"{what}:{key}"] = "yes"
    else:
        _mine(con).pop(f"{what}:{key}", None)
    return _done(con)


def _rate(con, n: str) -> str:
    key = _key(con)
    if not n:
        _mine(con).pop(f"{RATE}:{key}", None)
        return _done(con)
    try:
        v = int(n)
    except ValueError:
        v = 0
    if not 1 <= v <= 2048:
        raise devcli.CliError("% DHCP snooping rate limit: 1 to 2048 packets per second")
    _mine(con)[f"{RATE}:{key}"] = str(v)
    return _done(con)


def _validate(con, text: str) -> str:
    own = _mine(con)
    if not text.strip():
        own.pop("dai-validate", None)
        return _done(con)
    got = []
    for w in text.lower().split():
        hit = [v for v in VALIDATE if v.startswith(w)]
        if len(hit) != 1:
            raise devcli.CliError("% Invalid input: ip arp inspection validate {src-mac | dst-mac | ip} ...")
        got.append(hit[0])
    own["dai-validate"] = " ".join(v for v in VALIDATE if v in got)
    out = _done(con)
    if "dst-mac" in got:
        out = (out + "\n" if out else "") + ("% dst-mac is kept, not enforced: the router's nftables cannot "
                                             "compare a frame's destination MAC with the one inside its ARP")
    return out


# ---- show
def _live(con) -> dict:
    from . import portsec
    return portsec.live_of(con).get("snoop") or {}


def _port_rows(con) -> list:
    """(port name, key) of the switch's ports, machine ports first then the gigabit ones."""
    from . import portsec
    rows = [(p.name, p.key) for p in portsec.ports_of(con.lab, con.plan, _sw(con))]
    rows += [(g, g) for g in devcli.gig_names()]
    return rows


def show(con) -> str:
    lab, sw = con.lab, _sw(con)
    own = _own(lab, sw)
    conf = _vlans(own, "snoop-vlans")
    op = sorted(t for t in conf if own.get("snoop") and devcli.vlan_net(lab, sw, t) is not None)
    out = [f"Switch DHCP snooping is {'enabled' if own.get('snoop') else 'disabled'}",
           "Switch DHCP gleaning is disabled",
           "DHCP snooping is configured on following VLANs:", devcli.vlan_text(conf) or "none",
           "DHCP snooping is operational on following VLANs:", devcli.vlan_text(set(op)) or "none",
           "DHCP snooping is configured on the following L3 Interfaces:", "",
           f"Insertion of option 82 is {'disabled' if own.get('snoop-opt82') == 'off' else 'enabled'}",
           "   circuit-id default format: vlan-mod-port", "   remote-id: (switch MAC)",
           "Option 82 on untrusted port is not allowed", "Verification of hwaddr field is enabled",
           "Verification of giaddr field is enabled",
           "DHCP snooping trust/rate is configured on the following Interfaces:", "",
           f"{'Interface':<27}{'Trusted':<11}{'Allow option':<16}Rate limit (pps)",
           f"{'-' * 23:<27}{'-' * 7:<11}{'-' * 12:<16}{'-' * 16}"]
    for name, key in _port_rows(con):
        t, r = trusted(lab, sw, key), rate(lab, sw, key)
        if t or r:
            out.append(f"{name:<27}{'yes' if t else 'no':<11}{'yes' if t else 'no':<16}{r or 'unlimited'}")
    if own.get("snoop-opt82") != "off" and own.get("snoop"):
        out.append("% (option 82 is not actually inserted here: the router's bridge cannot rewrite DHCP)")
    return "\n".join(out)


def bindings(con, data: dict | None = None) -> list[tuple[str, str, int, int, str]]:
    """(mac, ip, seconds left, vlan, port name) of the switch's bindings, as the router last said."""
    from . import portsec
    data = _live(con) if data is None else data
    where = {p.iface: p for p in portsec.ports_of(con.lab, con.plan, _sw(con)) if p.iface}
    kset = set(data.get("set", []))
    out = []
    for b in data.get("bind", []):
        p = where.get(b["iface"])
        left = b["exp"] - (data.get("now") or int(time.time()))
        if p is None or left <= 0 or (data.get("table") and (b["ip"], b["mac"]) not in kset):
            continue
        out.append((b["mac"], b["ip"], left, _vlan(con.lab, p.link), p.name))
    return out


def show_binding(con) -> str:
    rows = bindings(con)
    out = [f"{'MacAddress':<20}{'IpAddress':<17}{'Lease(sec)':<12}{'Type':<15}{'VLAN':<6}Interface",
           f"{'-' * 18:<20}{'-' * 15:<17}{'-' * 10:<12}{'-' * 13:<15}{'-' * 4:<6}{'-' * 20}"]
    for mac, ip, left, vlan, port in sorted(rows, key=lambda r: ipaddress.IPv4Address(r[1])):
        out.append(f"{mac.upper():<20}{ip:<17}{left:<12}{'dhcp-snooping':<15}{vlan:<6}{port}")
    out.append(f"Total number of bindings: {len(rows)}")
    if not con.powered():
        out.append("% The network is off: the binding table lives in the running router")
    return "\n".join(out)


def show_stats(con) -> str:
    from . import portsec
    data = _live(con)
    c = data.get("count", {})
    mine = [p.iface for p in portsec.ports_of(con.lab, con.plan, _sw(con)) if p.iface]
    drop = sum(c.get(f"sdrop_{i}", 0) for i in mine) + c.get(f"sup_{_name(_sw(con))}", 0)
    rl = sum(c.get(f"srl_{i}", 0) for i in mine)
    return "\n".join([" Packets Forwarded                                     = (not counted)",
                      f" Packets Dropped                                       = {drop + rl}",
                      f" Packets Dropped From untrusted ports                  = {drop}",
                      f" Packets Dropped Over the rate limit                   = {rl}"])


def show_dai(con, vlan_text: str, stats_only: bool = False) -> str:
    from . import portsec
    lab, sw = con.lab, _sw(con)
    own = _own(lab, sw)
    val = set(own.get("dai-validate", "").split())
    want = sorted(inspected(lab, sw))
    if vlan_text:
        try:
            want = sorted(devcli.vlan_set(vlan_text) or set())
        except ValueError:
            raise devcli.CliError("% Invalid input: a VLAN list") from None
    data = _live(con)
    c = data.get("count", {})
    ports = portsec.ports_of(lab, con.plan, sw)
    n = _name(sw)
    stats = []
    for v in want:
        ifs = [p.iface for p in ports if p.iface and _vlan(lab, p.link) == v]
        fw = sum(c.get(f"daiok_{i}", 0) for i in ifs)
        dr = sum(c.get(f"dai_{i}", 0) for i in ifs) + (c.get(f"daiup_{n}", 0) if v in inspected(lab, sw) else 0)
        stats.append(f"{v:>5}{fw:>15}{dr:>15}{dr:>15}{0:>15}")
    head = [f" Vlan{'Forwarded':>15}{'Dropped':>15}{'DHCP Drops':>15}{'ACL Drops':>15}",
            f" ----{'---------':>15}{'-------':>15}{'----------':>15}{'---------':>15}"] + stats
    if stats_only:
        return "\n".join(head)
    out = [f"Source Mac Validation      : {'Enabled' if 'src-mac' in val else 'Disabled'}",
           f"Destination Mac Validation : {'Enabled' if 'dst-mac' in val else 'Disabled'}",
           f"IP Address Validation      : {'Enabled' if 'ip' in val else 'Disabled'}", "",
           " Vlan     Configuration    Operation   ACL Match          Static ACL",
           " ----     -------------    ---------   ---------          ----------"]
    for v in want:
        on = v in inspected(lab, sw)
        live = on and devcli.vlan_net(lab, sw, v) is not None
        out.append(f"{v:>5}     {'Enabled' if on else 'Disabled':<17}{'Active' if live else 'Inactive':<12}")
    out += ["", " Vlan     ACL Logging      DHCP Logging      Probe Logging",
            " ----     -----------      ------------      -------------"]
    out += [f"{v:>5}     {'Deny':<17}{'Deny':<18}Off" for v in want]
    out += [""] + head
    if "dst-mac" in val:
        out.append("% Destination MAC validation is kept, not enforced here")
    return "\n".join(out)


def show_dai_ifaces(con) -> str:
    lab, sw = con.lab, _sw(con)
    out = [f" {'Interface':<17}{'Trust State':<15}{'Rate (pps)':<13}Burst Interval",
           f" {'-' * 15:<17}{'-' * 11:<15}{'-' * 10:<13}{'-' * 14}"]
    for name, key in _port_rows(con):
        t = trusted(lab, sw, key, DTRUST)
        out.append(f" {devcli.short_if(name):<17}{'Trusted' if t else 'Untrusted':<15}{'None' if t else 'None':<13}N/A")
    out.append("% No ARP rate limit in this switch: untrusted ports are inspected, never rate-limited")
    return "\n".join(out)


def run_lines(lab, sw: str) -> list[str]:
    own, out = _own(lab, sw), []
    if own.get("snoop-vlans"):
        out.append(f"ip dhcp snooping vlan {own['snoop-vlans']}")
    if own.get("snoop-opt82") == "off":
        out.append("no ip dhcp snooping information option")
    if own.get("snoop"):
        out.append("ip dhcp snooping")
    if own.get("dai-vlans"):
        out.append(f"ip arp inspection vlan {own['dai-vlans']}")
    if own.get("dai-validate"):
        out.append(f"ip arp inspection validate {own['dai-validate']}")
    return out + (["!"] if out else [])


def place(lab, sw: str, out: list[str]) -> list[str]:
    """The trust and rate lines under the switch's gigabit ports in show
    running-config (the access ports' come with port security's)."""
    for g in devcli.gig_names():
        lines = iface_lines(lab, sw, g)
        if lines and f"interface {g}" in out:
            k = out.index(f"interface {g}") + 1
            while k < len(out) and out[k].startswith(" "):
                k += 1
            out[k:k] = lines
    return out


def iface_lines(lab, sw: str, key: str) -> list[str]:
    own, out = _own(lab, sw), []
    if own.get(f"{DTRUST}:{key}"):
        out.append(" ip arp inspection trust")
    if own.get(f"{TRUST}:{key}"):
        out.append(" ip dhcp snooping trust")
    if own.get(f"{RATE}:{key}"):
        out.append(f" ip dhcp snooping limit rate {own[f'{RATE}:{key}']}")
    return out


# ------------------------------------------------------------------ the troubleshooting fault
STATE_DIR = "/var/lib/winlab"


def _faults():
    from .guestfaults import LINUX, GuestFault
    drop = "/etc/systemd/network/$b.d/90-winlab-dhcp-server.conf"
    find = ("i=$(ip -4 route show default | awk '{print $5; exit}'); [ -n \"$i\" ] || i=eth0; "
            "f=$(networkctl status \"$i\" 2>/dev/null | sed -n 's/.*Network File: //p' | head -1); "
            "[ -n \"$f\" ] || f=$(ls /run/systemd/network/10-netplan-*.network 2>/dev/null | head -1); "
            "[ -n \"$f\" ] || { echo 'no systemd-networkd network file for this machine'; exit 1; }; "
            "b=$(basename \"$f\"); ")
    return [GuestFault(
        id="dhcp-rogue-server",
        images=("ubuntu",),
        title="A second DHCP server on the office LAN hands out the wrong gateway",
        os=LINUX,
        teaches="what a rogue DHCP server does to a LAN (whoever answers first wins), finding it from a "
                "client's lease and the switch's MAC table, and DHCP snooping: trusted and untrusted ports, "
                "the binding table it builds, and the server port or uplink that must be trusted",
        symptom="some PCs on the office LAN renew their address and lose everything beyond it: their default "
                "gateway and DNS server point at an address nobody answers on, while other PCs are fine",
        apply=(find + "mkdir -p /etc/systemd/network/$b.d " + STATE_DIR + "; "
               "a=$(ip -4 -o addr show dev \"$i\" | awk '{print $4}' | cut -d/ -f1 | head -1); n=${a%.*}; "
               "printf '[Network]\\nDHCPServer=yes\\n\\n[DHCPServer]\\nPoolOffset=150\\nPoolSize=50\\n"
               "EmitRouter=yes\\nRouter=%s.254\\nEmitDNS=yes\\nDNS=%s.254\\nDefaultLeaseTimeSec=600\\n' "
               "\"$n\" \"$n\" > " + drop + "; echo \"$i $b\" > " + STATE_DIR + "/ts-rogue-dhcp; "
               "networkctl reload && networkctl reconfigure \"$i\" && echo broken"),
        clear=(find + "rm -f " + drop + "; rmdir /etc/systemd/network/$b.d 2>/dev/null; "
               "rm -f " + STATE_DIR + "/ts-rogue-dhcp; networkctl reload; networkctl reconfigure \"$i\"; echo ok"),
        shell="sh",
        hints=(
            "On a PC that lost the network: ip route and resolvectl status (or ip -4 addr). Whose gateway is "
            "that, and which server gave the lease? sudo journalctl -u systemd-networkd | grep -i dhcp names "
            "the server's address; the router's own pool hands out the router as gateway.",
            "Find the box: from that PC, ping the server's address and ip neigh shows its MAC; on the switch's "
            "console show mac address-table finds the port it is on. Then protect the LAN from it: "
            "ip dhcp snooping, ip dhcp snooping vlan 1, no ip dhcp snooping information option, and "
            "ip dhcp snooping trust on Gi0/1 (the router's answers come in there). show ip dhcp snooping "
            "statistics and show logging count what is dropped from the untrusted port.",
            "Snooping stops the answers at the switch; the box itself still runs a DHCP server. On it: "
            "networkctl status shows DHCP server on its card, and /etc/systemd/network has a .network.d "
            "drop-in with DHCPServer=yes. Remove it, then sudo networkctl reload and sudo networkctl "
            "reconfigure on the card. On the PCs, renew (sudo networkctl renew eth0).",
        ),
        verify=("ss -Hlun 2>/dev/null | grep -qE '[:.]67[[:space:]]' && echo False || "
                "{ ls /etc/systemd/network/*.network.d/*.conf 2>/dev/null | xargs -r grep -qsi '^DHCPServer=yes' "
                "&& echo False || echo True; }"),
    )]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
