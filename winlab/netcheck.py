"""Does my network work? Asked from inside a machine, as an admin would.

The check runs on one lab machine (the source) over its agent channel, the
serial port, never the network, and tries what a person at that machine
would try, in the order a troubleshooter does: is the cable in, does the
card have an address and where did it come from, does the default gateway
answer, is a DNS server set and does it know the other machines' names,
and then, for every other running machine, does its name resolve, does it
answer a ping, and are its file sharing and Remote Desktop (or SSH) ports
open.

Nothing here comes from the lab plan. The other machines' addresses are the
ones they actually have, read from inside each of them the same way; a
machine the student has not given an address yet shows as having none. The
check changes nothing anywhere: it reads and it knocks.

    winlab net check <lab> <machine> [--to <machine> ...]

The desktop runs the same from a machine's menu ("Test the network from
here") and shows the answer in the Viewer window.
"""

from __future__ import annotations

import html
import ipaddress
from dataclasses import dataclass, field
from typing import Callable

# (machine, command, shell) -> (ran, output)
Runner = Callable[[str, str, str], "tuple[bool, str]"]

WINDOWS_PORTS = ((445, "file sharing (SMB)"), (3389, "Remote Desktop"))
LINUX_PORTS = ((22, "SSH"),)

# What each machine has, from inside it: its name, every card with its link
# state, MAC and IPv4 addresses (address/prefix/origin), the default gateway
# and the DNS servers it asks.
SELF_PS = r"""$ErrorActionPreference = 'SilentlyContinue'
"HOST`t$env:COMPUTERNAME"
foreach ($a in @(Get-NetAdapter | Where-Object { $_.HardwareInterface })) {
  $ips = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | ForEach-Object { '{0}/{1}/{2}' -f $_.IPAddress, $_.PrefixLength, $_.PrefixOrigin })
  "NIC`t{0}`t{1}`t{2}`t{3}" -f $a.Name, $a.Status, ($a.MacAddress -replace '-', ':').ToLower(), ($ips -join ',')
}
foreach ($r in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4)) { "GW`t$($r.NextHop)" }
foreach ($d in @(Get-DnsClientServerAddress -AddressFamily IPv4)) { foreach ($s in @($d.ServerAddresses)) { "DNS`t$s" } }
"""

SELF_SH = r"""echo "HOST	$(hostname)"
for i in /sys/class/net/*; do
  n=${i##*/}; [ "$n" = lo ] && continue; [ -e "$i/device" ] || continue
  st=$(cat "$i/operstate" 2>/dev/null); [ "$st" = up ] && st=Up || st=Disconnected
  ips=$(ip -o -4 addr show dev "$n" 2>/dev/null | awk '{o="Manual"; if ($0 ~ / dynamic /) o="Dhcp"; printf "%s/%s,", $4, o}')
  echo "NIC	$n	$st	$(cat "$i/address")	${ips%,}"
done
ip -4 route show default 2>/dev/null | awk '{print "GW\t" $3}'
if command -v resolvectl >/dev/null 2>&1; then
  resolvectl dns 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | sed 's/^/DNS\t/'
else
  awk '/^nameserver/{print "DNS\t" $2}' /etc/resolv.conf 2>/dev/null
fi
"""


@dataclass
class Nic:
    name: str
    up: bool
    mac: str
    addrs: list[tuple[str, int, str]] = field(default_factory=list)   # (ip, prefix, origin)

    @property
    def usable(self) -> list[str]:
        """The addresses that put the card on a network: not 169.254."""
        return [ip for ip, _, _ in self.addrs if not ip.startswith("169.254.")]


@dataclass
class Seen:
    """One machine as it sees itself."""
    node: str
    host: str = ""
    nics: list[Nic] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    reached: bool = False
    note: str = ""

    @property
    def addresses(self) -> list[str]:
        return [ip for n in self.nics for ip in n.usable]


def parse_self(node: str, text: str) -> Seen:
    s = Seen(node=node, reached=True)
    for line in (text or "").splitlines():
        f = line.rstrip("\r").split("\t")
        if f[0] == "HOST" and len(f) > 1:
            s.host = f[1].strip()
        elif f[0] == "NIC" and len(f) >= 4:
            nic = Nic(name=f[1], up=f[2].strip().lower() == "up", mac=f[3].strip().lower())
            for a in (f[4].split(",") if len(f) > 4 else []):
                parts = a.strip().split("/")
                if len(parts) >= 2 and parts[0]:
                    try:
                        ipaddress.IPv4Address(parts[0])
                        nic.addrs.append((parts[0], int(parts[1]), parts[2] if len(parts) > 2 else ""))
                    except ValueError:
                        continue
            s.nics.append(nic)
        elif f[0] == "GW" and len(f) > 1 and f[1].strip() not in ("", "0.0.0.0"):
            if f[1].strip() not in s.gateways:
                s.gateways.append(f[1].strip())
        elif f[0] == "DNS" and len(f) > 1 and f[1].strip():
            if f[1].strip() not in s.dns:
                s.dns.append(f[1].strip())
    return s


def _ps_list(items) -> str:
    return "@(" + ", ".join("'" + str(x).replace("'", "''") + "'" for x in items) + ")"


def probe_ps(gateways: list[str], targets: list[tuple[str, list[str], list[int]]]) -> str:
    """What the source machine tries: ping its gateways, resolve each target's
    name through DNS and through anything Windows uses (LLMNR, NetBIOS),
    ping each of the target's addresses and knock on its ports."""
    out = ["$ErrorActionPreference = 'SilentlyContinue'",
           "function Png($h) { try { $r = (New-Object System.Net.NetworkInformation.Ping).Send($h, 1000); "
           "[string]($r.Status -eq 'Success') } catch { 'False' } }",
           "function Tcp($h, $p) { $c = New-Object System.Net.Sockets.TcpClient; try { $t = $c.ConnectAsync($h, $p); "
           "[string]($t.Wait(1500) -and $c.Connected) } catch { 'False' } finally { $c.Close() } }"]
    for gw in gateways:
        out.append(f"\"PING`tgw`t{gw}`t$(Png '{gw}')\"")
    for name, ips, ports in targets:
        q = name.replace("'", "''")
        out.append(f"$d = @(Resolve-DnsName -Name '{q}' -Type A -DnsOnly -QuickTimeout | "
                   f"Where-Object {{ $_.IPAddress }} | ForEach-Object {{ $_.IPAddress }})")
        out.append(f"\"DNS`t{q}`t$($d -join ',')\"")
        out.append(f"$a = @(try {{ [System.Net.Dns]::GetHostAddresses('{q}') | Where-Object "
                   f"{{ $_.AddressFamily -eq 'InterNetwork' }} | ForEach-Object {{ $_.IPAddressToString }} }} catch {{}})")
        out.append(f"\"NAME`t{q}`t$($a -join ',')\"")
        for ip in ips:
            out.append(f"\"PING`t{q}`t{ip}`t$(Png '{ip}')\"")
            for p in ports:
                out.append(f"\"TCP`t{q}`t{ip}`t{p}`t$(Tcp '{ip}' {p})\"")
    return "\n".join(out) + "\n"


def probe_sh(gateways: list[str], targets: list[tuple[str, list[str], list[int]]]) -> str:
    out = ["png() { ping -c 1 -W 1 \"$1\" >/dev/null 2>&1 && echo True || echo False; }",
           "tcp() { if command -v bash >/dev/null 2>&1; then timeout 2 bash -c \"exec 3<>/dev/tcp/$1/$2\" "
           ">/dev/null 2>&1 && echo True || echo False; else nc -z -w 2 \"$1\" \"$2\" >/dev/null 2>&1 "
           "&& echo True || echo False; fi; }"]
    for gw in gateways:
        out.append(f"printf 'PING\\tgw\\t%s\\t%s\\n' '{gw}' \"$(png {gw})\"")
    for name, ips, ports in targets:
        q = "".join(c for c in name if c.isalnum() or c in "-._")
        out.append(f"printf 'NAME\\t%s\\t%s\\n' '{q}' \"$(getent ahostsv4 {q} 2>/dev/null | awk '{{print $1}}' "
                   f"| sort -u | tr '\\n' ',' | sed 's/,$//')\"")
        for ip in ips:
            out.append(f"printf 'PING\\t%s\\t%s\\t%s\\n' '{q}' '{ip}' \"$(png {ip})\"")
            for p in ports:
                out.append(f"printf 'TCP\\t%s\\t%s\\t%s\\t%s\\n' '{q}' '{ip}' {p} \"$(tcp {ip} {p})\"")
    return "\n".join(out) + "\n"


def parse_probe(text: str) -> dict:
    res: dict = {"ping": {}, "dns": {}, "name": {}, "tcp": {}}
    for line in (text or "").splitlines():
        f = line.rstrip("\r").split("\t")
        ok = lambda v: v.strip().lower() == "true"
        if f[0] == "PING" and len(f) >= 4:
            res["ping"][(f[1].lower(), f[2])] = ok(f[3])
        elif f[0] in ("DNS", "NAME") and len(f) >= 2:
            vals = [x for x in (f[2].split(",") if len(f) > 2 else []) if x.strip()]
            res[f[0].lower()][f[1].lower()] = vals
        elif f[0] == "TCP" and len(f) >= 5:
            try:
                res["tcp"][(f[1].lower(), f[2], int(f[3]))] = ok(f[4])
            except ValueError:
                continue
    return res


# ------------------------------------------------------------------ the lab
def shell_of(lab, node_id: str) -> str:
    """powershell, sh, or '' for a machine with no agent to ask (a firewall
    appliance on its serial console). A hand-installed Windows answers once
    the guide's check disc put the agent on it; until then the runner says
    its agent did not answer."""
    from .appliances import console_driven
    from .model import LINUX
    node = lab.nodes.get(node_id)
    if node is None:
        return ""
    if node.is_windows:
        return "powershell"
    if node.kind == LINUX and not console_driven(node.image):
        return "sh"
    return ""


def guest_runner(lab_name: str, timeout: float = 90.0) -> Runner:
    from . import state
    from .guestctl import GuestChannel, GuestError

    def run(node: str, cmd: str, shell: str) -> tuple[bool, str]:
        st = state.load(lab_name)
        ns = st.nodes.get(node) if st else None
        if not ns or not state.pid_alive(ns.pid):
            return False, "it is off"
        try:
            with GuestChannel(ns.serial_port, timeout=10).connect(retries=2, delay=1) as ch:
                res = ch.run(cmd, shell=shell, timeout=timeout)
        except GuestError as exc:
            return False, f"its agent did not answer ({exc})"
        return True, res.out
    return run


def running(lab_name: str) -> list[str]:
    from . import state
    st = state.load(lab_name)
    return sorted(n for n, ns in (st.nodes.items() if st else []) if n != "fabric" and state.pid_alive(ns.pid))


@dataclass
class Line:
    state: str          # ok, warn, fail, info
    text: str


def look(lab, node_id: str, runner: Runner) -> Seen:
    shell = shell_of(lab, node_id)
    if not shell:
        return Seen(node=node_id, note="it has no winlab agent to ask: check it from its own screen")
    ran, out = runner(node_id, SELF_PS if shell == "powershell" else SELF_SH, shell)
    if not ran:
        return Seen(node=node_id, note=out)
    return parse_self(node_id, out)


def check(lab, source: str, runner: Runner, to: list[str] | None = None,
          alive: list[str] | None = None, emit=lambda _l: None) -> dict:
    """Tests the network from inside `source`. Returns {"source", "lines":
    [Line], "ok": bool, "summary"}."""
    from . import naming
    if source not in lab.nodes:
        raise ValueError(f"no machine {source!r} in {lab.name}")
    shell = shell_of(lab, source)
    name = naming.display(lab, source)
    if not shell:
        raise ValueError(f"{name} has no winlab agent to run the test: try ping and nslookup on its own screen")
    alive = running(lab.name) if alive is None else alive
    if source not in alive:
        raise ValueError(f"{name} is off: power it on first")
    lines: list[Line] = []
    say = lambda st, text: (lines.append(Line(st, text)), emit(f"{_MARK[st]} {text}"))

    me = look(lab, source, runner)
    if not me.reached:
        raise ValueError(f"{name}: {me.note}")
    say("info", f"From {name} ({me.host or source}), as it sees the network from inside")

    # 1. the cable
    if not me.nics:
        say("fail", "No network card shows up in the machine: its driver may be missing (Device Manager)")
    for n in me.nics:
        if not n.up:
            say("fail", f"{n.name} ({n.mac}): network cable unplugged, or the switch port is shut down or dead")
        else:
            say("ok", f"{n.name} ({n.mac}): link up")
    # 2. the address
    for n in [n for n in me.nics if n.up]:
        if not n.addrs:
            say("fail", f"{n.name}: no IPv4 address at all")
        for ip, plen, origin in n.addrs:
            if ip.startswith("169.254."):
                say("fail", f"{n.name}: {ip}/{plen} is the address Windows gives itself when no DHCP server "
                            f"answers (APIPA): nothing on this LAN hands out addresses yet, or the requests do not reach it")
            elif origin.lower() == "dhcp":
                say("ok", f"{n.name}: {ip}/{plen}, leased from a DHCP server")
            else:
                say("ok", f"{n.name}: {ip}/{plen}, set by hand")
    if not me.addresses:
        say("info", "With no address there is nothing more to test: give the card one, by hand or from a DHCP server")
        return _done(source, lines)
    # 3. the gateway
    probe = (probe_ps if shell == "powershell" else probe_sh)
    targets_ids = [t for t in (to or alive) if t != source and t in lab.nodes]
    others = {t: look(lab, t, runner) for t in targets_ids}
    targets = []
    for t, seen in others.items():
        node = lab.nodes[t]
        ports = [p for p, _ in (WINDOWS_PORTS if node.is_windows else LINUX_PORTS)]
        targets.append(((seen.host or naming.hostname_of(node)), seen.addresses, ports))
    ran, out = runner(source, probe(me.gateways, targets), shell)
    if not ran:
        raise ValueError(f"{name}: {out}")
    res = parse_probe(out)
    if not me.gateways:
        say("warn", "No default gateway: this machine reaches only its own subnet")
    for gw in me.gateways:
        if res["ping"].get(("gw", gw)):
            say("ok", f"Default gateway {gw} answers")
        else:
            say("fail", f"Default gateway {gw} does not answer: a wrong gateway address, the wrong subnet or VLAN, "
                        f"or the router has no interface up there")
    # 4. DNS
    if not me.dns:
        say("warn", "No DNS server set: names resolve only by broadcast (LLMNR, NetBIOS) on this subnet, "
                    "and a domain cannot be found")
    else:
        say("info", f"DNS servers it asks: {', '.join(me.dns)}")
    # 5. every other machine
    for t, seen in others.items():
        node = lab.nodes[t]
        label = naming.display(lab, t)
        host = (seen.host or naming.hostname_of(node))
        key = host.lower()
        if not seen.reached:
            say("info", f"{label}: not tested, {seen.note}")
            continue
        if not seen.addresses:
            say("warn", f"{label}: it has no address of its own yet, so nothing can reach it")
            continue
        dns = res["dns"].get(key, [])
        anyname = res["name"].get(key, [])
        if shell == "powershell":
            if dns:
                say("ok", f"{label}: DNS knows {host} as {', '.join(dns)}")
            elif anyname:
                say("warn", f"{label}: DNS does not know {host}; Windows found it by broadcast "
                            f"(LLMNR or NetBIOS) as {', '.join(anyname)}, which works on one subnet only")
            else:
                say("fail", f"{label}: the name {host} does not resolve")
        else:
            if anyname:
                say("ok", f"{label}: {host} resolves to {', '.join(anyname)}")
            else:
                say("fail", f"{label}: the name {host} does not resolve")
        stale = [ip for ip in (dns or anyname) if ip not in seen.addresses]
        if stale and (dns or anyname):
            say("warn", f"{label}: the name points at {', '.join(stale)}, but the machine has "
                        f"{', '.join(seen.addresses)}: a stale or wrong record")
        for ip in seen.addresses:
            pinged = res["ping"].get((key, ip), False)
            ports = WINDOWS_PORTS if node.is_windows else LINUX_PORTS
            open_ = [what for p, what in ports if res["tcp"].get((key, ip, p))]
            if pinged:
                say("ok", f"{label} at {ip}: answers a ping" + (f"; open: {', '.join(open_)}" if open_ else
                                                                  "; no service port open (Windows Firewall, or the service is off)"))
            elif open_:
                say("warn", f"{label} at {ip}: drops pings but {', '.join(open_)} answers: its firewall blocks "
                            f"echo requests (Windows does until you allow them)")
            else:
                say("fail", f"{label} at {ip}: no answer. Another subnet with no route, a different VLAN, "
                            f"a firewall, or a cable: work up from the link")
    return _done(source, lines)


_MARK = {"ok": "[ok]  ", "warn": "[!]   ", "fail": "[x]   ", "info": "      "}


def _done(source: str, lines: list[Line]) -> dict:
    bad = sum(1 for l in lines if l.state == "fail")
    warn = sum(1 for l in lines if l.state == "warn")
    ok = sum(1 for l in lines if l.state == "ok")
    summary = ("Everything it tried works" if not bad and not warn else
               f"{bad} problem{'s' if bad != 1 else ''}, {warn} warning{'s' if warn != 1 else ''}, {ok} fine")
    return {"source": source, "lines": [{"state": l.state, "text": l.text} for l in lines],
            "ok": not bad, "summary": summary}


def render_text(res: dict) -> str:
    return "\n".join(f"{_MARK[l['state']]}{l['text']}" for l in res["lines"]) + f"\n\n{res['summary']}\n"


def render_html(res: dict | None, error: str = "") -> str:
    """The Viewer window's page."""
    head = ("<!doctype html><meta charset=utf-8><title>Network test</title><style>"
            ":root{color-scheme:light dark;--ok:#1a7f37;--warn:#9a6700;--fail:#cf222e;--mute:#57606a}"
            "@media (prefers-color-scheme:dark){:root{--ok:#3fb950;--warn:#d29922;--fail:#f85149;--mute:#8b949e}}"
            "body{font:14px 'Segoe UI',system-ui,sans-serif;margin:24px;max-width:860px}"
            "h1{font-size:18px;font-weight:600;margin:0 0 4px}p.s{color:var(--mute);margin:0 0 16px}"
            "ul{list-style:none;padding:0;margin:0}li{display:flex;gap:10px;padding:6px 0;border-bottom:1px solid #8883}"
            "li b{flex:0 0 18px;text-align:center}.ok b{color:var(--ok)}.warn b{color:var(--warn)}.fail b{color:var(--fail)}"
            ".info{color:var(--mute)}</style>")
    if res is None:
        return head + f"<h1>Network test</h1><p class=s>{html.escape(error)}</p>"
    sym = {"ok": "&#10003;", "warn": "!", "fail": "&#10007;", "info": ""}
    items = "".join(f"<li class={l['state']}><b>{sym[l['state']]}</b><span>{html.escape(l['text'])}</span></li>"
                    for l in res["lines"])
    return (head + "<h1>Network test</h1><p class=s>" + html.escape(res["summary"]) +
            ". Run from inside the machine over its agent, as ping, nslookup and Test-NetConnection would; "
            "it changed nothing.</p><ul>" + items + "</ul>")
