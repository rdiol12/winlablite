"""WPA2-Enterprise on the workbench's access points: Wi-Fi that lets a
laptop in only once the student's RADIUS server says who is signing in.

An Enterprise AP has no network key. It knows a RADIUS server (address,
port, shared secret, set in the AP's own web pages, LuCI: encryption
WPA2-EAP, the server, its port and secret) and has an address of its own
on its VLAN: the address its RADIUS requests come from, so the one the
server must list as its RADIUS client.

It is real, the same way 802.1X on a switch port is (winlab/dot1x.py). A
laptop's wireless card is a port of the router's bridge like any cable
(QEMU has no Wi-Fi card, winlab/wifi.py); when the laptop joins an
Enterprise network, hostapd's wired driver runs on that port with the AP's
RADIUS settings, its name as NAS-Identifier, NAS-Port-Type Wireless-802.11
and the SSID in Called-Station-Id, and an nftables bridge rule passes
nothing but EAPOL from the laptop until hostapd has heard Access-Accept.
Windows answers with Wired AutoConfig (dot3svc) and the Authentication tab
of its network adapter, since the card it sees is a wired one; a real
laptop would use WLAN AutoConfig and a wireless profile, with the same EAP
(PEAP and MS-CHAP v2) and the same server. Roaming to another AP
authenticates again, against that AP's settings.

The requests leave from the AP itself: the router's hostapd sends them to
the AP (from the router's own address on the AP's VLAN), and the AP, an
OpenWrt VM, sends them on to its RADIUS server from its own address with
two nftables NAT rules (relay_of, kept in the AP by winlab/workbench.py's
read of it), so the server sees the AP as its client, and an AP that
cannot reach its server (its gateway, a firewall) gets no answer, as a
real one would. The AP's panel shows who is associated and who is signed in (the
user name RADIUS saw), and why not: no EAP from Windows, no answer from the
server (the shared secret, or the AP not a RADIUS client there), rejected
at once (no network policy matches: the user not in its group), rejected in
the TLS handshake (the laptop does not trust the server's certificate), or
after the sign-in (the password). The last three are read from how far the
exchange got; the server's own log (NPS event 6273 and its reason code)
says it for certain.

What winlab last read of the AP's settings is in its ``[devices."ap:<id>"]``
table: security = "wpa2-ent", radius ("<ip> <port>"), radius-key, ip.
What was last seen of each laptop, the log and the drill are runtime state
in the lab's folder.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time

from . import devcli, dot1x, paths, state, wifi

RUN = "/run/winlab-wlan"
TABLE = "winlab_wlan"
NAS_PORT_WIRELESS = 19            # RADIUS NAS-Port-Type: Wireless - IEEE 802.11
LOG_KEEP = 60
_IF = re.compile(r"^[A-Za-z0-9]{1,12}$")


class WpaEntError(Exception):
    pass


# ------------------------------------------------------------------ settings
def enterprise(lab) -> dict[str, dict]:
    return {k: a for k, a in wifi.aps(lab).items() if a["security"] == "wpa2-ent"}


def source(plan, ap: dict) -> tuple[str, str]:
    """(where the AP's RADIUS requests come from: the AP's own address, the
    router's address on the AP's VLAN that hands them to the AP). Both ""
    when the AP's VLAN does not reach the router."""
    lab = plan.lab
    net = lab.networks.get(ap["network"])
    if not ap["ip"] or net is None:
        return "", ""
    try:
        seg = plan.segment_of(net.id)
    except KeyError:
        return "", ""
    if not seg.network.routed:
        return "", ""
    return ap["ip"], seg.network.router_ip


def relay_of(plan, ap: dict) -> str:
    """The AP's two NAT rules that carry the router's RADIUS requests on to
    its server from the AP's own address (winlab/openwrt.py)."""
    from . import openwrt
    _, router_ip = source(plan, ap)
    return openwrt.relay_script(ap, router_ip) if router_ip else ""


def issue(plan, ap: dict) -> str:
    """What stops the AP asking anyone, or ""."""
    if not ap["network"]:
        return "it has no cable, so no power"
    if not ap["radius"] or not ap["radius_key"]:
        return ("no RADIUS server: in the AP's own pages (LuCI, Network > Wireless, Wireless Security) "
                "set the server's address, its port and the shared secret")
    src, _ = source(plan, ap)
    if not src:
        return (f"its VLAN ({ap['network']}) is not cabled to the router, so the AP's address reaches nothing: "
                f"cable the switch to the router")
    return ""


def clients(plan) -> list[dict]:
    """The laptops on an Enterprise AP: the AP, the laptop and the router
    port its wireless card is."""
    lab, out = plan.lab, []
    for ap in enterprise(lab).values():
        if not ap["network"]:
            continue
        for node_id in wifi.clients(lab, ap["id"]):
            node = lab.nodes[node_id]
            idx = wifi.wireless(node)[:1]
            link = next((l for l in plan.ports_for(node_id) if idx and l.nic_index == idx[0] and l.plugged), None)
            if link is not None and _IF.match(link.fabric_iface or ""):
                out.append({"ap": ap, "node": node_id, "link": link, "iface": link.fabric_iface})
    return out


# ------------------------------------------------------------------ the router
def conf(plan, ap: dict, iface: str) -> str:
    """hostapd's configuration for one laptop's port: the wired driver,
    802.1X, the AP's RADIUS server and what a wireless AP tells it."""
    src, via = source(plan, ap)
    out = [f"# {ap['name']}: WPA2-Enterprise for the laptop on {iface} (winlab/wpaent.py)",
           f"interface={iface}", "driver=wired", "ieee8021x=1", "eapol_version=2", "use_pae_group_addr=1",
           "eap_reauth_period=3600", f"ctrl_interface={dot1x.CTRL}", f"nas_identifier={ap['name']}",
           f"ssid={ap['ssid']}",                      # Called-Station-Id: <its address>:<SSID>
           f"radius_auth_req_attr=61:d:{NAS_PORT_WIRELESS}",
           "logger_syslog=-1", "logger_syslog_level=2", "logger_stdout=-1", "logger_stdout_level=2"]
    # NAS-IP-Address is the AP's; the request goes to the AP, which sends it
    # on to auth_server from its own address (relay_of).
    out += [f"own_ip_addr={src}", f"radius_client_addr={via}", f"# relayed by {ap['name']} to {ap['radius']}",
            f"auth_server_addr={src}", "auth_server_port=1812",
            f"auth_server_shared_secret={ap['radius_key']}"]
    return "\n".join(out) + "\n"


ACT_SH = """#!/bin/sh
# hostapd_cli -a calls this: <port> <event> <address>. A laptop the RADIUS
# server accepted is let through its AP (winlab/wpaent.py).
echo "$(date +%s) $1 $2 $3" >> {run}/events
case "$2" in
AP-STA-CONNECTED) nft add element bridge {table} wl_$1 "{{ $3 }}" 2>/dev/null ;;
AP-STA-DISCONNECTED) nft delete element bridge {table} wl_$1 "{{ $3 }}" 2>/dev/null ;;
esac
"""


def render(plan, reset: bool = False) -> list[str]:
    """The Enterprise APs on the router: their own addresses, the gate on
    each laptop's port, one hostapd a laptop, each started again only when
    its settings changed (a laptop that stays keeps its session)."""
    want = [c for c in clients(plan) if not issue(plan, c["ap"])]
    gated = clients(plan)
    if not gated and not reset:
        return []
    out = ["### WPA2-Enterprise on the access points: 802.1X on each laptop's port (winlab/wpaent.py)",
           f"mkdir -p {RUN} {dot1x.CTRL}",
           # (an AP's own address was once a second address here; it is the AP's now)
           f"[ -f {RUN}/addrs ] && while read a d; do ip addr del $a dev $d 2>/dev/null; done < {RUN}/addrs; : > {RUN}/addrs"]
    confs = {c["iface"]: conf(plan, c["ap"], c["iface"]) for c in want}
    sums = {i: hashlib.sha256(t.encode()).hexdigest()[:16] for i, t in confs.items()}
    out.append("K=''")
    for i in sorted(confs):
        out.append(f"[ \"$(cat {RUN}/hapd-{i}.sum 2>/dev/null)\" = {sums[i]} ] && kill -0 $(cat {RUN}/hapd-{i}.pid "
                   f"2>/dev/null) 2>/dev/null && K=\"$K {i}\"")
    # what hostapd let in on the ports that keep their hostapd
    out += [f"for i in $K; do nft list set bridge {TABLE} wl_$i 2>/dev/null | tr -d '\\n\\t' | "
            f"sed -n 's/.*elements = {{\\([^}}]*\\)}}.*/\\1/p' > {RUN}/wl_$i.keep; done",
            # (by their pid files: the router runs this as sh -c, so a pkill -f
            # pattern would match this very script)
            f"for f in {RUN}/hapd-*.pid; do [ -e \"$f\" ] || continue; b=$(basename $f .pid); b=${{b#hapd-}}; "
            f"b=${{b%.cli}}; case \" $K \" in *\" $b \"*) ;; *) kill $(cat $f) 2>/dev/null; rm -f $f "
            f"{RUN}/hapd-$b.sum;; esac; done",
            f"nft delete table bridge {TABLE} 2>/dev/null; true"]
    if gated:
        sets, rules = [], []
        for c in gated:
            i = c["iface"]
            sets.append(f"  set wl_{i} {{ type ether_addr; }}   # {c['node']} on {c['ap']['name']} "
                        f"({c['ap']['ssid']}): let in by 802.1X")
            rules += [f"    iifname \"{i}\" ether type 0x888e accept",
                      f"    iifname \"{i}\" ether saddr != @wl_{i} drop"]
        out += ["nft -f - <<'WINLAB_EOF'", f"table bridge {TABLE} {{", *sets, "  chain ports {",
                "    type filter hook prerouting priority -190; policy accept;", *rules, "  }", "}", "WINLAB_EOF"]
    out.append(f"for i in $K; do [ -s {RUN}/wl_$i.keep ] && nft add element bridge {TABLE} wl_$i "
               f"\"{{ $(cat {RUN}/wl_$i.keep) }}\" 2>/dev/null; done; rm -f {RUN}/wl_*.keep")
    if confs:
        out += [f"cat > {RUN}/act.sh <<'WINLAB_EOF'", ACT_SH.format(run=RUN, table=TABLE).rstrip("\n"),
                "WINLAB_EOF", f"chmod +x {RUN}/act.sh",
                f"command -v hostapd >/dev/null || echo \"$(date +%s) - hostapd-missing -\" >> {RUN}/events"]
    for c in want:
        i = c["iface"]
        out += [f"case \" $K \" in *\" {i} \"*) ;; *)   # {c['node']} on {c['ap']['name']}",
                f"  cat > {RUN}/hapd-{i}.conf <<'WINLAB_EOF'", confs[i].rstrip("\n"), "WINLAB_EOF",
                f"  hostapd -B -P {RUN}/hapd-{i}.pid {RUN}/hapd-{i}.conf >> {RUN}/hostapd.log 2>&1",
                f"  hostapd_cli -p {dot1x.CTRL} -i {i} -a {RUN}/act.sh -B -P {RUN}/hapd-{i}.cli.pid >/dev/null 2>&1",
                # ask the laptop who it is, as an AP does once it has associated
                f"  sleep 1; hostapd_cli -p {dot1x.CTRL} -i {i} new_sta {c['link'].mac.lower()} >/dev/null 2>&1",
                f"  echo {sums[i]} > {RUN}/hapd-{i}.sum ;;", "esac"]
    out += ["true", ""]
    return out


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


def live_cmd(plan) -> str:
    ifaces = sorted({c["iface"] for c in clients(plan)})
    return (f"echo '#events'; tail -n 60 {RUN}/events 2>/dev/null; " + dot1x.live_cmd(ifaces) + "echo '#end'")


def parse_live(text: str) -> dict:
    """live_cmd's answer: {"events": [...], "dot1x": {iface: {"sta", "mib"}}}."""
    ev, rest, sec = [], [], ""
    for line in (text or "").splitlines():
        s = line.strip()
        if s in ("#events", "#end"):
            sec = s[1:]
            continue
        if s.startswith(("#sta ", "#mib ")):
            sec = "dx"
        if sec == "events" and s:
            ev.append(s)
        elif sec == "dx":
            rest.append(line)
    return {"events": ev, "dot1x": dot1x.parse("\n".join(rest))}


# ------------------------------------------------------------------ what the AP says about a laptop
CAUSES = {
    "auth": "signed in",
    "no-eap": ("associated, but Windows never answered 802.1X: start Wired AutoConfig (dot3svc) and turn on "
               "IEEE 802.1X on the adapter's Authentication tab"),
    "no-answer": ("waiting for the RADIUS server, which does not answer: the shared secret differs from the "
                  "server's, the server does not list the AP's address as a RADIUS client, or it is off"),
    "policy": ("rejected straight away, before the TLS handshake: no policy on the server matches the request "
               "(the user is not in the policy's group, or a condition such as NAS Port Type Wireless), or the "
               "server does not know the user"),
    "cert": ("rejected in the TLS handshake: the laptop does not trust the server's certificate (not from a CA "
             "it trusts, or not the server name it expects), or the server has no certificate for PEAP"),
    "credentials": ("rejected after the whole sign-in: a wrong user name or password, a disabled account, or "
                    "a policy that refuses this user (not in its group); the server's log says which "
                    "(NPS event 6273, its Reason Code)"),
    "running": "signing in",
    "issue": "",
}


def verdict(sta: dict | None, mib: dict) -> tuple[str, str]:
    """(auth | wait | fail, a CAUSES key) for one laptop, from hostapd's
    station (gone after a reject) and RADIUS counters (one hostapd a laptop,
    so they are the laptop's). A reject is placed by how far the EAP
    exchange got before it, in Access-Challenges a try: one at most (before
    the TLS handshake: policy), a few (in it: the certificate), or the whole
    of PEAP, eight or so (the password). Measured with hostapd, FreeRADIUS
    and wpa_supplicant: 1, 4 and 8."""
    def n(d, k):
        try:
            return int(d.get(k, "0"))
        except ValueError:
            return 0
    sta = sta or {}
    if sta.get("authorized"):
        return "auth", "auth"
    rej = n(mib, "radiusAuthClientAccessRejects") or n(sta, "dot1xAuthBackendAuthFails")
    if rej:
        ch = n(mib, "radiusAuthClientAccessChallenges") if n(mib, "radiusAuthClientAccessRejects") else \
            n(sta, "dot1xAuthBackendAccessChallenges")
        per = ch / rej
        return "fail", "policy" if per < 1.5 else "cert" if per <= 5 else "credentials"
    if not sta:
        return "wait", "no-eap"
    ch = n(sta, "dot1xAuthBackendAccessChallenges")
    if not sta.get("dot1xAuthSessionUserName"):
        return "wait", "no-eap"
    if not ch and (n(mib, "radiusAuthClientAccessRequests") or n(mib, "radiusAuthClientTimeouts")):
        return "wait", "no-answer"
    if ch and n(sta, "dot1xAuthAuthTimeoutsWhileAuthenticating"):
        return "fail", "cert"   # Windows stopped answering part-way, as it does over a certificate it rejects
    return "wait", "running"


# ------------------------------------------------------------------ runtime state
def _rt_path(lab_name: str):
    return paths.lab_dir(lab_name) / "wpaent.json"


def runtime(lab_name: str) -> dict:
    try:
        d = json.loads(_rt_path(lab_name).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _rt_save(lab_name: str, d: dict) -> None:
    state.save_json(_rt_path(lab_name), d)


_EVENT_TEXT = {"CTRL-EVENT-EAP-STARTED": "{node}: 802.1X started", "CTRL-EVENT-EAP-SUCCESS2": "{node}: EAP success",
               "AP-STA-CONNECTED": "{node}: authorized, its traffic passes",
               "CTRL-EVENT-EAP-FAILURE2": "{node}: EAP failure (the RADIUS server rejected it)",
               "AP-STA-DISCONNECTED": "{node}: off the AP"}


def _events(plan, events: list[str], rt: dict) -> None:
    """hostapd's events (ACT_SH) into the APs' logs, each once."""
    if not events:
        return
    def t(e):
        w = e.split()
        return int(w[0]) if w and w[0].isdigit() else 0
    last = rt.get("event", "")
    if last in events:
        start = len(events) - events[::-1].index(last)
    else:  # the tail moved past it: what is newer than it
        start = next((k for k, e in enumerate(events) if t(e) > t(last)), len(events)) if last else 0
    where = {c["iface"]: c for c in clients(plan)}
    log = rt.setdefault("log", [])
    for e in events[start:]:
        parts = e.split()
        if len(parts) >= 3 and parts[2] == "hostapd-missing":
            log.append({"t": t(e), "ap": "", "text": dot1x.MISSING})
            continue
        c = where.get(parts[1]) if len(parts) >= 4 else None
        fmt = _EVENT_TEXT.get(parts[2]) if len(parts) >= 3 else None
        if c is None or fmt is None:
            continue
        log.append({"t": t(e), "ap": c["ap"]["id"], "text": fmt.format(node=c["node"])})
    del log[:-LOG_KEEP]
    rt["event"] = events[-1]


def sessions(plan, data: dict) -> dict[str, dict]:
    """Per laptop on an Enterprise AP, what the AP says now."""
    out = {}
    dx = data.get("dot1x", {})
    for c in clients(plan):
        why = issue(plan, c["ap"])
        d = dx.get(c["iface"], {})
        sta = d.get("sta", {}).get(c["link"].mac.lower())
        if why:
            st, cause = "wait", "issue"
        elif not d:
            st, cause = "wait", "running"
        else:
            st, cause = verdict(sta, d.get("mib", {}))
        out[c["node"]] = {"ap": c["ap"]["id"], "state": st, "cause": cause, "why": why or CAUSES[cause],
                          "user": (sta or {}).get("dot1xAuthSessionUserName", ""),
                          "mac": devcli.dotted_mac(c["link"].mac.lower()), "t": int(time.time())}
    return out


# ------------------------------------------------------------------ the canvas
def view(lab, plan) -> dict:
    """Per Enterprise AP: where its requests come from, what stops it, and
    what was last seen of each laptop on it (the canvas's locks)."""
    rt = runtime(lab.name)
    seen = rt.get("seen", {})
    aps = {}
    for ap in enterprise(lab).values():
        src, _ = source(plan, ap)
        aps[ap["id"]] = {"from": src, "issue": issue(plan, ap), "log": [x for x in rt.get("log", []) if x["ap"] == ap["id"]][-12:],
                         "clients": {n: s for n, s in seen.items() if s.get("ap") == ap["id"]
                                     and n in wifi.clients(lab, ap["id"])}}
    d = drill_state(lab.name)
    drill = None
    if d:
        drill = {"id": d["id"], "ap": d["ap"], "shown": int(d.get("hints", 0)), "of": len(HINTS),
                 "hints": [_pt(h).format(**_words(lab, d)) for h in HINTS[:int(d.get("hints", 0))]],
                 "symptom": _pt(SYMPTOM).format(**_words(lab, d)), "done": bool(d.get("done")),
                 "title": _pt(TITLE) if d.get("done") else "", "fix": _pt(FIX) if d.get("done") else ""}
    return {"aps": aps, "drill": drill}


# ------------------------------------------------------------------ actions
def act(dash, action: str, params: dict) -> dict:
    try:
        if action == "wb-wpa-live":
            return live(dash)
        if action == "wb-wpa-drill":
            return drill(dash, str(params.get("op", "")), params)
    except WpaEntError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown WPA2-Enterprise action {action!r}"}


def live(dash) -> dict:
    """hostapd's sessions for the laptops on Enterprise APs, kept in the
    lab's folder: the canvas polls this while the router runs."""
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
    return take(dash, parse_live(text))


def take(dash, data: dict) -> dict:
    """A live read into the lab's folder: what changed, in a line."""
    rt = runtime(dash.lab.name)

    def key(s):
        return [s.get("state"), s.get("cause"), s.get("user"), s.get("ap")]
    was = {n: key(s) for n, s in rt.get("seen", {}).items()}
    now = sessions(dash.plan, data)
    for n, s in now.items():  # hostapd forgets a station it rejected: keep the name it gave
        old = rt.get("seen", {}).get(n, {})
        if not s["user"] and old.get("user") and old.get("ap") == s["ap"] and s["state"] == "fail":
            s["user"] = old["user"]
    _events(dash.plan, data.get("events", []), rt)
    rt["seen"] = now
    _rt_save(dash.lab.name, rt)
    said = [f"{n}: " + (f"signed in as {s['user']}" if s["state"] == "auth" else s["why"])
            for n, s in now.items() if was.get(n) != key(s)]
    return {"ok": True, "t": time.time(), "clients": now, "said": said[:1],
            "changed": was != {n: key(s) for n, s in now.items()}}


# ------------------------------------------------------------------ the drill
# A graded fault in the manner of portsec.DRILLS: the AP's shared secret
# changed without a word, a hint ladder, Check my fix, Give up.
TITLE = "The access point's RADIUS shared secret does not match the server's"
SYMPTOM = "laptops on {ap} cannot get on the Wi-Fi any more: they connect and then never get an address"
HINTS = (
    "Click {ap} on the canvas: under Connected, a laptop that stays 'waiting for the RADIUS server' was "
    "neither accepted nor rejected. The server is not answering at all.",
    "A server that answers nothing, rather than a reject, is the shared secret: it cannot verify the "
    "request, so it drops it. On NPS the System log has event 18 (a Message-Authenticator that is not "
    "valid) from {ap}'s address; FreeRADIUS -X says the shared secret is incorrect.",
    "In {ap}'s own pages (LuCI: Network > Wireless, Edit, Wireless Security), type the secret the server "
    "has for {ap} (its RADIUS client) as the RADIUS secret and Save & Apply; or set a new one on both sides.",
)
FIX = "the AP's shared secret back to the one the RADIUS server has for it"


def _pt(text: str) -> str:
    """A drill text in the desktop's language (content/i18n/content/<lang>/problems.json)."""
    from .content import problem_text
    return problem_text(text)


def _drill_path(lab_name: str):
    return paths.lab_dir(lab_name) / "wpaent-drill.json"


def drill_state(lab_name: str) -> dict | None:
    try:
        return json.loads(_drill_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _drill_save(lab_name: str, data: dict | None) -> None:
    state.save_json(_drill_path(lab_name), data)


def _words(lab, d: dict) -> dict:
    ap = wifi.aps(lab).get(d.get("ap", ""))
    return {"ap": ap["name"] if ap else d.get("ap", "")}


def _sum(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def drill(dash, op: str, params: dict) -> dict:
    from .workbench import _save, _sync
    lab = dash.lab
    d = drill_state(lab.name)
    if op == "start":
        if d and not d.get("done"):
            raise WpaEntError("a fault is already hidden in this network: find it, or give up")
        cands = [a for a in enterprise(lab).values() if a["radius_key"] and a["network"]]
        want = str(params.get("ap") or "")
        cands = [a for a in cands if a["id"] == want] or cands
        if not cands:
            raise WpaEntError("set WPA2-Enterprise up first: an access point with a RADIUS server and its shared secret")
        ap = random.choice(cands)
        key = ap["radius_key"]
        bad = key[:-1] + ("x" if not key.endswith("x") else "y")
        _on_ap(lab, ap, bad)
        lab.devices[wifi.PREFIX + ap["id"]]["radius-key"] = bad
        _save(dash)
        _drill_save(lab.name, {"id": "radius-secret", "ap": ap["id"], "key_sum": _sum(key), "was": key,
                               "hints": 0, "at": int(time.time())})
        return {"ok": True, "message": "something on the Wi-Fi is broken; find it with the canvas, the AP's panel "
                                       "and the server's log, then Check my fix" + _sync(dash)}
    if not d:
        raise WpaEntError("no Wi-Fi fault in this network")
    if op == "hint":
        d["hints"] = min(len(HINTS), int(d.get("hints", 0)) + 1)
        _drill_save(lab.name, d)
        return {"ok": True, "message": _pt(HINTS[d["hints"] - 1]).format(**_words(lab, d))}
    if op == "check":
        res = check(dash, d)
        if res["passed"]:
            d["done"] = True
            _drill_save(lab.name, d)
        return res
    if op in ("undo", "close"):
        if op == "undo" and not d.get("done"):
            own = lab.devices.get(wifi.PREFIX + d["ap"])
            if own is not None:
                ap = wifi.aps(lab).get(d["ap"])
                if ap is not None:
                    _on_ap(lab, ap, d["was"])
                own["radius-key"] = d["was"]
            _save(dash)
            _drill_save(lab.name, None)
            return {"ok": True, "message": f"put back: it was {_pt(TITLE)[0].lower() + _pt(TITLE)[1:]}{_sync(dash)}"}
        _drill_save(lab.name, None)
        return {"ok": True, "message": ""}
    raise WpaEntError(f"unknown drill step {op!r}")


ap_run = None   # (lab_name, ap_id, script) -> None: a seam for the tests


def _on_ap(lab, ap: dict, secret: str) -> None:
    """The secret into the AP's own configuration, as someone at its pages
    would leave it (the drill's fault, and Give up)."""
    from . import openwrt
    sec = ap.get("iface") or "default_radio0"
    script = (f"uci set wireless.{sec}.auth_secret='{secret}' && uci commit wireless && wifi reload")
    try:
        if ap_run is not None:
            ap_run(lab.name, ap["id"], script)
        else:
            openwrt.run(lab.name, ap["id"], script, timeout=30)
    except openwrt.OpenWrtError as exc:
        raise WpaEntError(f"{ap['name']} must be on for this: {exc}") from None


def check(dash, d: dict) -> dict:
    """Check my fix: the AP's secret is the server's again, or (the server
    took the new one) a laptop on it signs in."""
    lab = dash.lab
    ap = wifi.aps(lab).get(d["ap"])
    same = bool(ap and _sum(ap["radius_key"]) == d["key_sum"])
    authed = False
    from .workbench import _running
    if ap and not same and "fabric" in _running(lab.name):
        r = live(dash)
        authed = any(s["state"] == "auth" and s["ap"] == d["ap"] for s in r.get("clients", {}).values())
    name = _words(lab, d)["ap"]
    rows = [(f"{name}'s shared secret is the server's again (or the server took the new one and a laptop signs in)",
             same or authed)]
    passed = all(ok for _, ok in rows)
    msg = (f"fixed: it was {_pt(TITLE)[0].lower() + _pt(TITLE)[1:]}. The fix: {_pt(FIX)}." if passed else
           "not yet: " + "; ".join(t for t, ok in rows if not ok))
    return {"ok": True, "passed": passed, "message": msg, "results": [{"check": t, "passed": ok} for t, ok in rows]}
