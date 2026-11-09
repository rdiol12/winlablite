"""copy to and from a TFTP server: the router's and the switches' configurations
backed up to, and brought back from, a server the student set up in the lab.

``copy running-config tftp:`` and ``copy startup-config tftp:`` ask, as IOS
does, for the server (``Address or name of remote host []?``) and the file
name (``Destination filename [router-confg]?``), then send the
configuration. ``copy tftp: running-config`` asks for the server and the
file, fetches it and applies it line by line through the console's own
command engine, as if it had been pasted at ``configure terminal``: a merge
into what runs, every line that does not parse reported, as on IOS. ``copy
tftp: startup-config`` puts the file in NVRAM instead: it is applied to a
copy of a factory-fresh device, never to the running one, and that result
becomes the startup configuration the next ``reload`` brings up. ``copy
startup-config running-config`` merges NVRAM's text the same way.

How it is real. The transfer is TFTP on the wire, from the router: busybox's
``tftp`` client (Alpine's ``busybox-extras`` from the lab's own package
volume, installed on the router the first time a copy needs it) puts or
gets the file from the server's address, from the router's own address on
the way there; a switch's copy runs inside the switch's management
namespace (winlab/iosl2.py), from its ``interface vlan`` address, so a
switch with no management address cannot reach a server, as on a real
switch. The server is the student's: tftpd-hpa on an Ubuntu machine (the
``tftpd`` pack, winlab/debpacks.py), dnsmasq's TFTP on a Linux box, or any
other TFTP server they install in the lab. The router never has one.

FTP and SCP (``copy running-config ftp:``, ``copy scp: running-config``)
are winlab/ftpscp.py: the same prompts and the same applying of a file, with
a login.

Tested in the sandbox without a router: the prompts, the transfer's shell
(sh -n), its output read back into IOS's messages, and a running
configuration copied out, erased and brought back through the command
engine.
"""

from __future__ import annotations

import base64
import re
import shlex
import time

from . import devcli

MAX_BYTES = 262144
TMP = "/tmp/winlab-tftp.$$"
_HOST = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}))$")
_FILE = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")
CLIENT = ("T=$(command -v tftp || { apk add --no-network busybox-extras >/dev/null 2>&1; command -v tftp; }); "
          "[ -n \"$T\" ] || { echo '#notftp'; exit 0; }; ")
NO_CLIENT = ("% The router has no TFTP client: busybox-extras is not on its package volume. Prepare the router "
             "again (winlab images prepare fabric).")
# Lines show running-config prints that are not commands (IOS ignores them in a file too).
BOILER = ("version ", "boot-start-marker", "boot-end-marker", "no aaa new-model", "Building configuration",
          "Current configuration", "Using ", " negotiation auto", "negotiation auto")


def add_specs(con, add, E) -> None:
    add("copy running-config tftp:", lambda a: start(con, "running-config", "tftp:"), "Copy to tftp: file system", E)
    add("copy startup-config tftp:", lambda a: start(con, "startup-config", "tftp:"), "Copy to tftp: file system", E)
    add("copy tftp: running-config", lambda a: start(con, "tftp:", "running-config"),
        "Update (merge with) current system configuration", E)
    add("copy tftp: startup-config", lambda a: start(con, "tftp:", "startup-config"),
        "Copy to startup configuration", E)
    add("copy running-config <line>", lambda a: start(con, "running-config", a[0]), "Destination filename", E)
    add("copy startup-config <line>", lambda a: start(con, "startup-config", a[0]), "Destination filename", E)
    add("copy tftp: <line>", lambda a: start(con, "tftp:", a[0]), "Destination filename", E)
    add("copy <line>", lambda a: _copy_other(con, a[0]), "Source filename", E)


def _copy_other(con, text: str) -> str:
    words = text.split()
    if len(words) != 2:
        raise devcli.CliError("% Incomplete command." if len(words) < 2 else "% Invalid input detected at '^' marker.")
    return start(con, words[0], words[1])


def parse_url(text: str) -> tuple[str, str, str]:
    """'tftp://10.1.1.5/r1-confg' -> ('tftp', '10.1.1.5', 'r1-confg'); 'tftp:' -> ('tftp', '', '')."""
    m = re.match(r"^([a-z]+):(?://([^/]*)(?:/(.*))?)?$", text.strip(), re.I)
    if not m:
        return "", "", text.strip()
    return m.group(1).lower(), m.group(2) or "", m.group(3) or ""


def _kind(text: str) -> str:
    t = text.strip().lower()
    for word in ("running-config", "startup-config"):
        if len(t) >= 3 and word.startswith(t):
            return word
    if t in ("system:running-config", "nvram:startup-config"):
        return t.split(":")[1]
    scheme, _, _ = parse_url(t)
    return scheme + ":" if scheme else t


def default_name(con) -> str:
    return f"{devcli.ios_name(con.lab, con.device).lower()}-confg"


def start(con, src: str, dst: str) -> str:
    from . import iosimage, iosnv
    said = iosimage.copy(con, src, dst)   # flash at either end: images and configuration files
    if said is not None:
        return said
    s, d = _kind(src), _kind(dst)
    for scheme in ("ftp", "scp"):   # FTP and SCP: winlab/ftpscp.py
        if f"{scheme}:" in (s, d):
            from . import ftpscp
            if (s in ("running-config", "startup-config") and d == f"{scheme}:") or \
                    (s == f"{scheme}:" and d in ("running-config", "startup-config")):
                return ftpscp.start(con, scheme, src, dst)
            return (f"%Error: copy with {scheme}: goes between a server and running-config or startup-config "
                    "here")
    if s in ("running-config", "startup-config") and d == "tftp:":
        _, host, name = parse_url(dst)
        if s == "startup-config" and not startup_body(con):
            return "%Error opening nvram:/startup-config (No such file or directory)"
        iosnv.ask(con, "tftp-host", f"Address or name of remote host [{host}]? ", on=_answer,
                  step="host", src=s, host=host, name=name or default_name(con))
        return ""
    if s == "tftp:" and d in ("running-config", "startup-config"):
        _, host, name = parse_url(src)
        iosnv.ask(con, "tftp-host", f"Address or name of remote host [{host}]? ", on=_answer,
                  step="host", dst=d, host=host, name=name)
        return ""
    if s == "startup-config" and d == "running-config":
        body = startup_body(con)
        if not body:
            return "%Error opening nvram:/startup-config (No such file or directory)"
        errs = apply_config(con, body)
        return "\n".join(errs + [f"{len(body)} bytes copied in 0.0 secs"]).strip()
    if s == "running-config" and d == "startup-config":
        return iosnv.write(con)
    if s.endswith(":") or d.endswith(":"):
        where = s if s.endswith(":") else d
        return (f"%Error: {where} is not offered here: copy to and from a TFTP, FTP or SCP server (tftp:, ftp:, "
                f"scp:) or NVRAM")
    raise devcli.CliError("% Invalid input detected at '^' marker.")


def _answer(con, line: str, q: dict) -> str:
    from . import iosnv
    text = line.strip()
    step = q["step"]
    data = {k: v for k, v in q.items() if k not in ("kind", "prompt", "secret", "tries", "on", "step")}
    if step == "host":
        host = text or q.get("host", "")
        if not host or not _HOST.match(host):
            return "%Error parsing filename (Bad IP address or host name)"
        data["host"] = host
        if q.get("dst"):
            iosnv.ask(con, "tftp-src", f"Source filename [{q.get('name', '')}]? ", on=_answer, step="src", **data)
        else:
            iosnv.ask(con, "tftp-dst", f"Destination filename [{q['name']}]? ", on=_answer, step="put", **data)
        return ""
    if step == "src":
        name = text or q.get("name", "")
        if not name or not _FILE.match(name):
            return "%Error parsing filename (Bad file name)"
        data["name"] = name
        iosnv.ask(con, "tftp-dst", f"Destination filename [{q['dst']}]? ", on=_answer, step="get", **data)
        return ""
    if step == "put":
        name = text or q["name"]
        if not _FILE.match(name):
            return "%Error parsing filename (Bad file name)"
        return put(con, q["src"], q["host"], name)
    if step == "get":
        if text and _kind(text) != q["dst"]:
            return f"%Error opening {text} (Permission denied)"
        return get(con, q["host"], q["name"], q["dst"])
    return ""


# ------------------------------------------------------------------ the transfer
def startup_body(con) -> str:
    from . import iosnv
    data = iosnv.load(con.lab.name) or {}
    snap = (data.get("devices") or {}).get(con.device) or {}
    return "" if snap.get("erased") else snap.get("text", "") or ""


def running_body(con) -> str:
    """The running configuration as a file: show running-config without its header."""
    lines = con._show_run([]).split("\n")
    i = next((k for k, l in enumerate(lines) if l.startswith("Current configuration")), -1)
    return "\n".join(lines[i + 1:]) + "\n"


def netns(con) -> str:
    """Where the copy runs: "" on the router, the switch's management namespace."""
    if con.device == devcli.ROUTER:
        return ""
    from . import iosl2
    return iosl2.netns(con.lab, devcli.switch_id(con.device))


def _no_mgmt(con) -> str:
    return ("% The switch has no management address to reach a server from: interface vlan 1, ip address "
            "<address> <mask>, no shutdown (and ip default-gateway for a server in another network)")


def put_cmd(body: str, host: str, name: str, ns: str = "") -> str:
    b64 = base64.b64encode(body.encode()).decode()
    pre = f"ip netns exec {ns} " if ns else ""
    return (CLIENT + f"f={TMP}; printf %s '{b64}' | base64 -d > $f; "
            f"{pre}\"$T\" -p -l $f -r {shlex.quote(name)} {shlex.quote(host)} 2>&1; echo \"#rc=$?\"; rm -f $f")


def get_cmd(host: str, name: str, ns: str = "") -> str:
    pre = f"ip netns exec {ns} " if ns else ""
    return (CLIENT + f"f={TMP}; rm -f $f; {pre}\"$T\" -g -l $f -r {shlex.quote(name)} {shlex.quote(host)} 2>&1; "
            f"echo \"#rc=$?\"; [ -s $f ] && [ $(wc -c < $f) -le {MAX_BYTES} ] && {{ echo '#data'; base64 $f; }}; "
            f"rm -f $f; {pre}ip -o route get {shlex.quote(host)} 2>/dev/null | head -n 1 | sed 's/^/#via /'")


def parse_result(text: str) -> dict:
    """What the transfer's shell printed: rc, the error busybox gave, the
    file (bytes) and the route's interface."""
    out: dict = {"rc": None, "error": "", "data": None, "dev": "", "notftp": False}
    lines = (text or "").splitlines()
    b64, in_data = [], False
    for line in lines:
        if line == "#notftp":
            out["notftp"] = True
        elif line.startswith("#rc="):
            v = line[4:].strip()
            out["rc"] = int(v) if v.lstrip("-").isdigit() else None
            in_data = False
        elif line == "#data":
            in_data = True
        elif line.startswith("#via "):
            in_data = False
            m = re.search(r"\bdev (\S+)", line)
            out["dev"] = m.group(1) if m else ""
        elif in_data:
            b64.append(line.strip())
        elif line.strip() and out["rc"] is None:
            out["error"] = (out["error"] + " " + line.strip()).strip()
    if b64:
        try:
            out["data"] = base64.b64decode("".join(b64))
        except ValueError:
            out["data"] = None
    return out


def ios_error(err: str) -> str:
    """busybox tftp's complaint, as IOS words it."""
    e = err.lower()
    if "timeout" in e or "timed out" in e:
        return "Timed out"
    if "not found" in e or "no such file" in e:
        return "No such file or directory"
    if "access violation" in e or "permission" in e:
        return "Permission denied"
    if "unreachable" in e:
        return "Network is unreachable"
    if "bad address" in e or "resolve" in e or "unknown host" in e:
        return "Bad IP address or host name"
    if "disk full" in e or "allocation" in e:
        return "No space left on device"
    return err.replace("tftp: ", "") or "I/O error"


def _rate(n: int, secs: float) -> str:
    secs = max(secs, 0.001)
    return f"{n} bytes copied in {secs:.3f} secs ({int(n / secs)} bytes/sec)"


def put(con, src: str, host: str, name: str) -> str:
    body = running_body(con) if src == "running-config" else startup_body(con)
    if not body:
        return "%Error opening nvram:/startup-config (No such file or directory)"
    ns = netns(con)
    if con.device != devcli.ROUTER and not ns:
        return f"%Error opening tftp://{host}/{name} (No route to host)\n{_no_mgmt(con)}"
    t0 = time.time()
    res = parse_result(con._on_router(put_cmd(body, host, name, ns), timeout=40))
    secs = time.time() - t0
    if res["notftp"]:
        return NO_CLIENT
    if res["rc"] != 0:
        why = ios_error(res["error"])
        hint = ""
        if why == "Permission denied":
            hint = ("\n% The server refused to create the file: tftpd-hpa needs --create in TFTP_OPTIONS "
                    "(/etc/default/tftpd-hpa) and a directory its user (tftp) may write")
        return f"%Error opening tftp://{host}/{name} ({why}){hint}"
    return "!!\n" + _rate(len(body.encode()), secs)


def _via(con, dev: str) -> str:
    if con.device != devcli.ROUTER:
        from . import iosl2
        addrs = iosl2.svis(con.lab, devcli.switch_id(con.device))
        return f"Vlan{addrs[0][0] if addrs else 1}"
    m = re.match(r"^[a-z0-9]+\.(\d+)$", dev or "")
    if m:
        vid = int(m.group(1))
        for sid, seg in con.plan.segments.items():
            if seg.vid == vid:
                name = con.iface_of(seg.network)
                if name:
                    return name
    return dev or "unknown"


def get(con, host: str, name: str, dst: str) -> str:
    ns = netns(con)
    if con.device != devcli.ROUTER and not ns:
        return f"%Error opening tftp://{host}/{name} (No route to host)\n{_no_mgmt(con)}"
    t0 = time.time()
    res = parse_result(con._on_router(get_cmd(host, name, ns), timeout=40))
    secs = time.time() - t0
    head = f"Accessing tftp://{host}/{name}..."
    if res["notftp"]:
        return NO_CLIENT
    if res["rc"] != 0 or res["data"] is None:
        why = ios_error(res["error"]) if res["rc"] != 0 else "File too large or empty"
        return f"{head}\n%Error opening tftp://{host}/{name} ({why})"
    data = res["data"]
    text = data.decode("utf-8", "replace")
    n = len(data)
    via = _via(con, res["dev"]) if res["dev"] or con.device != devcli.ROUTER else ""
    out = [head, f"Loading {name} from {host}" + (f" (via {via})" if via else "") + ": !", f"[OK - {n} bytes]", ""]
    if dst == "running-config":
        errs = apply_config(con, text)
        out += errs + ([""] if errs else [])
        out += [_rate(n, secs), f"%SYS-5-CONFIG_I: Configured from tftp://{host}/{name} by console"]
    else:
        errs = to_startup(con, text)
        out += errs + ([""] if errs else []) + ["[OK]", _rate(n, secs)]
    return "\n".join(out)


# ------------------------------------------------------------------ applying a file
def config_lines(text: str) -> list[str]:
    """A configuration file's command lines, in order: comments, the
    header show running-config prints, and what follows 'end' left out."""
    out = []
    for raw in (text or "").replace("\r", "").split("\n"):
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("!"):
            continue
        if s == "end":
            break
        if line.startswith(BOILER) or s.startswith(BOILER):
            continue
        out.append(line)
    return out


def _error(out: str) -> str:
    for marker in ("% Invalid input", "% Incomplete command", "% Ambiguous command"):
        if marker in out:
            return next(l for l in out.splitlines() if marker in l).strip()
    return ""


def apply_config(con, text: str, live: bool = True) -> list[str]:
    """Each line of a configuration file typed at configure terminal, as a
    paste does: the lines that do not parse, each with IOS's complaint. The
    lab file is written as it goes and the running network takes it once,
    at the end."""
    saved_mode, saved_ctx, saved_hist = con.s.mode, con.s.ctx, list(con.s.history)
    real = type(con)._save.__get__(con)
    had_own = "_save" in con.__dict__
    if not had_own:
        con._save = lambda live=True: real(False)
    errs: list[str] = []
    # A file's lines are not commands a person typed: no per-line command
    # authorization or accounting (winlab/aaa.py), as on IOS.
    had_no_author = getattr(con, "_no_author", False)
    con._no_author = True
    try:
        con.s.mode, con.s.ctx = "config", ""
        for line in config_lines(text):
            out = con.run(line)
            err = _error(out or "")
            if err:
                errs.append(f"{line.strip()}\n{err}")
            if con.s.ask:   # a line that asked something (a [confirm]): not in a file
                con.s.ask = None
    finally:
        con._no_author = had_no_author
        if not had_own:
            del con._save
        con.s.mode, con.s.ctx, con.s.history = saved_mode if saved_mode != "config" else "enable", "", saved_hist
    if live and not had_own:
        note = con._save().strip()
        if note:
            errs.append(note)
    return errs


class _Shadow:
    """A dashboard for a copy of the lab: the device the file is applied to
    for NVRAM, never the running one."""

    def __init__(self, lab, plan):
        self.lab, self.plan = lab, plan

    def reload(self) -> None:
        pass


def to_startup(con, text: str) -> list[str]:
    """copy tftp: startup-config: the file applied to a factory-fresh copy
    of the device, and that kept as the startup configuration."""
    import copy
    from . import iosnv, netplan
    lab = copy.deepcopy(con.lab)
    iosnv.revert(lab, con.device, None)
    try:
        plan = netplan.compile_topology(lab, check_ports=False)
    except Exception:  # noqa: BLE001 - the running plan does for a copy that does not compile
        plan = con.plan
    sh = devcli.Console(_Shadow(lab, plan), con.device,
                        runner_factory=lambda: (None, "not while a file goes to NVRAM"), link=lambda l, up: None)
    sh._save = lambda live=True: ""
    sh.powered = lambda: True
    sh._fresh = lambda: None
    sh.s.mode, sh.s.authed = "enable", True
    errs = apply_config(sh, text, live=False)
    iosnv.write(sh)
    return errs
