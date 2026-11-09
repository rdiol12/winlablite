"""copy to and from FTP and SCP servers: the router's and the switches'
configurations backed up to a server that asks for a login, over FTP, or
over SSH with SCP.

TFTP (winlab/tftpcopy.py) has no login at all. FTP asks for a user and a
password (both cross the wire in clear), SCP runs over SSH, so the login and
the file are encrypted. On IOS:

- ``ip ftp username <user>`` and ``ip ftp password <password>`` are kept in
  the configuration and used by every ``copy ... ftp:``; a URL with
  ``ftp://<user>:<password>@<host>/<file>`` overrides them for one copy.
  ``copy running-config ftp:`` asks for the server and the file name as the
  TFTP copy does; ``copy ftp: running-config`` merges a file into what runs,
  ``copy ftp: startup-config`` writes NVRAM.
- ``copy running-config scp:`` asks for the server, the user name (the
  session's own by default), the file name, then the password; ``copy scp:
  running-config`` the server, user, source file and password. The file
  name is relative to that user's home directory on the server.

How it is real. The transfer is FTP or SSH on the wire, from the router (a
switch's from inside its management namespace, winlab/iosl2.py, so from
its ``interface vlan`` address, as the TFTP copy does). The clients are
Alpine's own packages from the lab's package volume, installed on the
router the first time a copy needs them: curl for FTP (it speaks FTP's
USER, PASS, STOR and RETR, passive mode, as IOS does by default), and
Dropbear's scp with its dbclient for SCP (dbclient takes the password from
the environment, never the command line, and accepts the server's host key
the first time, as answering yes does). The server is the student's: vsftpd
from the ``ftpd`` pack and OpenSSH, which every lab Ubuntu machine already
runs.

What is not here: ``ip scp server enable`` (the device as an SCP server
that a PC copies into), ``ip ftp source-interface``, and active-mode FTP
(``no ip ftp passive``): passive mode only.
"""

from __future__ import annotations

import base64
import re
import shlex
import time
from urllib.parse import quote

from . import devcli, tftpcopy

MAX_BYTES = tftpcopy.MAX_BYTES
_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
_SECRET = re.compile(r"^[!-~]{1,64}$")
FTP_CLIENT = ("C=$(command -v curl || { apk add --no-network curl >/dev/null 2>&1; command -v curl; }); "
              "[ -n \"$C\" ] || { echo '#noclient'; exit 0; }; ")
SCP_CLIENT = ("S=$(command -v scp); D=$(command -v dbclient); "
              "if [ -z \"$S\" ] || [ -z \"$D\" ]; then apk add --no-network dropbear-scp dropbear-dbclient "
              ">/dev/null 2>&1; S=$(command -v scp); D=$(command -v dbclient); fi; "
              "{ [ -n \"$S\" ] && [ -n \"$D\" ]; } || { echo '#noclient'; exit 0; }; ")
NO_CLIENT = {
    "ftp": "% The router has no FTP client: curl is not on its package volume. Prepare the router again "
           "(winlab images prepare fabric).",
    "scp": "% The router has no SCP client: dropbear-scp is not on its package volume. Prepare the router again "
           "(winlab images prepare fabric).",
}


# ------------------------------------------------------------------ the settings
def ftp_login(lab, device: str) -> tuple[str, str]:
    own = lab.devices.get(device, {})
    return own.get("ftp-user", ""), own.get("ftp-pass", "")


def add_specs(con, add, C) -> None:
    add("ip ftp username <name>", lambda a: _set(con, "ftp-user", a[0]), "Specify username for FTP connections", C)
    add("ip ftp password <line>", lambda a: _set(con, "ftp-pass", a[0]), "Specify password for FTP connections", C)
    add("no ip ftp username", lambda a: _set(con, "ftp-user", ""), "Negate a command or set its defaults", C)
    add("no ip ftp password", lambda a: _set(con, "ftp-pass", ""), "Negate a command or set its defaults", C)
    add("no ip ftp username <line>", lambda a: _set(con, "ftp-user", ""), "Negate a command or set its defaults", C)
    add("no ip ftp password <line>", lambda a: _set(con, "ftp-pass", ""), "Negate a command or set its defaults", C)
    add("ip ftp passive", lambda a: "", "Connect using passive mode", C)
    add("no ip ftp passive", lambda a: "% Active-mode FTP is not offered here: the copies use passive mode",
        "Negate a command or set its defaults", C)


def _set(con, key: str, value: str) -> str:
    own = devcli.settings(con.lab, con.device)
    value = value.strip()
    if not value:
        own.pop(key, None)
    else:
        w = value.split()
        if key == "ftp-pass" and len(w) == 2 and w[0] in ("0", "7"):
            if w[0] == "7":
                raise devcli.CliError("% Only a clear-text password here (ip ftp password <text>, or 0 <text>)")
            w = w[1:]
        if len(w) != 1:
            raise devcli.CliError("% One word, no spaces")
        if key == "ftp-user" and not _USER.match(w[0]):
            raise devcli.CliError("% A user name: letters, digits, _ . - (up to 32)")
        if key == "ftp-pass" and not _SECRET.match(w[0]):
            raise devcli.CliError("% A password: 1 to 64 printable characters, no spaces")
        own[key] = w[0]
    con._save(live=False)
    return ""


def run_lines(lab, device: str) -> list[str]:
    user, pw = ftp_login(lab, device)
    return ([f"ip ftp username {user}"] if user else []) + ([f"ip ftp password {pw}"] if pw else [])


# ------------------------------------------------------------------ the prompts
def parse_url(text: str) -> tuple[str, str, str, str, str]:
    """'ftp://u:p@10.1.1.5/dir/r1-confg' -> ('ftp', 'u', 'p', '10.1.1.5', 'dir/r1-confg')."""
    m = re.match(r"^([a-z]+):(?://(?:([^:@/]*)(?::([^@/]*))?@)?([^/]*)(?:/(.*))?)?$", text.strip(), re.I)
    if not m:
        return "", "", "", "", text.strip()
    return (m.group(1).lower(), m.group(2) or "", m.group(3) or "", m.group(4) or "", m.group(5) or "")


def start(con, scheme: str, src: str, dst: str) -> str:
    """copy <running|startup>-config ftp:|scp: and copy ftp:|scp: <running|startup>-config."""
    s, d = tftpcopy._kind(src), tftpcopy._kind(dst)
    out_going = s in ("running-config", "startup-config")
    url = dst if out_going else src
    _, user, pw, host, name = parse_url(url)
    if out_going and s == "startup-config" and not tftpcopy.startup_body(con):
        return "%Error opening nvram:/startup-config (No such file or directory)"
    data = {"scheme": scheme, "user": user, "pw": pw, "host": host}
    if out_going:
        data.update(src=s, name=name or tftpcopy.default_name(con))
    else:
        data.update(dst=d, name=name)
    _ask(con, "host", f"Address or name of remote host [{host}]? ", data)
    return ""


def _ask(con, step: str, prompt: str, data: dict, secret: bool = False) -> None:
    from . import iosnv
    iosnv.ask(con, f"{data['scheme']}-{step}", prompt, secret=secret, on=_answer, step=step,
              **{k: v for k, v in data.items() if k != "step"})


def _session_user(con) -> str:
    return getattr(con, "user", "") or getattr(con, "aaa_user", "") or ""


def _answer(con, line: str, q: dict) -> str:
    text = line.strip()
    step = q["step"]
    data = {k: v for k, v in q.items() if k not in ("kind", "prompt", "secret", "tries", "on", "step")}
    scheme = data["scheme"]
    if step == "host":
        host = text or data.get("host", "")
        if not host or not tftpcopy._HOST.match(host):
            return "%Error parsing filename (Bad IP address or host name)"
        data["host"] = host
        if scheme == "scp":
            dflt = data.get("user") or _session_user(con)
            word = "Destination" if data.get("src") else "Source"
            _ask(con, "user", f"{word} username [{dflt}]? ", {**data, "user": dflt})
        elif data.get("dst"):
            _ask(con, "src", f"Source filename [{data.get('name', '')}]? ", data)
        else:
            _ask(con, "put", f"Destination filename [{data['name']}]? ", data)
        return ""
    if step == "user":
        user = text or data.get("user", "")
        if not user or not _USER.match(user):
            return "%Error parsing filename (Bad user name)"
        data["user"] = user
        if data.get("dst"):
            _ask(con, "src", f"Source filename [{data.get('name', '')}]? ", data)
        else:
            _ask(con, "put", f"Destination filename [{data['name']}]? ", data)
        return ""
    if step == "src":
        name = text or data.get("name", "")
        if not name or not tftpcopy._FILE.match(name):
            return "%Error parsing filename (Bad file name)"
        data["name"] = name
        _ask(con, "get", f"Destination filename [{data['dst']}]? ", data)
        return ""
    if step in ("put", "get"):
        if step == "put":
            name = text or data["name"]
            if not tftpcopy._FILE.match(name):
                return "%Error parsing filename (Bad file name)"
            data["name"] = name
        elif text and tftpcopy._kind(text) != data["dst"]:
            return f"%Error opening {text} (Permission denied)"
        if scheme == "scp" and not data.get("pw"):
            _ask(con, "pass" + step, "Password: ", data, secret=True)
            return ("Writing " + data["name"] + " ") if step == "put" else ""
        return transfer(con, data, step)
    if step in ("passput", "passget"):
        data["pw"] = line.rstrip("\r\n")
        return transfer(con, data, step[4:])
    return ""


# ------------------------------------------------------------------ the transfer
def _creds(con, data: dict) -> tuple[str, str]:
    if data["scheme"] == "ftp":
        user, pw = ftp_login(con.lab, con.device)
        return data.get("user") or user or "anonymous", data.get("pw") or pw or ""
    return data.get("user", ""), data.get("pw", "")


def _curl_cfg(user: str, pw: str) -> str:
    esc = (user + ":" + pw).replace("\\", "\\\\").replace('"', '\\"')
    return base64.b64encode(f'user = "{esc}"\n'.encode()).decode()


def ftp_cmd(op: str, host: str, name: str, user: str, pw: str, body: str = "", ns: str = "") -> str:
    """The router's shell for one FTP transfer (op put or get): curl with the
    login in a file only root reads, passive mode, the file relative to the
    user's home."""
    pre = f"ip netns exec {shlex.quote(ns)} " if ns else ""
    url = shlex.quote(f"ftp://{host}/{quote(name)}")
    head = (FTP_CLIENT + "f=/tmp/winlab-ftp.$$; k=/tmp/winlab-ftpk.$$; umask 077; "
            f"printf %s '{_curl_cfg(user, pw)}' | base64 -d > $k; ")
    run = f"{pre}\"$C\" -sS --connect-timeout 10 -m 60 -K $k"
    if op == "put":
        b64 = base64.b64encode(body.encode()).decode()
        return (head + f"printf %s '{b64}' | base64 -d > $f; {run} -T $f {url} 2>&1; echo \"#rc=$?\"; rm -f $f $k")
    return (head + f"rm -f $f; {run} -o $f {url} 2>&1; echo \"#rc=$?\"; "
            f"[ -s $f ] && [ $(wc -c < $f) -le {MAX_BYTES} ] && {{ echo '#data'; base64 $f; }}; rm -f $f $k; "
            f"{pre}ip -o route get {shlex.quote(host)} 2>/dev/null | head -n 1 | sed 's/^/#via /'")


def scp_cmd(op: str, host: str, name: str, user: str, pw: str, body: str = "", ns: str = "") -> str:
    """The router's shell for one SCP transfer: Dropbear's scp through a
    dbclient that accepts the host key, the password from the environment."""
    pre = f"ip netns exec {shlex.quote(ns)} " if ns else ""
    pwb = base64.b64encode(pw.encode()).decode()
    remote = shlex.quote(f"{user}@{host}:{name}")
    head = (SCP_CLIENT + "f=/tmp/winlab-scp.$$; w=/tmp/winlab-ssh.$$; umask 077; "
            "printf '#!/bin/sh\\nexec \"%s\" -y -y \"$@\"\\n' \"$D\" > $w; chmod 700 $w; "
            f"DROPBEAR_PASSWORD=$(printf %s '{pwb}' | base64 -d); export DROPBEAR_PASSWORD; ")
    run = f"{pre}timeout 60 \"$S\" -S $w"
    if op == "put":
        b64 = base64.b64encode(body.encode()).decode()
        return (head + f"printf %s '{b64}' | base64 -d > $f; {run} $f {remote} 2>&1; echo \"#rc=$?\"; rm -f $f $w")
    return (head + f"rm -f $f; {run} {remote} $f 2>&1; echo \"#rc=$?\"; "
            f"[ -s $f ] && [ $(wc -c < $f) -le {MAX_BYTES} ] && {{ echo '#data'; base64 $f; }}; rm -f $f $w; "
            f"{pre}ip -o route get {shlex.quote(host)} 2>/dev/null | head -n 1 | sed 's/^/#via /'")


def ios_error(scheme: str, err: str, rc: int | None) -> str:
    """What curl or scp said, as IOS words it."""
    e = (err or "").lower()
    if scheme == "ftp":
        if rc == 67 or "530" in e or "login denied" in e or "access denied: 530" in e:
            return "Not logged in: the server refused the user name or password"
        if rc in (25, 9) or "553" in e or "550" in e or "upload failed" in e or "permission" in e:
            return "Permission denied"
        if rc == 78 or "not found" in e or "does not exist" in e:
            return "No such file or directory"
    else:
        if "permission denied" in e and ("password" in e or "auth" in e or "publickey" in e):
            return "Not logged in: the server refused the user name or password"
        if "bad password" in e or "authentication" in e or "no auth methods" in e:
            return "Not logged in: the server refused the user name or password"
        if "no such file" in e:
            return "No such file or directory"
        if "permission denied" in e:
            return "Permission denied"
    if rc == 28 or "timed out" in e or "timeout" in e or rc == 124:
        return "Timed out"
    if rc == 7 or "connection refused" in e or "couldn't connect" in e or "failed to connect" in e:
        return "Connection refused"
    if "unreachable" in e or "no route" in e:
        return "Network is unreachable"
    if rc == 6 or "resolve" in e or "unknown host" in e:
        return "Bad IP address or host name"
    return (err or "I/O error").strip()[:160]


def transfer(con, data: dict, op: str) -> str:
    scheme, host, name = data["scheme"], data["host"], data["name"]
    user, pw = _creds(con, data)
    if scheme == "scp" and not user:
        return "%Error parsing filename (Bad user name)"
    ns = tftpcopy.netns(con)
    where = f"{scheme}://{host}/{name}"
    if con.device != devcli.ROUTER and not ns:
        return f"%Error opening {where} (No route to host)\n{tftpcopy._no_mgmt(con)}"
    build = ftp_cmd if scheme == "ftp" else scp_cmd
    if op == "put":
        body = tftpcopy.running_body(con) if data["src"] == "running-config" else tftpcopy.startup_body(con)
        if not body:
            return "%Error opening nvram:/startup-config (No such file or directory)"
        t0 = time.time()
        res = tftpcopy.parse_result(con._on_router(build("put", host, name, user, pw, body, ns), timeout=80))
        secs = time.time() - t0
        if res["notftp"] or "#noclient" in (res["error"] or ""):
            return NO_CLIENT[scheme]
        if res["rc"] != 0:
            why = ios_error(scheme, res["error"], res["rc"])
            hint = ""
            if scheme == "ftp" and why == "Permission denied":
                hint = ("\n% The server refused to store the file: vsftpd needs write_enable=YES in /etc/vsftpd.conf "
                        "(then systemctl restart vsftpd), and a directory that user may write")
            if why.startswith("Not logged in") and scheme == "ftp" and not data.get("user"):
                hint = "\n% The login comes from ip ftp username and ip ftp password (or ftp://<user>:<password>@<host>/)"
            return f"%Error opening {where} ({why}){hint}"
        head = "" if scheme == "scp" else f"Writing {name} "
        return f"{head}!\n" + tftpcopy._rate(len(body.encode()), secs)
    t0 = time.time()
    res = tftpcopy.parse_result(con._on_router(build("get", host, name, user, pw, "", ns), timeout=80))
    secs = time.time() - t0
    if res["notftp"] or "#noclient" in (res["error"] or ""):
        return NO_CLIENT[scheme]
    head = f"Accessing {where}..."
    if res["rc"] != 0 or res["data"] is None:
        why = ios_error(scheme, res["error"], res["rc"]) if res["rc"] != 0 else "File too large or empty"
        return f"{head}\n%Error opening {where} ({why})"
    raw = res["data"]
    text = raw.decode("utf-8", "replace")
    n = len(raw)
    via = tftpcopy._via(con, res["dev"]) if res["dev"] or con.device != devcli.ROUTER else ""
    out = [head, f"Loading {name}" + (f" from {host} (via {via})" if via else "") + " !", f"[OK - {n} bytes]", ""]
    if data["dst"] == "running-config":
        errs = tftpcopy.apply_config(con, text)
        out += errs + ([""] if errs else [])
        out += [tftpcopy._rate(n, secs), f"%SYS-5-CONFIG_I: Configured from {where} by console"]
    else:
        errs = tftpcopy.to_startup(con, text)
        out += errs + ([""] if errs else []) + ["[OK]", tftpcopy._rate(n, secs)]
    return "\n".join(out)


# ------------------------------------------------------------ the drill
# The folder the devices' last FTP upload went to on the backup server, from
# vsftpd's own log (the path is inside the chroot when chroot_local_user is
# on, so it is put back under the account's home), and the account it went in
# as. The drill gives that folder to root; the fix gives it back.
_FTP_DIR = (
    "l=$(grep 'OK UPLOAD' /var/log/vsftpd.log 2>/dev/null | tail -n 1); "
    "u=$(printf '%s' \"$l\" | sed -n 's/.*\\] \\[\\([^]]*\\)\\] OK UPLOAD.*/\\1/p'); "
    "f=$(printf '%s' \"$l\" | sed -n 's/.*OK UPLOAD: Client \"[^\"]*\", \"\\([^\"]*\\)\".*/\\1/p'); "
    "h=$(getent passwd \"$u\" | cut -d: -f6); d=$(dirname \"$f\"); "
    "case \"$d\" in \"$h\"|\"$h\"/*) ;; *) d=\"$h$(printf '%s' \"$d\" | sed 's,/$,,')\" ;; esac; "
)
_FTP_SAVED = "/var/lib/winlab/ftp-upload-dir"


def _faults():
    from .guestfaults import LINUX, GuestFault
    return [
        GuestFault(
            id="ftp-upload-dir-not-writable",
            images=("ubuntu",),
            os=LINUX,
            title="The router's FTP backup is refused, though it logs in",
            teaches="that an FTP upload needs three things, the login, write_enable and a folder the account "
                    "may write to, and that the server's own log names which one failed; vsftpd.log, ls -ld, "
                    "and an ftp put by hand",
            symptom="copy running-config ftp: on the router ends in %Error opening ftp://... (Permission denied); "
                    "the user name and password are right, vsftpd runs, and yesterday's backup went through",
            apply=(_FTP_DIR + '[ -n "$u" ] && [ -n "$h" ] && [ -d "$d" ] || { echo "no upload in '
                   '/var/log/vsftpd.log on this machine: do lesson config-copy-ftp-scp first"; exit 1; }; '
                   'mkdir -p /var/lib/winlab && printf \'%s %s %s %s\\n\' "$u" "$(stat -c %U:%G "$d")" '
                   '"$(stat -c %a "$d")" "$d" > ' + _FTP_SAVED + ' && chown root:root "$d" && chmod 755 "$d" '
                   '&& echo broken'),
            clear=('[ -s ' + _FTP_SAVED + ' ] && read u o m d < ' + _FTP_SAVED + ' && chown "$o" "$d" '
                   '&& chmod "$m" "$d"; echo ok'),
            shell="sh",
            hints=(
                "The router reached the server and logged in, so it is not the network and not the password. "
                "Ask the server: sudo tail /var/log/vsftpd.log on pc-office shows the router's attempt, and "
                "whether it was the login or the upload that failed.",
                "FAIL UPLOAD with a 553 means vsftpd would not create the file. write_enable=YES is still in "
                "/etc/vsftpd.conf, so look at the folder: ls -ld on the backup account's home. Who owns it, and "
                "may the account write there? Try it as that account: ftp localhost, put /etc/hostname test.txt.",
                "Give the folder back to the account: sudo chown <account>:<account> <folder> (and chmod 755 or "
                "750). copy running-config ftp: on the router again says [OK], and vsftpd.log says OK UPLOAD.",
            ),
            verify=('[ -s ' + _FTP_SAVED + ' ] && read u o m d < ' + _FTP_SAVED + ' && '
                    'runuser -u "$u" -- test -w "$d" && systemctl is-active -q vsftpd '
                    '&& grep -Eq "^write_enable=(YES|yes)" /etc/vsftpd.conf && echo True || echo False'),
        ),
    ]


FAULT_IDS = ("ftp-upload-dir-not-writable",)


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
