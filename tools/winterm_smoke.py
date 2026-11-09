"""Smoke test of the Windows console host (content/agent/winlab-term.cs) on a
real Windows: CI's windows-latest runner, which has no COM3, so the host
listens on a loopback TCP port instead (-Listen) and the desktop's own line
code (winlab/winterm.py) talks to it.

  1. as the runner's account (-Test, no sign-in): cmd.exe and powershell.exe
     in a real pseudoconsole: output, tab completion, the window's size, exit;
  2. as SYSTEM from a scheduled task, the way a lab machine runs it: the
     sign-in prompt, a wrong password refused, a local account signed in
     (whoami), "Run as administrator" refused for a non-administrator.

Run on Windows from the repository root:  python tools/winterm_smoke.py
"""
from __future__ import annotations

import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from winlab import winterm  # noqa: E402

AGENT = ROOT / "content" / "agent"
PS = "powershell.exe"
# Windows PowerShell 5.1 as a machine starts it: a PowerShell 7 step's module
# path would point 5.1 at PowerShell 7's own modules.
PS_ENV = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
FAILED: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f"\n     {detail[-1500:]}"), flush=True)
    if not cond:
        FAILED.append(name)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_line(port: int, timeout: float = 180.0) -> winterm.Line:
    """The host compiles itself with Add-Type first: wait for it to listen
    and answer."""
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            line = winterm.Line(port)
            if line.hello(5.0):
                return line
            line.close_line()
        except winterm.TermError as exc:
            last = str(exc)
        time.sleep(2)
    raise SystemExit(f"the console host never answered on {port}: {last}")


class Console:
    def __init__(self, line: winterm.Line, shell: str, admin: bool = False, cols: int = 120, rows: int = 30) -> None:
        self.line = line
        self.buf = b""
        self.exit: list = []
        self.sid = line.open(shell, cols, rows, admin, self._out, lambda c, w: self.exit.append((c, w)))

    def _out(self, data: bytes) -> None:
        self.buf += data

    def text(self) -> str:
        # The screen as text, without the VT sequences ConPTY draws it with.
        t = self.buf.decode("utf-8", "replace")
        t = re.sub(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", "", t)
        return re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", t)

    def type(self, s: str) -> None:
        self.line.write(self.sid, s.encode())

    def wait(self, pattern: str, timeout: float = 60.0) -> bool:
        deadline = time.monotonic() + timeout
        rx = re.compile(pattern, re.I)
        while time.monotonic() < deadline:
            if rx.search(self.text()):
                return True
            if self.exit:
                return bool(rx.search(self.text()))
            time.sleep(0.2)
        return False

    def wait_exit(self, timeout: float = 30.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self.exit:
            time.sleep(0.2)
        return self.exit[0] if self.exit else None


def as_runner() -> None:
    port = free_port()
    log = Path(tempfile.gettempdir()) / "winterm-test.log"
    proc = subprocess.Popen([PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(AGENT / "winlab-term.ps1"),
                             "-Listen", f"127.0.0.1:{port}", "-Test", "-Log", str(log)], env=PS_ENV)
    try:
        line = wait_line(port)
        check("the host compiles under Windows PowerShell 5.1 and reports the desktop's build",
              line.info and line.info["build"] == winterm.build_id(), str(line.info))
        cmd = Console(line, "cmd")
        check("cmd.exe starts in a pseudoconsole", cmd.wait(r"Microsoft Windows \[Version"), cmd.text())
        cmd.type("echo winlab-%COMPUTERNAME%\r")
        name = os.environ.get("COMPUTERNAME", "")
        check("cmd runs what is typed", cmd.wait(re.escape(f"winlab-{name}")), cmd.text())
        cmd.type("exit 3\r")
        check("exit ends the session with its code", cmd.wait_exit() == (3, ""), str(cmd.exit))

        ps = Console(line, "powershell", cols=100, rows=30)
        check("powershell.exe starts", ps.wait(r"PS [A-Z]:\\.*>"), ps.text())
        ps.type("Get-ChildIt\t")
        check("tab completion is PowerShell's own", ps.wait(r"Get-ChildItem"), ps.text())
        ps.type("\x03")          # Ctrl+C drops the half-typed line, as at the keyboard
        time.sleep(1)
        line.resize(ps.sid, 132, 40)
        time.sleep(1)
        ps.type("'w=' + $Host.UI.RawUI.WindowSize.Width\r")
        check("the window's size reaches the console", ps.wait(r"w=132"), ps.text())
        ps.type("Write-Host -ForegroundColor Green colour-test\r")
        check("colours come through as VT", ps.wait("colour-test") and "\x1b[" in ps.buf.decode("utf-8", "replace"), ps.text())
        ps.type("exit\r")
        check("exit ends PowerShell", ps.wait_exit() is not None, str(ps.exit))
        line.close_line()
    finally:
        proc.kill()
        if log.exists():
            print(log.read_text(errors="replace"))


def as_system() -> None:
    port = free_port()
    log = Path(tempfile.gettempdir()) / "winterm-system.log"
    user = "wlsmoke"
    # 14 characters: net user asks a yes/no question for anything longer.
    typed_key = "Wl-" + secrets.token_urlsafe(6) + "-9z"
    task = "winlab-terminal-smoke"
    script = str(AGENT / "winlab-term.ps1")
    ps_setup = f"""
$ErrorActionPreference = 'Stop'
$a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "{script}" -Listen 127.0.0.1:{port} -Log "{log}"'
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName '{task}' -Action $a -Principal $p -Force | Out-Null
Start-ScheduledTask -TaskName '{task}'
"""
    subprocess.run(["net", "user", user, typed_key, "/add"], check=True, capture_output=True)
    try:
        subprocess.run([PS, "-NoProfile", "-Command", ps_setup], check=True, env=PS_ENV)
        line = wait_line(port)
        c = Console(line, "cmd")
        check("as SYSTEM, the console asks for an account", c.wait(r"User name: $"), c.text())
        c.type(user + "\r")
        check("then its password, without echo", c.wait(r"Password: $"), c.text())
        c.type("not-the-right-one\r")
        check("a wrong password is refused with Windows' own message",
              c.wait(r"user name or password is incorrect") and c.wait(r"User name: $"), c.text())
        c.buf = b""
        c.type(user + "\r")
        c.wait(r"Password: $")
        c.type(typed_key + "\r")
        check("the account signs in and cmd.exe starts as it", c.wait(r"Microsoft Windows \[Version", 90), c.text())
        c.type("whoami\r")
        check("whoami is the account typed", c.wait(re.escape(user)), c.text())
        check("cmd starts in the account's profile", c.wait(re.escape(f"\\{user}>")), c.text())
        c.type("exit\r")
        check("exit ends it", c.wait_exit() is not None, str(c.exit))

        a = Console(line, "powershell", admin=True)
        a.wait(r"User name: $")
        a.type(user + "\r")
        a.wait(r"Password: $")
        a.type(typed_key + "\r")
        check("Run as administrator is refused for an account that is no administrator",
              a.wait(r"is not an administrator"), a.text())
        line.close(a.sid)
        line.close_line()
    finally:
        subprocess.run([PS, "-NoProfile", "-Command",
                        f"Stop-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue; "
                        f"Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false -ErrorAction SilentlyContinue; "
                        f"Get-CimInstance Win32_Process -Filter \"Name = 'powershell.exe'\" | "
                        f"Where-Object {{ $_.CommandLine -like '*{port}*' }} | "
                        f"ForEach-Object {{ Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }}"], env=PS_ENV)
        subprocess.run(["net", "user", user, "/delete"], capture_output=True)
        if log.exists():
            print(log.read_text(errors="replace"))


if __name__ == "__main__":
    if os.name != "nt":
        raise SystemExit("this runs on Windows only")
    as_runner()
    as_system()
    print(f"\n{len(FAILED)} failed" + (": " + "; ".join(FAILED) if FAILED else ""))
    sys.exit(1 if FAILED else 0)
