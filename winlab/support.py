"""The support file: one zip a customer sends when something does not work.

`winlab doctor --bundle [out.zip]` and the Help window's "Make a support
file" button both call make_bundle(). It gathers what support needs to see
why a lab will not start, and nothing else:

  report.txt     the doctor report, winlab's version, the OS, Python, QEMU
  labs.txt       every lab, and each machine's run state
  logs/          the tails of QEMU's log and the console log of every machine,
                 the base preparation logs (images/downloads/prep-*.log), the
                 template logs and anything under var/logs
  settings/      winlab.local.toml, the desktop's preferences and the run
                 state files, every one with secrets taken out
  manifest.txt   what is in the zip, and what was left out and why

It never takes a disk image, an ISO, a USB stick, a lab's generated
Administrator password, the license key or token, or a file of the user's.
It works from an allowlist (named files and *.log), so a file type nobody
thought of stays out. Every text that goes in passes through the redactor,
which removes the lab passwords it knows by value, anything written as a
password, secret, token or key, the product key pattern, and makes the
user's home folder generic. The whole zip is capped (MAX_BYTES); a log is
cut from its start, so its last lines, where the error is, survive.
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, paths

# The address the Help window shows and the CLI prints. One place: Ron
# replaces this placeholder with the real support address before release.
SUPPORT_EMAIL = "support@example.com"

MAX_BYTES = 20 * 1024 * 1024      # the whole bundle, before compression
LOG_TAIL = 512 * 1024             # the most of any one log
REDACTED = "[redacted]"

# Files that never go in, whatever directory they sit in.
NEVER_SUFFIXES = (".qcow2", ".img", ".iso", ".vhd", ".vhdx", ".vmdk", ".fd", ".wim", ".esd",
                  ".bin", ".raw", ".vars", ".zip", ".wlact", ".wlnet")
NEVER_NAMES = ("admin-password", "license.json")

_SECRET_WORD = r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|signature|sig|apikey|api_key|private[_-]?key|key)"
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # key = value, "key": "value", key: value (TOML, JSON, INI, logs)
    (re.compile(r"(?i)(?<![A-Za-z])(" + _SECRET_WORD + r")([\"']?\s*[:=]\s*)([\"']?)(?!\[redacted\])([^\"'\s,}\]]+)"),
     r"\1\2\3" + REDACTED),
    # PowerShell and command-line switches: -Password x, -SharedSecret x, -password:x
    (re.compile(r"(?i)(-(?:Password|Pass|SharedSecret|Secret|Token|Key|PreSharedKey|Psk)(?:\s+|:))(\S+)"),
     r"\1" + REDACTED),
    # a winlab product key, wherever it appears
    (re.compile(r"\bWLAB(?:-[A-Z0-9]{5}){4}-[A-Z0-9]\b"), "[product key]"),
]
_HOME_PART = re.compile(r"(?i)([\\/](?:Users|home)[\\/])([^\\/\s\"':;]+)")


@dataclass
class Bundle:
    path: Path
    files: list[str] = field(default_factory=list)
    left_out: list[str] = field(default_factory=list)
    truncated: list[str] = field(default_factory=list)
    size: int = 0


class Redactor:
    """Takes secrets out of text. Known secret values (the lab passwords,
    the license key) go by value; the rest by pattern."""

    def __init__(self, secrets: list[str] | None = None, home: str = "") -> None:
        self.secrets = sorted({s for s in (secrets or []) if s and len(s) >= 4}, key=len, reverse=True)
        self.home = home.rstrip("\\/")

    def __call__(self, text: str) -> str:
        for s in self.secrets:
            text = text.replace(s, REDACTED)
        for rx, repl in _PATTERNS:
            text = rx.sub(repl, text)
        if self.home and len(self.home) > 3:
            text = text.replace(self.home, "<home>")
        return _HOME_PART.sub(r"\1<user>", text)


def known_secrets() -> list[str]:
    """Secret values winlab itself stored: every lab's generated password,
    and the license key and signature from the cached token."""
    out: list[str] = []
    labs = paths.VAR / "labs"
    if labs.is_dir():
        for f in labs.glob("*/admin-password"):
            try:
                out.append(f.read_text(encoding="utf-8").strip())
            except OSError:
                pass
    try:
        tok = json.loads((paths.VAR / "license.json").read_text(encoding="utf-8"))
        for k in ("key", "sig", "signature", "token"):
            v = tok.get(k)
            if isinstance(v, str):
                out.append(v)
                out.append(v.replace("-", ""))
    except (OSError, ValueError, AttributeError):
        pass
    return [s for s in out if s]


def default_redactor() -> Redactor:
    return Redactor(known_secrets(), str(Path.home()))


def support_dir() -> Path:
    return paths.VAR / "support"


def default_path(now: float | None = None) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now if now is not None else time.time()))
    return support_dir() / f"winlab-support-{stamp}.zip"


def allowed(p: Path) -> bool:
    name = p.name.lower()
    return not (name in NEVER_NAMES or name.endswith(NEVER_SUFFIXES))


_CUT = b"[... earlier lines cut to keep the support file small ...]\n"


def tail(data: bytes, limit: int) -> tuple[bytes, bool]:
    """At most `limit` bytes: the last part, starting at a line break when
    there is one, under a line that says the start was cut."""
    if len(data) <= limit:
        return data, False
    cut = data[-max(limit - len(_CUT), 0):]
    nl = cut.find(b"\n")
    if 0 <= nl < len(cut) - 1:
        cut = cut[nl + 1:]
    return _CUT + cut, True


def _read_tail(f: Path, limit: int) -> tuple[bytes, bool]:
    size = f.stat().st_size
    with f.open("rb") as fh:
        if size > limit:
            fh.seek(size - limit)
        data = fh.read()
    if size > limit:
        nl = data.find(b"\n")
        if 0 <= nl < len(data) - 1:
            data = data[nl + 1:]
        return _CUT + data, True
    return data, False


def qemu_version() -> str:
    exe = paths.qemu_exe()
    if not exe.exists():
        return "not fetched (winlab bootstrap)"
    try:
        r = subprocess.run([str(exe), "--version"], capture_output=True, text=True, timeout=15)
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr).strip() else "unknown"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"did not answer: {exc}"


def report_text(doctor: str = "") -> str:
    lines = [
        f"winlab {__version__} ({'winlab.exe' if paths.FROZEN else 'source'})",
        f"made {time.strftime('%Y-%m-%d %H:%M:%S %z')}",
        f"os {platform.platform()} ({platform.machine()})",
        f"python {sys.version.split()[0]} ({platform.python_implementation()})",
        f"qemu {qemu_version()}",
        f"winlab folder {paths.ROOT}",
        f"image store {paths.images_dir()}",
        "",
    ]
    try:
        from .licensing import client
        s = client.status()
        lines.append(f"license {s.state}{(', plan ' + s.plan) if s.plan else ''}")
    except Exception as exc:  # noqa: BLE001 the bundle is made when things are broken
        lines.append(f"license state unknown: {exc}")
    lines.append("")
    if doctor:
        lines.append(doctor)
    return "\n".join(lines) + "\n"


def labs_text() -> str:
    from . import state
    lines = []
    try:
        names = sorted(p.stem for p in paths.LABS.glob("*.toml"))
    except OSError:
        names = []
    known = set(state.known_labs()) if paths.STATE.exists() else set()
    for name in sorted(set(names) | known):
        st = state.load(name)
        if not st or not st.nodes:
            lines.append(f"{name}: not started")
            continue
        lines.append(f"{name}: accel {st.accel or '?'}, display {st.display or '?'}")
        for nid, ns in sorted(st.nodes.items()):
            alive = state.pid_alive(ns.pid) if ns.pid else False
            lines.append(f"  {nid:<12} {ns.phase:<12} {'running' if alive else 'not running'}"
                         f"  serial {ns.serial_port or '-'}  vnc {ns.vnc_port or '-'}")
    return "\n".join(lines) + "\n" if lines else "no labs\n"


def _log_sources() -> list[tuple[str, Path]]:
    """(name in the zip, file) for every log support may read, newest first
    within each group so the cap drops the oldest."""
    out: list[tuple[str, Path]] = []

    def add(prefix: str, files) -> None:
        fs = [f for f in files if f.is_file() and allowed(f)]
        fs.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        for f in fs:
            out.append((prefix + f.name, f))

    labs = paths.VAR / "labs"
    if labs.is_dir():
        for lab in sorted(p for p in labs.iterdir() if p.is_dir()):
            for node in sorted(p for p in lab.iterdir() if p.is_dir()):
                add(f"logs/labs/{lab.name}/{node.name}/", node.glob("*.log"))
    for base, prefix in ((paths.downloads_dir(), "logs/downloads/"), (paths.bases_dir(), "logs/bases/")):
        if base.is_dir():
            add(prefix, base.glob("*.log"))
    if paths.LOGS.is_dir():
        add("logs/var/", paths.LOGS.rglob("*.log"))
    return out


def _settings_sources() -> list[tuple[str, Path]]:
    out = []
    for name, f in (("settings/winlab.local.toml", paths.ROOT / "winlab.local.toml"),
                    ("settings/desktop.json", paths.VAR / "desktop.json"),
                    ("settings/last-lab", paths.VAR / "last-lab")):
        if f.is_file():
            out.append((name, f))
    if paths.STATE.is_dir():
        for f in sorted(paths.STATE.glob("*.json")):
            if allowed(f):
                out.append((f"settings/state/{f.name}", f))
    return out


def make_bundle(out: Path | str | None = None, doctor: str | None = None,
                redactor: Redactor | None = None, max_bytes: int = MAX_BYTES,
                log_tail: int = LOG_TAIL, now: float | None = None) -> Bundle:
    """Writes the support zip and says what is in it. `doctor` is the
    doctor report's text; None runs the probe here."""
    if doctor is None:
        try:
            from . import hostprobe
            doctor = hostprobe.render(hostprobe.probe())
        except Exception as exc:  # noqa: BLE001
            doctor = f"winlab doctor failed: {exc}"
    red = redactor or default_redactor()
    dest = Path(out) if out else default_path(now)
    dest.parent.mkdir(parents=True, exist_ok=True)
    b = Bundle(path=dest)
    budget = max_bytes

    entries: list[tuple[str, bytes]] = []

    def put(name: str, text: str, trunc: bool = False, limit: int = 0) -> None:
        nonlocal budget
        data = red(text).encode("utf-8")
        if limit and len(data) > limit:
            # redaction can make a tail a little longer than it was read
            data = tail(data[len(_CUT):] if trunc else data, limit)[0]
            trunc = True
        if len(data) > budget:
            if budget < 1024:
                b.left_out.append(f"{name}: the support file reached its size limit")
                return
            data, _ = tail(data, budget)
            trunc = True
        entries.append((name, data))
        budget -= len(data)
        b.files.append(name)
        if trunc:
            b.truncated.append(name)

    put("report.txt", report_text(doctor))
    put("labs.txt", labs_text())
    for name, f in _settings_sources():
        try:
            put(name, f.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            b.left_out.append(f"{name}: {exc}")
    for name, f in _log_sources():
        try:
            data, cut = _read_tail(f, log_tail)
        except OSError as exc:
            b.left_out.append(f"{name}: {exc}")
            continue
        put(name, data.decode("utf-8", errors="replace"), cut, log_tail)

    never = ("Never included: disk images, ISOs, USB sticks, firmware variables, lab passwords, "
             "the license key and token, your own files.")
    manifest = ["winlab support file", f"winlab {__version__}", "", never, "", "files:"]
    manifest += [f"  {n}{'  (last part only)' if n in b.truncated else ''}" for n in b.files]
    if b.left_out:
        manifest += ["", "left out:"] + [f"  {x}" for x in b.left_out]
    entries.append(("manifest.txt", ("\n".join(manifest) + "\n").encode("utf-8")))

    tmp = dest.with_suffix(".zip.tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    tmp.replace(dest)
    b.size = dest.stat().st_size
    return b


def render(b: Bundle) -> str:
    lines = [f"support file: {b.path}", f"  {len(b.files)} files, {b.size / 1024:.0f} KB"]
    if b.truncated:
        lines.append(f"  {len(b.truncated)} long log(s) cut to their last part")
    if b.left_out:
        lines.append(f"  {len(b.left_out)} left out (see manifest.txt in the zip)")
    lines.append(f"Send it to {SUPPORT_EMAIL} with a few words on what you were doing.")
    return "\n".join(lines)


def open_folder(folder: Path | None = None) -> None:
    """Shows the support folder in the file manager (only that folder)."""
    d = folder or support_dir()
    d.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        os.startfile(str(d))  # noqa: S606 a fixed folder of winlab's own
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(d)])
    else:
        subprocess.Popen(["xdg-open", str(d)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
