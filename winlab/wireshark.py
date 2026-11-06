"""Wireshark for the lab's Windows PCs, on a stick.

Wireshark (GPL-2.0-or-later, wireshark.org) is fetched from the Wireshark
Foundation's own download site onto this PC (the Windows x64 installer of the
pinned stable release, or a newer one the download directory lists, verified
against the SHA-256 in that release's SIGNATURES file) and written onto a
"Wireshark" stick on the lab's media shelf. The student installs it inside
the PC from the stick. Nothing is bundled with winlab and nothing is
installed for the student.

Npcap, the Windows capture driver, is never fetched, carried or installed by
winlab on its own. Its free licence does not let others redistribute it.
Wireshark's own installer carries an Npcap installer inside it, under that
licence, and asks whether to install it; the stick's README says so, and
says what works without it. Without Npcap, Wireshark on Windows cannot
capture live (USBPcap, also offered by the installer, captures USB only):
it opens capture files. The lab's capture probe (role capture) captures on
any VLAN with tshark or tcpdump; its .pcapng files open in Wireshark on the
PC.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to, _get

PRODUCT = "Wireshark"
LICENSE = "GPL-2.0-or-later"
DOWNLOAD = "https://www.wireshark.org/download"
WIN64 = f"{DOWNLOAD}/win64"
ALL_VERSIONS = f"{WIN64}/all-versions"
PAGE = "https://www.wireshark.org/"
# The release fetched when the download directory cannot be read.
PINNED_VERSION = "4.6.9"
JOB = "wireshark-fetch"
STEP_LABEL = "Fetch Wireshark (wireshark.org)"
SIZE_TEXT = "about 95 MB"
STICK_LABEL = "WIRESHARK"
META_NAME = "wireshark.json"


class WiresharkError(Exception):
    pass


def store() -> Path:
    return paths.RUNTIME / "wireshark"


def installer_name(version: str) -> str:
    return f"Wireshark-{version}-x64.exe"


def meta() -> dict:
    try:
        return json.loads((store() / META_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ready() -> bool:
    m = meta()
    f = store() / str(m.get("file") or "-")
    return bool(m.get("version")) and f.is_file() and f.stat().st_size > 0


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in version.split("."))


def newest_stable(listing: str) -> str:
    """The newest stable release in a win64 directory listing. Wireshark's
    stable releases have an even minor number (4.4, 4.6); odd ones are
    development builds."""
    found = {m[1] for m in re.finditer(r"Wireshark-(\d+\.\d+\.\d+)-x64\.exe", listing)}
    stable = [v for v in found if int(v.split(".")[1]) % 2 == 0]
    return max(stable, key=_key) if stable else ""


def discover(get=_get) -> str:
    """The newest stable release the download directory lists; the pinned
    release when it cannot be read."""
    try:
        v = newest_stable(get(f"{WIN64}/", timeout=30).decode("utf-8", "replace"))
        if v:
            return v
    except BootstrapError:
        pass
    return PINNED_VERSION


def parse_signatures(text: str) -> dict[str, str]:
    """A SIGNATURES-<version>.txt -> {file: sha256}. The file lists each
    download as 'SHA256(<file>)=<hex>' (inside its PGP-signed block);
    'sha256sum'-style '<hex>  <file>' lines are read as well."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^SHA256\(([^)]+)\)\s*=\s*([0-9a-fA-F]{64})$", line)
        if m:
            out[m[1]] = m[2].lower()
            continue
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(\S+)$", line)
        if m:
            out.setdefault(m[2], m[1].lower())
    return out


def fetch(progress=None, get=_get, download=_download_to) -> dict:
    """The Windows x64 installer, checked against its release's SHA-256."""
    say = progress or (lambda _m: None)
    version = discover(get)
    name = installer_name(version)
    try:
        sums = parse_signatures(get(f"{DOWNLOAD}/SIGNATURES-{version}.txt", timeout=60).decode("utf-8", "replace"))
    except BootstrapError as exc:
        raise WiresharkError(str(exc)) from exc
    sha = sums.get(name)
    if not sha:
        raise WiresharkError(f"SIGNATURES-{version}.txt lists no SHA-256 for {name}")
    d = store()
    d.mkdir(parents=True, exist_ok=True)
    say(f"Wireshark {version}: {name}")
    last = None
    for base in (WIN64, ALL_VERSIONS):   # an older release moves to all-versions
        try:
            download(f"{base}/{name}", d / name, expect_sha=sha, label=name)
            break
        except BootstrapError as exc:
            last = exc
    else:
        raise WiresharkError(str(last))
    m = {"name": PRODUCT, "version": version, "license": LICENSE, "file": name, "sha256": sha,
         "source": f"{WIN64}/{name}", "fetched": time.strftime("%Y-%m-%d")}
    (d / META_NAME).write_text(json.dumps(m, indent=1), encoding="utf-8")
    for f in d.iterdir():
        if f.name not in (name, META_NAME):
            f.unlink()
    say(f"Wireshark {version} ready: {d}")
    return m


def readme(m: dict) -> str:
    name = m.get("file", "")
    lines = [
        f"{PRODUCT} {m.get('version', '')} ({LICENSE}), from wireshark.org",
        f"fetched {m.get('fetched', '?')}, checked against the SHA-256 in the release's SIGNATURES file.", "",
        "Install it on a Windows PC of the lab: run Windows\\" + name + " from this stick.", "",
        "Npcap, the capture driver: Wireshark's installer carries an Npcap installer inside it and offers it",
        "on one of its pages. Npcap is not Wireshark's: it has its own licence (npcap.com), which allows its",
        "free edition on a few machines for your own use and does not allow passing it on. winlab never",
        "fetched it or put it here on its own; whether you tick that box is your call under that licence.", "",
        "Without Npcap, Wireshark on Windows cannot capture from a network card. (USBPcap, also offered,",
        "captures USB traffic only.) It still opens and analyses capture files: capture on the lab's",
        "capture probe instead, which sees every VLAN, for example",
        "  tshark -i eth0.10 -w /tmp/dns.pcapng -a duration:60   (or tcpdump -i eth0.10 -w /tmp/dns.pcapng)",
        "and carry the file to the PC (copy it to a share, or onto a blank stick from the media shelf), then",
        "open it in Wireshark: File > Open.", "",
        "Wireshark is a registered trademark of the Wireshark Foundation; winlab only carries the file you fetched.",
    ]
    return "\r\n".join(lines) + "\r\n"


def stick_files() -> dict[str, bytes]:
    if not ready():
        raise WiresharkError("Wireshark is not on this PC yet: fetch it in Images (Wireshark), "
                             "or winlab wireshark fetch")
    m = meta()
    return {f"Windows/{m['file']}": (store() / m["file"]).read_bytes(), "README.txt": readme(m).encode("utf-8")}


def to_stick(lab_name: str) -> dict:
    """A new Wireshark stick on the lab's media shelf."""
    from . import media, mediashelf
    files = stick_files()
    title = f"Wireshark {meta().get('version', '')}".strip()
    sid = mediashelf._new_id(lab_name, "wireshark")
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise WiresharkError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title, "files": len(files), "mb": sum(len(b) for b in files.values()) >> 20}


def summary() -> dict:
    m = meta()
    f = store() / str(m.get("file") or "-")
    return {"id": "wireshark", "title": PRODUCT, "ready": ready(), "version": m.get("version", ""),
            "fetched": m.get("fetched", ""), "license": LICENSE, "page": PAGE,
            "size_mb": round(f.stat().st_size / 1048576, 1) if f.is_file() else 0}


def render_status() -> str:
    s = summary()
    state = (f"ready (Wireshark {s['version']}, {s['size_mb']} MB, fetched {s['fetched']})"
             if s["ready"] else f"not fetched ({SIZE_TEXT})")
    return "\n".join([f"wireshark store: {store()}", "",
                      f"  wireshark  {state}",
                      f"             {PRODUCT}, {LICENSE}, the Windows x64 installer from {WIN64}",
                      "             Npcap is never fetched: the installer carries it under its own licence",
                      "             onto a stick: the media shelf's Wireshark stick button",
                      "" if s["ready"] else "             then:    winlab wireshark fetch", ""])


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """A Setup step when a lab's PCs install Wireshark (vars downloads)."""
    who = [n.id for n in lab.node_list() if "wireshark" in (n.vars.get("downloads") or [])]
    if not who or "wireshark" in set(have or ()):
        return []
    return [{"id": "wireshark", "label": STEP_LABEL, "done": ready(), "blocked": False,
             "hint": f"{', '.join(who)} install it from the Wireshark stick: {PRODUCT}, {LICENSE}, checked "
                     f"against the release's SHA-256, {SIZE_TEXT} once; Npcap is never fetched",
             "link": PAGE, "job": JOB}]


def act(dash, action: str, params: dict) -> dict:
    """wb-wireshark-stick writes the Wireshark stick onto the shelf."""
    if action == "wb-wireshark-stick":
        try:
            r = to_stick(dash.lab.name)
        except WiresharkError as exc:
            return {"ok": False, "message": str(exc), "fetch": not ready()}
        return {"ok": True, "message": f"{r['title']} is on the shelf: drag it onto a PC", "stick": r["id"]}
    return {"ok": False, "message": f"unknown Wireshark action {action!r}"}
