"""The admin toolkit stick: the tools an admin carries from desk to desk.

Every sysadmin has a USB stick with the same few programs on it: PuTTY for
SSH and serial consoles, WinSCP to copy files over SFTP or SCP, the
Sysinternals Suite (Process Explorer, Autoruns, PsExec and the rest) and
Notepad++. Windows has none of them, and the lab has no internet to get
them, so winlab fetches them onto this PC from each project's own download
site and writes them onto an "Admin toolkit" stick on the lab's media shelf.
The student plugs the stick into any lab Windows machine and runs the
installers or the portable programs from it. Nothing is installed by
winlab, and nothing is bundled with it or hosted by it.

Each tool is checked the way its publisher allows:
  PuTTY (MIT): the release's sha256sums file on the.earth.li, the
    project's own download host (linked from chiark.greenend.org.uk).
  WinSCP (GPL-3.0): the SHA-256 that winscp.net prints beside each file
    on its download page; the file itself from the link that page gives.
  Notepad++ (GPL-3.0): the SHA-256 list attached to the GitHub release,
    or GitHub's own digest of each release asset.
  Sysinternals Suite (Microsoft's Sysinternals licence): Microsoft does
    not allow anyone else to pass it on, so winlab fetches it only when the
    customer asks for it and accepts that licence (winlab toolkit fetch
    --sysinternals), from download.sysinternals.com, onto their own PC for
    their own lab. Microsoft publishes no checksum for the zip: winlab
    checks that it is a whole zip with the Suite's programs in it, records
    its SHA-256, and the README says how to check Microsoft's signature on
    each program inside Windows (Get-AuthenticodeSignature).

A tool that cannot be verified is not written to the stick.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import time
import urllib.parse
import zipfile
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to, _get

JOB = "toolkit-fetch"
JOB_SYSINTERNALS = "toolkit-sysinternals-fetch"
STICK_LABEL = "ADMINTOOLS"
META_NAME = "toolkit.json"
SIZE_TEXT = "about 35 MB, the Sysinternals Suite about 50 MB more"

PUTTY_BASE = "https://the.earth.li/~sgtatham/putty/latest"
PUTTY_PAGE = "https://www.chiark.greenend.org.uk/~sgtatham/putty/"
WINSCP_PAGE = "https://winscp.net/eng/downloads.php"
WINSCP_DL = "https://winscp.net/download/{name}/download"
NPP_API = "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest"
NPP_PAGE = "https://notepad-plus-plus.org/"
SYSINTERNALS_URL = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
SYSINTERNALS_PAGE = "https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite"
SYSINTERNALS_LICENSE = "https://learn.microsoft.com/sysinternals/license-terms"
# Programs the Suite's zip must hold, or it is not the Suite.
SYSINTERNALS_EXPECT = ("procexp.exe", "Autoruns.exe", "PsExec.exe", "tcpview.exe")

TOOLS = {
    "putty": {"product": "PuTTY", "license": "MIT", "folder": "PuTTY", "page": PUTTY_PAGE,
              "source": "the.earth.li (PuTTY's download host)", "check": "the release's sha256sums",
              "text": "SSH, Telnet and serial console client, with PSCP and PSFTP"},
    "winscp": {"product": "WinSCP", "license": "GPL-3.0", "folder": "WinSCP", "page": "https://winscp.net/",
               "source": "winscp.net", "check": "the SHA-256 on winscp.net's download page",
               "text": "file copies over SFTP, SCP and FTP"},
    "notepadpp": {"product": "Notepad++", "license": "GPL-3.0", "folder": "Notepad++", "page": NPP_PAGE,
                  "source": "the project's GitHub releases", "check": "the release's SHA-256 list (or GitHub's digest)",
                  "text": "a text and configuration file editor"},
    "sysinternals": {"product": "Sysinternals Suite", "license": "Microsoft Sysinternals Software License Terms",
                     "folder": "Sysinternals", "page": SYSINTERNALS_PAGE, "source": "download.sysinternals.com",
                     "check": "a whole zip with the Suite's programs; Microsoft's signature on each program",
                     "text": "Process Explorer, Process Monitor, Autoruns, PsExec, TCPView and the rest"},
}
OPEN_SOURCE = ("putty", "winscp", "notepadpp")


class ToolkitError(Exception):
    pass


# ------------------------------------------------------------------ the store
def store() -> Path:
    return paths.RUNTIME / "toolkit"


def meta() -> dict:
    try:
        d = json.loads((store() / META_NAME).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_meta(m: dict) -> None:
    store().mkdir(parents=True, exist_ok=True)
    (store() / META_NAME).write_text(json.dumps(m, indent=1), encoding="utf-8")


def tool_ready(tool: str) -> bool:
    t = meta().get(tool) or {}
    files = t.get("files") or []
    return bool(files) and all((store() / tool / f["file"]).is_file() for f in files)


def ready() -> bool:
    """Whether a stick can be written: at least one tool is fetched."""
    return any(tool_ready(t) for t in TOOLS)


# ------------------------------------------------------------------ the sources
def parse_sums(text: str) -> dict[str, str]:
    """A sha256sum-style list ('<hex>  <file>' or '<hex> *<file>') -> {file: sha256}."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]{64})\s+\*?(\S.*?)\s*$", line)
        if m:
            out[m[2]] = m[1].lower()
    return out


def putty_files(get=_get) -> tuple[str, list[dict]]:
    """PuTTY's 64-bit MSI installer and the zip of all its programs, with
    their SHA-256 from the release's sha256sums."""
    try:
        sums = parse_sums(get(f"{PUTTY_BASE}/sha256sums", timeout=60).decode("utf-8", "replace"))
    except BootstrapError as exc:
        raise ToolkitError(f"PuTTY: {exc}") from exc
    msi = sorted(p for p in sums if re.fullmatch(r"w64/putty-64bit-[\d.]+-installer\.msi", p))
    out = []
    if msi:
        out.append(msi[-1])
    if "w64/putty.zip" in sums:
        out.append("w64/putty.zip")
    if not out:
        raise ToolkitError("PuTTY: the release's sha256sums lists no 64-bit installer or zip")
    version = re.search(r"putty-64bit-([\d.]+)-installer", out[0])
    return (version[1] if version else "latest"), [
        {"file": p.rsplit("/", 1)[-1], "url": f"{PUTTY_BASE}/{p}", "sha256": sums[p]} for p in out]


def parse_winscp(page: str) -> tuple[str, dict[str, str]]:
    """winscp.net's download page -> (version, {file: sha256}) for the
    Windows installer and the portable zip. The page lists each file with
    its SHA-256 a little after the file's name."""
    names = re.findall(r"WinSCP-(\d+\.\d+(?:\.\d+)*)-Setup\.exe", page)
    if not names:
        raise ToolkitError("WinSCP: the download page names no installer")
    version = max(names, key=lambda v: tuple(int(x) for x in v.split(".")))
    out = {}
    for name in (f"WinSCP-{version}-Setup.exe", f"WinSCP-{version}-Portable.zip"):
        i = page.find(name)
        while i >= 0:
            m = re.search(r"SHA-?256[^0-9a-fA-F]{0,80}([0-9a-fA-F]{64})", page[i:i + 3000])
            if m:
                out[name] = m[1].lower()
                break
            i = page.find(name, i + 1)
    return version, out


def winscp_files(get=_get) -> tuple[str, list[dict]]:
    try:
        page = get(WINSCP_PAGE, timeout=60).decode("utf-8", "replace")
    except BootstrapError as exc:
        raise ToolkitError(f"WinSCP: {exc}") from exc
    version, sums = parse_winscp(page)
    if not sums:
        raise ToolkitError("WinSCP: the download page gives no SHA-256 for its files")
    out = []
    for name, sha in sums.items():
        try:
            dl = get(WINSCP_DL.format(name=urllib.parse.quote(name)), timeout=60).decode("utf-8", "replace")
        except BootstrapError as exc:
            raise ToolkitError(f"WinSCP: {exc}") from exc
        m = re.search(r'https://[A-Za-z0-9.-]*winscp\.net/[^"\'<> ]*' + re.escape(name) + r'[^"\'<> ]*', dl)
        if not m:
            raise ToolkitError(f"WinSCP: the download page for {name} has no link to the file")
        out.append({"file": name, "url": html_unescape(m[0]), "sha256": sha})
    return version, out


def html_unescape(s: str) -> str:
    import html
    return html.unescape(s)


def notepadpp_files(get=_get) -> tuple[str, list[dict]]:
    """The x64 installer and portable zip of Notepad++'s latest release,
    with the SHA-256 from the release's own list, else GitHub's digest."""
    try:
        rel = json.loads(get(NPP_API, timeout=60).decode("utf-8"))
    except (BootstrapError, ValueError) as exc:
        raise ToolkitError(f"Notepad++: {exc}") from exc
    assets = {a.get("name", ""): a for a in rel.get("assets") or [] if isinstance(a, dict)}
    want = [n for n in sorted(assets) if re.fullmatch(r"npp\.[\d.]+\.(Installer\.x64\.exe|portable\.x64\.zip)", n)]
    if not want:
        raise ToolkitError("Notepad++: the latest release has no x64 installer or portable zip")
    sums: dict[str, str] = {}
    for n, a in assets.items():
        if re.search(r"(checksums?|sha256)[^/]*$", n, re.I) and not n.endswith((".sig", ".asc")):
            try:
                sums.update(parse_sums(get(a["browser_download_url"], timeout=60).decode("utf-8", "replace")))
            except (BootstrapError, KeyError):
                pass
    out = []
    for n in want:
        sha = sums.get(n, "")
        if not sha:
            d = str(assets[n].get("digest") or "")
            sha = d.split(":", 1)[1].lower() if d.startswith("sha256:") else ""
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ToolkitError(f"Notepad++: no SHA-256 published for {n}; not fetched")
        out.append({"file": n, "url": assets[n]["browser_download_url"], "sha256": sha})
    return str(rel.get("tag_name") or "").lstrip("v"), out


def check_sysinternals(data: bytes) -> list[str]:
    """The Suite's zip, checked: a whole zip (every member's CRC) with the
    Suite's programs in it. Returns the names of its programs."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            bad = z.testzip()
            if bad:
                raise ToolkitError(f"Sysinternals Suite: {bad} is damaged in the zip")
            names = z.namelist()
    except zipfile.BadZipFile as exc:
        raise ToolkitError("Sysinternals Suite: the download is not a zip") from exc
    low = {n.lower() for n in names}
    missing = [e for e in SYSINTERNALS_EXPECT if e.lower() not in low]
    if missing:
        raise ToolkitError(f"Sysinternals Suite: the zip has no {', '.join(missing)}: not the Suite")
    return sorted(n for n in names if n.lower().endswith(".exe"))


# ------------------------------------------------------------------ fetching
def fetch(tools: tuple[str, ...] | None = None, accept_sysinternals: bool = False, progress=None,
          get=_get, download=_download_to) -> dict:
    """Fetches the tools (the open-source three unless named; the
    Sysinternals Suite only with accept_sysinternals) and records them.
    A tool that fails is reported; the others are kept."""
    say = progress or (lambda _m: None)
    tools = tuple(tools or OPEN_SOURCE)
    if "sysinternals" in tools and not accept_sysinternals:
        raise ToolkitError("the Sysinternals Suite is Microsoft's, under its own licence ("
                           f"{SYSINTERNALS_LICENSE}): fetch it only if you accept those terms, "
                           "with winlab toolkit fetch --sysinternals")
    m = meta()
    errors = []
    for tool in tools:
        if tool not in TOOLS:
            raise ToolkitError(f"no tool {tool!r}: {', '.join(TOOLS)}")
        info = TOOLS[tool]
        d = store() / tool
        try:
            if tool == "sysinternals":
                say(f"{info['product']} from {SYSINTERNALS_URL} (you accepted Microsoft's licence)")
                dest = d / "SysinternalsSuite.zip"
                try:
                    download(SYSINTERNALS_URL, dest, expect_sha="", label=dest.name)
                except BootstrapError as exc:
                    raise ToolkitError(f"Sysinternals Suite: {exc}") from exc
                data = dest.read_bytes()
                try:
                    progs = check_sysinternals(data)
                except ToolkitError:
                    dest.unlink(missing_ok=True)
                    raise
                files = [{"file": dest.name, "url": SYSINTERNALS_URL, "sha256": hashlib.sha256(data).hexdigest(),
                          "programs": len(progs)}]
                version = time.strftime("%Y-%m-%d")
                checked = "zip whole, Suite programs present; SHA-256 recorded on this PC"
            else:
                version, files = {"putty": putty_files, "winscp": winscp_files,
                                  "notepadpp": notepadpp_files}[tool](get)
                say(f"{info['product']} {version}: {', '.join(f['file'] for f in files)}")
                for f in files:
                    try:
                        download(f["url"], d / f["file"], expect_sha=f["sha256"], label=f["file"])
                    except BootstrapError as exc:
                        raise ToolkitError(f"{info['product']}: {exc}") from exc
                checked = info["check"]
        except ToolkitError as exc:
            errors.append(str(exc))
            say(f"failed: {exc}")
            continue
        keep = {f["file"] for f in files}
        for f in d.iterdir():
            if f.name not in keep:
                f.unlink()
        m[tool] = {"product": info["product"], "version": version, "license": info["license"],
                   "fetched": time.strftime("%Y-%m-%d"), "checked": checked,
                   "files": [{k: v for k, v in f.items() if k != "url"} | {"source": f["url"]} for f in files]}
        _write_meta(m)
        say(f"{info['product']} {version} ready")
    if errors:
        raise ToolkitError("; ".join(errors))
    return m


# ------------------------------------------------------------------ the stick
def readme(m: dict) -> str:
    lines = ["ADMIN TOOLKIT", "",
             "The tools an admin carries, fetched by winlab onto the PC this lab runs on, each from its",
             "publisher's own site and checked as noted. Nothing on this stick installs by itself:",
             "run an installer, or copy a portable program to the machine and run it from there.", ""]
    for tool, info in TOOLS.items():
        t = m.get(tool)
        if not t:
            continue
        lines.append(f"{info['product']} {t.get('version', '')} ({info['license']}): {info['text']}")
        lines.append(f"  from {info['source']}, fetched {t.get('fetched', '?')}, checked: {t.get('checked', '')}")
        for f in t.get("files") or []:
            lines.append(f"  {info['folder']}\\{f['file']}  SHA-256 {f['sha256']}")
        if tool == "putty":
            lines.append("  Install: run the .msi (or msiexec /i putty-64bit-<version>-installer.msi /qn).")
            lines.append("  Portable: unzip putty.zip; putty.exe, pscp.exe, psftp.exe and plink.exe run as they are.")
        elif tool == "winscp":
            lines.append("  Install: run WinSCP-<version>-Setup.exe. Portable: unzip the Portable zip and run WinSCP.exe.")
        elif tool == "notepadpp":
            lines.append("  Install: run the Installer.x64.exe. Portable: unzip the portable zip and run notepad++.exe.")
        else:
            lines.append("  Unzip SysinternalsSuite.zip to a folder (C:\\Tools\\Sysinternals) and run the programs from it.")
            lines.append("  Microsoft signs each program: Get-AuthenticodeSignature .\\procexp64.exe should say Valid,")
            lines.append("  or open the file's Properties > Digital Signatures.")
            lines.append(f"  Licence: {SYSINTERNALS_LICENSE} (for your own use; not to be passed on).")
        lines.append("")
    lines.append("Each program is its publisher's; winlab only carries the files you fetched. LICENSES.txt lists the licences.")
    return "\r\n".join(lines) + "\r\n"


def licenses(m: dict) -> str:
    lines = ["Licences of the programs on this stick", ""]
    for tool, info in TOOLS.items():
        if tool in m:
            lines += [f"{info['product']}: {info['license']}", f"  {info['page']}",
                      "  fetched on your PC from the publisher, not bundled with winlab", ""]
    return "\r\n".join(lines) + "\r\n"


def stick_files() -> dict[str, bytes]:
    if not ready():
        raise ToolkitError("no admin tools on this PC yet: winlab toolkit fetch (and, if you accept Microsoft's "
                           "licence, winlab toolkit fetch --sysinternals), or Setup > Images")
    m = {t: v for t, v in meta().items() if t in TOOLS and tool_ready(t)}
    out = {}
    for tool, t in m.items():
        for f in t["files"]:
            out[f"{TOOLS[tool]['folder']}/{f['file']}"] = (store() / tool / f["file"]).read_bytes()
    out["README.txt"] = readme(m).encode("utf-8")
    out["LICENSES.txt"] = licenses(m).encode("utf-8")
    return out


def to_stick(lab_name: str, node: str = "") -> dict:
    """A new Admin toolkit stick on the lab's media shelf; with `node`,
    plugged straight into that machine's first free USB port."""
    from . import media, mediashelf
    files = stick_files()
    names = [TOOLS[t]["product"] for t in TOOLS if any(k.startswith(TOOLS[t]["folder"] + "/") for k in files)]
    title = "Admin toolkit"
    sid = mediashelf._new_id(lab_name, "admin-toolkit")
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise ToolkitError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    out = {"id": sid, "title": title, "files": len(files), "tools": names,
           "mb": sum(len(b) for b in files.values()) >> 20, "plugged": None}
    if node:
        from . import schema
        lab = schema.load(lab_name)
        try:
            out["plugged"] = mediashelf.plug(lab, node, sid)
        except mediashelf.ShelfError as exc:
            raise ToolkitError(f"the stick is on the shelf, but: {exc}") from exc
    return out


def summary() -> dict:
    m = meta()
    rows = []
    for tool, info in TOOLS.items():
        t = m.get(tool) or {}
        size = sum((store() / tool / f["file"]).stat().st_size for f in t.get("files") or []
                   if (store() / tool / f["file"]).is_file())
        rows.append({"id": tool, "product": info["product"], "license": info["license"], "ready": tool_ready(tool),
                     "version": t.get("version", ""), "fetched": t.get("fetched", ""), "page": info["page"],
                     "size_mb": round(size / 1048576, 1), "optional": tool not in OPEN_SOURCE})
    return {"id": "toolkit", "title": "Admin toolkit", "ready": ready(), "tools": rows,
            "license_url": SYSINTERNALS_LICENSE}


def render_status() -> str:
    s = summary()
    lines = [f"admin toolkit store: {store()}", ""]
    for r in s["tools"]:
        state = (f"ready ({r['version']}, {r['size_mb']} MB, fetched {r['fetched']})" if r["ready"]
                 else "not fetched")
        lines.append(f"  {r['product']:<20} {state}")
        lines.append(f"  {'':<20} {r['license']}, from {TOOLS[r['id']]['source']}")
    lines += ["", "  fetch:   winlab toolkit fetch                 (PuTTY, WinSCP, Notepad++)",
              "           winlab toolkit fetch --sysinternals  (only if you accept Microsoft's Sysinternals licence)",
              "  stick:   winlab toolkit stick <lab> [<machine>]", ""]
    return "\n".join(lines)


def act(dash, action: str, params: dict) -> dict:
    """toolkit-stick writes the Admin toolkit stick onto the shelf."""
    if action == "toolkit-stick":
        try:
            r = to_stick(dash.lab.name, str(params.get("node") or ""))
        except ToolkitError as exc:
            return {"ok": False, "message": str(exc), "fetch": not ready()}
        where = f"in {params['node']}" if r.get("plugged") else "on the shelf: drag it onto a Windows machine"
        return {"ok": True, "message": f"{r['title']} ({', '.join(r['tools'])}) is {where}", "stick": r["id"]}
    return {"ok": False, "message": f"unknown toolkit action {action!r}"}


# ------------------------------------------------------------------ the command line
def add_cli(sub) -> None:
    p = sub.add_parser("toolkit", help="the admin toolkit stick: PuTTY, WinSCP, Notepad++ and (if you accept "
                                       "Microsoft's licence) the Sysinternals Suite, fetched onto this PC")
    s = p.add_subparsers(dest="tkcmd", metavar="<op>")
    s.add_parser("status", help="which tools are fetched, which release")
    f = s.add_parser("fetch", help="fetch PuTTY, WinSCP and Notepad++ from their publishers, checksum-verified")
    f.add_argument("--sysinternals", action="store_true",
                   help="also fetch the Sysinternals Suite from download.sysinternals.com: you accept "
                        "Microsoft's Sysinternals licence terms")
    f.add_argument("--only", default="", help="comma-separated tools to fetch (putty, winscp, notepadpp, sysinternals)")
    st = s.add_parser("stick", help="write the Admin toolkit stick onto a lab's media shelf")
    st.add_argument("lab")
    st.add_argument("node", nargs="?", default="", help="plug it straight into this machine")


def run_cli(args) -> int:
    import sys
    try:
        if args.tkcmd == "fetch":
            only = tuple(t.strip() for t in args.only.split(",") if t.strip())
            tools = only or (OPEN_SOURCE + (("sysinternals",) if args.sysinternals else ()))
            fetch(tools, accept_sysinternals=args.sysinternals, progress=lambda m: print(f"  {m}"))
            print()
        elif args.tkcmd == "stick":
            r = to_stick(args.lab, args.node)
            where = f"plugged into {args.node}" if r.get("plugged") else f"on {args.lab}'s media shelf"
            print(f"{r['title']} ({', '.join(r['tools'])}) is {where} as {r['id']} ({r['files']} files, {r['mb']} MB)")
            return 0
        print(render_status())
        return 0
    except ToolkitError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3
