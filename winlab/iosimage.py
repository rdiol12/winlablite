"""Flash: the software images of the lab router and the switches, and the
files kept beside them.

A real router keeps its operating system as an image file in flash
(``bootflash:`` on the ISR, ``flash:`` on the 2960), loads one of them at
every start and keeps configuration files there too. Here each device's
flash is a list winlab keeps in the lab folder (``boot.json``, shared with
winlab/iosboot.py), and what happens to it is real where it can be:

* ``copy tftp: flash:`` fetches an image from the student's TFTP server
  with the router's own TFTP client (the same busybox client and the same
  switch namespaces as winlab/tftpcopy.py). The router measures what came
  over the wire (its size, its MD5, and the SHA-256 of the image body) and
  winlab keeps those numbers as the file in flash; the bytes themselves are
  dropped, as winlab's devices run no image.
* ``verify /md5 flash:<file>`` prints that MD5, or compares it with the one
  the release notes give; ``verify flash:<file>`` checks the hash the image
  carries in its own header against its body, so a damaged download shows.
* ``boot system flash:<file>`` (a line of the configuration, kept in the
  startup configuration) decides what the next start loads
  (winlab/iosboot.py), and ``show version`` says what is running.
* ``copy running-config flash:<name>`` keeps a configuration file in flash;
  ``copy flash:<name> running-config`` replays it like a paste, and
  ``copy flash:<name> startup-config`` makes it the next start's.
* On a switch, ``config.text`` is the startup configuration itself:
  renaming it away (from the boot loader during a password recovery, or
  from IOS) leaves the switch to start with none.

The images are winlab's own stand-ins, not anybody's software: a short text
header (platform, version, the SHA-256 of the body) and a body of
deterministic filler. They go on the tftpd pack's stick beside tftpd-hpa
(winlab/debpacks.py, own_tools) with a list of their MD5 sums. One of them,
router-universal-15.2.9WL.bin, is damaged on purpose: its MD5 does not match
the list and its body does not match its header, which is what verify is
for. Real images are hundreds of megabytes; these are a few, so the
transfer takes seconds.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import time
from dataclasses import dataclass
from functools import lru_cache

from . import devcli, paths

STORE = "boot.json"
MAGIC = "WINLAB IMAGE 1"
HEADER_LINES = 6
ROUTER_PLATFORM, SWITCH_PLATFORM = "ISR4321", "C2960"
FLASH_TOTAL = {devcli.ROUTER: 7194652672, "switch": 64016384}
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,96}$")
_HOST = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}))$")


@dataclass(frozen=True)
class Image:
    name: str
    platform: str
    version: str
    size: int            # the body's bytes
    good: bool = True    # False: damaged after it was built (the header no longer matches)


FACTORY = {devcli.ROUTER: Image("router-universal.bin", ROUTER_PLATFORM, "15.2(7)WL", 3 * 1048576),
           "switch": Image("switch-lanbase.bin", SWITCH_PLATFORM, "15.2(7)WL", 1536 * 1024)}
RELEASES = (
    Image("router-universal-15.2.8WL.bin", ROUTER_PLATFORM, "15.2(8)WL", 2 * 1048576),
    Image("router-universal-15.2.9WL.bin", ROUTER_PLATFORM, "15.2(9)WL", 2 * 1048576, good=False),
    Image("switch-lanbase-15.2.8WL.bin", SWITCH_PLATFORM, "15.2(8)WL", 1048576),
)
UPGRADE = {devcli.ROUTER: RELEASES[0], "switch": RELEASES[2]}


# ------------------------------------------------------------------ the image files
def _filler(seed: str, n: int) -> bytes:
    out = bytearray()
    block = hashlib.sha256(f"winlab-image/{seed}".encode()).digest()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(block + i.to_bytes(8, "big")).digest()
        i += 1
    return bytes(out[:n])


def header(img: Image, body_sha: str) -> bytes:
    return (f"{MAGIC}\nplatform {img.platform}\nversion {img.version}\nbuilt by winlab, not a real "
            f"operating system\nbody-sha256 {body_sha}\n\n").encode()


@lru_cache(maxsize=8)
def build(img: Image) -> bytes:
    """The image file: header then body. A damaged one has its header from
    the good body and a body with a few bytes changed, as a bad download."""
    body = _filler(img.name, img.size)
    head = header(img, hashlib.sha256(body).hexdigest())
    if not img.good:
        b = bytearray(body)
        for k in range(7, len(b), len(b) // 5):
            b[k] ^= 0x5A
        body = bytes(b)
    return head + body


@lru_cache(maxsize=8)
def published_md5(img: Image) -> str:
    """The MD5 the release list gives: the good build's, also for the one
    that was damaged on the way."""
    return hashlib.md5(build(Image(img.name, img.platform, img.version, img.size))).hexdigest()


def meta_of(img: Image) -> dict:
    data = build(img)
    hl = len(header(img, "0" * 64))
    return {"kind": "image", "size": len(data), "md5": hashlib.md5(data).hexdigest(), "platform": img.platform,
            "version": img.version, "magic": True, "valid": img.good,
            "declared": hashlib.sha256(_filler(img.name, img.size)).hexdigest(),
            "body": hashlib.sha256(data[hl:]).hexdigest()}


def stick_files() -> dict[str, bytes]:
    """What the tftpd pack's stick carries beside the packages: the images,
    their MD5 list and a note (winlab's own files, MIT like winlab)."""
    files = {img.name: build(img) for img in RELEASES}
    files["IMAGES-MD5.txt"] = "".join(f"{published_md5(img)}  {img.name}\r\n" for img in RELEASES).encode()
    files["IMAGES.txt"] = (
        "winlab device images: stand-ins made by winlab for its lab router (ISR4321) and its switches (C2960).\r\n"
        "They are not anybody's operating system: a text header (platform, version, the SHA-256 of the body)\r\n"
        "and filler. Copy them to the TFTP server's directory, then on the device: copy tftp: flash:,\r\n"
        "verify /md5 flash:<file> <the sum in IMAGES-MD5.txt>, boot system flash:<file>, write memory, reload.\r\n"
        "  sudo cp /mnt/winlab-pack/*.bin /srv/tftp/ && sudo chmod 644 /srv/tftp/*.bin\r\n").encode()
    return files


# ------------------------------------------------------------------ the store (shared with iosboot)
def _path(lab_name: str):
    return paths.lab_dir(lab_name) / STORE


def load(lab_name: str) -> dict:
    try:
        data = json.loads(_path(lab_name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save(lab_name: str, data: dict) -> None:
    p = _path(lab_name)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


def device(lab_name: str, dev: str) -> dict:
    return dict((load(lab_name).get("devices") or {}).get(dev) or {})


def put_device(lab_name: str, dev: str, rec: dict) -> None:
    data = load(lab_name)
    data.setdefault("devices", {})[dev] = rec
    save(lab_name, data)


def kind(dev: str) -> str:
    return devcli.device_kind(dev)


def files(lab_name: str, dev: str) -> dict[str, dict]:
    """The device's flash: its factory image until the student changes it."""
    rec = device(lab_name, dev)
    if "files" in rec and isinstance(rec["files"], dict):
        return dict(rec["files"])
    img = FACTORY[kind(dev)]
    return {img.name: meta_of(img)}


def put_files(lab_name: str, dev: str, fl: dict[str, dict]) -> None:
    rec = device(lab_name, dev)
    rec["files"] = fl
    put_device(lab_name, dev, rec)


def fs(dev: str) -> str:
    return "bootflash:" if dev == devcli.ROUTER else "flash:"


def flash_name(dev: str, text: str) -> str | None:
    """'bootflash:x' / 'flash:/x' -> 'x' ('' for the file system alone);
    None when the text is not this device's flash."""
    t = text.strip()
    m = re.match(r"^(bootflash|flash):/?(.*)$", t, re.I)
    if not m:
        return None
    if m.group(1).lower() == "bootflash" and dev != devcli.ROUTER:
        return None
    return m.group(2)


def running_image(lab_name: str, dev: str) -> tuple[str, str]:
    """(file, version) the device runs now."""
    rec = device(lab_name, dev)
    img = FACTORY[kind(dev)]
    return rec.get("running") or img.name, rec.get("version") or img.version


def bootable(meta: dict, dev: str) -> str:
    """'' when a file can be booted on this device, else why not."""
    if meta.get("kind") != "image" or not meta.get("magic"):
        return "not a bootable image"
    want = ROUTER_PLATFORM if dev == devcli.ROUTER else SWITCH_PLATFORM
    if meta.get("platform") != want:
        return f"the image is for a {meta.get('platform') or 'different'} platform, not {want}"
    if not meta.get("valid"):
        return "the image's contents do not match the hash in its header (it is damaged)"
    return ""


def boot_entries(own: dict) -> list[str]:
    return [e for e in (own.get("boot-system") or "").split("|") if e]


def choose(lab_name: str, dev: str, own: dict) -> tuple[str, list[str]]:
    """What a start loads: each boot system entry in turn, then the first
    image in flash that boots. ('', notes) when nothing does."""
    fl = files(lab_name, dev)
    notes = []
    for entry in boot_entries(own):
        name = flash_name(dev, entry)
        meta = fl.get(name or "")
        why = "file not found" if meta is None else bootable(meta, dev)
        if not why:
            return name, notes
        notes.append(f"%BOOT-3-BOOTFAIL: boot of {entry} failed: {why}")
    for name, meta in fl.items():
        if not bootable(meta, dev):
            if notes:
                notes.append(f"%BOOT-5-FALLBACK: loading the first image in {fs(dev)} instead: {name}")
            return name, notes
    notes.append(f"%BOOT-3-NOIMAGE: no bootable image in {fs(dev)}")
    return "", notes


# ------------------------------------------------------------------ show and dir
def _config_text(con) -> str:
    from . import tftpcopy
    return tftpcopy.startup_body(con)


def listing(con) -> list[tuple[str, int, str]]:
    """(permissions, size, name) of every file in the device's flash."""
    lab_name, dev = con.lab.name, con.device
    rows = [("-rw-" if dev == devcli.ROUTER else "-rwx", int(m.get("size", 0)), n)
            for n, m in files(lab_name, dev).items()]
    cfg = len(_config_text(con))
    if dev == devcli.ROUTER:
        rows.append(("-rw-", cfg, "nvram_config"))
    else:
        rows.append(("-rwx", 616, "vlan.dat"))
        from . import iosnv
        snap = ((iosnv.load(lab_name) or {}).get("devices") or {}).get(dev) or {}
        if snap and not snap.get("erased"):
            rows.append(("-rwx", cfg, "config.text"))
    return rows


def show_flash(con, a=None) -> str:
    rows = listing(con)
    total = FLASH_TOTAL[kind(con.device)]
    out = [f"Directory of {fs(con.device)}/", ""]
    out += [f"{i:>4}  {p}  {n:>10}  {name}" for i, (p, n, name) in enumerate(rows, 1)]
    used = sum(n for _, n, _ in rows)
    out += ["", f"{total} bytes total ({total - used} bytes free)"]
    return "\n".join(out)


def dir_cmd(con, a) -> str:
    arg = (a[0] if a else "").strip()
    if arg and flash_name(con.device, arg) is None:
        return f"%Error opening {arg} (No such device)"
    name = flash_name(con.device, arg) if arg else ""
    if name:
        rows = [r for r in listing(con) if r[2] == name]
        if not rows:
            return f"%Error opening {fs(con.device)}/{name} (No such file or directory)"
        p, n, nm = rows[0]
        return f"Directory of {fs(con.device)}/{nm}\n\n   1  {p}  {n:>10}  {nm}\n"
    return show_flash(con)


# ------------------------------------------------------------------ verify, delete, rename
def _file_arg(con, text: str) -> str:
    name = flash_name(con.device, text)
    if not name:
        raise devcli.CliError(f"%Error opening {text} (No such device or file)")
    return name


def verify(con, a) -> str:
    words = (a[0] if a else "").split()
    md5 = bool(words) and words[0].lower() == "/md5"
    if md5:
        words = words[1:]
    if not words:
        raise devcli.CliError("% Incomplete command.")
    name = _file_arg(con, words[0])
    meta = files(con.lab.name, con.device).get(name)
    where = f"{fs(con.device)}{name}"
    if meta is None:
        return f"%Error opening {where} (No such file or directory)"
    if md5:
        dots = "." * max(4, min(60, int(meta.get("size", 0)) // 65536)) + "Done!"
        got = meta.get("md5", "")
        if len(words) > 1:
            want = words[1].lower()
            if want == got:
                return f"{dots}\nVerified (verify /md5 ({where}) = {got})"
            return (f"{dots}\n%Error verifying {where}\nComputed signature  = {got}\n"
                    f"Submitted signature = {want}")
        return f"{dots}\nverify /md5 ({where}) = {got}"
    if meta.get("kind") != "image" or not meta.get("magic"):
        return f"%Error: {where} is not an image: it carries no header to check"
    head = [f"Verifying file integrity of {where}" + "." * 20, f"Embedded hash   : {meta.get('declared', '')}",
            f"Computed hash   : {meta.get('body', '')}"]
    if meta.get("valid"):
        return "\n".join(head + [f"Image verified: platform {meta.get('platform')}, version {meta.get('version')}"])
    return "\n".join(head + [f"%Error: {where} is damaged: its body does not match the hash in its header. "
                             "Do not boot it; copy it again from the server"])


def delete(con, a) -> str:
    from . import iosnv
    text = (a[0] if a else "").strip()
    for flag in ("/force", "/recursive"):
        text = text.replace(flag, "").strip()
    name = _file_arg(con, text)
    if name not in files(con.lab.name, con.device):
        return f"%Error deleting {fs(con.device)}/{name} (No such file or directory)"
    iosnv.ask(con, "flash-delete", f"Delete filename [{name}]? ", on=_delete_answer, step="name", name=name)
    return ""


def _delete_answer(con, line: str, q: dict) -> str:
    from . import iosnv
    text = line.strip()
    if q["step"] == "name":
        name = text or q["name"]
        iosnv.ask(con, "flash-delete", f"Delete {fs(con.device)}/{name}? [confirm]", on=_delete_answer,
                  step="confirm", name=name)
        return ""
    if text.lower() not in ("", "y", "yes"):
        return ""
    fl = files(con.lab.name, con.device)
    if q["name"] not in fl:
        return f"%Error deleting {fs(con.device)}/{q['name']} (No such file or directory)"
    fl.pop(q["name"])
    put_files(con.lab.name, con.device, fl)
    return ""


def rename(con, a, loader: bool = False) -> str:
    """rename flash:a flash:b (IOS and the switch's boot loader). config.text
    is the switch's startup configuration: moving it away leaves NVRAM
    empty; moving a file to it makes that the startup configuration."""
    words = (a[0] if a else "").split()
    if len(words) != 2:
        raise devcli.CliError("% Incomplete command." if len(words) < 2 else "% Invalid input detected at '^' marker.")
    src, dst = (flash_name(con.device, w) for w in words)
    if not src or not dst or not _NAME.match(dst):
        return f"%Error renaming {words[0]} (Invalid argument)"
    return move(con, src, dst)


def move(con, src: str, dst: str) -> str:
    from . import iosnv
    lab_name, dev = con.lab.name, con.device
    fl = files(lab_name, dev)
    store = iosnv.load(lab_name) or {}
    snap = (store.get("devices") or {}).get(dev) or {}
    has_cfg = dev != devcli.ROUTER and bool(snap) and not snap.get("erased")
    if src == dst:
        return ""
    if src == "config.text" and dev != devcli.ROUTER:
        if not has_cfg:
            return f"%Error renaming flash:/{src} (No such file or directory)"
        fl[dst] = {"kind": "nvram", "snap": snap, "size": len(snap.get("text", "") or "")}
        store.setdefault("devices", {})[dev] = {"erased": True}
        iosnv._save_store(lab_name, store)
        put_files(lab_name, dev, fl)
        return ""
    if src not in fl:
        return f"%Error renaming {fs(dev)}/{src} (No such file or directory)"
    if dst == "config.text" and dev != devcli.ROUTER:
        meta = fl.pop(src)
        if meta.get("kind") == "nvram":
            store.setdefault("devices", {})[dev] = meta["snap"]
            iosnv._save_store(lab_name, store)
        elif meta.get("kind") == "config":
            from . import tftpcopy
            tftpcopy.to_startup(con, meta.get("text", ""))
        else:
            return f"%Error renaming {fs(dev)}/{src}: an image is not a configuration"
        put_files(lab_name, dev, fl)
        return ""
    fl[dst] = fl.pop(src)
    put_files(lab_name, dev, fl)
    return ""


# ------------------------------------------------------------------ copy
def copy(con, src: str, dst: str) -> str | None:
    """copy with flash at either end (winlab/tftpcopy.py hands these over);
    None when neither end is flash."""
    from . import iosnv, tftpcopy
    dev = con.device
    sn, dn = flash_name(dev, src), flash_name(dev, dst)
    if sn is None and dn is None:
        return None
    s = tftpcopy._kind(src) if sn is None else "flash"
    d = tftpcopy._kind(dst) if dn is None else "flash"
    if s == "tftp:" and d == "flash":
        _, host, name = tftpcopy.parse_url(src)
        iosnv.ask(con, "img-host", f"Address or name of remote host [{host}]? ", on=_answer, step="host",
                  host=host, name=name, dst=dn)
        return ""
    if s in ("running-config", "startup-config") and d == "flash":
        body = tftpcopy.running_body(con) if s == "running-config" else tftpcopy.startup_body(con)
        if not body:
            return "%Error opening nvram:/startup-config (No such file or directory)"
        default = dn or f"{devcli.ios_name(con.lab, dev).lower()}-confg"
        iosnv.ask(con, "img-cfg", f"Destination filename [{default}]? ", on=_answer, step="cfg", name=default,
                  body=body)
        return ""
    if s == "flash":
        if not sn:
            return f"%Error opening {src} (Is a directory)"
        if dev != devcli.ROUTER and sn == "config.text":
            text = tftpcopy.startup_body(con)
            if not text:
                return "%Error opening flash:/config.text (No such file or directory)"
        else:
            meta = files(con.lab.name, dev).get(sn)
            if meta is None:
                return f"%Error opening {fs(dev)}/{sn} (No such file or directory)"
            if meta.get("kind") == "image":
                if d == "flash":
                    fl = files(con.lab.name, dev)
                    fl[dn or sn] = dict(meta)
                    put_files(con.lab.name, dev, fl)
                    return f"{meta.get('size', 0)} bytes copied"
                return f"%Error: {fs(dev)}/{sn} is an image: winlab copies images into flash, not out of it"
            text = meta.get("text", "") if meta.get("kind") == "config" else (meta.get("snap") or {}).get("text", "")
        if d == "running-config":
            errs = tftpcopy.apply_config(con, text)
            return "\n".join(errs + [f"{len(text)} bytes copied in 0.0 secs"]).strip()
        if d == "startup-config":
            errs = tftpcopy.to_startup(con, text)
            return "\n".join(errs + ["[OK]", f"{len(text)} bytes copied"]).strip()
        if d == "flash":
            fl = files(con.lab.name, dev)
            fl[dn] = {"kind": "config", "text": text, "size": len(text)}
            put_files(con.lab.name, dev, fl)
            return f"{len(text)} bytes copied"
        if d == "tftp:":
            _, host, name = tftpcopy.parse_url(dst)
            iosnv.ask(con, "img-put-host", f"Address or name of remote host [{host}]? ", on=_answer,
                      step="put-host", host=host, name=name or sn, body=text)
            return ""
    return f"%Error: copy from {src} to {dst} is not offered here"


def _answer(con, line: str, q: dict) -> str:
    from . import iosnv, tftpcopy
    text = line.strip()
    step = q["step"]
    data = {k: v for k, v in q.items() if k not in ("kind", "prompt", "secret", "tries", "on", "step")}
    if step in ("host", "put-host"):
        host = text or q.get("host", "")
        if not host or not _HOST.match(host):
            return "%Error parsing filename (Bad IP address or host name)"
        data["host"] = host
        if step == "put-host":
            iosnv.ask(con, "img-put", f"Destination filename [{q['name']}]? ", on=_answer, step="put", **data)
        else:
            iosnv.ask(con, "img-src", f"Source filename [{q.get('name', '')}]? ", on=_answer, step="src", **data)
        return ""
    if step == "src":
        name = text or q.get("name", "")
        if not name or not _NAME.match(name.split("/")[-1]):
            return "%Error parsing filename (Bad file name)"
        data["name"] = name
        default = q.get("dst") or name.split("/")[-1]
        iosnv.ask(con, "img-dst", f"Destination filename [{default}]? ", on=_answer, step="dst", **{**data, "dst": default})
        return ""
    if step == "dst":
        dst = text or q["dst"]
        if not _NAME.match(dst):
            return "%Error parsing filename (Bad file name)"
        data["dst"] = dst
        if dst in files(con.lab.name, con.device):
            iosnv.ask(con, "img-over", "%Warning: There is a file already existing with this name\n"
                      "Do you want to over write? [confirm]", on=_answer, step="over", **data)
            return ""
        return fetch(con, q["host"], q["name"], dst)
    if step == "over":
        if text.lower() not in ("", "y", "yes"):
            return ""
        return fetch(con, q["host"], q["name"], q["dst"])
    if step == "cfg":
        name = text or q["name"]
        if not _NAME.match(name) or name == "config.text":
            return "%Error parsing filename (Bad file name)"
        fl = files(con.lab.name, con.device)
        fl[name] = {"kind": "config", "text": q["body"], "size": len(q["body"])}
        put_files(con.lab.name, con.device, fl)
        return f"{len(q['body'])} bytes copied in 0.0 secs"
    if step == "put":
        name = text or q["name"]
        if not tftpcopy._FILE.match(name):
            return "%Error parsing filename (Bad file name)"
        ns = tftpcopy.netns(con)
        if con.device != devcli.ROUTER and not ns:
            return f"%Error opening tftp://{q['host']}/{name} (No route to host)\n{tftpcopy._no_mgmt(con)}"
        res = tftpcopy.parse_result(con._on_router(tftpcopy.put_cmd(q["body"], q["host"], name, ns), timeout=40))
        if res["notftp"]:
            return tftpcopy.NO_CLIENT
        if res["rc"] != 0:
            return f"%Error opening tftp://{q['host']}/{name} ({tftpcopy.ios_error(res['error'])})"
        return f"!!\n{len(q['body'])} bytes copied"
    return ""


def fetch_cmd(host: str, name: str, ns: str = "") -> str:
    """Fetches a file to the router's memory, prints what it measured, drops it."""
    from . import tftpcopy
    pre = f"ip netns exec {ns} " if ns else ""
    q = shlex.quote
    return (tftpcopy.CLIENT + f"f=/tmp/winlab-img.$$; rm -f $f; {pre}\"$T\" -g -l $f -r {q(name)} {q(host)} 2>&1; "
            f"echo \"#rc=$?\"; if [ -s $f ]; then echo \"#size $(wc -c < $f)\"; "
            f"echo \"#md5 $(md5sum $f | cut -d' ' -f1)\"; h=$(head -n {HEADER_LINES} $f | wc -c); "
            f"echo \"#body $(tail -c +$((h+1)) $f | sha256sum | cut -d' ' -f1)\"; "
            f"head -n {HEADER_LINES - 1} $f | head -c 600 | tr -cd '\\11\\12\\40-\\176' | sed 's/^/#head /'; fi; "
            f"rm -f $f; {pre}ip -o route get {q(host)} 2>/dev/null | head -n 1 | sed 's/^/#via /'")


def parse_fetch(text: str) -> dict:
    out: dict = {"rc": None, "error": "", "size": 0, "md5": "", "body": "", "head": [], "dev": "", "notftp": False}
    for line in (text or "").splitlines():
        if line == "#notftp":
            out["notftp"] = True
        elif line.startswith("#rc="):
            v = line[4:].strip()
            out["rc"] = int(v) if v.lstrip("-").isdigit() else None
        elif line.startswith("#size "):
            v = line[6:].strip()
            out["size"] = int(v) if v.isdigit() else 0
        elif line.startswith("#md5 "):
            out["md5"] = line[5:].strip().lower()
        elif line.startswith("#body "):
            out["body"] = line[6:].strip().lower()
        elif line.startswith("#head "):
            out["head"].append(line[6:].rstrip())
        elif line.startswith("#via "):
            m = re.search(r"\bdev (\S+)", line)
            out["dev"] = m.group(1) if m else ""
        elif line.strip() and out["rc"] is None:
            out["error"] = (out["error"] + " " + line.strip()).strip()
    return out


def meta_from(res: dict) -> dict:
    """What flash keeps of a fetched file: an image when its header says so."""
    head = res.get("head") or []
    meta = {"kind": "file", "size": res.get("size", 0), "md5": res.get("md5", ""), "body": res.get("body", "")}
    if head and head[0].strip() == MAGIC:
        fields = {}
        for line in head[1:]:
            k, _, v = line.partition(" ")
            fields[k.strip()] = v.strip()
        declared = fields.get("body-sha256", "").lower()
        meta.update(kind="image", magic=True, platform=fields.get("platform", ""), version=fields.get("version", ""),
                    declared=declared, valid=bool(declared) and declared == res.get("body", ""))
    return meta


def fetch(con, host: str, name: str, dst: str) -> str:
    from . import tftpcopy
    ns = tftpcopy.netns(con)
    if con.device != devcli.ROUTER and not ns:
        return f"%Error opening tftp://{host}/{name} (No route to host)\n{tftpcopy._no_mgmt(con)}"
    t0 = time.time()
    res = parse_fetch(con._on_router(fetch_cmd(host, name, ns), timeout=180))
    secs = max(time.time() - t0, 0.001)
    head = f"Accessing tftp://{host}/{name}..."
    if res["notftp"]:
        return tftpcopy.NO_CLIENT
    if res["rc"] != 0 or not res["size"]:
        why = tftpcopy.ios_error(res["error"]) if res["rc"] != 0 else "File is empty"
        return f"{head}\n%Error opening tftp://{host}/{name} ({why})"
    meta = meta_from(res)
    fl = files(con.lab.name, con.device)
    fl[dst] = meta
    put_files(con.lab.name, con.device, fl)
    via = tftpcopy._via(con, res["dev"]) if res["dev"] or con.device != devcli.ROUTER else ""
    bangs = "!" * max(1, min(70, meta["size"] // 32768))
    return "\n".join([head, f"Loading {name} from {host}" + (f" (via {via})" if via else "") + f": {bangs}",
                      f"[OK - {meta['size']} bytes]", "",
                      f"{meta['size']} bytes copied in {secs:.3f} secs ({int(meta['size'] / secs)} bytes/sec)"])


# ------------------------------------------------------------------ boot system
def boot_system(con, a) -> str:
    text = (a[0] if a else "").strip()
    words = text.split()
    if words and words[0].lower() in ("flash", "bootflash") and len(words) == 2:
        text = f"{words[0]}:{words[1]}"
    name = flash_name(con.device, text)
    if not name or not _NAME.match(name):
        raise devcli.CliError("% Invalid input detected at '^' marker.")
    own = devcli.settings(con.lab, con.device)
    entries = boot_entries(own)
    entry = f"{fs(con.device)}{name}"
    if entry not in entries:
        entries.append(entry)
    own["boot-system"] = "|".join(entries)
    con._save(live=False)
    return ""


def no_boot_system(con, a) -> str:
    own = devcli.settings(con.lab, con.device)
    text = (a[0] if a else "").strip()
    if not text:
        own.pop("boot-system", None)
    else:
        name = flash_name(con.device, text.replace(" ", ":", 1) if ":" not in text else text)
        entries = [e for e in boot_entries(own) if flash_name(con.device, e) != name]
        if entries:
            own["boot-system"] = "|".join(entries)
        else:
            own.pop("boot-system", None)
    con._save(live=False)
    return ""


def boot_lines(lab, dev: str) -> list[str]:
    return [f"boot system {e}" for e in boot_entries(lab.devices.get(dev, {}))]


def add_specs(con, add, U, E, C) -> None:
    router = con.device == devcli.ROUTER
    add("dir", lambda a: show_flash(con), "List files on a filesystem", E)
    add("dir <line>", lambda a: dir_cmd(con, a), "List files on a filesystem", E)
    if router:
        add("show bootflash:", lambda a: show_flash(con), "display information about bootflash: file system", U)
    add("verify <line>", lambda a: verify(con, a), "Verify a file", E)
    add("delete <line>", lambda a: delete(con, a), "Delete a file", E)
    add("rename <line>", lambda a: rename(con, a), "Rename a file", E)
    add("boot system <line>", lambda a: boot_system(con, a), "System image file", C)
    add("no boot system", lambda a: no_boot_system(con, []), "Negate a command or set its defaults", C)
    add("no boot system <line>", lambda a: no_boot_system(con, a), "Negate a command or set its defaults", C)
