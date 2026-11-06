"""Windows Server Backup the way an admin runs it: to the NAS, on a schedule,
and the bare-metal recovery that proves it.

The app connects things; the student configures Windows. So nothing here
installs the feature or writes the backup for anyone from the desktop. What
the desktop offers is physical and read-only: the NAS's Backups share (what
Windows wrote there, read on the NAS over its agent), the bare-metal drill
(the system disk dies, a new blank one goes in, the Windows Server DVD goes
into the drive and first in the boot order) and the check that grades it.

Two roles stay for the command line (winlab roles apply), CI and the career
game, never as a button: server-backup (the feature and its tools) and
backup-nas (a nightly full-server backup, bare metal and system state, to
\\\\<nas>\\Backups at 21:00 lab time, vars.backup_at): the model answer.

The NAS is the workbench's OpenMediaVault appliance (winlab/omv.py,
content/roles/nas.sh). Out of the box it shares nothing: the student builds
the file system, the Backups shared folder, its SMB share and the NAS's own
account for the backup (svc-backup) in its web UI. Backups land there as
Windows writes them, WindowsImageBackup\\<COMPUTER>\\Backup <date>, in the
folder the Backups share serves (read from the Samba configuration
OpenMediaVault deployed, never a fixed path).

The drill, step by step: the student leaves a marker on the server (its
machine SID and its system disk's serial number, one PowerShell line from
the lesson), backs it up, the system disk dies (winlab/sysdisk.py), power
off, fit a new blank disk, DVD in and first, System Image Recovery from the
NAS, then the check: the marker is back, the machine SID is the one it had,
the system disk is a different drive, the backup's own log came back.
Nothing here uses winlab's checkpoints; the backup is Windows' own.

Two graded faults on the NAS register with guestfaults: the backup target
full, and the Backups share made read-only.
"""

from __future__ import annotations

import json

from . import naming, omv, paths, state
from .model import WINDOWS_SERVER

BACKUP_SHARE = "Backups"
DEFAULT_AT = "21:00"
NAS_USER = omv.BACKUP_USER     # the NAS's own account, created in its web UI
# The folder the Backups share serves, read on the NAS (sh).
SHARE_DIR = f"$({omv.share_path_sh(BACKUP_SHARE)})"
MARKER = "C:\\winlab\\bmr-marker.json"
FLOW_FILE = "bmr.json"
FEATURE = "Windows-Server-Backup"


class BackupError(Exception):
    pass


# ----------------------------------------------------------------- the NAS
def nas_of(lab):
    """The lab's NAS appliance (the first), or None."""
    from .appliance import device_of
    return next((n for n in lab.node_list() if device_of(n) == "nas"), None)


def nas_address(lab) -> tuple[str, str]:
    """(name, address) Windows reaches the NAS by; the address is '' when
    it takes one from DHCP."""
    nas = nas_of(lab)
    if nas is None:
        return "", ""
    nic = nas.nics[0] if nas.nics else None
    return naming.hostname_of(nas).lower(), (nic.ip if nic is not None and nic.ip else "")


def target_unc(lab) -> str:
    host, _ = nas_address(lab)
    return f"\\\\{host}\\{BACKUP_SHARE}" if host else ""


def parse_share(out: str) -> str:
    """The Backups share's folder from the listing's first line (share|path),
    '' when the NAS has no such share yet."""
    for line in out.splitlines():
        if line.startswith("share|"):
            return line[len("share|"):].strip()
    return ""


def parse_sets(out: str) -> list[dict]:
    """The NAS's listing (computer|backup folder|MB lines) as backup sets."""
    rows = []
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) == 3 and parts[1].startswith("Backup") and parts[2].isdigit():
            rows.append({"computer": parts[0], "set": parts[1], "mb": int(parts[2]),
                         "when": parts[1][len("Backup "):].strip()})
    return sorted(rows, key=lambda r: (r["computer"].lower(), r["set"]))


LIST_SH = (f"d={SHARE_DIR}; echo \"share|$d\"; [ -n \"$d\" ] || exit 0; "
           "cd \"$d/WindowsImageBackup\" 2>/dev/null || exit 0; "
           "for h in *; do [ -d \"$h\" ] || continue; for b in \"$h\"/Backup*; do "
           "[ -d \"$b\" ] && echo \"$h|${b#*/}|$(du -sm \"$b\" | cut -f1)\"; done; done")


def nas_listing(lab, factory=None, wait: bool = False) -> str:
    """The NAS's answer to LIST_SH: the share's folder, then the sets."""
    from . import appliance
    nas = nas_of(lab)
    if nas is None:
        raise BackupError("the lab has no NAS: add one from the Workbench shelf")
    try:
        ch = appliance._channel(lab.name, nas.id, factory or appliance.GuestChannel, wait)
    except appliance.ApplianceError as exc:  # off or still starting: the window shows the rest
        raise BackupError(str(exc)) from None
    try:
        r = ch.run(LIST_SH, shell="sh", timeout=60)
    except Exception as exc:  # noqa: BLE001 - the device's answer, whatever went wrong
        raise BackupError(f"{nas.id}: {exc}") from None
    finally:
        ch.close()
    return r.out


def nas_sets(lab, factory=None, wait: bool = False) -> list[dict]:
    """The full-server backups on the NAS, read on the NAS itself."""
    return parse_sets(nas_listing(lab, factory, wait))


# ----------------------------------------------------------------- scripts
def schedule_scripts(lab, at: str = DEFAULT_AT) -> tuple[str, str]:
    """(test, set) for the nightly backup to the NAS: every critical volume
    (what bare-metal recovery needs) and the system state."""
    host, _ = nas_address(lab)
    if not host:
        raise BackupError("backup-nas needs a NAS in the lab: add one from the Workbench shelf")
    unc = target_unc(lab)
    test = ("Import-Module WindowsServerBackup -ErrorAction SilentlyContinue\n"
            "$p = Get-WBPolicy -ErrorAction SilentlyContinue\n"
            "if (-not $p) { return $false }\n"
            "$t = Get-WBBackupTarget -Policy $p | Out-String\n"
            f"[bool]($p.BMR -and $p.SystemState -and $p.Schedule -and $t -match [regex]::Escape('{unc}'))")
    set_ = ("$f = Get-Content -Path 'C:\\winlab\\facts.json' -Raw | ConvertFrom-Json\n"
            # The NAS's own account: Samba knows nobody from the domain.
            f"$a = @('enable', 'backup', '-addtarget:{unc}', '-user:{host}\\{NAS_USER}', "
            "('-password:' + $f.lab.admin_password),\n"
            f"       '-allCritical', '-systemState', '-schedule:{at}', '-quiet')\n"
            "$out = & wbadmin.exe @a 2>&1 | Out-String\n"
            "if ($LASTEXITCODE -ne 0) { throw ('wbadmin enable backup: ' + $out.Trim()) }")
    return test, set_


# The machine SID (the local Administrator's, less its RID) and the system
# disk's serial number, read the same way when marking and when checking.
# MARK_PS is what the lesson has the student type; the app never runs it.
_IDENTITY = (
    "$a = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' | "
    "Where-Object { $_.SID -like '*-500' } | Select-Object -First 1\n"
    "$sid = [string]$a.SID -replace '-500$', ''\n"
    "$disk = ([string](Get-Disk | Where-Object IsBoot | Select-Object -First 1).SerialNumber).Trim()\n"
)
MARK_PS = (
    _IDENTITY
    + "New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null\n"
    "[ordered]@{ computer = $env:COMPUTERNAME; sid = $sid; disk = $disk; at = (Get-Date).ToString('s') } | "
    f"ConvertTo-Json | Set-Content -Path '{MARKER}' -Encoding UTF8"
)
MARK_ONE_LINE = MARK_PS.replace("\n", "; ")
READ_MARKER_PS = (f"$m = Get-Content -Path '{MARKER}' -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json\n"
                  "if ($m) { '{0}|{1}|{2}' -f $m.computer, $m.sid, $m.disk } else { 'none' }")
CHECK_PS = (
    f"$m = Get-Content -Path '{MARKER}' -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json\n"
    "if (-not $m) { 'marker=missing'; return }\n"
    + _IDENTITY
    + "$ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Backup'; Id = 1, 4, 14 } "
    "-ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge [datetime]$m.at })\n"
    "'marker=ok'\n"
    "'sid=' + $(if ($sid -eq $m.sid) { 'same' } else { 'different' })\n"
    "'disk=' + $(if ($disk -and $disk -ne $m.disk) { 'new' } else { 'same' })\n"
    "'backup-log=' + $ev.Count"
)


def parse_check(out: str) -> dict:
    """CHECK_PS's answer: marker, sid, disk, backup log events, and passed."""
    got = {}
    for line in out.splitlines():
        k, sep, v = line.strip().partition("=")
        if sep:
            got[k] = v
    events = int(got.get("backup-log", "0") or 0) if got.get("backup-log", "0").isdigit() else 0
    ok = got.get("marker") == "ok" and got.get("sid") == "same" and got.get("disk") == "new" and events > 0
    return {"marker": got.get("marker", "missing"), "sid": got.get("sid", ""), "disk": got.get("disk", ""),
            "events": events, "passed": ok}


# ----------------------------------------------------------------- roles
def build_server_backup(cfg) -> None:
    cfg.feature(FEATURE, subfeatures=True)
    cfg.notes.append("server-backup: the feature only; the backup, its target and schedule are yours")


def build_backup_nas(cfg) -> None:
    from .dsc import DscError
    try:
        test, set_ = schedule_scripts(cfg.lab, str(cfg.vars.get("backup_at") or DEFAULT_AT))
    except BackupError as exc:
        raise DscError(f"{cfg.node.id}: {exc}") from None
    feat = cfg.feature(FEATURE, subfeatures=True)
    cfg.script("BackupToNas", test, set_, depends=[feat])
    cfg.notes.append(f"backup-nas: full server (bare metal, system state) to {target_unc(cfg.lab)} at "
                     f"{cfg.vars.get('backup_at') or DEFAULT_AT} lab time, as {nas_address(cfg.lab)[0]}\\{NAS_USER}")


BUILDERS = {"server-backup": build_server_backup, "backup-nas": build_backup_nas}


# ----------------------------------------------------------------- the drill
def _flow_load(lab_name: str, node_id: str) -> dict:
    try:
        d = json.loads((paths.lab_dir(lab_name) / node_id / FLOW_FILE).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _flow_save(lab_name: str, node_id: str, data: dict) -> None:
    p = paths.lab_dir(lab_name) / node_id / FLOW_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")


def server_disc(lab_name: str, node) -> dict | None:
    """The Windows Server DVD on the shelf that matches the machine's
    Windows (the one Setup's recovery environment must come from), else
    any Windows Server DVD there."""
    from . import images, mediashelf
    want = node.image
    tpl = images.templates().get(want)
    if tpl is not None:
        want = tpl.image
    want = images.SHARES_INSTALLER.get(want, want)
    win = [d for d in mediashelf.discs(lab_name) if d["kind"] == "windows"]
    exact = next((d for d in win if d["ref"] == f"image:{want}"), None)
    return exact or next((d for d in win if d["ref"].startswith("image:ws")), None)


def flow(lab, node, sets: list[dict] | None = None) -> dict:
    """The bare-metal recovery drill for one server, each step with whether
    it is done and the action that does it."""
    from . import mediashelf, sysdisk
    f = _flow_load(lab.name, node.id)
    disk = sysdisk.status(lab.name, node)
    if "gen0" not in f:
        # The drive the drill starts on: a disk fitted after this is the new
        # one. A drill first opened on a drive just fitted started before it.
        g = disk["generation"]
        f["gen0"] = g - 1 if g and disk["health"] in ("new", "replaced") else g
        _flow_save(lab.name, node.id, f)
    gen0 = int(f["gen0"])
    swapped = disk["generation"] > gen0
    on = state.is_running(lab.name, node.id)
    media = mediashelf.contents(lab.name, node)
    drive = (media["drives"] or [{}])[0].get("disc") if media["drives"] else None
    host, ip = nas_address(lab)
    unc = target_unc(lab)
    me = naming.hostname_of(node).upper()
    mine = [s for s in (sets or []) if s["computer"].upper() == me]
    restored = swapped and disk["health"] == "replaced"
    # Physical steps and what is true of the machine: the window is its
    # hardware (the disk, the drive, the boot order, the power), never a
    # recipe. What to type in Windows and in its recovery environment is the
    # lesson's, and its hint ladder's.
    steps = [
        {"id": "mark", "title": "A marker on the server", "done": bool(f.get("marker")),
         "act": "wsb-look" if on and not swapped else "",
         "text": f"The lesson's marker file, {MARKER}, read from the server (Look): the proof that the server "
                 "that comes back is this one."},
        {"id": "backup", "title": "A full-server backup on the NAS", "done": bool(mine), "act": "wsb-nas" if host else "",
         "text": ("Read on the NAS's Backups share." if host else "The lab has no NAS.")
         + (f" On the NAS now: {mine[-1]['set']}, {mine[-1]['mb']} MB." if mine else "")},
        {"id": "die", "title": "The system disk dies", "done": disk["dead"] or swapped,
         "act": "sysdisk-die" if not disk["dead"] and not swapped else "",
         "text": "Every read and write fails."},
        {"id": "off", "title": "Powered off", "done": (disk["dead"] or swapped) and not on,
         "act": "power-cut" if on and disk["dead"] else "", "text": "Its plug."},
        {"id": "replace", "title": "A new blank system disk", "done": swapped,
         "act": "sysdisk-replace" if not on and not swapped else "",
         "text": f"The same size{(' (' + str(disk['gb']) + ' GB)') if disk['gb'] else ''}, its own serial number."},
        {"id": "disc", "title": "A Windows Server DVD in the drive",
         "done": bool(drive and drive.get("kind") == "windows"), "act": "",
         "text": "From the media shelf (the drive below)."},
        {"id": "boot", "title": "DVD drive first in the boot order", "done": media["boot"] == mediashelf.BOOT_DVD
         or restored, "act": "", "text": "The boot order below, or the firmware's boot menu at power-on."},
        {"id": "restore", "title": "Restored onto the new disk", "done": restored,
         "act": "boot-node" if not on and swapped else "", "text": "On the machine's own screen."},
        {"id": "after", "title": "Booting from its disk again, DVD out",
         "done": restored and media["boot"] != mediashelf.BOOT_DVD and not drive, "act": "", "text": ""},
        {"id": "check", "title": "The same server", "done": bool(f.get("verified")),
         "act": "wsb-check" if on and restored else "",
         "text": "The marker, the machine SID, the system disk's serial number and the backup's log."},
    ]
    return {"node": node.id, "computer": me, "running": on, "disk": disk, "target": unc, "nas": host,
            "nas_ip": ip, "steps": steps, "boot": media["boot"], "drive": drive,
            "discs": [{"ref": d["ref"], "title": d["title"]} for d in mediashelf.discs(lab.name)], "sets": mine, "last_check": f.get("last_check") or {},
            "marker": f.get("marker") or {}, "done": sum(1 for s in steps if s["done"])}


def _guest(lab, node):
    from .guestctl import GuestChannel
    st = state.load(lab.name)
    ns = st.nodes.get(node.id) if st else None
    if not ns or not state.pid_alive(ns.pid):
        raise BackupError(f"{node.id} is not running")
    return GuestChannel(ns.serial_port).connect(retries=4, delay=2)


def look(lab, node, channel=None) -> dict:
    """Reads the marker the student left on the server (grading: nothing is
    written) and keeps what it says."""
    ch = channel or _guest(lab, node)
    try:
        r = ch.run(READ_MARKER_PS, shell="powershell", timeout=120)
    finally:
        if channel is None:
            ch.close()
    last = [ln for ln in r.out.strip().splitlines() if ln.count("|") == 2]
    f = _flow_load(lab.name, node.id)
    if not last:
        f.pop("marker", None)
        _flow_save(lab.name, node.id, f)
        return {}
    comp, sid, disk = last[-1].strip().split("|")
    f.update({"marker": {"computer": comp, "sid": sid, "disk": disk}, "verified": False})
    _flow_save(lab.name, node.id, f)
    return f["marker"]


def check(lab, node, channel=None) -> dict:
    ch = channel or _guest(lab, node)
    try:
        r = ch.run(CHECK_PS, shell="powershell", timeout=120)
    finally:
        if channel is None:
            ch.close()
    res = parse_check(r.out)
    f = _flow_load(lab.name, node.id)
    f["last_check"] = res
    f["verified"] = res["passed"]
    _flow_save(lab.name, node.id, f)
    return res


# ----------------------------------------------------------------- desktop actions
def _server(lab, node_id: str):
    node = lab.nodes.get(naming.resolve(lab, node_id))
    if node is None or node.kind != WINDOWS_SERVER:
        raise BackupError(f"{node_id or 'that machine'} is not a Windows server in {lab.name}")
    return node


def act(dash, action: str, params: dict) -> dict:
    try:
        return _act(dash, action, params)
    except (BackupError, KeyError, ValueError) as exc:
        return {"ok": False, "message": str(exc).strip("'")}


def _act(dash, action: str, params: dict) -> dict:
    from . import mediashelf
    lab = dash.lab
    node = _server(lab, str(params.get("node") or ""))
    who = naming.display(lab, node.id)
    if action == "wsb-state":
        sets, ready = None, None   # None: not asked (the NAS is off, or not looked at)
        nas = nas_of(lab)
        if params.get("nas") and nas is not None and state.is_running(lab.name, nas.id):
            try:
                out = nas_listing(lab)
                sets, ready = parse_sets(out), bool(parse_share(out))
            except BackupError:
                sets = None
        return {"ok": True, **flow(lab, node, sets), "has_nas": nas is not None, "share_ready": ready}
    if action == "wsb-look":
        m = look(lab, node)
        return ({"ok": True, "message": f"the marker on {who}: machine SID {m['sid']}, system disk {m['disk'] or '?'}"}
                if m else {"ok": False, "message": f"no marker on {who} yet"})
    if action == "wsb-check":
        r = check(lab, node)
        if r["passed"]:
            return {"ok": True, "message": f"{who} is the same server, restored from its backup onto a new disk", **r}
        why = ("the marker is not there: the image restored predates it, or it is a new install"
               if r["marker"] != "ok" else "the machine SID changed: this is a reinstall, not a restore"
               if r["sid"] != "same" else "the system disk is the same drive: it was never replaced"
               if r["disk"] != "new" else "the backup's own log is empty since the marker")
        return {"ok": False, "message": f"not yet: {why}", **r}
    if action == "wsb-nas":
        sets = [s for s in nas_sets(lab, wait=True) if s["computer"].upper() == naming.hostname_of(node).upper()]
        return {"ok": True, "sets": sets, "message": (f"{len(sets)} backup(s) of {who} on the NAS, the latest "
                f"{sets[-1]['set']} ({sets[-1]['mb']} MB)" if sets else f"no backup of {who} on the NAS yet")}
    if action == "wsb-reset":
        from . import sysdisk
        _flow_save(lab.name, node.id, {"gen0": sysdisk.generation(paths.lab_dir(lab.name) / node.id)})
        return {"ok": True, "message": f"the recovery drill on {who} starts again"}
    raise BackupError(f"unknown action {action}")


# ----------------------------------------------------------------- guest faults
# The faults find the share where OpenMediaVault put it; with no Backups
# share built yet there is nothing to break (apply fails and says so).
_SHARE = '"$d"'
_FIND = f"d={SHARE_DIR}; [ -n \"$d\" ] || {{ echo 'the NAS has no {BACKUP_SHARE} share yet' >&2; exit 1; }}; "
_JUNK = '"$d/old-exports"'
_FREE = "$(df -Pk \"$d\" | awk 'NR==2 {print $4}')"
_SECTION = f"/^\\[{BACKUP_SHARE}\\]/,/^\\[/"
# The share's read-only switch in OpenMediaVault's database (what its web UI
# sets: Services > SMB/CIFS > Shares, Read only), then Samba deployed again
# from it, as the web UI's Apply does. Falls back to the deployed file alone.
_OMV_READONLY = (
    "import json, subprocess, sys\n"
    "on = sys.argv[1] == '1'\n"
    "rd = lambda k: json.loads(subprocess.run(['omv-confdbadm', 'read', k], capture_output=True, text=True, check=True).stdout)\n"
    f"sf = [f['uuid'] for f in rd('conf.system.sharedfolder') if f.get('name', '').lower() == '{BACKUP_SHARE.lower()}']\n"
    "hit = 0\n"
    "for sh in rd('conf.service.smb.share'):\n"
    "    if sh.get('sharedfolderref') in sf:\n"
    "        sh['readonly'] = on\n"
    "        subprocess.run(['omv-confdbadm', 'update', 'conf.service.smb.share', json.dumps(sh)], check=True)\n"
    "        hit = 1\n"
    "sys.exit(0 if hit else 1)\n"
)


def _readonly_sh(on: bool) -> str:
    import shlex
    want, was = ("yes", "no") if on else ("no", "yes")
    return (f"{{ python3 -c {shlex.quote(_OMV_READONLY)} {1 if on else 0} && omv-salt deploy run samba >/dev/null 2>&1; }} || "
            f"{{ sed -i '{_SECTION} s/read only = {was}/read only = {want}/' {omv.SMB_CONF} && "
            "(smbcontrol smbd reload-config 2>/dev/null || pkill -HUP smbd); }")


def _faults():
    from .guestfaults import LINUX, GuestFault
    return [
        GuestFault(
            id="nas-backups-full",
            roles=("nas",),
            images=(omv.IMAGE,),
            title="The nightly backup fails: the NAS is full",
            os=LINUX,
            shell="sh",
            teaches="reading a failed backup from the server's side (Get-WBJob, the Backup event log), free space "
                    "on a network target, and cleaning a share up over SMB",
            symptom="last night's Windows Server Backup to \\\\<nas>\\Backups failed; Get-WBSummary shows the last "
                    "backup result as an error and the Backup log has event 5 or 517 ('not enough disk space')",
            # The junk is owned like the share's folder, so the backup's own
            # account can delete it over SMB.
            apply=(_FIND + f"mkdir -p {_JUNK} && f={_FREE} && n=$((f / 1024 - 150)) && [ $n -gt 0 ] && "
                   f"(fallocate -l ${{n}}M {_JUNK}/crm-export-2019.bak 2>/dev/null || "
                   f"dd if=/dev/zero of={_JUNK}/crm-export-2019.bak bs=1M count=$n 2>/dev/null); "
                   f"chown -R --reference={_SHARE} {_JUNK}; chmod -R g+rwX {_JUNK}; sync"),
            clear=f"d={SHARE_DIR}; [ -n \"$d\" ] && rm -rf {_JUNK}; true",
            hints=(
                "Start on the server. Get-WBJob -Previous 1 and Get-WBSummary say how the last backup ended; "
                "Get-WinEvent -LogName Microsoft-Windows-Backup -MaxEvents 10 | Format-List Id, Message gives the "
                "reason in words. A backup that ran every night and stopped is rarely the server's fault: look at "
                "the target.",
                "How full is the target? From the server: dir \\\\<nas>\\Backups (the last line is the free space), "
                f"or map it (net use B: \\\\<nas>\\Backups /user:<nas>\\{NAS_USER}) and Get-PSDrive B. A few hundred MB "
                "free on a NAS that holds full-server images is the cause. Something that is not a backup "
                "is taking the space.",
                "In \\\\<nas>\\Backups there is an old-exports folder with a multi-GB file nobody needs (in "
                "production, ask whose it is first). Delete it from the server over SMB (Remove-Item -Recurse "
                "B:\\old-exports), then run the backup again: wbadmin start backup ... or Start-WBBackup -Policy "
                "(Get-WBPolicy). Keep backups and other data on separate shares, with a quota on the other one.",
            ),
            verify=(f"d={SHARE_DIR}; [ -n \"$d\" ] || {{ echo False; exit 0; }}; "
                    f"[ -d {_JUNK} ] && echo False || {{ [ {_FREE} -gt 4194304 ] && echo True || echo False; }}"),
        ),
        GuestFault(
            id="nas-backups-read-only",
            roles=("nas",),
            images=(omv.IMAGE,),
            title="The backup to the NAS is denied",
            os=LINUX,
            shell="sh",
            teaches="share permissions against folder permissions, what 'Access is denied' (0x80070005) means "
                    "from a backup job, and fixing a share on the device that serves it",
            symptom="Windows Server Backup to \\\\<nas>\\Backups fails with 'Access is denied'; the server opens "
                    "the share and lists its files, but cannot create anything in it",
            apply=_FIND + _readonly_sh(True),
            clear=_readonly_sh(False),
            hints=(
                "Reading works and writing does not, as the same user: that is a permission, not a password or "
                "the network. Prove it from the server: New-Item \\\\<nas>\\Backups\\test.txt fails with "
                "'Access to the path is denied' while Get-ChildItem \\\\<nas>\\Backups works.",
                "A share has two locks: the share's own setting and the folder's permissions under it. On a "
                "Windows file server that is Get-SmbShareAccess and Get-Acl; on this NAS it is the share's "
                "settings in OpenMediaVault. Sign in to its web UI from a lab PC's browser (admin, the lab "
                "password) and open Services > SMB/CIFS > Shares: the Backups share has Read only ticked. Its "
                "console says the same: testparm -s --section-name=Backups shows read only = Yes.",
                "Make the share writable again where the NAS keeps it: in the web UI, edit the Backups share, "
                "untick Read only, Save, then Apply the pending change (the yellow bar). OpenMediaVault writes "
                "Samba's configuration again from its own database, so an edit of smb.conf by hand would be "
                "undone at the next Apply. Check the folder's permissions too (Storage > Shared Folders, "
                "Permissions: svc-backup Read/Write). Then run the backup again.",
            ),
            verify=(f"grep -qi '^[[:space:]]*\\[{BACKUP_SHARE}\\]' {omv.SMB_CONF} || {{ echo False; exit 0; }}; "
                    f"sed -n '{_SECTION}p' {omv.SMB_CONF} | grep -qi 'read only *= *yes' "
                    "&& echo False || echo True"),
        ),
    ]


FAULT_IDS = ("nas-backups-full", "nas-backups-read-only")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
