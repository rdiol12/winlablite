"""Automation at scale inside the lab: Ansible pushing configuration to many
machines from a control node, PowerShell remoting fan-out and a DSC push
configuration from a Windows admin box, configuration drift, and the drills
that break each of them.

The automation lab (content/labs/automation.toml) starts empty. The student
builds every part inside the machines, lesson by lesson (ansible-* and
powershell-dsc-push in the operations module):

  ctl01  the Ansible control node on Ubuntu: the 'ansible' pack (Ubuntu's
         ansible package, which is the full community bundle and so carries
         the ansible.windows, community.windows and microsoft.ad collections;
         python3-winrm, python3-requests-kerberos and krb5-user for the
         Windows servers). An inventory, SSH keys, ad-hoc commands,
         playbooks with templates and handlers, roles, check mode. It also
         serves the 'baseline' pack (nginx and chrony) as the lab's own apt
         repository over HTTP, which the playbook points the managed Ubuntu
         servers at: they never get a stick of their own.
  lnx01-03  three managed Ubuntu servers (512 MB each).
  srv01, srv02  two managed Windows Server Core machines, reached by
         Ansible over WinRM with Kerberos (HTTPS with a certificate from a
         lab CA is the optional variant), and by DSC from adm01.
  adm01  the Windows admin box: Invoke-Command fan-out, persistent sessions,
         jobs; DSC configurations and an LCM meta-configuration the student
         writes, compiles to MOF files and pushes to srv01 and srv02.

Both packs come from the Ubuntu archive onto this PC (winlab/debpacks.py,
`winlab automation fetch`, or Setup, which lists the packs a lab's machines
install by hand). The DSC lessons use the in-box PSDesiredStateConfiguration
resources (Registry, Service, File) and need nothing else. The optional DSC
modules step uses NetworkingDsc and ComputerManagementDsc from the PowerShell
Gallery: the same pinned, MIT-licensed modules winlab/psmodules.py already
fetches onto this PC at bootstrap, written onto a "DSC modules" stick from
the media shelf, which the student copies into the module path of adm01 and
of every target (push mode needs the module on the target, not only where the
configuration is compiled).

winlab's own DSC engine (winlab/dsc.py, which builds the role-based labs)
never touches these machines, and nothing is installed or configured for the
student: every inventory, playbook, role and configuration is theirs.

What is not here, and why: Ansible Galaxy downloads (ansible-galaxy
collection install) are not possible in a sealed lab, and not needed: every
collection the lessons use is in Ubuntu's ansible package. A DSC pull server
(the DSC-Service feature) is deprecated by Microsoft and Azure Automation
State Configuration is retired and needs the internet; the lessons explain
the pull model and an SMB pull share, and build push. AWX / Ansible
Automation Platform need container images from the internet and several GB
of memory, so they are left out. The lab never reaches the internet, not even
optionally: everything above is fetched on this PC and carried in on sticks.
"""

from __future__ import annotations

import json

from . import debpacks, paths

PACKS = ("ansible", "baseline")
# Where the lessons build the Ansible project on ctl01, as the cloud image's
# administrator: the drills and the exercises read it there.
PROJECT = "/home/ubuntu/automation"
DSC_MODULES = ("NetworkingDsc", "ComputerManagementDsc")
DOWNLOAD_ID = "dscmodules"   # node vars downloads = ["dscmodules"]
JOB = "dscmodules-fetch"
STEP_LABEL = "Fetch the DSC resource modules (PowerShell Gallery)"
STICK_LABEL = "DSCMODS"
STICK_TITLE = "DSC modules (NetworkingDsc, ComputerManagementDsc)"
SIZE_TEXT = "a few MB"


class AutomationError(Exception):
    pass


# ----------------------------------------------------------- the packs
def status() -> list[dict]:
    return [debpacks.status(p) for p in PACKS]


def fetch(progress=None, refresh: bool = False, get=None, download=None, modules=None) -> list[dict]:
    """Fetches both packs from the Ubuntu archive (the Ubuntu image first),
    each .deb against the SHA-256 the archive's index gives, then the DSC
    modules from the PowerShell Gallery if this PC does not have them yet."""
    say = progress or (lambda _m: None)
    extra = {k: v for k, v in (("get", get), ("download", download)) if v is not None}
    out = []
    for p in PACKS:
        try:
            out.append(debpacks.fetch(p, progress=say, refresh=refresh, **extra))
        except debpacks.PackError as exc:
            raise AutomationError(f"{p}: {exc}") from exc
    if not modules_ready():
        say("DSC modules: fetching from the PowerShell Gallery")
        fetch_modules(modules)
    return out


# ------------------------------------------------------- the DSC modules
def _modules():
    from . import psmodules
    have = {m.name: m for m in psmodules.MODULES}
    return [have[n] for n in DSC_MODULES]


def modules_ready() -> bool:
    from . import psmodules
    return all((psmodules.modules_dir() / m.name / m.version).is_dir() for m in _modules())


def fetch_modules(run=None) -> None:
    """The DSC modules through psmodules.fetch (the bootstrap's own step):
    pinned versions, from the PowerShell Gallery, onto this PC."""
    from . import psmodules
    from .bootstrap import BootstrapError
    try:
        (run or psmodules.fetch)()
    except (BootstrapError, psmodules.ModuleError) as exc:
        raise AutomationError(f"the DSC modules: {exc}") from exc


def readme() -> str:
    mods = _modules()
    lines = ["DSC resource modules for the automation lab, fetched on the host PC from the PowerShell",
             "Gallery (https://www.powershellgallery.com), MIT-licensed, pinned versions:", ""]
    lines += [f"  {m.name} {m.version}: {m.purpose}" for m in mods]
    lines += ["",
              "Push mode needs a module on every machine that applies the configuration, not only on",
              "the machine that compiles it. Copy each module folder, as it is, into",
              "C:\\Program Files\\WindowsPowerShell\\Modules on adm01 and on each target:",
              "",
              "  Copy-Item -Path E:\\Modules\\* -Destination 'C:\\Program Files\\WindowsPowerShell\\Modules' -Recurse",
              "  $s = New-PSSession -ComputerName srv01, srv02",
              "  Copy-Item -Path E:\\Modules\\* -Destination 'C:\\Program Files\\WindowsPowerShell\\Modules' "
              "-Recurse -ToSession $s[0]",
              "  (and the same for $s[1]), then Get-DscResource -Module NetworkingDsc lists its resources.",
              "",
              "In the configuration: Import-DscResource -ModuleName NetworkingDsc -ModuleVersion "
              + next(m.version for m in mods if m.name == "NetworkingDsc"),
              "E: is the stick's drive letter on adm01; Get-Volume shows the one Windows gave it."]
    return "\r\n".join(lines) + "\r\n"


def stick_files() -> dict[str, bytes]:
    from . import psmodules
    if not modules_ready():
        raise AutomationError("the DSC modules are not on this PC yet: winlab automation fetch "
                              "(or winlab dsc fetch, or Setup)")
    out: dict[str, bytes] = {}
    for m in _modules():
        root = psmodules.modules_dir() / m.name / m.version
        for f in sorted(root.rglob("*")):
            if f.is_file():
                out[f"Modules/{m.name}/{m.version}/{f.relative_to(root).as_posix()}"] = f.read_bytes()
    out["README.txt"] = readme().encode("utf-8")
    return out


def to_stick(lab_name: str) -> dict:
    """A new DSC modules stick on the lab's media shelf."""
    from . import media, mediashelf
    files = stick_files()
    sid = mediashelf._new_id(lab_name, "dsc-modules")
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise AutomationError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": STICK_TITLE}) + "\n", encoding="utf-8")
    return {"id": sid, "title": STICK_TITLE, "files": len(files),
            "mb": sum(len(b) for b in files.values()) >> 20}


def act(dash, action: str, params: dict) -> dict:
    """The workbench's automation action: wb-auto-stick writes the DSC
    modules stick onto the shelf."""
    if action == "wb-auto-stick":
        try:
            r = to_stick(dash.lab.name)
        except AutomationError as exc:
            return {"ok": False, "message": str(exc), "fetch": not modules_ready()}
        return {"ok": True, "message": f"{r['title']} is on the shelf: drag it onto adm01", "stick": r["id"]}
    return {"ok": False, "message": f"unknown automation action {action!r}"}


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """The Setup step for the DSC modules when a machine in the lab names
    them (node vars downloads = ["dscmodules"]); the packs come through
    mail.setup_steps, which lists every hand-installed pack."""
    have = set(have or ())
    who = [n.id for n in lab.node_list() if DOWNLOAD_ID in (n.vars.get("downloads") or [])]
    if not who or DOWNLOAD_ID in have:
        return []
    return [{"id": DOWNLOAD_ID, "label": STEP_LABEL, "done": modules_ready(), "blocked": False,
             "hint": f"{', '.join(who)} copies NetworkingDsc and ComputerManagementDsc from the DSC modules "
                     f"stick for the optional DSC step (MIT, pinned versions), {SIZE_TEXT} once; "
                     f"winlab bootstrap fetches them too",
             "link": "https://www.powershellgallery.com/packages/NetworkingDsc", "job": JOB}]


def summary() -> dict:
    return {"id": DOWNLOAD_ID, "title": STICK_TITLE, "ready": modules_ready(),
            "modules": [{"name": m.name, "version": m.version} for m in _modules()],
            "packs": status()}


def render_status() -> str:
    lines = ["automation lab: what this PC fetches for it", ""]
    for st in status():
        state = (f"ready ({st['count']} packages, {st['size_mb']} MB, fetched {st['fetched']})"
                 if st["ready"] else f"not fetched (about {st['typical_mb']} MB)")
        lines += [f"  pack {st['id']:<9} {state}", f"  {'':<14} {st['title']}"]
    mods = ", ".join(f"{m.name} {m.version}" for m in _modules())
    lines += [f"  DSC modules    {'ready' if modules_ready() else 'not fetched'} ({mods}; PowerShell Gallery, MIT)",
              f"  {'':<14} store: {paths.RUNTIME / 'psmodules'}", ""]
    if not all(st["ready"] for st in status()) or not modules_ready():
        lines.append("  then:  winlab automation fetch   (or winlab packs fetch ansible / baseline)")
    lines.append("  onto a stick: the media shelf's DSC modules stick button, or winlab automation stick <lab>")
    lines.append("  Ansible's Windows collections come inside Ubuntu's ansible package: nothing from Galaxy.")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------- the lab
def _nodes(lab, part: str) -> list:
    return [n for n in lab.node_list() if str(n.vars.get("automation") or "") == part]


def _fqdn(lab, n) -> str:
    name = (n.hostname or n.id).lower()
    return f"{name}.{lab.domain}" if lab.domain else name


def fault_params(lab) -> dict[str, str]:
    """The drills' parameters (guestfaults.lab_params): the control node,
    the managed Ubuntu server whose host key changes, the DSC target."""
    ctl = _nodes(lab, "control")
    if not ctl:
        return {}   # not an automation lab: guestfaults.DEFAULTS stand
    lin = _nodes(lab, "linux-target")
    win = _nodes(lab, "windows-target")
    t = lin[1] if len(lin) > 1 else (lin[0] if lin else None)
    out = {"anscontrol": _fqdn(lab, ctl[0])}
    if t is not None:
        nic = t.primary_nic
        out.update({"anstarget": (t.hostname or t.id).lower(), "anstargetfqdn": _fqdn(lab, t),
                    "anstargetip": nic.ip if nic is not None and nic.ip else ""})
    if win:
        out["dscnode"] = (win[0].hostname or win[0].id).lower()
    return out


# ------------------------------------------------------------- the drills
_KH = "/home/ubuntu/.ssh/known_hosts"
_NO_HKC = ("grep -qsiE '^[[:space:]]*host_key_checking[[:space:]]*=[[:space:]]*(false|no|0)' "
           f"{PROJECT}/ansible.cfg /home/ubuntu/.ansible.cfg /etc/ansible/ansible.cfg && ok=0; "
           "grep -qsiE '^[[:space:]]*(export[[:space:]]+)?ANSIBLE_HOST_KEY_CHECKING=(false|no|0)' "
           "/home/ubuntu/.bashrc /home/ubuntu/.profile /etc/environment && ok=0; "
           "grep -rqsiE '^[[:space:]]*StrictHostKeyChecking[[:space:]=]+no' /home/ubuntu/.ssh/config "
           "/etc/ssh/ssh_config /etc/ssh/ssh_config.d && ok=0; ")
_LCM = ("[DSCLocalConfigurationManager()] Configuration WinlabLcm {{ Node localhost {{ Settings {{ "
        "RefreshMode = 'Push'; ConfigurationMode = '{mode}'; ConfigurationModeFrequencyMins = 15 }} }} }}\n"
        "$d = Join-Path $env:TEMP 'winlab-lcm'\n"
        "WinlabLcm -OutputPath $d | Out-Null\n"
        "Set-DscLocalConfigurationManager -Path $d -Force\n"
        "Remove-Item -Path $d -Recurse -Force\n")
_BASE_KEY = "HKLM:\\SOFTWARE\\Corp\\Baseline"


def _faults():
    from .guestfaults import LINUX, WINDOWS, GuestFault
    return [
        GuestFault(
            id="winrm-listener-missing",
            title="Ansible and Invoke-Command cannot reach a Windows server: no WinRM listener, no firewall rule",
            os=WINDOWS,
            teaches="what WinRM needs to answer (the service, a listener, a firewall rule), Test-WSMan, "
                    "telling refused from filtered, and winrm enumerate",
            symptom="from ctl01, ansible windows -m ansible.windows.win_ping says this server is UNREACHABLE "
                    "(the connection times out), the other Windows server answers SUCCESS; from adm01, "
                    "Invoke-Command to it fails with 'WinRM cannot complete the operation'; the WinRM service "
                    "is running",
            apply=("$http = @(Get-ChildItem -Path WSMan:\\localhost\\Listener | Where-Object { $_.Keys -contains "
                   "'Transport=HTTP' })\n"
                   "if ($http.Count -eq 0) { 'this machine has no WinRM HTTP listener to remove'; exit 1 }\n"
                   "$http | Remove-Item -Recurse -Force\n"
                   "Get-NetFirewallRule | Where-Object { $_.Name -like 'WINRM-HTTP-In-TCP*' } | Disable-NetFirewallRule\n"
                   "'broken'"),
            clear=("Set-WSManQuickConfig -Force -SkipNetworkProfileCheck | Out-Null\n"
                   "Get-NetFirewallRule | Where-Object { $_.Name -like 'WINRM-HTTP-In-TCP*' } | Enable-NetFirewallRule\n"
                   "'ok'"),
            hints=(
                "Ask from outside first. On adm01: Test-WSMan with this server's name fails, and Test-NetConnection "
                "with -Port 5985 waits and then says TcpTestSucceeded False. A long wait means something drops "
                "the packets; an instant refusal means the machine answered and nothing listens. Here it is both.",
                "On the server (sconfig, option 15 for PowerShell): Get-Service WinRM is Running, but "
                "Get-ChildItem WSMan:\\localhost\\Listener (or winrm enumerate winrm/config/listener) lists no "
                "listener, and Get-NetFirewallRule -Name WINRM-HTTP-In-TCP shows Enabled False. A running "
                "service with no listener answers nobody.",
                "Enable-PSRemoting -Force puts back the HTTP listener on 5985 and enables the firewall rule "
                "(winrm quickconfig does the same). Or by hand: New-Item -Path WSMan:\\localhost\\Listener "
                "-Transport HTTP -Address * -Force, then Enable-NetFirewallRule -Name WINRM-HTTP-In-TCP. "
                "Test-WSMan from adm01 answers, and win_ping from ctl01 says SUCCESS.",
            ),
            verify=("$l = @(Get-ChildItem -Path WSMan:\\localhost\\Listener | Where-Object { $_.Keys -match "
                    "'^Transport=HTTPS?$' }).Count -gt 0\n"
                    "$p = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | "
                    "Get-NetFirewallPortFilter | Where-Object { @($_.LocalPort) -contains '5985' -or "
                    "@($_.LocalPort) -contains '5986' }).Count -gt 0\n"
                    "($l -and $p)"),
        ),
        GuestFault(
            id="ssh-host-key-changed",
            images=("ubuntu",),
            title="Ansible refuses one Linux server: REMOTE HOST IDENTIFICATION HAS CHANGED",
            os=LINUX,
            teaches="SSH host keys and known_hosts, checking a fingerprint out of band, ssh-keygen -R and "
                    "-F, and why host key checking stays on",
            symptom="on ctl01, ansible linux -m ping answers SUCCESS for two servers and UNREACHABLE for "
                    "{anstarget}, with 'Host key verification failed'; ssh {anstargetfqdn} prints a warning that "
                    "someone could be eavesdropping",
            apply=(f"kh={_KH}; [ -f \"$kh\" ] || {{ echo 'ctl01 has never connected over SSH: build the inventory "
                   "first (lesson ansible-inventory-adhoc)'; exit 1; }; names=''; "
                   "for n in {anstarget} {anstargetfqdn} {anstargetip}; do ssh-keygen -F \"$n\" -f \"$kh\" "
                   ">/dev/null 2>&1 && names=\"$names $n\"; done; [ -n \"$names\" ] || { echo 'ctl01 does not "
                   "know {anstarget} yet: connect to it once first'; exit 1; }; "
                   "[ -e /root/.winlab-known_hosts ] || cp -p \"$kh\" /root/.winlab-known_hosts; "
                   "echo \"$names\" > /root/.winlab-sshkey-names; t=$(mktemp -d); "
                   "ssh-keygen -q -t ed25519 -N '' -C '' -f \"$t/k\" >/dev/null; key=$(cut -d' ' -f1,2 \"$t/k.pub\"); "
                   "rm -rf \"$t\"; for n in $names; do ssh-keygen -R \"$n\" -f \"$kh\" >/dev/null 2>&1; "
                   "echo \"$n $key\" >> \"$kh\"; done; chown ubuntu:ubuntu \"$kh\"; rm -f \"$kh.old\"; echo broken"),
            clear=(f"kh={_KH}; if [ -f /root/.winlab-known_hosts ]; then mv /root/.winlab-known_hosts \"$kh\"; "
                   "chown ubuntu:ubuntu \"$kh\"; fi; rm -f /root/.winlab-sshkey-names; echo ok"),
            shell="sh",
            hints=(
                "Read the whole warning: it names the file and the line (Offending ED25519 key in "
                "/home/ubuntu/.ssh/known_hosts:3) and the fingerprint the server offers now. ssh-keygen -F "
                "{anstargetfqdn} shows what ctl01 remembers for that name.",
                "Before you trust the new key, check it where nobody can be in the middle: on {anstarget}'s own "
                "console, ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub prints its real fingerprint. Compare "
                "it with the one in the warning; if they differ from what ctl01 remembers but match each other, "
                "the server was rebuilt or ctl01's entry is wrong, not an attack.",
                "Remove only the stale entries, for every name ctl01 uses for that server: ssh-keygen -R "
                "{anstargetfqdn}, the short name and its address too. Then ssh {anstargetfqdn} once, compare the "
                "fingerprint and answer yes. Never fix this with host_key_checking = False or "
                "StrictHostKeyChecking no: that turns the check off for every server.",
            ),
            verify=(f"kh={_KH}; names=$(cat /root/.winlab-sshkey-names 2>/dev/null); [ -n \"$names\" ] || "
                    "names={anstargetfqdn}; ok=1; for n in $names; do runuser -u ubuntu -- ssh -o BatchMode=yes "
                    "-o StrictHostKeyChecking=yes -o ConnectTimeout=10 \"$n\" true </dev/null >/dev/null 2>&1 || "
                    "ok=0; done; " + _NO_HKC + "[ $ok = 1 ] && echo True || echo False"),
        ),
        GuestFault(
            id="ansible-group-typo",
            images=("ubuntu",),
            title="The playbook runs green and the Windows servers are never touched",
            os=LINUX,
            teaches="inventory groups and group_vars by name, ansible-inventory --graph and --host, and "
                    "reading 'no hosts matched' instead of trusting a green recap",
            symptom="ansible-playbook site.yml on ctl01 ends with failed=0, but the Windows play says "
                    "'skipping: no hosts matched' and PLAY RECAP lists only the Linux servers; ansible windows "
                    "-m ansible.windows.win_ping warns that the pattern matches nothing",
            apply=(f"f={PROJECT}/inventory.ini; [ -f \"$f\" ] || {{ echo \"no $f yet: build the inventory first "
                   "(lesson ansible-inventory-adhoc)\"; exit 1; }; grep -q '^\\[windows\\]' \"$f\" || { echo 'the "
                   "inventory has no [windows] group yet: lesson ansible-windows-winrm'; exit 1; }; "
                   "[ -e /root/.winlab-inventory.ini ] || cp -p \"$f\" /root/.winlab-inventory.ini; "
                   "sed -i 's/^\\[windows\\]/[window]/' \"$f\"; echo broken"),
            clear=(f"f={PROJECT}/inventory.ini; [ -f /root/.winlab-inventory.ini ] && mv /root/.winlab-inventory.ini "
                   "\"$f\" && chown ubuntu:ubuntu \"$f\"; echo ok"),
            shell="sh",
            hints=(
                "A green recap only says nothing failed. Read the play headers: the Windows play matched no "
                "hosts. Ask the inventory what it holds: ansible-inventory --graph, in the project folder.",
                "The graph shows the two Windows servers under a group called window, not windows. The plays "
                "say hosts: windows, and group_vars/windows.yml (the WinRM and Kerberos settings) applies to a "
                "group of that exact name; ansible-inventory --host srv01.corp.lab shows none of them now.",
                "Put the group header in inventory.ini back to [windows]. ansible-inventory --graph windows "
                "lists both servers, ansible-inventory --host shows ansible_connection winrm, and ansible windows "
                "-m ansible.windows.win_ping answers SUCCESS (after kinit if your ticket expired).",
            ),
            verify=("runuser -l ubuntu -c 'cd " + PROJECT + " && ansible-inventory --list 2>/dev/null' | python3 -c "
                    "'import json, sys\ntry:\n    d = json.load(sys.stdin)\nexcept ValueError:\n    print(False); "
                    "sys.exit()\nw = d.get(\"windows\", {}).get(\"hosts\", [])\nhv = d.get(\"_meta\", {})"
                    ".get(\"hostvars\", {})\nprint(len(w) >= 2 and all(hv.get(h, {}).get(\"ansible_connection\") "
                    "in (\"winrm\", \"psrp\") for h in w))'"),
        ),
        GuestFault(
            id="dsc-lcm-applyonly",
            title="Someone changed a setting DSC owns, and DSC leaves it changed",
            os=WINDOWS,
            teaches="the Local Configuration Manager's ConfigurationMode (ApplyOnly, ApplyAndMonitor, "
                    "ApplyAndAutoCorrect), meta-configurations, Test-DscConfiguration -Detailed and "
                    "Get-DscConfigurationStatus",
            symptom="the Owner value under HKLM:\\SOFTWARE\\Corp\\Baseline on {dscnode} says changed-by-hand; "
                    "hours later it still does, although the DSC configuration pushed from adm01 sets it to IT "
                    "and the LCM checks every 15 minutes",
            apply=("if (-not (Get-DscConfigurationStatus -ErrorAction SilentlyContinue)) { 'no DSC configuration "
                   "on this machine yet: push one first (lesson powershell-dsc-push)'; exit 1 }\n"
                   + _LCM.format(mode="ApplyOnly")
                   + f"if (Test-Path -Path '{_BASE_KEY}') {{ Set-ItemProperty -Path '{_BASE_KEY}' -Name Owner "
                   "-Value 'changed-by-hand' }\n'broken'"),
            clear=(_LCM.format(mode="ApplyAndAutoCorrect")
                   + "Start-DscConfiguration -UseExisting -Wait -Force -ErrorAction SilentlyContinue | Out-Null\n'ok'"),
            hints=(
                "Ask DSC whether the machine is where it should be: Test-DscConfiguration -Detailed on "
                "{dscnode} (or with -ComputerName from adm01) lists the Registry resource under "
                "ResourcesNotInDesiredState. So DSC knows; why does it not act?",
                "Get-DscLocalConfigurationManager shows ConfigurationMode ApplyOnly: the LCM applied the "
                "configuration once and never looks again. ApplyAndMonitor would only report the drift; "
                "ApplyAndAutoCorrect puts it right on every consistency check.",
                "Fix the meta-configuration, not the registry value: on adm01, set ConfigurationMode = "
                "'ApplyAndAutoCorrect' in your LCM configuration, compile it and Set-DscLocalConfigurationManager "
                "-Path to {dscnode}. Then Start-DscConfiguration -UseExisting -Wait -ComputerName {dscnode} (or "
                "wait for the next check): Test-DscConfiguration says True and Owner is IT again.",
            ),
            verify=("$m = (Get-DscLocalConfigurationManager).ConfigurationMode\n"
                    "$t = Test-DscConfiguration -ErrorAction SilentlyContinue\n"
                    "($m -eq 'ApplyAndAutoCorrect' -and $t -eq $true)"),
        ),
    ]


FAULT_IDS = ("winrm-listener-missing", "ssh-host-key-changed", "ansible-group-typo", "dsc-lcm-applyonly")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
