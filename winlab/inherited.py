"""The inherited company: a pre-built scenario, the one lab that is not empty.

Every other lab starts empty and the student builds it. Ron asked for one
clearly labelled exception: the job where you arrive at a company that has
run for years and the last admin has just left. The lab is
content/labs/inherited-company.toml. Its machines start as fresh Windows
like any lab; nothing happens until the student presses "Hand over the
company" (the Inherited company window, or `winlab inherited
inherited-company handover`). Then, over the serial agent and inside the guests:

1. the domain is built from the lab's roles (the model answer every lab has:
   the old DC promoted as the forest root, the newer one as a replica, the
   file server and the admin PC joined);
2. the predecessor's company is laid on top, by the scripts in this module:
   a few hundred staff generated like winlab/people.py does (departments,
   managers, titles), leavers disabled but never removed, accounts nobody
   has used for years, service accounts whose passwords never expire,
   nested, circular and empty groups, a bloated Domain Admins, overlapping
   Group Policy (some unlinked, two in conflict, one broken), DNS records
   for servers long gone, shares open to everyone on a disk that is full,
   scheduled tasks nobody wrote down, certificates about to expire, every
   FSMO role still on the old DC;
3. the handover notes from "the previous admin" go on the admin PC's
   desktop: partly right, partly wrong, as handover notes are.

Every account the mess makes gets a random password generated inside the
guest (dayops.SECRET); nothing secret is in the repository or in the notes.
It is all defensive housekeeping: no attack tooling, nothing that reaches
outside the lab.

What was planted stays on the host, rebuilt from the lab's seed, and is
handed to a check only while it runs (exercises.with_host_values), so the
"First 30 days in a company you inherited" exercises grade the end state
against it (audit, document, clean up, fix) without an answer key inside the
guests. The handover runs in steps
and remembers which are done (var/labs/<lab>/company.json), so pressing it
again after a failure carries on where it stopped, and every script is safe
to run twice.
"""

from __future__ import annotations

import base64
import json
import random
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import paths
from .dayops import SECRET

COMPANY = "Harbourline"
LAB = "inherited-company"
STAFF = 300
BATCH = 50
KEY = "HKLM:\\SOFTWARE\\winlab\\company"
DOC_NAME = "HANDOVER - from Morgan.txt"
# The predecessor: an account that is still enabled, still a Domain Admin.
PREV = {"sam": "mhale", "first": "Morgan", "last": "Hale", "title": "IT manager"}
CONTRACTOR = {"sam": "ext-jvoss", "first": "Jo", "last": "Voss",
              "description": "Contractor, Exchange migration (project ended)"}

# (department, OU and group tag, titles: the last one is the department's manager, relative size)
DEPARTMENTS = (
    ("IT", "IT", ("Helpdesk technician", "Systems administrator", "IT manager"), 8),
    ("Finance", "Finance", ("Accountant", "Payroll officer", "Credit controller", "Finance manager"), 26),
    ("Sales", "Sales", ("Sales rep", "Account manager", "Sales manager"), 46),
    ("Customer Service", "CustomerService", ("Service agent", "Team leader", "Customer service manager"), 50),
    ("Warehouse", "Warehouse", ("Warehouse operative", "Forklift driver", "Shift lead", "Warehouse manager"), 72),
    ("Operations", "Operations", ("Buyer", "Planner", "Operations manager"), 34),
    ("HR", "HR", ("HR officer", "Recruiter", "HR manager"), 12),
    ("Marketing", "Marketing", ("Marketing executive", "Designer", "Marketing manager"), 16),
    ("Legal", "Legal", ("Paralegal", "Legal counsel"), 6),
)

FIRST = ("Alex", "Amara", "Ana", "Chloe", "Daniel", "Diego", "Farid", "Grace", "Hannah", "Jamal",
         "Jonas", "Kofi", "Lars", "Lena", "Marco", "Maya", "Mei", "Nadia", "Omar", "Priya",
         "Rosa", "Sam", "Tomas", "Yuki", "Zara", "Ivan", "Leila", "Noah", "Elif", "Ben",
         "Aisha", "Bruno", "Carla", "Dmitri", "Emma", "Felix", "Gita", "Hugo", "Ines", "Jack",
         "Kira", "Liam", "Mila", "Nico", "Olga", "Pablo", "Ravi", "Sofia", "Theo", "Uma",
         "Victor", "Wen", "Yara", "Zeynep", "Adam", "Beatriz", "Cyril", "Dana", "Erik", "Fatima")
LAST = ("Abara", "Berg", "Costa", "Dubois", "Evans", "Fischer", "Garcia", "Haddad", "Ito", "Jensen",
        "Kowalski", "Lindqvist", "Mensah", "Novak", "Okafor", "Patel", "Quinn", "Rossi", "Silva",
        "Tanaka", "Ueda", "Varga", "Weber", "Xu", "Yilmaz", "Zimmer", "Moreau", "Nguyen", "Park", "Reyes",
        "Adler", "Bianchi", "Chen", "Dahl", "Ekstrom", "Fontaine", "Gallo", "Horvat", "Ivanova", "Kaur",
        "Larsen", "Mora", "Nilsen", "Ortiz", "Petrov", "Ramos", "Sato", "Torres", "Vidal", "Walsh",
        "Brennan", "Castillo", "Duarte", "Eriksen", "Ferreira", "Hughes", "Kim", "Lopez", "Murphy", "Santos")

# Service accounts: (account, description, still used by something here, privileged group or "", SPN)
SERVICE = (
    ("svc-backup", "Backup jobs", True, "Domain Admins", ""),
    ("svc-scan", "Scanner on the first floor: scan to \\\\fs01\\Scans", True, "", ""),
    ("svc-sql", "SQL Server service (sql01)", False, "Domain Admins", "MSSQLSvc/sql01.{dns}:1433"),
    ("svc-print", "Print server print02", False, "Print Operators", ""),
    ("svc-crm-legacy", "CRM (the old one)", False, "", "HTTP/crm.{dns}"),
    ("svc-ftp", "FTP upload for the old website", False, "", ""),
)
EMPTY_GROUPS = ("G-Project-Phoenix", "G-Temp-Access-2021", "DL-Board-RO", "G-Wifi-Guests",
                "G-Marketing-Interns", "SharePoint-Migration")
CIRCULAR = ("G-Ops-Leads", "G-Warehouse-Leads")
OLD_ADMIN_GROUPS = ("IT-Admins-Old", "Helpdesk")   # Helpdesk is nested in IT-Admins-Old, which is in Domain Admins
STALE_COMPUTERS = (("WKS-0107", 412), ("WKS-0119", 233), ("WKS-0142", 618), ("LAP-0031", 301),
                   ("LAP-0044", 190), ("SQL01", 540), ("PRINT02", 702))
# Group Policy: (name, where it is linked: "" none, "workstations", "servers", "staff", "domain";
# link enabled, what it sets as (key, value name, type, value) rows, what is wrong with it)
SCREENSAVER = ("HKCU\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop", "ScreenSaveTimeOut")
GPOS = (
    ("Workstation Lockdown", "workstations", True,
     ((SCREENSAVER[0], SCREENSAVER[1], "String", "900"), (SCREENSAVER[0], "ScreenSaveActive", "String", "1")),
     "conflict"),
    ("Workstation Lockdown v2", "workstations", True,
     ((SCREENSAVER[0], SCREENSAVER[1], "String", "300"),
      ("HKLM\\Software\\Policies\\Microsoft\\Windows\\Personalization", "NoLockScreen", "DWord", "1")),
     "conflict"),
    ("Drive Maps (OLD)", "", True,
     (("HKCU\\Software\\Harbourline\\Drives", "S", "String", "\\\\print02\\scans"),), "unlinked"),
    ("Printers 2019", "", True,
     (("HKCU\\Software\\Harbourline\\Printers", "Default", "String", "\\\\print02\\Floor1"),), "unlinked"),
    ("Test - Morgan", "domain", False,
     (("HKLM\\Software\\Policies\\Harbourline", "Test", "DWord", "1"),), "disabled-link"),
    ("Software Deployment", "staff", True,
     (("HKLM\\Software\\Policies\\Harbourline", "Deploy", "DWord", "1"),), "broken"),
    ("Server Hardening", "servers", True,
     (("HKLM\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services", "fDisableCdm", "DWord", "1"),),
     "all-settings-disabled"),
)
# DNS: records for machines that are gone (the last octet), and two that point the wrong way.
DNS_STALE = (("old-exch01", 31), ("print02", 32), ("sql01", 33), ("wsus01", 34), ("ftp", 35))
DNS_WRONG_FILES = 21          # "files" should be fs01 (.20)
DNS_DEAD_CNAME = ("intranet", "web-old")
# Shares on the file server: (name, folder, share access given to Everyone, NTFS grant for broad groups)
SHARES = (
    ("Public", "Public", "Full", "Everyone:(OI)(CI)F"),
    ("Finance", "Finance", "Full", "Authenticated Users:(OI)(CI)M"),
    ("HR$", "HR", "Read", "Domain Users:(OI)(CI)RX"),
    ("Scans", "Scans", "Full", "Everyone:(OI)(CI)M"),
    ("OldProjects", "OldProjects", "Change", "Everyone:(OI)(CI)M"),
    ("Software", "Software", "Full", "Everyone:(OI)(CI)F"),
)
FINANCE_FILES = 30
FILL_TO_PCT = 96              # the data volume is left this full
FILL_CHUNK_MB = 512
# Scheduled tasks nobody wrote down: (node, name, what it runs, runs as, what is wrong)
TASKS = (
    ("fs01", "Nightly Copy", "robocopy.exe", "SYSTEM", "copies Finance to \\\\nas-old, which no longer exists"),
    ("fs01", "Cleanup Temp", "powershell.exe", "SYSTEM", "deletes old .tmp files on Public"),
    ("fs01", "Weekly Report", "powershell.exe", "svc-backup", "runs as a Domain Admin service account"),
    ("dc01", "Restart Spooler", "powershell.exe", "SYSTEM", "restarts the print spooler every night on a DC"),
    ("dc01", "AD Export", "powershell.exe", "SYSTEM", "exports every user to a folder everyone can read"),
    ("dc01", "Old Updater", "C:\\Tools\\update.bat", "SYSTEM", "runs a script that no longer exists"),
)
# Certificates: (node, friendly name, DNS name prefix, days left: negative is expired)
CERTS = (
    ("fs01", "Intranet TLS", "files", 11),
    ("fs01", "Old intranet", "intranet", -25),
    ("dc01", "Remote Desktop (dc01)", "dc01", 16),
)


@dataclass
class Plan:
    lab: object
    staff: list[dict]
    netbios: str
    subnet: str               # "10.44.0" from the file server's address
    fs_ip: str
    planted: dict = field(default_factory=dict)


# ------------------------------------------------------------- the staff
def _seed(lab_name: str) -> int:
    return zlib.crc32(("company/" + lab_name).encode("utf-8"))


def generate_staff(lab_name: str, count: int = STAFF, rng: random.Random | None = None) -> list[dict]:
    """The company's people, the same for the same lab: a managing director,
    then each department's manager, then everyone else, each with a unique
    full name, an account name like people.py's (first initial and surname,
    numbered on a clash), a title and a manager; and what became of them:
    active (signed in this fortnight), stale (left without anyone noticing:
    enabled, last sign-in months or years ago), leaver (disabled on the way
    out and never removed) or never (made for a starter who never started)."""
    rng = rng or random.Random(_seed(lab_name))
    pairs = [(f, l) for f in FIRST for l in LAST]
    rng.shuffle(pairs)
    taken = {PREV["sam"], CONTRACTOR["sam"], "administrator", "guest", "krbtgt"}
    taken |= {s[0] for s in SERVICE}
    names = iter(pairs)

    def person(dept: str, tag: str, title: str, manager: str, where: str = "dept") -> dict:
        first, last = next(names)
        base = (first[0] + last).lower()
        sam, n = base, 2
        while sam in taken:
            sam, n = f"{base}{n}", n + 1
        taken.add(sam)
        return {"sam": sam, "first": first, "last": last, "name": f"{first} {last}", "department": dept,
                "tag": tag, "title": title, "manager": manager, "state": "active", "days": rng.randint(0, 13),
                "where": where, "boss": False}

    total_weight = sum(d[3] for d in DEPARTMENTS)
    out = [person("Management", "Management", "Managing director", "")]
    out[0]["boss"] = True
    md = out[0]["sam"]
    heads = {}
    for dept, tag, titles, _w in DEPARTMENTS:
        head = person(dept, tag, titles[-1], md)
        head["boss"] = True
        heads[dept] = head["sam"]
        out.append(head)
    left = max(0, count - len(out))
    for dept, tag, titles, w in DEPARTMENTS:
        for _ in range(max(1, round(left * w / total_weight))):
            if len(out) >= count:
                break
            out.append(person(dept, tag, titles[rng.randrange(len(titles) - 1)] if len(titles) > 1 else titles[0],
                              heads[dept]))
    for p in out[1 + len(DEPARTMENTS):]:
        r = rng.random()
        if r < 0.08:
            p["state"], p["days"] = "leaver", rng.randint(60, 900)
            p["where"] = "old" if rng.random() < 0.5 else "dept"
        elif r < 0.14:
            p["state"], p["days"] = "stale", rng.randint(180, 900)
        elif r < 0.16:
            p["state"], p["days"] = "never", rng.randint(120, 500)
        elif r < 0.19:
            p["where"] = "users"   # an active account the predecessor left in the Users container
    return out


def to_people(staff: list[dict], domain: str) -> list[dict]:
    """The company as winlab/people.py's directory (helpdesk callers, the
    workday, the IT manager): the student first, then everyone still here."""
    from . import people
    out = [{"id": "admin", "first": "You", "last": "", "name": "You (the new admin)", "department": "IT",
            "title": "Systems administrator", "account": "administrator", "mail": f"administrator@{domain}",
            "ext": people.FIRST_EXT, "pc": "pc01", "manager": False, "admin": True}]
    ext = people.FIRST_EXT
    for p in staff:
        if p["state"] not in ("active",):
            continue
        ext += 1
        out.append({"id": p["sam"], "first": p["first"], "last": p["last"], "name": p["name"],
                    "department": p["department"], "title": p["title"], "account": p["sam"],
                    "mail": f"{p['sam']}@{domain}", "ext": ext, "pc": "",
                    "manager": bool(p["boss"]), "admin": False})
    # The IT manager the on-call page goes to: the IT department's head.
    for p in out:
        if p["department"] == "IT" and p["title"] == "IT manager":
            p["manager"] = True
    return out


def plan(lab) -> Plan:
    fs = lab.nodes.get("fs01")
    ip = (fs.primary_nic.ip if fs and fs.primary_nic and fs.primary_nic.ip else "10.44.0.20")
    p = Plan(lab=lab, staff=generate_staff(lab.name), netbios=lab.netbios or "HARBOUR",
             subnet=ip.rsplit(".", 1)[0], fs_ip=ip)
    p.planted = planted(p)
    return p


def planted(p: Plan) -> dict:
    """What the handover leaves behind, for the exercises to grade against."""
    s = p.staff
    by = lambda st: sorted(x["sam"] for x in s if x["state"] == st)
    it = [x for x in s if x["department"] == "IT" and x["state"] == "active" and not x["boss"]]
    sales = next(x["sam"] for x in s if x["department"] == "Sales" and x["state"] == "active" and not x["boss"])
    a_leaver = next((x["sam"] for x in s if x["state"] == "leaver"), "")
    return {
        "company": COMPANY,
        "active": by("active"), "stale": by("stale"), "leavers": by("leaver"), "never": by("never"),
        "managers": sorted(x["sam"] for x in s if x["boss"]),
        "in_users_container": sorted(x["sam"] for x in s if x["where"] == "users"),
        "service": [sv[0] for sv in SERVICE],
        "service_used": [sv[0] for sv in SERVICE if sv[2]],
        "service_unused": [sv[0] for sv in SERVICE if not sv[2]],
        "previous_admin": PREV["sam"], "contractor": CONTRACTOR["sam"],
        "da_users": [PREV["sam"], CONTRACTOR["sam"], s[0]["sam"]] + [sv[0] for sv in SERVICE if sv[3] == "Domain Admins"]
                    + [x["sam"] for x in it[:1]] + ([a_leaver] if a_leaver else []),
        "da_groups": [OLD_ADMIN_GROUPS[0]],
        "old_admin_members": [x["sam"] for x in it[1:3]] + [sales],
        "helpdesk_members": [x["sam"] for x in it[:2]],
        "empty_groups": list(EMPTY_GROUPS), "circular": list(CIRCULAR),
        "stale_computers": [c for c, _ in STALE_COMPUTERS],
        "gpo_unlinked": [g[0] for g in GPOS if g[4] == "unlinked"],
        "gpo_conflict": [g[0] for g in GPOS if g[4] == "conflict"],
        "gpo_broken": [g[0] for g in GPOS if g[4] == "broken"],
        "gpo_disabled_link": [g[0] for g in GPOS if g[4] == "disabled-link"],
        "gpo_all_disabled": [g[0] for g in GPOS if g[4] == "all-settings-disabled"],
        "dns_stale": [n for n, _ in DNS_STALE], "dns_dead_cname": DNS_DEAD_CNAME[0],
        "files_ip": f"{p.subnet}.{DNS_WRONG_FILES}", "fs_ip": p.fs_ip,
        "shares": [sh[0] for sh in SHARES],
        "tasks": {"fs01": [t[1] for t in TASKS if t[0] == "fs01"], "dc01": [t[1] for t in TASKS if t[0] == "dc01"]},
        "certs": [{"node": c[0], "name": c[1], "days": c[3]} for c in CERTS],
        "finance_files": FINANCE_FILES,
    }


# ------------------------------------------------------- script helpers
def _q(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


_DOM = ("$dom = Get-ADDomain; $dns = $dom.DNSRoot; $base = $dom.DistinguishedName; $now = Get-Date; "
        f"$co = 'OU={COMPANY},' + $base; ")
_KEYMAKE = f"if (-not (Test-Path -Path '{KEY}')) {{ New-Item -Path '{KEY}' -Force | Out-Null }}; "


def _ou(parent: str, name: str) -> str:
    """An OU under the DN held in the PowerShell variable `parent` ("$co")."""
    return (f"if (-not (Get-ADOrganizationalUnit -Filter \"DistinguishedName -eq 'OU={name},{parent}'\" "
            f"-ErrorAction SilentlyContinue)) {{ New-ADOrganizationalUnit -Name {_q(name)} "
            f"-Path {parent} -ProtectedFromAccidentalDeletion $false }}; ")


def _group(name: str, scope: str, path_ps: str, desc: str = "") -> str:
    d = f" -Description {_q(desc)}" if desc else ""
    return (f"if (-not (Get-ADGroup -Filter \"Name -eq '{name}'\")) {{ New-ADGroup -Name {_q(name)} "
            f"-GroupScope {scope} -GroupCategory Security -Path {path_ps}{d} }}; ")


def _b64(obj) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode("utf-8")).decode("ascii")


# ---------------------------------------------------------- dc01: the domain
def ps_structure(p: Plan) -> str:
    """OUs and groups: the departments' OUs under Staff, the predecessor's
    groups, nested, circular and empty ones."""
    out = [_DOM, _ou("$base", COMPANY)]
    for sub in ("Staff", "Groups", "Servers", "Workstations", "Old Staff"):
        out.append(_ou("$co", sub))
    out.append("$st = 'OU=Staff,' + $co; ")
    for dept, tag, _t, _w in (("Management", "Management", (), 0),) + DEPARTMENTS:
        out.append(_ou("$st", dept))
    g = "('OU=Groups,' + $co)"
    for dept, tag, _t, _w in (("Management", "Management", (), 0),) + DEPARTMENTS:
        out.append(_group(f"G-{tag}", "Global", g, f"{dept} staff"))
        out.append(_group(f"DL-{tag}-Share-RW", "DomainLocal", g, f"{dept} share, change"))
        out.append(f"Add-ADGroupMember -Identity 'DL-{tag}-Share-RW' -Members 'G-{tag}' -ErrorAction SilentlyContinue; ")
    out.append(_group("G-AllStaff", "Global", g, "Everyone"))
    out.append(_group("All Company", "Global", g))
    out.append(_group("G-Managers", "Global", g, "Managers"))
    tags = ["Management"] + [d[1] for d in DEPARTMENTS]
    out.append("Add-ADGroupMember -Identity 'G-AllStaff' -Members " + ", ".join(f"'G-{t}'" for t in tags)
               + " -ErrorAction SilentlyContinue; ")
    out.append("Add-ADGroupMember -Identity 'All Company' -Members 'G-AllStaff' -ErrorAction SilentlyContinue; ")
    # Finance nested in the Sales share by mistake.
    out.append("Add-ADGroupMember -Identity 'DL-Sales-Share-RW' -Members 'G-Finance' -ErrorAction SilentlyContinue; ")
    for name in CIRCULAR:
        out.append(_group(name, "Global", g, "Team leads"))
    out.append(f"Add-ADGroupMember -Identity '{CIRCULAR[0]}' -Members '{CIRCULAR[1]}' -ErrorAction SilentlyContinue; "
               f"Add-ADGroupMember -Identity '{CIRCULAR[1]}' -Members '{CIRCULAR[0]}' -ErrorAction SilentlyContinue; ")
    for name in EMPTY_GROUPS:
        out.append(_group(name, "DomainLocal" if name.startswith("DL-") else "Global", g))
    out.append(_group(OLD_ADMIN_GROUPS[0], "Global", "$dom.UsersContainer", "IT admins"))
    out.append(_group(OLD_ADMIN_GROUPS[1], "Global", "$dom.UsersContainer"))
    out.append(f"Add-ADGroupMember -Identity '{OLD_ADMIN_GROUPS[0]}' -Members '{OLD_ADMIN_GROUPS[1]}' -ErrorAction SilentlyContinue; ")
    out.append("@(Get-ADOrganizationalUnit -SearchBase $co -Filter *).Count")
    return "".join(out)


def _row(x: dict) -> str:
    return "|".join([x["sam"], x["first"], x["last"], x["department"], x["tag"], x["title"],
                     x["manager"], x["state"], str(x["days"]), x["where"], "1" if x["boss"] else ""])


def ps_users(rows: list[dict]) -> str:
    """One batch of staff: made where the predecessor put them, in their
    department's group, with their manager, and then what became of them."""
    data = ";".join(_row(x) for x in rows)
    return (
        _DOM
        + f"$rows = {_q(data)}.Split(';'); $made = 0; "
        "foreach ($r in $rows) { $f = $r.Split('|'); $sam = $f[0]; "
        "$ou = if ($f[9] -eq 'users') { $dom.UsersContainer } elseif ($f[9] -eq 'old') { 'OU=Old Staff,' + $co } "
        "else { 'OU=' + $f[3] + ',OU=Staff,' + $co }; "
        "if (-not (Get-ADUser -Filter \"SamAccountName -eq '$sam'\")) { "
        "New-ADUser -Name ($f[1] + ' ' + $f[2]) -SamAccountName $sam -GivenName $f[1] -Surname $f[2] "
        "-DisplayName ($f[1] + ' ' + $f[2]) -UserPrincipalName ($sam + '@' + $dns) "
        "-EmailAddress (($f[1] + '.' + $f[2]).ToLower() + '@' + $dns) -Department $f[3] -Title $f[5] "
        f"-Company '{COMPANY}' -Description ($f[5] + ', ' + $f[3]) -Path $ou "
        f"-AccountPassword ({SECRET}) -Enabled $true; $made++ }}; "
        "if ($f[6]) { Set-ADUser -Identity $sam -Manager $f[6] -ErrorAction SilentlyContinue }; "
        "if ($f[7] -ne 'never') { Add-ADGroupMember -Identity ('G-' + $f[4]) -Members $sam -ErrorAction SilentlyContinue }; "
        "if ($f[10]) { Add-ADGroupMember -Identity 'G-Managers' -Members $sam -ErrorAction SilentlyContinue }; "
        "$ago = $now.AddDays(0 - [int]$f[8]); "
        "if ($f[7] -eq 'leaver') { Disable-ADAccount -Identity $sam; "
        "Set-ADUser -Identity $sam -Description ('Left ' + $ago.AddDays(14).ToString('MMMM yyyy')) "
        "-Replace @{ lastLogonTimestamp = $ago.ToFileTime() } } "
        "elseif ($f[7] -eq 'never') { Set-ADUser -Identity $sam -Description ('New starter, starts ' + $ago.ToString('d MMMM yyyy')) } "
        "else { Set-ADUser -Identity $sam -Replace @{ lastLogonTimestamp = $ago.ToFileTime() } } }; "
        "'made ' + $made + ' of ' + $rows.Count"
    )


def ps_people_extra(p: Plan) -> str:
    """The predecessor, the contractor and the service accounts."""
    out = [_DOM, "$it = 'OU=IT,OU=Staff,' + $co; "]
    out.append(
        f"if (-not (Get-ADUser -Filter \"SamAccountName -eq '{PREV['sam']}'\")) {{ New-ADUser -Name '{PREV['first']} {PREV['last']}' "
        f"-SamAccountName {PREV['sam']} -GivenName {PREV['first']} -Surname {PREV['last']} -Title '{PREV['title']}' -Department IT "
        f"-UserPrincipalName ('{PREV['sam']}@' + $dns) -Description 'IT manager (leaving: last day today)' -Path $it "
        f"-AccountPassword ({SECRET}) -PasswordNeverExpires $true -Enabled $true }}; "
        f"Set-ADUser -Identity {PREV['sam']} -Replace @{{ lastLogonTimestamp = $now.ToFileTime() }}; ")
    out.append(
        f"if (-not (Get-ADUser -Filter \"SamAccountName -eq '{CONTRACTOR['sam']}'\")) {{ New-ADUser -Name '{CONTRACTOR['first']} {CONTRACTOR['last']}' "
        f"-SamAccountName {CONTRACTOR['sam']} -Description {_q(CONTRACTOR['description'])} -Path $dom.UsersContainer "
        f"-AccountPassword ({SECRET}) -PasswordNeverExpires $true -Enabled $true }}; "
        f"Set-ADUser -Identity {CONTRACTOR['sam']} -Replace @{{ lastLogonTimestamp = $now.AddDays(-160).ToFileTime() }}; ")
    for sam, desc, _used, _priv, spn in SERVICE:
        out.append(
            f"if (-not (Get-ADUser -Filter \"SamAccountName -eq '{sam}'\")) {{ New-ADUser -Name '{sam}' -SamAccountName {sam} "
            f"-Description {_q(desc)} -Path $dom.UsersContainer -AccountPassword ({SECRET}) "
            "-PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true }; ")
        if spn:
            out.append(f"Set-ADUser -Identity {sam} -ServicePrincipalNames @{{ Add = ({_q(spn)}.Replace('{{dns}}', $dns)) }} "
                       "-ErrorAction SilentlyContinue; ")
    out.append("Add-ADGroupMember -Identity 'G-AllStaff' -Members 'svc-scan' -ErrorAction SilentlyContinue; ")
    # What the service accounts' passwords were last set at: a reset after the handover shows as a newer value.
    out.append(_KEYMAKE + "$pls = @{}; foreach ($s in @(" + ", ".join(_q(s[0]) for s in SERVICE) + ")) { "
               "$pls[$s] = [string](Get-ADUser -Identity $s -Properties pwdLastSet).pwdLastSet }; "
               f"Set-ItemProperty -Path '{KEY}' -Name 'svc-pwdlastset' -Value (ConvertTo-Json -InputObject $pls -Compress); ")
    out.append("@(Get-ADUser -Filter \"SamAccountName -like 'svc-*'\").Count")
    return "".join(out)


def ps_admins(p: Plan) -> str:
    """Domain Admins and its friends, the way they grew."""
    pl = p.planted
    out = [_DOM, "$daSid = $dom.DomainSID.Value + '-512'; $eaSid = $dom.DomainSID.Value + '-519'; $saSid = $dom.DomainSID.Value + '-518'; "]
    out.append("Add-ADGroupMember -Identity $daSid -Members " + ", ".join(_q(u) for u in pl["da_users"])
               + f", '{OLD_ADMIN_GROUPS[0]}' -ErrorAction SilentlyContinue; ")
    out.append(f"Add-ADGroupMember -Identity $eaSid -Members '{PREV['sam']}', '{OLD_ADMIN_GROUPS[0]}' -ErrorAction SilentlyContinue; ")
    out.append(f"Add-ADGroupMember -Identity $saSid -Members '{PREV['sam']}' -ErrorAction SilentlyContinue; ")
    out.append(f"Add-ADGroupMember -Identity '{OLD_ADMIN_GROUPS[0]}' -Members "
               + ", ".join(_q(u) for u in pl["old_admin_members"]) + " -ErrorAction SilentlyContinue; ")
    out.append(f"Add-ADGroupMember -Identity '{OLD_ADMIN_GROUPS[1]}' -Members "
               + ", ".join(_q(u) for u in pl["helpdesk_members"]) + " -ErrorAction SilentlyContinue; ")
    for sam, _d, _u, priv, _s in SERVICE:
        if priv and priv != "Domain Admins":
            out.append(f"Add-ADGroupMember -Identity {_q(priv)} -Members {sam} -ErrorAction SilentlyContinue; ")
    out.append("@(Get-ADGroupMember -Identity $daSid -Recursive).Count")
    return "".join(out)


def ps_computers(p: Plan) -> str:
    out = [_DOM, "$srv = 'OU=Servers,' + $co; $wks = 'OU=Workstations,' + $co; "]
    for name, days in STALE_COMPUTERS:
        where = "$srv" if not name.startswith(("WKS", "LAP")) else "$wks"
        out.append(f"if (-not (Get-ADComputer -Filter \"Name -eq '{name}'\")) {{ New-ADComputer -Name '{name}' "
                   f"-SamAccountName '{name}$' -Path {where} -Enabled $true }}; "
                   f"Set-ADComputer -Identity '{name}$' -Replace @{{ lastLogonTimestamp = $now.AddDays(-{days}).ToFileTime() }}; ")
    out.append("@(Get-ADComputer -SearchBase $co -Filter *).Count")
    return "".join(out)


def ps_gpos(p: Plan) -> str:
    """Overlapping Group Policy: two linked to the same OU that disagree,
    two never linked, a test linked to the domain with the link off, one
    whose SYSVOL folder is gone (broken), one with all its settings off."""
    out = [_DOM, "Import-Module GroupPolicy; $links = @{ workstations = ('OU=Workstations,' + $co); "
           "servers = ('OU=Servers,' + $co); staff = ('OU=Staff,' + $co); domain = $base }; "]
    for name, link, enabled, values, wrong in GPOS:
        out.append(f"$g = Get-GPO -Name {_q(name)} -ErrorAction SilentlyContinue; "
                   f"if (-not $g) {{ $g = New-GPO -Name {_q(name)}; ")
        for key, vname, typ, val in values:
            v = val if typ == "DWord" else _q(val)
            out.append(f"Set-GPRegistryValue -Name {_q(name)} -Key {_q(key)} -ValueName {_q(vname)} -Type {typ} -Value {v} | Out-Null; ")
        if link:
            out.append(f"New-GPLink -Name {_q(name)} -Target $links['{link}'] -LinkEnabled {'Yes' if enabled else 'No'} | Out-Null; ")
        if wrong == "all-settings-disabled":
            out.append("$g.GpoStatus = 'AllSettingsDisabled'; ")
        if wrong == "broken":
            out.append("Remove-Item -Path ('\\\\' + $env:COMPUTERNAME + '\\SYSVOL\\' + $dns + '\\Policies\\{' + $g.Id + '}') "
                       "-Recurse -Force -ErrorAction SilentlyContinue; ")
        out.append("}; ")
    out.append("@(Get-GPO -All).Count")
    return "".join(out)


def ps_dns(p: Plan) -> str:
    out = [_DOM]
    for name, last in DNS_STALE:
        out.append(f"if (-not (Get-DnsServerResourceRecord -ZoneName $dns -Name '{name}' -ErrorAction SilentlyContinue)) {{ "
                   f"Add-DnsServerResourceRecordA -ZoneName $dns -Name '{name}' -IPv4Address '{p.subnet}.{last}' }}; ")
    out.append(f"if (-not (Get-DnsServerResourceRecord -ZoneName $dns -Name 'files' -ErrorAction SilentlyContinue)) {{ "
               f"Add-DnsServerResourceRecordA -ZoneName $dns -Name 'files' -IPv4Address '{p.subnet}.{DNS_WRONG_FILES}' }}; ")
    out.append(f"if (-not (Get-DnsServerResourceRecord -ZoneName $dns -Name '{DNS_DEAD_CNAME[0]}' -ErrorAction SilentlyContinue)) {{ "
               f"Add-DnsServerResourceRecordCName -ZoneName $dns -Name '{DNS_DEAD_CNAME[0]}' -HostNameAlias ('{DNS_DEAD_CNAME[1]}.' + $dns) }}; ")
    out.append("@(Get-DnsServerResourceRecord -ZoneName $dns -RRType A).Count")
    return "".join(out)


def _task(name: str, exe: str, args: str, user: str, at: str, netbios: str, args_ps: str = "") -> str:
    """A daily task with no description: nobody wrote down what it is for.
    `args_ps` is a PowerShell expression for the arguments, when they are
    built in the guest."""
    if user == "SYSTEM":
        who = "$pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; "
    else:
        # S4U: runs as the account without its password being stored or typed.
        who = f"$pr = New-ScheduledTaskPrincipal -UserId '{netbios}\\{user}' -LogonType S4U -RunLevel Highest; "
    return (f"if (-not (Get-ScheduledTask -TaskName {_q(name)} -ErrorAction SilentlyContinue)) {{ "
            f"$a = New-ScheduledTaskAction -Execute {_q(exe)}" + (f" -Argument {args_ps or _q(args)}" if args or args_ps else "") + "; "
            f"$t = New-ScheduledTaskTrigger -Daily -At '{at}'; " + who
            + f"Register-ScheduledTask -TaskName {_q(name)} -TaskPath '\\' -Action $a -Trigger $t -Principal $pr | Out-Null }}; ")


def ps_dc_tasks_certs(p: Plan) -> str:
    out = [_DOM, "New-Item -ItemType Directory -Path 'C:\\Scripts\\out', 'C:\\IT' -Force | Out-Null; ",
           "Set-Content -Path 'C:\\Scripts\\export-users.ps1' -Value \"Get-ADUser -Filter * -Properties Description, LastLogonDate | "
           "Export-Csv -Path C:\\Scripts\\out\\users.csv -NoTypeInformation\"; ",
           "icacls 'C:\\Scripts\\out' /grant 'Everyone:(OI)(CI)R' | Out-Null; ",
           "if (-not (Get-SmbShare -Name 'Scripts$' -ErrorAction SilentlyContinue)) { "
           "New-SmbShare -Name 'Scripts$' -Path 'C:\\Scripts' -ReadAccess 'Everyone' | Out-Null }; "]
    out.append(_task("Restart Spooler", "powershell.exe", "-NoProfile -Command Restart-Service -Name Spooler -Force",
                     "SYSTEM", "03:00", p.netbios))
    out.append(_task("AD Export", "powershell.exe", "-NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\export-users.ps1",
                     "SYSTEM", "02:00", p.netbios))
    out.append(_task("Old Updater", "C:\\Tools\\update.bat", "", "SYSTEM", "04:30", p.netbios))
    out.append(_certs("dc01"))
    out.append("@(Get-ScheduledTask -TaskPath '\\').Count")
    return "".join(out)


def _certs(node: str) -> str:
    out = ["$dns = (Get-WmiObject -Class Win32_ComputerSystem).Domain; "]
    for n, friendly, prefix, days in CERTS:
        if n != node:
            continue
        out.append(f"if (-not (Get-ChildItem -Path 'Cert:\\LocalMachine\\My' | Where-Object {{ $_.FriendlyName -eq {_q(friendly)} }})) {{ "
                   f"New-SelfSignedCertificate -DnsName ('{prefix}.' + $dns) -CertStoreLocation 'Cert:\\LocalMachine\\My' "
                   f"-FriendlyName {_q(friendly)} -NotBefore (Get-Date).AddDays(-400) -NotAfter (Get-Date).AddDays({days}) | Out-Null }}; ")
    return "".join(out)


def ps_record(p: Plan, node: str) -> str:
    """Marks the machine as handed over. What was planted stays on the host
    (planted_for_grading): a guest the student administers never holds the
    answer key. A value left by an older winlab is removed."""
    return (_KEYMAKE + f"Remove-ItemProperty -Path '{KEY}' -Name 'planted' -ErrorAction SilentlyContinue; "
            f"Set-ItemProperty -Path '{KEY}' -Name 'handed-over' -Value ((Get-Date).ToUniversalTime().ToString('o')); "
            f"Set-ItemProperty -Path '{KEY}' -Name 'scenario' -Value 'inherited company (pre-built by winlab)'; 'recorded'")


# ------------------------------------------------------- fs01: the files
_ROOT = ("$v = Get-Volume -FileSystemLabel 'Data' -ErrorAction SilentlyContinue | Select-Object -First 1; "
         "$root = if ($v -and $v.DriveLetter) { [string]$v.DriveLetter + ':\\Shares' } else { 'C:\\Shares' }; ")


def ps_fs_disk(p: Plan) -> str:
    return ("$raw = Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' } | Select-Object -First 1; "
            "if ($raw -and -not (Get-Volume -FileSystemLabel 'Data' -ErrorAction SilentlyContinue)) { "
            "$letter = @('E', 'F', 'G', 'S') | Where-Object { -not (Get-PSDrive -Name $_ -ErrorAction SilentlyContinue) } | Select-Object -First 1; "
            "Initialize-Disk -Number $raw.Number -PartitionStyle GPT -PassThru | "
            "New-Partition -DriveLetter $letter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Data' -Confirm:$false | Out-Null }; "
            + _ROOT + "$root")


def ps_fs_shares(p: Plan) -> str:
    nb = p.netbios
    out = [_ROOT, "Install-WindowsFeature -Name FS-FileServer | Out-Null; "]
    for name, folder, everyone, grant in SHARES:
        acc = {"Full": "-FullAccess", "Change": "-ChangeAccess", "Read": "-ReadAccess"}[everyone]
        out.append(f"$d = Join-Path $root '{folder}'; New-Item -ItemType Directory -Path $d -Force | Out-Null; "
                   f"if (-not (Get-SmbShare -Name '{name}' -ErrorAction SilentlyContinue)) {{ "
                   f"New-SmbShare -Name '{name}' -Path $d {acc} 'Everyone' | Out-Null }}; "
                   f"icacls $d /grant '{grant}' | Out-Null; ")
    out.append(f"icacls (Join-Path $root 'Finance') /grant '{nb}\\G-Finance:(OI)(CI)M' | Out-Null; ")
    out.append(f"icacls (Join-Path $root 'Scans') /grant '{nb}\\svc-scan:(OI)(CI)M' | Out-Null; ")
    # Files: Finance's working files, HR's, and on Public what should never be there.
    out.append(f"$fd = Join-Path $root 'Finance'; foreach ($i in 1..{FINANCE_FILES}) {{ "
               "$n = Join-Path $fd ('ledger-{0:d2}.csv' -f $i); if (-not (Test-Path $n)) { "
               "Set-Content -Path $n -Value @('winlab practice file', 'account,period,amount', ('4000,{0},{1}' -f $i, ($i * 131))) } }; ")
    out.append("$hd = Join-Path $root 'HR'; foreach ($n in 'salary-review.txt', 'disciplinary-notes.txt', 'new-starters.txt') { "
               "Set-Content -Path (Join-Path $hd $n) -Value ('winlab practice file: ' + $n + ', HR only') }; ")
    out.append("$pd = Join-Path $root 'Public'; New-Item -ItemType Directory -Path (Join-Path $pd 'IT') -Force | Out-Null; "
               "Set-Content -Path (Join-Path $pd 'IT\\service accounts.txt') -Value @('Service accounts and where they run.', "
               "'svc-backup: the backup jobs on fs01. svc-sql: sql01. svc-scan: the scanner.', "
               "'Their sign-in secrets used to be kept in this file. winlab put none here: nothing secret is in the lab.'); "
               "foreach ($i in 1..12) { Set-Content -Path (Join-Path $pd ('old-{0:d2}.tmp' -f $i)) -Value 'temp' }; ")
    out.append("$od = Join-Path $root 'OldProjects'; foreach ($n in 'phoenix', 'website-2019', 'migration') { "
               "New-Item -ItemType Directory -Path (Join-Path $od $n) -Force | Out-Null; "
               "Set-Content -Path (Join-Path $od ($n + '\\notes.txt')) -Value ('winlab practice file: project ' + $n) }; ")
    out.append("@(Get-SmbShare | Where-Object { -not $_.Special }).Count")
    return "".join(out)


def ps_fs_fill(p: Plan) -> str:
    """The Scans share's archive fills the data volume: zero-filled files
    (fsutil, quick, no data), which the student archives or deletes."""
    return (_ROOT + "$ad = Join-Path $root 'Scans\\Archive 2019-2022'; New-Item -ItemType Directory -Path $ad -Force | Out-Null; "
            "$vol = Get-Volume -FileSystemLabel 'Data' -ErrorAction SilentlyContinue | Select-Object -First 1; "
            "if ($vol) { $i = 0; "
            f"while ((($vol.SizeRemaining * 100) / $vol.Size) -gt {100 - FILL_TO_PCT} -and $i -lt 400) {{ $i++; "
            f"$chunk = [math]::Min([int64]{FILL_CHUNK_MB}MB, [int64]($vol.SizeRemaining - ($vol.Size * {100 - FILL_TO_PCT} / 100))); "
            "if ($chunk -lt 1MB) { break }; "
            "$f = Join-Path $ad ('ScanArchive-{0:d3}.zip' -f $i); if (-not (Test-Path $f)) { fsutil file createnew $f $chunk | Out-Null }; "
            "$vol = Get-Volume -FileSystemLabel 'Data' }; "
            "[math]::Round(($vol.SizeRemaining * 100) / $vol.Size, 1) } else { 'no data volume' }")


def ps_fs_tasks_certs(p: Plan) -> str:
    out = [_ROOT, "New-Item -ItemType Directory -Path 'C:\\Scripts' -Force | Out-Null; ",
           "Set-Content -Path 'C:\\Scripts\\cleanup.ps1' -Value ('Get-ChildItem -Path ''' + (Join-Path $root 'Public') + ''' -Filter *.tmp | "
           "Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item'); ",
           "Set-Content -Path 'C:\\Scripts\\report.ps1' -Value 'Get-SmbShare | Out-File -FilePath C:\\Scripts\\report.txt'; "]
    out.append(_task("Nightly Copy", "robocopy.exe", "", "SYSTEM", "01:00", p.netbios,
                     args_ps="('\"' + (Join-Path $root 'Finance') + '\" \\\\nas-old\\backup\\finance /MIR /R:1 /W:1')"))
    out.append(_task("Cleanup Temp", "powershell.exe", "-NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\cleanup.ps1",
                     "SYSTEM", "05:00", p.netbios))
    out.append(_task("Weekly Report", "powershell.exe", "-NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\report.ps1",
                     "svc-backup", "06:00", p.netbios))
    out.append(_certs("fs01"))
    out.append("@(Get-ScheduledTask -TaskPath '\\').Count")
    return "".join(out)


# ------------------------------------------------- pc01: the handover notes
def handover_text(p: Plan) -> str:
    """The previous admin's notes: some right, some wrong, as they always are.
    What is wrong is the student's to find (the as-built exercise)."""
    dns = (p.lab.domain or "harbourline.lab").lower()
    md = p.staff[0]
    bmcs = [f"{n.id} {n.vars['bmc_ip']}" for n in p.lab.node_list() if n.vars.get("bmc") and n.vars.get("bmc_ip")]
    return "\r\n".join([
        "HANDOVER NOTES",
        f"From: {PREV['first']} {PREV['last']}, IT manager (last day today)",
        "To: whoever takes over IT",
        "",
        "This lab is a pre-built scenario: winlab built this company for you when you",
        "pressed Hand over the company. Everything below is what the previous admin wrote.",
        "",
        f"Domain: {dns} ({p.netbios}). About {len(p.staff)} accounts, everyone is in AD.",
        "Servers: dc01 and dc02 (domain controllers), fs01 (files). They are in the",
        "server room; use RDP or Server Manager from your PC, the room key is with reception.",
        *([f"Each server's BMC is on the office network ({', '.join(bmcs)}); the user and",
           "its password are on the toe tag of each box (the Machines window shows them)."] if bmcs else []),
        "",
        "- dc02 is the new DC and holds all the FSMO roles. dc01 is old, you can switch it",
        "  off whenever you like.",
        "- dc01 does DHCP for the office.",
        "- Domain Admins is just me and Administrator. Remove me when I've gone.",
        "- Leavers: HR tells me and I delete the account on their last day.",
        "- Service accounts: svc-backup runs the nightly copy of Finance to the NAS (nas-old).",
        "  It works, don't touch it. The others are probably still needed.",
        "- Group Policy: Workstation Lockdown v2 replaced v1, which is unlinked now.",
        "- Shares on fs01: Public, Finance, Scans, Software, OldProjects and HR$.",
        "  Finance is locked down to the Finance team.",
        "- The data disk on fs01 has loads of space.",
        "- Certificates were all renewed last month and are good for a year.",
        "- DNS is clean. 'files' points at the file server.",
        "- There are a few scheduled tasks; nothing important.",
        "",
        "Service account sign-ins: I kept them in my head. Reset them if you need them.",
        f"Ask {md['name']} ({md['title']}) if you need anything signed off.",
        "Good luck!",
        "",
    ])


def ps_handover_doc(p: Plan) -> str:
    text = base64.b64encode(handover_text(p).encode("utf-8")).decode("ascii")
    return ("$t = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + text + "')); "
            f"$f = Join-Path $env:PUBLIC ('Desktop\\{DOC_NAME}'); Set-Content -Path $f -Value $t -Encoding UTF8; "
            "New-Item -ItemType Directory -Path 'C:\\IT' -Force | Out-Null; Set-Content -Path 'C:\\IT\\handover.txt' -Value $t -Encoding UTF8; "
            "(Test-Path $f)")


# ------------------------------------------------------------ the handover
@dataclass
class Step:
    id: str
    node: str
    title: str
    script: Callable[[Plan], str] | None = None   # None: the node's roles (the domain)


def steps(p: Plan) -> list[Step]:
    """The handover in order: the domain first (each machine's roles, in boot
    order), then the predecessor's years on top of it."""
    out = [Step(f"roles-{n.id}", n.id, f"{n.id}: {', '.join(n.roles)}") for n in p.lab.node_list() if n.roles]
    out += [Step("structure", "dc01", "OUs and groups", ps_structure),
            Step("people-extra", "dc01", "the previous admin, a contractor and the service accounts", ps_people_extra)]
    for i in range(0, len(p.staff), BATCH):
        chunk = p.staff[i:i + BATCH]
        out.append(Step(f"staff-{i // BATCH + 1}", "dc01", f"staff {i + 1} to {i + len(chunk)}",
                        lambda _p, rows=chunk: ps_users(rows)))
    out += [Step("admins", "dc01", "Domain Admins as it grew", ps_admins),
            Step("computers", "dc01", "computer accounts for machines long gone", ps_computers),
            Step("gpos", "dc01", "Group Policy, overlapping", ps_gpos),
            Step("dns", "dc01", "DNS records nobody removed", ps_dns),
            Step("dc-tasks", "dc01", "scheduled tasks and a certificate on dc01", ps_dc_tasks_certs),
            Step("record-dc01", "dc01", "what was planted (for grading)", lambda q: ps_record(q, "dc01")),
            Step("fs-disk", "fs01", "the file server's data disk", ps_fs_disk),
            Step("fs-shares", "fs01", "shares open to everyone", ps_fs_shares),
            Step("fs-fill", "fs01", "the scans archive that fills the disk", ps_fs_fill),
            Step("fs-tasks", "fs01", "scheduled tasks and certificates on fs01", ps_fs_tasks_certs),
            Step("record-fs01", "fs01", "what was planted (for grading)", lambda q: ps_record(q, "fs01")),
            Step("handover-doc", "pc01", "the handover notes on your desktop", ps_handover_doc)]
    return [s for s in out if s.node in p.lab.nodes]


def planted_for_grading(lab_name: str) -> str:
    """What the handover planted, as the checks read it (base64 JSON), once
    the record step ran on dc01; empty before that. Rebuilt on the host from
    the lab's seed, so it never has to be stored in a guest."""
    if "record-dc01" not in load_state(lab_name)["done"]:
        return ""
    from . import schema
    try:
        lab = schema.load(lab_name)
    except Exception:  # noqa: BLE001 - no such lab: nothing was planted
        return ""
    if not getattr(lab, "inherited", False):
        return ""
    return _b64(plan(lab).planted)


def state_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / "company.json"


def load_state(lab_name: str) -> dict:
    try:
        raw = json.loads(state_file(lab_name).read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            raw.setdefault("done", [])
            return raw
    except (OSError, ValueError):
        pass
    return {"done": [], "started": 0.0, "finished": 0.0, "last_error": ""}


def save_state(lab_name: str, st: dict) -> None:
    f = state_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2), encoding="utf-8")
    tmp.replace(f)


Runner = Callable[[str, str, str], "tuple[bool, str]"]


class HandoverError(Exception):
    pass


def handover(lab, runner: Runner, build: Callable[[str], str], running: list[str],
             emit: Callable[[str], None] = print, now: Callable[[], float] = time.time) -> dict:
    """Hands the company over: runs every step not yet done, in order, and
    stops at the first that fails (pressing it again carries on there).
    runner(node, script, shell) -> (ok, output) runs a script over the agent;
    build(node) applies that machine's roles and returns what it did."""
    if not getattr(lab, "inherited", False):
        raise HandoverError(f"{lab.name} is not the inherited company scenario: every other lab starts empty "
                            "and is yours to build")
    p = plan(lab)
    st = load_state(lab.name)
    todo = [s for s in steps(p) if s.id not in st["done"]]
    need = sorted({s.node for s in todo} - set(running))
    if need:
        raise HandoverError(f"start {', '.join(need)} first: the handover works inside the machines")
    if not st.get("started"):
        st["started"] = now()
    total = len(steps(p))
    for s in todo:
        n = len(st["done"]) + 1
        emit(f"[{n}/{total}] {s.title}")
        try:
            if s.script is None:
                out, ok = build(s.node), True
            else:
                ok, out = runner(s.node, s.script(p), "powershell")
        except Exception as exc:  # noqa: BLE001 - say what failed, keep what is done
            ok, out = False, str(exc)
        last = (out or "").strip().splitlines()[-1:] or [""]
        if not ok:
            st["last_error"] = f"{s.title}: {(out or '').strip()[-400:]}"
            save_state(lab.name, st)
            raise HandoverError(f"{s.title} on {s.node} failed: {(out or '').strip()[-400:]}. "
                                "Press Hand over the company again to carry on from here.")
        emit(f"      {last[0][:160]}")
        st["done"].append(s.id)
        st["last_error"] = ""
        save_state(lab.name, st)
    if not st.get("finished"):
        st["finished"] = now()
        save_state(lab.name, st)
        from . import people
        people.save(lab.name, to_people(p.staff, (lab.domain or "harbourline.lab").lower()))
    emit(f"the company is yours: {len(p.staff)} staff, the handover notes are on {('pc01' if 'pc01' in lab.nodes else 'the admin PC')}'s desktop")
    return st


def guest_runner(lab_name: str, timeout: float = 900.0) -> Runner:
    """A runner over the serial agent with room for a long step."""
    from . import state
    from .guestctl import GuestChannel, GuestError

    def run(node: str, cmd: str, shell: str) -> tuple[bool, str]:
        st = state.load(lab_name)
        ns = st.nodes.get(node) if st else None
        if not ns or not state.pid_alive(ns.pid):
            return False, f"{node} is not running"
        try:
            ch = GuestChannel(ns.serial_port).connect(retries=20, delay=3)
        except GuestError as exc:
            return False, str(exc)
        try:
            res = ch.run(cmd, shell=shell, timeout=timeout)
        except GuestError as exc:
            return False, str(exc)
        finally:
            ch.close()
        return res.ok, (res.out or "") + (("\n" + res.err) if res.err and not res.ok else "")
    return run


def role_builder(lab, topology) -> Callable[[str], str]:
    """Applies a machine's roles over its agent, as `winlab roles apply` does."""
    from . import roles, state
    from .guestctl import GuestChannel

    def build(node_id: str) -> str:
        st = state.load(lab.name)
        ns = st.nodes.get(node_id) if st else None
        if not ns or not state.pid_alive(ns.pid):
            raise HandoverError(f"{node_id} is not running")
        ch = GuestChannel(ns.serial_port).connect(retries=40, delay=3)
        try:
            res = roles.apply_roles(lab.nodes[node_id], ch, topology=topology, lab=lab)
        finally:
            ch.close()
        return f"applied {', '.join(res.applied) or 'nothing new'}"
    return build


# ------------------------------------------------------------- the window
LESSONS = ("inherited-audit", "inherited-privileged", "inherited-leavers", "inherited-service-accounts",
           "inherited-gpo-cleanup", "inherited-file-shares", "inherited-scheduled-tasks", "inherited-certs-dns",
           "inherited-old-dc", "inherited-as-built", "server-room-remote-only")


def view(lab) -> dict:
    if not getattr(lab, "inherited", False):
        return {"inherited": False}
    p = plan(lab)
    st = load_state(lab.name)
    all_steps = steps(p)
    from . import lessons as ls
    items = []
    for lid in LESSONS:
        try:
            l = ls.load(lid)
            items.append({"id": lid, "title": l.title, "minutes": l.minutes, "summary": l.summary})
        except Exception:  # noqa: BLE001 - a lesson locked in the trial still lists its id
            items.append({"id": lid, "title": lid, "minutes": 0, "summary": ""})
    return {
        "inherited": True, "company": COMPANY, "staff": len(p.staff),
        "label": "Pre-built scenario: the only lab that does not start empty",
        "steps": [{"id": s.id, "title": s.title, "node": s.node, "done": s.id in st["done"]} for s in all_steps],
        "done": len([s for s in all_steps if s.id in st["done"]]), "total": len(all_steps),
        "handed_over": bool(st.get("finished")), "last_error": st.get("last_error", ""),
        "notes": handover_text(p), "lessons": items,
    }


def render(lab) -> str:
    v = view(lab)
    if not v["inherited"]:
        return f"{lab.name} is not the inherited company scenario"
    lines = [f"{lab.name}: {v['label']}",
             f"{v['company']}: {v['staff']} staff; handover {v['done']} of {v['total']} steps done"
             + (" (handed over)" if v["handed_over"] else "")]
    if v["last_error"]:
        lines.append(f"last error: {v['last_error']}")
    for s in v["steps"]:
        lines.append(f"  [{'x' if s['done'] else ' '}] {s['node']:<5} {s['title']}")
    return "\n".join(lines)


# -------------------------------------------------------------------- CLI
def add_cli(sub) -> None:
    p = sub.add_parser("inherited", help="the inherited company scenario (pre-built): hand it over, its status, "
                                       "the previous admin's notes")
    p.add_argument("lab")
    p.add_argument("op", nargs="?", default="status", choices=("status", "handover", "notes"),
                   help="status (default), handover (build the predecessor's company inside the running "
                        "machines), or notes (the handover notes)")


def run_cli(args) -> int:
    import sys
    from . import netplan, oncall, schema
    lab = schema.load(args.lab)
    if args.op == "status":
        print(render(lab))
        return 0
    if args.op == "notes":
        if not lab.inherited:
            print(f"{lab.name} is not the inherited company scenario", file=sys.stderr)
            return 1
        print(handover_text(plan(lab)))
        return 0
    try:
        handover(lab, guest_runner(lab.name), role_builder(lab, netplan.compile_topology(lab, check_ports=False)),
                 oncall.running_nodes(lab))
    except HandoverError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0
