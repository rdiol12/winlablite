"""The people who work at the lab's company.

A lab that feels like a job has colleagues: someone in Finance whose PC is
pc01, a receptionist on extension 201, a manager who calls when the printer
jams. The directory is made once per lab, from a seed so the same lab always
gets the same staff, and kept in var/labs/<lab>/people.json where the student
(or a teacher) can edit it. Nothing here touches a machine: the helpdesk
queue takes its callers from here, the simulated workday logs these people on
and has them save, print and mail, on-call alerts page the admin listed here,
and the inventory names an owner for each PC.

Accounts are not made for anyone. A person's `account` is the user name the
student is expected to create (from the new-starter sheet), and their
password is the student's business: the workday asks the student to type it
into the staff list, never a value stored in the repo.
"""

from __future__ import annotations

import json
import random
import zlib
from pathlib import Path

from . import paths

FIRST = ("Alex", "Amara", "Ana", "Chloe", "Daniel", "Diego", "Farid", "Grace", "Hannah", "Jamal",
         "Jonas", "Kofi", "Lars", "Lena", "Marco", "Maya", "Mei", "Nadia", "Omar", "Priya",
         "Rosa", "Sam", "Tomas", "Yuki", "Zara", "Ivan", "Leila", "Noah", "Elif", "Ben")
LAST = ("Abara", "Berg", "Costa", "Dubois", "Evans", "Fischer", "Garcia", "Haddad", "Ito", "Jensen",
        "Kowalski", "Lindqvist", "Mensah", "Novak", "Okafor", "Patel", "Quinn", "Rossi", "Silva",
        "Tanaka", "Ueda", "Varga", "Weber", "Xu", "Yilmaz", "Zimmer", "Moreau", "Nguyen", "Park", "Reyes")
# (department, job titles); the first entry of the first department is the admin: the student.
DEPARTMENTS = (
    ("IT", ("Systems administrator", "IT manager")),
    ("Front desk", ("Receptionist",)),
    ("Finance", ("Accountant", "Finance manager", "Payroll officer")),
    ("Sales", ("Sales rep", "Sales manager", "Account manager")),
    ("HR", ("HR officer", "HR manager")),
    ("Operations", ("Office manager", "Operations lead", "Buyer")),
)
DEFAULT_COUNT = 12
FIRST_EXT = 201


def people_file(lab_name: str) -> Path:
    return paths.lab_dir(lab_name) / "people.json"


def _seed(lab_name: str) -> int:
    return zlib.crc32(lab_name.encode("utf-8"))


def desk_pcs(lab) -> list[str]:
    """Machines a member of staff sits at: Windows clients first, then any
    other non-server, in lab order."""
    from .model import LINUX, WINDOWS_CLIENT
    wins = [nid for nid, n in lab.nodes.items() if n.kind == WINDOWS_CLIENT]
    others = [nid for nid, n in lab.nodes.items()
              if n.kind == LINUX and nid.startswith(("pc", "ws", "laptop", "desk"))]
    return wins + others


def generate(lab, count: int = DEFAULT_COUNT, rng: random.Random | None = None) -> list[dict]:
    """A fresh directory for `lab`: one admin (the student, `admin`) and
    `count - 1` staff spread over the departments, each with an account name,
    a mail address in the lab's domain, a phone extension and, while there
    are desk PCs left, a PC; then the IT manager the admin reports to, who
    takes the on-call page the admin leaves unanswered. The manager comes
    last so that adding them changed nobody else's name, account or PC."""
    rng = rng or random.Random(_seed(lab.name))
    domain = (lab.domain or "corp.lab").lower()
    pcs = desk_pcs(lab)
    firsts, lasts = list(FIRST), list(LAST)
    rng.shuffle(firsts)
    rng.shuffle(lasts)
    out: list[dict] = []
    taken: set[str] = set()
    for i in range(max(1, count)):
        first, last = firsts[i % len(firsts)], lasts[i % len(lasts)]
        if i == 0:
            dept, title = DEPARTMENTS[0][0], DEPARTMENTS[0][1][0]
        else:
            dept, titles = DEPARTMENTS[1 + (i - 1) % (len(DEPARTMENTS) - 1)]
            title = titles[rng.randrange(len(titles))]
        account = (first[0] + last).lower()
        n = 2
        while account in taken:
            account, n = f"{(first[0] + last).lower()}{n}", n + 1
        taken.add(account)
        out.append({
            "id": "admin" if i == 0 else account,
            "first": first, "last": last, "name": f"{first} {last}",
            "department": dept, "title": title,
            "account": account, "mail": f"{account}@{domain}",
            "ext": FIRST_EXT + i,
            "pc": pcs[i - 1] if 0 < i <= len(pcs) else "",
            "manager": False,
            "admin": i == 0,
        })
    for dept, _ in DEPARTMENTS[1:]:
        staff = [p for p in out if p["department"] == dept]
        if staff:
            mgr = next((p for p in staff if "manager" in p["title"].lower()), staff[0])
            mgr["manager"] = True
    out.append(_it_manager(out, firsts, lasts, domain))
    return out


def _it_manager(out: list[dict], firsts: list[str], lasts: list[str], domain: str) -> dict:
    i = len(out)
    first, last = firsts[i % len(firsts)], lasts[i % len(lasts)]
    taken = {p["account"] for p in out}
    account, n = (first[0] + last).lower(), 2
    while account in taken:
        account, n = f"{(first[0] + last).lower()}{n}", n + 1
    return {"id": account, "first": first, "last": last, "name": f"{first} {last}",
            "department": DEPARTMENTS[0][0], "title": DEPARTMENTS[0][1][1],
            "account": account, "mail": f"{account}@{domain}",
            "ext": max([FIRST_EXT - 1] + [int(p.get("ext") or 0) for p in out]) + 1,
            "pc": "", "manager": True, "admin": False}


def it_manager(people: list[dict]) -> dict | None:
    return next((p for p in people if p.get("department") == DEPARTMENTS[0][0] and p.get("manager")), None)


def load(lab) -> list[dict]:
    """The lab's directory: what people.json holds, or a generated one
    (saved, so it stays put once the lab has used it)."""
    f = people_file(lab.name)
    try:
        raw = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(raw, list) and raw:
            if it_manager(raw) is None:
                # A directory made before IT had a manager: add one, keep everyone else.
                rng = random.Random(_seed(lab.name))
                firsts, lasts = list(FIRST), list(LAST)
                rng.shuffle(firsts)
                rng.shuffle(lasts)
                raw.append(_it_manager(raw, firsts, lasts, (lab.domain or "corp.lab").lower()))
                save(lab.name, raw)
            return raw
    except (OSError, ValueError):
        pass
    out = generate(lab)
    save(lab.name, out)
    return out


def save(lab_name: str, people: list[dict]) -> None:
    f = people_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(people, indent=2), encoding="utf-8")
    tmp.replace(f)


def find(people: list[dict], key: str) -> dict | None:
    """A person by id, account, mail, extension or full name (any case)."""
    k = str(key).strip().lower()
    for p in people:
        if k in (str(p.get("id", "")).lower(), str(p.get("account", "")).lower(),
                 str(p.get("mail", "")).lower(), str(p.get("ext", "")), str(p.get("name", "")).lower()):
            return p
    return None


def admin(people: list[dict]) -> dict:
    return next((p for p in people if p.get("admin")), people[0])


def at_pc(people: list[dict], node_id: str) -> dict | None:
    return next((p for p in people if p.get("pc") == node_id), None)


# The columns HR hands IT: who works here, where, and at which PC.
DIRECTORY_FIELDS = ("account", "name", "department", "title", "mail", "ext", "pc")


def directory_csv(people: list[dict]) -> str:
    """The staff directory as a CSV (UTF-8, comma separated, a header row),
    for the HR stick and for import into an inventory or a vault."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(DIRECTORY_FIELDS)
    for p in people:
        w.writerow([p.get(k, "") for k in DIRECTORY_FIELDS])
    return buf.getvalue()


def directory_text(people: list[dict], domain: str = "") -> str:
    """The same directory as a printout to read on screen or pin up."""
    rows = [("Name", "Account", "Department", "Title", "Ext", "PC")]
    rows += [(p.get("name", ""), p.get("account", ""), p.get("department", ""), p.get("title", ""),
              str(p.get("ext", "")), p.get("pc", "") or "-") for p in people]
    width = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    out = [f"Staff directory{' - ' + domain if domain else ''}", ""]
    for i, r in enumerate(rows):
        out.append("  ".join(c.ljust(width[j]) for j, c in enumerate(r)).rstrip())
        if i == 0:
            out.append("  ".join("-" * w for w in width))
    return "\r\n".join(out) + "\r\n"
