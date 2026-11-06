"""The command reference: every command the lessons use, searchable.

content/commands.toml says what each command does in one line; this module
finds where the lessons use it (their steps, the commands they run to show a
result, concepts and pitfalls) and keeps those lines as worked examples, so
the reference is a cheat sheet built from the course itself. Exercise hints
stay out: they are the answers.

Every PowerShell cmdlet a lesson names must have an entry; undocumented()
lists the ones that do not, and the test suite keeps that list empty.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field

from . import paths

COMMANDS = paths.CONTENT / "commands.toml"

KINDS: tuple[tuple[str, str], ...] = (
    ("powershell", "PowerShell"),
    ("windows", "Windows tools"),
    ("linux", "Linux"),
    ("firewall", "Firewall shell"),
    ("sql", "SQL Server"),
    ("cloud", "Azure"),
    ("switch", "Switch and router console"),
)
KIND_IDS = tuple(k for k, _ in KINDS)

# PowerShell's approved verbs plus the few common cmdlets that use others
# (ForEach-Object, Where-Object, Sort-Object, Tee-Object).
_VERBS = (
    "Add Approve Assert Backup Block Build Checkpoint Clear Close Compare Complete Compress "
    "Confirm Connect Convert ConvertFrom ConvertTo Copy Debug Deny Deploy Disable Disconnect "
    "Dismount Edit Enable Enter Exit Expand Export Find ForEach Format Get Grant Group Hide "
    "Import Initialize Install Invoke Join Limit Lock Measure Merge Mount Move New Open "
    "Optimize Out Ping Pop Protect Publish Push Read Receive Redo Register Remove Rename "
    "Repair Request Reset Resize Resolve Restart Restore Resume Revoke Save Search Select "
    "Send Set Show Skip Sort Split Start Step Stop Submit Suspend Switch Sync Tee Test Trace "
    "Unblock Undo Uninstall Unlock Unprotect Unpublish Unregister Update Use Wait Watch "
    "Where Write").split()
CMDLET = re.compile(r"(?<![\w-])(?:" + "|".join(_VERBS) + r")-[A-Z][A-Za-z0-9]+\b")

# What a cmdlet is about, from its noun; first match wins.
_AREAS: tuple[tuple[str, str], ...] = (
    ("ADReplication", "Sites and replication"),
    ("Laps", "Security"), ("BitLocker", "Security"), ("Mp", "Security"), ("AppLocker", "Security"),
    ("NTFS", "Files and storage"),
    ("AD", "Active Directory"), ("Kds", "Active Directory"), ("Computer", "Active Directory"),
    ("Dns", "DNS"), ("Dhcp", "DHCP"), ("GP", "Group Policy"),
    ("Cluster", "Clustering"), ("VM", "Clustering"),
    ("Dfs", "Files and storage"), ("Fsrm", "Files and storage"), ("Smb", "Files and storage"),
    ("Dedup", "Files and storage"), ("Iscsi", "Files and storage"), ("Storage", "Files and storage"),
    ("VirtualDisk", "Files and storage"), ("Disk", "Files and storage"), ("Volume", "Files and storage"),
    ("Partition", "Files and storage"),
    ("NetFirewall", "Firewall"), ("Net", "Networking"), ("VpnS2S", "Networking"),
    ("RemoteAccess", "Networking"), ("Nps", "Networking"),
    ("WB", "Backup"), ("Wsus", "Updates"), ("WindowsUpdate", "Updates"),
    ("IIS", "Web and certificates"), ("Web", "Web and certificates"), ("Certificate", "Web and certificates"),
    ("Printer", "Printing"), ("PrintJob", "Printing"),
    ("PSSession", "Remoting"), ("PSRole", "Remoting"), ("Command", "Remoting"),
    ("Dsc", "Desired state"), ("Az", "Azure"), ("CM", "Configuration Manager"),
    ("Adfs", "Federation"),
)


class CommandError(Exception):
    pass


@dataclass
class Use:
    lesson: str
    title: str
    text: str


@dataclass
class Command:
    name: str
    kind: str
    what: str
    area: str = ""
    pattern: str = ""
    uses: list[Use] = field(default_factory=list)

    @property
    def lessons(self) -> list[str]:
        out: list[str] = []
        for u in self.uses:
            if u.lesson not in out:
                out.append(u.lesson)
        return out


def area_of(cmdlet: str) -> str:
    noun = cmdlet.split("-", 1)[1] if "-" in cmdlet else cmdlet
    for prefix, area in _AREAS:
        if noun.startswith(prefix):
            return area
    return "PowerShell"


_WORD = re.compile(r"[\w-]+")


def _regex(c: Command) -> re.Pattern:
    if c.pattern:
        return re.compile(c.pattern)
    return re.compile(r"(?<![\w-])" + re.escape(c.name) + r"(?![\w-])",
                      re.IGNORECASE if c.kind == "powershell" else 0)


def load_catalog() -> dict[str, Command]:
    """The entries of commands.toml, without their uses."""
    with COMMANDS.open("rb") as fh:
        raw = tomllib.load(fh)
    unknown = set(raw) - set(KIND_IDS) - {"match"}
    if unknown:
        raise CommandError(f"commands.toml: unknown section(s) {', '.join(sorted(unknown))}")
    match = raw.get("match") or {}
    out: dict[str, Command] = {}
    for kind in KIND_IDS:
        for name, what in (raw.get(kind) or {}).items():
            if name in out:
                raise CommandError(f"commands.toml: {name} is listed twice")
            if not str(what).strip():
                raise CommandError(f"commands.toml: {name} says nothing")
            out[name] = Command(name=name, kind=kind, what=str(what).strip(),
                                area=area_of(name) if kind == "powershell" else dict(KINDS)[kind],
                                pattern=str(match.get(name, "")))
    for name in match:
        if name not in out:
            raise CommandError(f"commands.toml: [match] names {name}, which no section lists")
    return out


def _lesson_texts(lesson) -> list[str]:
    return ([*lesson.steps] + [v.cmd for v in lesson.verify]
            + [*lesson.concepts] + [*lesson.pitfalls])


def catalog(lessons_=None, per_command: int = 6) -> list[Command]:
    """Every command with up to per_command lines from the lessons that use
    it, in path order, sorted by kind then name."""
    from . import lessons as ls

    cmds = load_catalog()
    regex = {n: _regex(c) for n, c in cmds.items()}
    keys = {n: n.lower() for n in cmds}
    # A plain name only ever matches as a whole word of the line.
    plain = {n for n, c in cmds.items() if not c.pattern and _WORD.fullmatch(n)}
    for lesson in (ls.list_available() if lessons_ is None else lessons_):
        texts = _lesson_texts(lesson)
        # The plain name is in every match: a cheap test on the whole lesson
        # first leaves a few names to try on each line.
        blob = "\n".join(texts).lower()
        words = set(_WORD.findall(blob))
        here = [(n, rx) for n, rx in regex.items() if (keys[n] in words if n in plain else keys[n] in blob)]
        for text in texts:
            low = text.lower()
            for name, rx in here:
                if keys[name] in low and rx.search(text):
                    c = cmds[name]
                    if len(c.uses) < per_command and not any(u.text == text for u in c.uses):
                        c.uses.append(Use(lesson.id, lesson.title, text))
                    elif lesson.id not in c.lessons:
                        c.uses.append(Use(lesson.id, lesson.title, ""))
    return sorted(cmds.values(), key=lambda c: (KIND_IDS.index(c.kind), c.name.lower()))


def undocumented(lessons_=None) -> list[tuple[str, str]]:
    """(cmdlet, lesson id) for every cmdlet a lesson names that commands.toml
    does not list."""
    from . import lessons as ls

    known = {n.lower() for n, c in load_catalog().items() if c.kind == "powershell"}
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for lesson in (ls.list_available() if lessons_ is None else lessons_):
        for text in _lesson_texts(lesson):
            for m in CMDLET.findall(text):
                if m.lower() not in known and m.lower() not in seen:
                    seen.add(m.lower())
                    out.append((m, lesson.id))
    return out


def search(query: str, kind: str = "", cmds: list[Command] | None = None) -> list[Command]:
    """Commands whose name, description or area match every word of the
    query; a name match ranks first, then a description match, then a match
    only in the lessons' lines."""
    cmds = catalog() if cmds is None else cmds
    words = [w for w in query.lower().split() if w]
    out: list[tuple[int, Command]] = []
    for c in cmds:
        if kind and c.kind != kind:
            continue
        name, desc = c.name.lower(), f"{c.what} {c.area}".lower()
        body = " ".join(u.text for u in c.uses).lower() + " " + " ".join(c.lessons)
        if not words:
            out.append((0, c))
            continue
        if not all(w in name or w in desc or w in body for w in words):
            continue
        rank = 0 if all(w in name for w in words) else 1 if all(w in name or w in desc for w in words) else 2
        out.append((rank, c))
    return [c for _, c in sorted(out, key=lambda x: x[0])]


def as_dict(c: Command) -> dict:
    return {"name": c.name, "kind": c.kind, "area": c.area, "what": c.what,
            "lessons": c.lessons,
            "examples": [{"lesson": u.lesson, "title": u.title, "text": u.text} for u in c.uses if u.text]}


def render(cmds: list[Command], examples: int = 2) -> str:
    if not cmds:
        return "no command matches"
    lines: list[str] = []
    kind = ""
    for c in cmds:
        if c.kind != kind:
            kind = c.kind
            if lines:
                lines.append("")
            lines.append(dict(KINDS)[kind])
        lines.append(f"  {c.name:<38} {c.what}")
        for u in [u for u in c.uses if u.text][:examples]:
            lines.append(f"  {'':<38}   e.g. ({u.lesson}) {u.text}")
        if c.lessons:
            more = len(c.lessons)
            lines.append(f"  {'':<38}   in {more} lesson{'s' if more != 1 else ''}: {', '.join(c.lessons[:5])}"
                         + (" ..." if more > 5 else ""))
    return "\n".join(lines)
