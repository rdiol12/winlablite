"""Lessons: the study layer over the lab.

A lesson is one topic a student works through on a lab: why it matters, the
concepts, the hands-on steps, commands that show whether it worked, and the
check. The check is the graded exercise when one exists; a lesson with none
is done when its steps are ticked. A lesson that names a role can show the
configuration winlab itself generates for that role as the model answer, and
a troubleshooting lesson names a guest fault to inject and then diagnose.

Lessons are TOML in content/lessons/, one per topic, ordered by module and
`order`. The modules follow CURRICULUM.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import content, paths

LESSONS = paths.CONTENT / "lessons"

# (id, title, blurb) in path order
MODULES: tuple[tuple[str, str, str], ...] = (
    ("start", "Getting started",
     "How the lab works, how to reach a machine, and how a lesson is checked."),
    ("identity", "Identity and Active Directory",
     "The directory everything else depends on: domain controllers, OUs, users, groups, Group Policy."),
    ("network", "Core network services",
     "DNS, DHCP, time, routing and VLANs: what a machine needs before it can find the domain."),
    ("workloads", "Server workloads",
     "File services, DFS, quotas, printing, PKI, web, updates, remote desktop, storage and backup."),
    ("security", "Security",
     "Firewall, hardening, auditing, LAPS, Defender, tiered admin accounts, reading the wire and "
     "spotting an attack in the logs."),
    ("endpoint", "Windows 11 endpoints",
     "The PC people sit at: BitLocker, local policy, apps and user profiles; then the desktop "
     "team's work: update rings, Edge, Microsoft 365 Apps, USMT, App Control, Credential Guard "
     "and Configuration Manager's applications, updates and task sequences."),
    ("cloud", "Hybrid cloud",
     "An office joined to a cloud virtual network by a site-to-site VPN: subnets and security "
     "groups, a jump host, private DNS, a replica DC, a share and a backup across the tunnel; "
     "then, in your own browser on a free Azure account, Entra ID, Conditional Access, Intune, "
     "Arc, Monitor and Update Manager; and for the desktop, Autopilot, Intune apps and update "
     "rings, co-management and Defender for Endpoint. Offline, against a simulated tenant inside "
     "the lab: directory sync with pass-through and password hash sign-in, device enrolment, "
     "compliance, profiles against Group Policy and Conditional Access."),
    ("linux", "Linux in the Windows domain",
     "The Linux track: Linux servers inside an Active Directory domain. A Samba file server joined "
     "with winbind whose shares take their permissions from Explorer, BIND as a secondary of the "
     "domain's zones and the primary of a delegated subdomain, Linux clients that log domain users "
     "in with SSSD and mount shares with Kerberos, and the faults that break them."),
    ("troubleshoot", "Troubleshooting",
     "Break a machine on purpose, read the symptom, find the cause, verify the fix."),
    ("operations", "Operations and automation",
     "Desired state, monitoring, remote administration, and the habits that keep a fleet healthy."),
    ("powershell", "PowerShell automation",
     "The PowerShell track: objects and the pipeline, functions with real parameters, a "
     "module of your own with help and Pester tests, remoting to many servers at once, bulk "
     "work from a CSV that is safe to run twice, and scripts that run on a schedule as a "
     "gMSA. The check calls your code with fresh data and compares the result with the "
     "machines."),
    ("devops", "DevOps and infrastructure as code",
     "The DevOps track, in a lab with no internet: your own Git server (Forgejo), branches and "
     "reviewed pull requests, a CI runner that tests, builds and pushes images to the lab's "
     "registry, secrets kept out of the code, deployments with Docker Compose, Ansible and "
     "OpenTofu run from the pipeline, a bad release rolled back, and a GitOps repository the "
     "servers follow."),
    ("capstone", "Capstone",
     "Bare machines and a client's brief: build the whole office yourself, graded in one go."),
)
MODULE_IDS = tuple(m[0] for m in MODULES)


class LessonError(Exception):
    pass


@dataclass
class Verify:
    label: str
    node: str
    cmd: str
    shell: str = "powershell"


@dataclass
class Question:
    """A recall question after the lesson: one right answer among two or
    three wrong ones (shown shuffled), and why the right one is right."""
    q: str
    answer: str
    wrong: list[str]
    why: str = ""

    @property
    def choices(self) -> list[str]:
        return [self.answer, *self.wrong]


@dataclass
class Lesson:
    id: str
    title: str
    module: str
    order: int = 100
    lab: str = ""
    node: str = ""
    role: str = ""          # model answer: the DSC configuration for this role
    answer_lab: str = ""    # where that role is defined, when not this lesson's lab/node
    answer_node: str = ""
    exercise: str = ""      # the graded check
    problem: str = ""       # a guest fault to inject (troubleshooting lessons)
    fault: str = ""         # a network fault to inject on the router instead
    fault_on: str = ""      # the segment that fault targets
    minutes: int = 30
    summary: str = ""
    why: str = ""
    concepts: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    verify: list[Verify] = field(default_factory=list)
    pitfalls: list[str] = field(default_factory=list)
    further: list[str] = field(default_factory=list)
    source: str = ""
    nodes: list[str] = field(default_factory=list)   # machines it needs running, when declared
    browser: bool = False   # done in the student's own browser, on their own cloud tenant: no machine
    quiz: list[Question] = field(default_factory=list)   # recall questions after the lesson
    tracks: list[str] = field(default_factory=list)   # tracks it counts toward beyond its module's (winlab/tracks.py)

    def needed_nodes(self) -> list[str]:
        """The machines the Lab guide's "Start these machines" boots for this
        lesson (plus the domain controller they depend on, added at boot time
        by membudget.with_dependencies): the declared `nodes`, or else every
        machine the lesson works on, verifies on, or its exercise checks."""
        if self.browser:
            return []
        if self.nodes:
            return list(self.nodes)
        out: list[str] = []
        for n in [self.node] + [v.node for v in self.verify]:
            if n and n not in out and n != "fabric":   # the router is always up
                out.append(n)
        if self.exercise:
            from . import exercises
            try:
                for n in exercises.load(self.exercise).needed_nodes():
                    if n not in out:
                        out.append(n)
            except (exercises.ExerciseError, OSError):
                pass
        return out

    @property
    def module_title(self) -> str:
        for mid, title, _ in MODULES:
            if mid == self.module:
                return title
        return self.module

    @property
    def check_kind(self) -> str:
        """How the lesson is checked: a graded exercise, a verified fix, or
        the student ticking the steps."""
        if self.exercise:
            return "exercise"
        if self.problem:
            return "problem"
        return "steps"


def lesson_path(ident: str) -> Path:
    p = Path(ident)
    if content.exists(p):
        return p
    cand = LESSONS / f"{ident}.toml"
    if content.exists(cand):
        return cand
    if content.locked(cand):
        raise LessonError(f"the lesson {ident} is part of the full version. {content.UNLOCK_HINT}")
    raise LessonError(f"lesson not found: {ident}")


def _strs(raw, key: str, path: Path) -> list[str]:
    v = raw.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise LessonError(f"{path.name}: '{key}' must be a list of strings")
    return [x.strip() for x in v if x.strip()]


def load(ident: str) -> Lesson:
    path = lesson_path(ident)
    raw = content.load_toml(path)
    meta = raw.get("lesson")
    if not isinstance(meta, dict) or not meta.get("id"):
        raise LessonError(f"{path.name}: [lesson] missing 'id'")
    module = str(meta.get("module", ""))
    if module not in MODULE_IDS:
        raise LessonError(f"{path.name}: unknown module '{module}' (use {', '.join(MODULE_IDS)})")
    verify = []
    for v in raw.get("verify", []):
        if not v.get("cmd"):
            raise LessonError(f"{path.name}: a [[verify]] needs 'cmd'")
        verify.append(Verify(label=str(v.get("label", v["cmd"])), node=str(v.get("node", meta.get("node", ""))),
                             cmd=str(v["cmd"]), shell=str(v.get("shell", "powershell"))))
    quiz = []
    for i, q in enumerate(raw.get("quiz", []), 1):
        wrong = q.get("wrong", [])
        if not q.get("q") or not q.get("answer"):
            raise LessonError(f"{path.name}: quiz question {i} needs 'q' and 'answer'")
        if not isinstance(wrong, list) or not 1 <= len(wrong) <= 4 or not all(isinstance(w, str) for w in wrong):
            raise LessonError(f"{path.name}: quiz question {i} needs one to four 'wrong' answers")
        if str(q["answer"]).strip() in [w.strip() for w in wrong]:
            raise LessonError(f"{path.name}: quiz question {i} lists its answer as wrong")
        quiz.append(Question(q=str(q["q"]).strip(), answer=str(q["answer"]).strip(),
                             wrong=[w.strip() for w in wrong], why=str(q.get("why", "")).strip()))
    lesson = Lesson(
        id=str(meta["id"]),
        title=str(meta.get("title", meta["id"])),
        module=module,
        order=int(meta.get("order", 100)),
        lab=str(meta.get("lab", "")),
        node=str(meta.get("node", "")),
        role=str(meta.get("role", "")),
        answer_lab=str(meta.get("answer_lab", "")) or str(meta.get("lab", "")),
        answer_node=str(meta.get("answer_node", "")) or str(meta.get("node", "")),
        exercise=str(meta.get("exercise", "")),
        problem=str(meta.get("problem", "")),
        fault=str(meta.get("fault", "")),
        fault_on=str(meta.get("fault_on", "")),
        minutes=int(meta.get("minutes", 30)),
        summary=str(meta.get("summary", "")).strip(),
        why=str(meta.get("why", "")).strip(),
        concepts=_strs(meta, "concepts", path),
        steps=_strs(meta, "steps", path),
        verify=verify,
        pitfalls=_strs(meta, "pitfalls", path),
        further=_strs(meta, "further", path),
        source=str(path),
        nodes=_strs(meta, "nodes", path),
        browser=bool(meta.get("browser", False)),
        quiz=quiz,
        tracks=_strs(meta, "tracks", path),
    )
    from . import edition
    if edition.is_core() and lesson.role and not content.exists(paths.LABS / f"{lesson.answer_lab}.toml"):
        # The model answer is built from a lab winlab core does not ship.
        lesson.role = lesson.answer_node = ""
    lesson = translated(lesson)
    # Written against winlab's names; read in the ones the student chose.
    from . import naming
    return naming.for_lab(lesson.lab).lesson(lesson) if lesson.lab else lesson


def translated(lesson: Lesson, lang: str | None = None) -> Lesson:
    """The lesson in the desktop's language: content/i18n/lessons/<lang>/<id>.json
    holds its title, summary, why, concepts, steps, pitfalls, verify labels and
    quiz. A field whose translation is missing, or a list whose length does not
    match the English one, stays in English; commands and checks never change."""
    from . import i18n
    lang = lang or i18n.current()
    if lang == "en":
        return lesson
    tr = i18n.lesson_table(lang, lesson.id)
    if not tr:
        return lesson
    from dataclasses import replace

    def text(key, cur):
        v = tr.get(key)
        return v.strip() if isinstance(v, str) and v.strip() else cur

    def strs(key, cur):
        v = tr.get(key)
        ok = isinstance(v, list) and len(v) == len(cur) and all(isinstance(x, str) and x.strip() for x in v)
        return [x.strip() for x in v] if ok else cur

    labels = strs("verify", [v.label for v in lesson.verify])
    verify = [replace(v, label=l) for v, l in zip(lesson.verify, labels)]
    quiz = list(lesson.quiz)
    tq = tr.get("quiz")
    if isinstance(tq, list) and len(tq) == len(quiz):
        out = []
        for q, t in zip(quiz, tq):
            if not isinstance(t, dict):
                out.append(q)
                continue
            wrong = t.get("wrong")
            wrong = [w.strip() for w in wrong] if isinstance(wrong, list) and len(wrong) == len(q.wrong) \
                and all(isinstance(w, str) and w.strip() for w in wrong) else None
            ans = t.get("answer")
            if not (isinstance(t.get("q"), str) and isinstance(ans, str) and ans.strip() and wrong) \
                    or ans.strip() in wrong:
                out.append(q)
                continue
            out.append(Question(q=t["q"].strip(), answer=ans.strip(), wrong=wrong,
                                why=t["why"].strip() if isinstance(t.get("why"), str) else q.why))
        quiz = out
    return replace(lesson, title=text("title", lesson.title), summary=text("summary", lesson.summary),
                   why=text("why", lesson.why), concepts=strs("concepts", lesson.concepts),
                   steps=strs("steps", lesson.steps), pitfalls=strs("pitfalls", lesson.pitfalls),
                   verify=verify, quiz=quiz)


def footprint(lesson: Lesson) -> tuple[list[str], int, int] | None:
    """(machines, MB as defined, MB trimmed to the floor) that starting this
    lesson's machines costs, the fabric and the domain controller they need
    included; None when the lesson names no lab or it cannot be loaded."""
    from . import membudget, netplan, schema

    if not lesson.lab or lesson.browser:
        return None
    try:
        lab = schema.load(lesson.lab)
        ids, _ = membudget.with_dependencies(lab, lesson.needed_nodes())
    except (schema.LabError, membudget.BudgetError):
        return None
    fabric = netplan.compile_topology(lab, check_ports=False).fabric_memory_mb
    return ids, membudget.plan(lab, ids, fabric, 0).need_mb, membudget.floor_mb(lab, ids, fabric)


def list_available() -> list[Lesson]:
    """Every lesson, in path order: module order, then `order`, then id."""
    out: list[Lesson] = []
    if not LESSONS.exists():
        return out
    for f in content.glob(LESSONS, "*.toml"):
        try:
            out.append(load(f))
        except LessonError:
            continue
    out.sort(key=lambda x: (MODULE_IDS.index(x.module), x.order, x.id))
    return out


def by_module(lessons: list[Lesson] | None = None) -> list[dict]:
    lessons = list_available() if lessons is None else lessons
    out = []
    for mid, title, blurb in MODULES:
        items = [l for l in lessons if l.module == mid]
        if items:
            out.append({"id": mid, "title": title, "blurb": blurb, "lessons": items})
    return out


def validate_all(lessons: list[Lesson] | None = None) -> list[str]:
    """Problems a content author must fix: dangling lab, node, exercise, role
    or problem references, duplicate ids, exercises without a lesson."""
    from . import exercises, guestfaults, roles, schema

    lessons = list_available() if lessons is None else lessons
    problems: list[str] = []
    seen: set[str] = set()
    manifest = roles.load_manifest()
    ex_ids = {e.id for e in exercises.list_available()}
    labs: dict[str, object] = {}
    for l in lessons:
        if l.id in seen:
            problems.append(f"{l.id}: duplicate id")
        seen.add(l.id)
        if not l.lab:
            problems.append(f"{l.id}: no lab")
            continue
        if l.lab not in labs:
            try:
                labs[l.lab] = schema.load(l.lab)
            except schema.LabError as exc:
                problems.append(f"{l.id}: lab {l.lab}: {exc}")
                labs[l.lab] = None
        lab = labs[l.lab]
        if lab is not None:
            if l.node and l.node not in lab.nodes:
                problems.append(f"{l.id}: node {l.node} not in lab {l.lab}")
            for v in l.verify:
                if v.node and v.node != "fabric" and v.node not in lab.nodes:
                    problems.append(f"{l.id}: verify '{v.label}' targets {v.node}, not in {l.lab}")
            for n in l.nodes:
                if n not in lab.nodes:
                    problems.append(f"{l.id}: nodes lists {n}, not in {l.lab}")
        if l.role and l.role not in manifest:
            problems.append(f"{l.id}: unknown role {l.role}")
        elif l.role:
            if l.answer_lab not in labs:
                try:
                    labs[l.answer_lab] = schema.load(l.answer_lab)
                except schema.LabLocked:
                    labs[l.answer_lab] = None   # trial: the model answer opens with a licence
                except schema.LabError as exc:
                    problems.append(f"{l.id}: answer lab {l.answer_lab}: {exc}")
                    labs[l.answer_lab] = None
            alab = labs[l.answer_lab]
            if alab is not None:
                anode = alab.nodes.get(l.answer_node)
                if anode is None:
                    problems.append(f"{l.id}: answer node {l.answer_node} not in {l.answer_lab}")
                elif l.role not in roles.effective_roles(anode):
                    problems.append(f"{l.id}: role {l.role} is not on {l.answer_node} in {l.answer_lab}")
        if l.exercise and l.exercise not in ex_ids:
            problems.append(f"{l.id}: unknown exercise {l.exercise}")
        if l.problem and l.problem not in guestfaults.SCENARIOS:
            problems.append(f"{l.id}: unknown problem {l.problem}")
        elif l.problem and lab is not None and l.node in lab.nodes:
            n = lab.nodes[l.node]
            if not guestfaults.applies_to(guestfaults.SCENARIOS[l.problem], n.kind, n.image,
                                          roles.effective_roles(n)):
                problems.append(f"{l.id}: problem {l.problem} cannot run on {l.node}")
        if l.fault:
            from . import faults
            if l.fault not in faults.SCENARIOS:
                problems.append(f"{l.id}: unknown network fault {l.fault}")
            elif l.lab and l.fault_on:
                try:
                    if l.fault_on not in schema.load(l.lab).networks:
                        problems.append(f"{l.id}: fault_on {l.fault_on} not in {l.lab}")
                except schema.LabError:
                    pass
        if not l.steps:
            problems.append(f"{l.id}: no steps")
        if not l.why:
            problems.append(f"{l.id}: no 'why'")
        if len(l.quiz) < 3:
            problems.append(f"{l.id}: fewer than three recall questions")
    covered = {l.exercise for l in lessons if l.exercise}
    # an exam-only exercise is graded by a practice exam's lab tasks instead
    covered |= {e.id for e in exercises.list_available() if e.exam_only}
    for ex_id in sorted(ex_ids - covered):
        problems.append(f"exercise {ex_id} has no lesson")
    return problems


def write_scripts(out: Path) -> list[Path]:
    """Every PowerShell snippet the learning layer runs in a guest, one .ps1
    per snippet: exercise checks, lesson verify commands, and each guest
    fault's break, fix and verify (parameters filled with the defaults). CI
    parses them all with Windows PowerShell 5.1 (tools/Test-PsSyntax.ps1),
    which is the only parser that can say a check is well formed before a
    student runs it."""
    from . import exercises, guestfaults

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    def put(name: str, text: str) -> None:
        f = out / f"{name}.ps1"
        f.write_text(text.strip() + "\n", encoding="utf-8-sig")
        written.append(f)

    for ex in exercises.list_available():
        for i, c in enumerate(ex.checks, 1):
            if c.shell == "powershell":
                put(f"exercise-{ex.id}-{i}", c.script)
    for l in list_available():
        for i, v in enumerate(l.verify, 1):
            if v.shell == "powershell":
                put(f"lesson-{l.id}-{i}", v.cmd)
    from . import guide
    for g in [guide.load(f) for f in content.glob(guide.GUIDES, "*.toml")]:
        for i, st in enumerate(g.steps, 1):
            if st.check == "guest" and st.shell == "powershell":
                put(f"guide-{g.id}-{i}", st.script)
    for f in guestfaults.catalog():
        if f.shell != "powershell":
            continue
        cmd, _ = guestfaults.build_command(f.id, {}, False)
        put(f"fault-{f.id}-break", cmd)
        cmd, _ = guestfaults.build_command(f.id, {}, True)
        put(f"fault-{f.id}-fix", cmd)
        cmd, _, _ = guestfaults.verify_command(f.id, {})
        put(f"fault-{f.id}-verify", cmd)
    # Scenario days: their own injections, their task checks and the checks
    # that say the lab is ready (winlab/scenarios.py).
    from . import scenariofaults, scenarios
    for f in scenariofaults.FAULTS.values():
        for part in ("apply", "clear", "verify"):
            put(f"scenario-fault-{f.id}-{part}", guestfaults._fill(getattr(f, part), {}))
    for scn in scenarios.list_available():
        for t in scn.tasks:
            if not t.fault_beat and t.shell == "powershell":
                put(f"scenario-{scn.id}-{t.id}", t.script)
        for i, r in enumerate(scn.requires, 1):
            if r.shell == "powershell":
                put(f"scenario-{scn.id}-requires-{i}", r.script)
    return written


def model_answer(lesson: Lesson) -> str:
    """The DSC configuration winlab generates for the lesson's role on its
    node (the role plus what it needs), as the reference the student can
    compare their by-hand work against."""
    from . import dsc, netplan, roles, schema

    if not lesson.role or not lesson.answer_node:
        raise LessonError(f"{lesson.id} names no role and node for a model answer")
    lab = schema.load(lesson.answer_lab)
    node = lab.nodes.get(lesson.answer_node)
    if node is None:
        raise LessonError(f"{lesson.answer_node} is not in {lesson.answer_lab}")
    manifest = roles.load_manifest()
    plan = [rd.name for rd in roles.order_roles([lesson.role], manifest) if rd.engine == "dsc"]
    if not plan:
        raise LessonError(f"{lesson.role} is not a DSC role")
    topology = netplan.compile_topology(lab, check_ports=False)
    cfg = dsc.compile_node(node, lab, topology, plan)
    return dsc.render(cfg)


def quiz_view(lesson: Lesson, seed: int | None = None) -> list[dict]:
    """The questions with their choices shuffled, answers left out: what the
    Lab guide shows before the student answers."""
    import random
    rnd = random.Random(seed)
    out = []
    for i, q in enumerate(lesson.quiz):
        choices = q.choices
        rnd.shuffle(choices)
        out.append({"n": i, "q": q.q, "choices": choices})
    return out


def grade_quiz(lesson: Lesson, picked: list[str]) -> dict:
    """Marks the student's picks (one choice text per question, '' for a
    skipped one) and says why each right answer is right."""
    results = []
    for i, q in enumerate(lesson.quiz):
        got = picked[i].strip() if i < len(picked) and picked[i] else ""
        results.append({"n": i, "q": q.q, "picked": got, "ok": got == q.answer,
                        "answer": q.answer, "why": q.why})
    right = sum(1 for r in results if r["ok"])
    return {"right": right, "total": len(results), "results": results}


def render_brief(lesson: Lesson) -> str:
    lines = [f"{lesson.title}  [{lesson.id}]",
             f"module: {lesson.module_title}   lab: {lesson.lab}   about {lesson.minutes} min"]
    fp = footprint(lesson)
    if fp and fp[0]:
        least = f", {fp[2] / 1024:.1f} GiB at the least" if fp[2] < fp[1] else ""
        lines.append(f"machines: {', '.join(fp[0])}  ({fp[1] / 1024:.1f} GiB{least}): "
                     f"winlab learn start {lesson.id}")
    if lesson.summary:
        lines += ["", lesson.summary]
    if lesson.why:
        lines += ["", "why:", *("  " + ln for ln in lesson.why.splitlines())]
    if lesson.concepts:
        lines += ["", "concepts:", *(f"  - {c}" for c in lesson.concepts)]
    if lesson.steps:
        lines += ["", "steps:", *(f"  {i}. {s}" for i, s in enumerate(lesson.steps, 1))]
    if lesson.verify:
        lines += ["", "verify:", *(f"  {v.node}: {v.cmd}   # {v.label}" for v in lesson.verify)]
    if lesson.pitfalls:
        lines += ["", "pitfalls:", *(f"  - {p}" for p in lesson.pitfalls)]
    if lesson.exercise:
        lines += ["", f"check: winlab exercise grade {lesson.exercise}"]
    elif lesson.problem:
        lines += ["", f"check: winlab break {lesson.node} {lesson.problem}, fix it, "
                      f"then winlab break {lesson.node} {lesson.problem} --verify"]
    else:
        lines += ["", "check: tick every step in the dashboard's Learn tab"]
    if lesson.role:
        lines.append(f"model answer: winlab learn answer {lesson.id}")
    if lesson.quiz:
        lines.append(f"recall: {len(lesson.quiz)} questions, winlab learn quiz {lesson.id}")
    return "\n".join(lines)

