"""Exam readiness: the lessons mapped onto a certification's skill areas.

An exam file in content/exams/ names the exam, its skill areas with the
weights the study guide gives them, and the lessons that train each area.
Readiness is read from the student's own progress: the share of an area's
lessons done, and an overall figure where each area counts by the middle of
its exam weight. It says where to work next, not whether someone will pass.

A track is "practice for" an exam: winlab is not affiliated with the vendor,
and each file carries that notice. An area winlab has no lesson for is listed
as not covered (lessons = []), and every area can name the topics in it that
winlab does not train (gaps), so a student knows what to study elsewhere.
Readiness counts only the covered areas. The practice exam's question bank
for a track lives beside it, in <track>-questions.toml (winlab/practice_exam.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import paths

EXAMS = paths.CONTENT / "exams"


class ExamError(Exception):
    pass


@dataclass
class Area:
    id: str
    title: str
    weight: tuple[int, int]
    lessons: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)   # topics in this area winlab does not train

    @property
    def covered(self) -> bool:
        return bool(self.lessons)

    @property
    def mid_weight(self) -> float:
        return (self.weight[0] + self.weight[1]) / 2


@dataclass
class Exam:
    id: str
    title: str
    replaces: list[str] = field(default_factory=list)
    source: str = ""
    ready_at: int = 80
    areas: list[Area] = field(default_factory=list)
    vendor: str = ""
    notice: str = ""         # the not-affiliated and trademark line
    weights_note: str = ""   # where the weights come from and how sure they are
    pass_mark: int = 75      # the practice exam's target percent (not the real exam's scaled score)
    minutes: int = 60        # practice exam default length
    questions: int = 30      # practice exam default size


def load(ident: str) -> Exam:
    from . import content
    path = Path(ident) if Path(ident).suffix == ".toml" else EXAMS / f"{ident}.toml"
    try:
        raw = content.load_toml(path)
    except OSError as exc:
        raise ExamError(f"exam not found: {ident}") from exc
    meta = raw.get("exam") or {}
    if not meta.get("id"):
        raise ExamError(f"{path.name}: [exam] missing 'id'")
    areas = []
    for a in raw.get("area", []):
        w = a.get("weight") or [0, 0]
        if not a.get("id") or len(w) != 2:
            raise ExamError(f"{path.name}: an [[area]] needs 'id' and weight = [low, high]")
        areas.append(Area(id=str(a["id"]), title=str(a.get("title", a["id"])),
                          weight=(int(w[0]), int(w[1])), lessons=[str(x) for x in a.get("lessons", [])],
                          gaps=[str(x) for x in a.get("gaps", [])]))
    return Exam(id=str(meta["id"]), title=str(meta.get("title", meta["id"])),
                replaces=[str(x) for x in meta.get("replaces", [])], source=str(meta.get("source", "")),
                ready_at=int(meta.get("ready_at", 80)), areas=areas, vendor=str(meta.get("vendor", "")),
                notice=str(meta.get("notice", "")), weights_note=str(meta.get("weights_note", "")),
                pass_mark=int(meta.get("pass_mark", 75)), minutes=int(meta.get("minutes", 60)),
                questions=int(meta.get("questions", 30)))


def is_bank(path: Path) -> bool:
    """A track's question bank, not a track."""
    return path.stem.endswith("-questions")


def list_available() -> list[Exam]:
    out = []
    from . import content
    for f in content.glob(EXAMS, "*.toml"):
        if is_bank(f):
            continue
        try:
            out.append(load(str(f)))
        except ExamError:
            continue
    return out


def validate(exam: Exam, lesson_ids: set[str]) -> list[str]:
    """Problems an author must fix: unknown lessons, a lesson in two areas,
    weights that cannot add up to an exam."""
    problems = []
    seen: dict[str, str] = {}
    for a in exam.areas:
        for lid in a.lessons:
            if lid not in lesson_ids:
                problems.append(f"{exam.id}/{a.id}: unknown lesson {lid}")
            if lid in seen:
                problems.append(f"{exam.id}: {lid} is in {seen[lid]} and {a.id}")
            seen[lid] = a.id
        if a.weight[0] > a.weight[1] or a.weight[0] < 0:
            problems.append(f"{exam.id}/{a.id}: weight {list(a.weight)} is not [low, high]")
        if not a.lessons and not a.gaps:
            problems.append(f"{exam.id}/{a.id}: an area with no lessons must say what it lacks (gaps)")
    ids = [a.id for a in exam.areas]
    if len(set(ids)) != len(ids):
        problems.append(f"{exam.id}: duplicate area ids")
    if not any(a.covered for a in exam.areas):
        problems.append(f"{exam.id}: no area has a lesson")
    low = sum(a.weight[0] for a in exam.areas)
    high = sum(a.weight[1] for a in exam.areas)
    if not low <= 100 <= high:
        problems.append(f"{exam.id}: area weights {low}-{high}% cannot make 100%")
    if not 1 <= exam.pass_mark <= 100 or exam.minutes < 1 or exam.questions < 1:
        problems.append(f"{exam.id}: pass_mark, minutes and questions must be positive (pass_mark at most 100)")
    return problems


def readiness(exam: Exam, data: dict | None = None, titles: dict[str, str] | None = None) -> dict:
    """Per area: lessons done of total and percent; overall weighted percent;
    the weakest area and the next lesson to take in it. titles (lesson id ->
    title of every lesson) saves reading the lessons again per track."""
    from . import lessons as ls
    from . import progress

    data = progress.load() if data is None else data
    titles = {l.id: l.title for l in ls.list_available()} if titles is None else titles
    done = {k for k, v in data["lessons"].items() if v.get("status") == progress.STATUS_DONE}
    rows = []
    for a in exam.areas:
        have = [l for l in a.lessons if l in titles]
        n_done = sum(1 for l in have if l in done)
        pct = round(100 * n_done / len(have)) if have else 0
        nxt = next((l for l in have if l not in done), "")
        rows.append({"id": a.id, "title": a.title, "weight": list(a.weight), "done": n_done,
                     "total": len(have), "percent": pct, "next": nxt, "next_title": titles.get(nxt, ""),
                     "lessons": [{"id": l, "title": titles[l], "done": l in done} for l in have],
                     "covered": bool(have), "gaps": list(a.gaps)})
    pairs = [(r, a) for r, a in zip(rows, exam.areas) if r["covered"]]
    wsum = sum(a.mid_weight for _, a in pairs) or 1
    overall = round(sum(r["percent"] * a.mid_weight for r, a in pairs) / wsum)
    cov = [r for r, _ in pairs]
    weakest = min(cov, key=lambda r: (r["percent"], -r["weight"][1])) if cov else None
    total_w = sum(a.mid_weight for a in exam.areas) or 1
    return {"id": exam.id, "title": exam.title, "replaces": exam.replaces, "source": exam.source,
            "vendor": exam.vendor, "notice": exam.notice, "weights_note": exam.weights_note,
            "pass_mark": exam.pass_mark, "minutes": exam.minutes, "questions": exam.questions,
            "covered_weight": round(100 * sum(a.mid_weight for _, a in pairs) / total_w),
            "not_covered": [r["title"] for r in rows if not r["covered"]],
            "ready_at": exam.ready_at, "overall": overall, "areas": rows,
            "ready": bool(cov) and all(r["percent"] >= exam.ready_at for r in cov),
            "weakest": weakest["id"] if weakest else "",
            "next": weakest["next"] if weakest else "", "next_title": weakest["next_title"] if weakest else ""}


def render(r: dict) -> str:
    lines = [r["title"], f"replaces {', '.join(r['replaces'])}" if r["replaces"] else None, ""]
    for a in r["areas"]:
        w = f"{a['weight'][0]}-{a['weight'][1]}%" if a["weight"][0] != a["weight"][1] else f"{a['weight'][0]}%"
        if not a.get("covered", True):
            lines.append(f"  [{'not covered in winlab':^20}]        {a['title']} ({w} of the exam)")
            continue
        bar = "#" * (a["percent"] // 5) + "." * (20 - a["percent"] // 5)
        lines.append(f"  [{bar}] {a['percent']:>3}%  {a['done']}/{a['total']}  "
                     f"{a['title']} ({w} of the exam)")
        if a.get("gaps"):
            lines.append(f"{'':30}not covered in winlab: {'; '.join(a['gaps'])}")
    lines += ["", f"overall {r['overall']}% (weighted by the exam's areas); "
                  + ("ready to book it" if r["ready"] else f"aim for {r['ready_at']}% in every area")]
    if r["next"]:
        lines.append(f"next: {r['next']}  {r['next_title']}  (winlab learn show {r['next']})")
    if r.get("notice"):
        lines += ["", r["notice"]]
    return "\n".join(x for x in lines if x is not None)
