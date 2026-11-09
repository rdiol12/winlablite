"""Lesson translations: what to translate and what is still missing.

  python tools/i18n_lessons.py source <lesson-id>      the English fields as JSON
  python tools/i18n_lessons.py missing <lang>          lesson ids with no (or an incomplete) translation
  python tools/i18n_lessons.py check <lang>            problems in the translation files

A translation is content/i18n/lessons/<lang>/<id>.json with the same shape as
`source`: title, summary, why, concepts, steps, pitfalls, verify (the check
labels) and quiz ([{q, answer, wrong, why}]). Commands, paths, names and
anything a student types stay exactly as in English.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from winlab import content, paths  # noqa: E402

LESSONS = paths.CONTENT / "lessons"
OUT = paths.CONTENT / "i18n" / "lessons"


def source(ident: str) -> dict:
    raw = content.load_toml(LESSONS / f"{ident}.toml")
    m = raw["lesson"]
    s = lambda k: str(m.get(k, "")).strip()
    lst = lambda k: [str(x).strip() for x in m.get(k, [])]
    return {"title": s("title"), "summary": s("summary"), "why": s("why"),
            "concepts": lst("concepts"), "steps": lst("steps"), "pitfalls": lst("pitfalls"),
            "verify": [str(v.get("label", v.get("cmd", ""))) for v in raw.get("verify", [])],
            "quiz": [{"q": str(q["q"]).strip(), "answer": str(q["answer"]).strip(),
                      "wrong": [str(w).strip() for w in q.get("wrong", [])], "why": str(q.get("why", "")).strip()}
                     for q in raw.get("quiz", [])]}


def problems(lang: str, ident: str) -> list[str]:
    f = OUT / lang / f"{ident}.json"
    if not f.exists():
        return ["missing"]
    try:
        t = json.loads(f.read_text(encoding="utf-8"))
    except ValueError as e:
        return [f"bad json: {e}"]
    src, out = source(ident), []
    if any(c in f.read_text(encoding="utf-8") for c in "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"):
        out.append("right-to-left control characters (leave them out)")
    for k, v in src.items():
        tv = t.get(k)
        if isinstance(v, str):
            if v and not (isinstance(tv, str) and tv.strip()):
                out.append(f"{k} missing")
        elif k == "quiz":
            if not isinstance(tv, list) or len(tv) != len(v):
                out.append("quiz length")
            else:
                for i, (a, b) in enumerate(zip(v, tv)):
                    if not isinstance(b, dict) or len(b.get("wrong", [])) != len(a["wrong"]) or not b.get("q") or not b.get("answer"):
                        out.append(f"quiz {i + 1}")
        elif not isinstance(tv, list) or len(tv) != len(v):
            out.append(f"{k} length {len(tv) if isinstance(tv, list) else '-'} != {len(v)}")
    return out


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "source":
        print(json.dumps(source(argv[1]), ensure_ascii=False, indent=1))
        return 0
    if len(argv) >= 2 and argv[0] in ("missing", "check"):
        ids = sorted(p.stem for p in LESSONS.glob("*.toml"))
        bad = {i: problems(argv[1], i) for i in ids}
        bad = {i: p for i, p in bad.items() if p and (argv[0] == "missing" or p != ["missing"])}
        for i, p in bad.items():
            print(i if argv[0] == "missing" else f"{i}: {', '.join(p)}")
        return 1 if bad and argv[0] == "check" else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
