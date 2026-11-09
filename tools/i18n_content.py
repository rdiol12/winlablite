"""Translations of exercises, exams, guides, scenarios, sites, help topics,
commands.toml, interviews.toml and tracks.toml (lessons: tools/i18n_lessons.py).

  python tools/i18n_content.py files                 every content file translated this way
  python tools/i18n_content.py source <file>         its English texts, as a JSON list
  python tools/i18n_content.py missing <lang>        files with texts that have no translation
  python tools/i18n_content.py check <lang> [file]   which texts are missing, per file

<file> is relative to content/, e.g. exercises/foundation-ad-ds-basics.toml.
The translation is content/i18n/content/<lang>/<file with .json>: a JSON object
mapping each English text (exactly as `source` prints it) to its translation.
Keep commands, paths, names and addresses inside a text exactly as in English.

The file `problems` is the troubleshooting problems' texts (title, symptom,
teaches and hints of guestfaults.SCENARIOS and faults.SCENARIOS, and of the
other drills in content.drill_strings()), collected from winlab's registries; its table is content/i18n/content/<lang>/problems.json.
Keep every {placeholder} (filled with the lab's names at run time) as it is.
"""
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from winlab import content, paths  # noqa: E402


def files() -> list[str]:
    out = []
    for d in content.TRANSLATED_DIRS:
        out += sorted(p.relative_to(paths.CONTENT).as_posix() for p in (paths.CONTENT / d).rglob("*.toml"))
    out += [f for f in content.TRANSLATED_FILES if (paths.CONTENT / f).exists()]
    out.append(content.PROBLEMS)
    return out


def source(rel: str) -> list[str]:
    if rel == content.PROBLEMS:
        return content.problem_strings()
    p = paths.CONTENT / rel
    return content.text_strings(p, tomllib.loads(p.read_text(encoding="utf-8")))


PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


def placeholders_lost(lang: str) -> list[str]:
    """Problem texts whose translation does not keep the English {placeholders}
    and braces (some drills fill theirs with str.format)."""
    table = content.problem_table(lang)
    return [s for s in content.problem_strings() if isinstance(table.get(s), str) and table[s].strip()
            and (sorted(PLACEHOLDER.findall(s)) != sorted(PLACEHOLDER.findall(table[s]))
                 or s.count("{") != table[s].count("{") or s.count("}") != table[s].count("}"))]


def missing(lang: str, rel: str) -> list[str]:
    if rel == content.PROBLEMS:
        table = content.problem_table(lang)
        return [s for s in source(rel) if not (isinstance(table.get(s), str) and table[s].strip())]
    f = content.translation_file(paths.CONTENT / rel, lang)
    try:
        table = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        table = {}
    return [s for s in source(rel) if not (isinstance(table.get(s.strip()), str) and table[s.strip()].strip())]


def main(argv: list[str]) -> int:
    if argv[:1] == ["files"]:
        print("\n".join(files()))
        return 0
    if len(argv) >= 2 and argv[0] == "source":
        print(json.dumps([s.strip() for s in source(argv[1])], ensure_ascii=False, indent=1))
        return 0
    if len(argv) >= 2 and argv[0] in ("missing", "check"):
        bad = 0
        for rel in ([argv[2]] if len(argv) > 2 else files()):
            m = missing(argv[1], rel)
            if m:
                bad += 1
                print(rel if argv[0] == "missing" else f"{rel}: {len(m)} missing, e.g. {m[0][:80]!r}")
        if argv[0] == "check" and (len(argv) == 2 or argv[2] == content.PROBLEMS):
            lost = placeholders_lost(argv[1])
            if lost:
                bad += 1
                print(f"{content.PROBLEMS}: {len(lost)} lose a {{placeholder}}, e.g. {lost[0][:80]!r}")
        return 1 if bad and argv[0] == "check" else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
