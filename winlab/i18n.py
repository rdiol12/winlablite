"""The desktop's language: English, Spanish, Hebrew or Arabic.

The page (webui_page.html) is written in English. A language's file,
content/i18n/<lang>.json, maps each English text the page shows to its
translation; tools/i18n_extract.py lists those texts. Keys with {} are
patterns: {} stands for a value the page fills in (a machine name, a count),
and the translation places them with {} in order or {1}, {2} by number.

The choice is kept in var/language.json, so it holds across restarts and
whichever browser window shows the desktop.
"""
from __future__ import annotations

import json

from . import paths

# code: (name in its own language, right-to-left)
LANGS = {
    "en": ("English", False),
    "es": ("Español", False),
    "he": ("עברית", True),
    "ar": ("العربية", True),
}


def _store():
    return paths.VAR / "language.json"


def current() -> str:
    try:
        lang = json.loads(_store().read_text(encoding="utf-8")).get("lang", "en")
    except (OSError, ValueError, AttributeError):
        return "en"
    return lang if lang in LANGS else "en"


def choose(lang: str) -> dict:
    if lang not in LANGS:
        return {"error": f"no such language: {lang}"}
    _store().parent.mkdir(parents=True, exist_ok=True)
    _store().write_text(json.dumps({"lang": lang}), encoding="utf-8")
    return {"ok": True, "lang": lang}


def table(lang: str) -> dict[str, str]:
    """The English-to-<lang> table; empty for English or a missing file."""
    if lang == "en" or lang not in LANGS:
        return {}
    try:
        data = json.loads((paths.CONTENT / "i18n" / f"{lang}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str) and v}


def lesson_table(lang: str, lesson_id: str) -> dict:
    """One lesson's translation (content/i18n/lessons/<lang>/<id>.json), or {}."""
    if lang == "en" or lang not in LANGS or not lesson_id.replace("-", "").isalnum():
        return {}
    try:
        from . import content  # a plain file, or the trial's pack (winlab/content.py)
        data = json.loads(content.read_text(paths.CONTENT / "i18n" / "lessons" / lang / f"{lesson_id}.json"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def view(lang: str | None = None) -> dict:
    lang = lang if lang in LANGS else current()
    return {"lang": lang, "rtl": LANGS[lang][1],
            "langs": [{"code": c, "name": n, "rtl": r} for c, (n, r) in LANGS.items()],
            "table": table(lang)}
