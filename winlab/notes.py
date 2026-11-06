"""The Notes window: the student's own notebook, one per lab, kept on this
PC under var/notes. Plain text; nothing graded, nothing sent anywhere."""
from __future__ import annotations

import re
import time
from pathlib import Path

from . import paths

MAX_CHARS = 200_000


def notes_file(lab_name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", lab_name) or "lab"
    return paths.VAR / "notes" / f"{safe}.txt"


def load(lab_name: str) -> dict:
    f = notes_file(lab_name)
    try:
        text = f.read_text(encoding="utf-8")
        saved = f.stat().st_mtime
    except OSError:
        text, saved = "", 0.0
    return {"lab": lab_name, "text": text, "saved": saved, "max": MAX_CHARS}


def save(lab_name: str, text: str) -> dict:
    if len(text) > MAX_CHARS:
        raise ValueError(f"notes are limited to {MAX_CHARS} characters")
    f = notes_file(lab_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(text.replace("\r\n", "\n"), encoding="utf-8")
    tmp.replace(f)
    return {"lab": lab_name, "saved": time.time(), "chars": len(text)}
