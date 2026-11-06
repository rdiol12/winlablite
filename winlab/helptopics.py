"""The Help window's topics, read from content/help/*.toml.

Each file is one topic: an id, a title, a category the window groups by,
an order inside the category, keywords the search box also matches, a one
line summary and a Markdown body. A topic may name an `action` the window
renders under its body (only "support-bundle" exists: the Make a support
file button). Topics are content, so support can correct or add one by
shipping a file, with no new winlab.
"""

from __future__ import annotations

import re

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import paths

ACTIONS = ("", "support-bundle")
# Categories the window shows first, in this order; any other comes after.
CATEGORY_ORDER = ("Start here", "Using winlab", "Common problems", "Support")


@dataclass
class Topic:
    id: str
    title: str
    category: str
    body: str
    order: int = 100
    summary: str = ""
    keywords: list[str] = field(default_factory=list)
    action: str = ""


def help_dir() -> Path:
    return paths.CONTENT / "help"


def load(f: Path) -> Topic:
    with f.open("rb") as fh:
        raw = tomllib.load(fh).get("topic", {})
    return Topic(id=str(raw.get("id") or f.stem), title=str(raw.get("title", "")),
                 category=str(raw.get("category", "")), body=str(raw.get("body", "")).strip(),
                 order=int(raw.get("order", 100)), summary=str(raw.get("summary", "")),
                 keywords=[str(k) for k in raw.get("keywords", [])], action=str(raw.get("action", "")))


def _cat_key(c: str) -> tuple[int, str]:
    return (CATEGORY_ORDER.index(c) if c in CATEGORY_ORDER else len(CATEGORY_ORDER), c)


def load_all(d: Path | None = None) -> list[Topic]:
    d = d or help_dir()
    out = []
    for f in sorted(d.glob("*.toml")) if d.is_dir() else []:
        try:
            out.append(load(f))
        except (OSError, tomllib.TOMLDecodeError, ValueError):
            continue        # validate() names it; the window shows the rest
    return sorted(out, key=lambda t: (_cat_key(t.category), t.order, t.title))


def validate(d: Path | None = None) -> list[str]:
    """Problems a content author must fix: unreadable files, missing fields,
    duplicate ids, an unknown action, and wording the product avoids."""
    d = d or help_dir()
    problems: list[str] = []
    seen: dict[str, str] = {}
    for f in sorted(d.glob("*.toml")) if d.is_dir() else []:
        try:
            t = load(f)
        except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
            problems.append(f"help/{f.name}: {exc}")
            continue
        where = f"help/{f.name}"
        for name in ("title", "category", "body"):
            if not getattr(t, name):
                problems.append(f"{where}: no {name}")
        if t.id in seen:
            problems.append(f"{where}: id '{t.id}' is also used by {seen[t.id]}")
        seen[t.id] = where
        if t.action not in ACTIONS:
            problems.append(f"{where}: unknown action '{t.action}'")
        if "—" in t.body or "—" in t.title or "—" in t.summary:
            problems.append(f"{where}: uses an em-dash; write two sentences instead")
    if not any(t.action == "support-bundle" for t in load_all(d)):
        problems.append("help: no topic offers the support file (action = \"support-bundle\")")
    return problems


def search(q: str, topics: list[Topic] | None = None) -> list[Topic]:
    """Topics matching every word of q in their title, keywords, summary or
    body; title and keyword hits first. The window searches the same way."""
    topics = load_all() if topics is None else topics
    words = [w for w in q.lower().split() if w]
    if not words:
        return list(topics)
    scored = []
    for t in topics:
        head = " ".join([t.title, " ".join(t.keywords)]).lower()
        text = " ".join([head, t.summary, t.body]).lower()
        if all(w in text for w in words):
            scored.append((-sum(_weight(t, head, w) for w in words), t))
    return [t for _, t in sorted(scored, key=lambda x: x[0])]


def _weight(t: Topic, head: str, w: str) -> int:
    """4 for a whole word of the title, 3 for a keyword, 2 for a word that
    starts with w in the title or keywords, 1 for w inside them, 0 for body
    only."""
    rx = re.escape(w)
    if re.search(rf"\b{rx}\b", t.title.lower()):
        return 4
    if w in (k.lower() for k in t.keywords):
        return 3
    if re.search(rf"\b{rx}", head):
        return 2
    return 1 if w in head else 0


def view() -> dict:
    from . import support
    topics = load_all()
    cats: list[str] = []
    for t in topics:
        if t.category not in cats:
            cats.append(t.category)
    return {"topics": [{"id": t.id, "title": t.title, "category": t.category, "summary": t.summary,
                        "keywords": t.keywords, "body": t.body, "action": t.action} for t in topics],
            "categories": cats, "support_email": support.SUPPORT_EMAIL,
            "support_dir": str(support.support_dir())}
