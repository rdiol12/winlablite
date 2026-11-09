"""Tracks: job-shaped groups of lessons, each with its own certificate.

content/tracks.toml names each track's modules (and any extra lessons); a
lesson can also join a track with `tracks = [...]` in its [lesson] table.
A module no track names becomes a track of its own, so new content always
shows on the Progress window.

A track is complete when every lesson in it that winlab checks (a graded
exercise or a verified fix) is done. Lessons done by ticking steps are the
student's own word: they show as progress but never count toward a
certificate, as on the path certificate before tracks existed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import content, lessons as lmod, paths, progress

TRACKS_FILE = paths.CONTENT / "tracks.toml"


class TrackError(Exception):
    pass


@dataclass
class Track:
    id: str
    title: str
    role: str = ""
    summary: str = ""
    modules: list[str] = field(default_factory=list)
    lessons: list[str] = field(default_factory=list)


def list_tracks() -> list[Track]:
    out: list[Track] = []
    seen: set[str] = set()
    named: set[str] = set()
    raw = content.load_toml(TRACKS_FILE) if TRACKS_FILE.exists() else {}
    for t in raw.get("track", []):
        tid = str(t.get("id", "")).strip()
        if not tid or tid in seen:
            continue
        seen.add(tid)
        mods = [str(m) for m in t.get("modules", []) if str(m) in lmod.MODULE_IDS]
        named.update(mods)
        out.append(Track(id=tid, title=str(t.get("title", tid)), role=str(t.get("role", "")),
                         summary=str(t.get("summary", "")).strip(), modules=mods,
                         lessons=[str(x) for x in t.get("lessons", [])]))
    for mid, title, blurb in lmod.MODULES:
        if mid not in named and mid not in seen:
            out.append(Track(id=mid, title=title, summary=blurb, modules=[mid]))
    from . import edition
    if edition.is_core():   # the trial shows only the tracks its lessons fill
        everything = lmod.list_available()
        out = [t for t in out if lessons_in(t, everything)]
    return out


def list_paths() -> list[Track]:
    """The career paths the lesson picker groups lessons into ([[path]] in
    content/tracks.toml). Same shape as a track, so status() reads them too;
    a path has no certificate of its own."""
    raw = content.load_toml(TRACKS_FILE) if TRACKS_FILE.exists() else {}
    out: list[Track] = []
    for p in raw.get("path", []):
        pid = str(p.get("id", "")).strip()
        if not pid or any(x.id == pid for x in out):
            continue
        out.append(Track(id=pid, title=str(p.get("title", pid)), role=str(p.get("role", "")),
                         summary=str(p.get("summary", "")).strip(),
                         modules=[str(m) for m in p.get("modules", []) if str(m) in lmod.MODULE_IDS],
                         lessons=[str(x) for x in p.get("lessons", [])]))
    return out


def paths_status(data: dict | None = None, all_lessons: list | None = None) -> list[dict]:
    """Each career path with its lesson ids and how far the student is, for
    the Learn window's path cards. `done`/`total` count every lesson on the
    path; the bar uses them, since a picker shows what is left to do."""
    data = data or progress.load()
    all_lessons = lmod.list_available() if all_lessons is None else all_lessons
    out = []
    for p in list_paths():
        ls = lessons_in(p, all_lessons)
        s = status(p, data, all_lessons)
        nxt = next((l for l in ls if (data["lessons"].get(l.id) or {}).get("status") != progress.STATUS_DONE), None)
        s.pop("certificate", None)
        s.update({"lessons": [l.id for l in ls],
                  "percent": round(100 * s["done"] / s["total"]) if s["total"] else 0,
                  "next": nxt.id if nxt else "", "next_title": nxt.title if nxt else "",
                  "hours": round(sum(l.minutes for l in ls) / 60)})
        out.append(s)
    return out


def get(track_id: str) -> Track:
    for t in list_tracks():
        if t.id == track_id:
            return t
    raise TrackError(f"no track named {track_id!r} (winlab tracks list shows them)")


def lessons_in(track: Track, all_lessons: list | None = None) -> list:
    """The track's lessons in path order."""
    all_lessons = lmod.list_available() if all_lessons is None else all_lessons
    extra = set(track.lessons)
    return [l for l in all_lessons
            if l.module in track.modules or l.id in extra or track.id in (l.tracks or [])]


def status(track: Track, data: dict | None = None, all_lessons: list | None = None) -> dict:
    """Where the student stands on one track."""
    data = data or progress.load()
    ls = lessons_in(track, all_lessons)
    entry = lambda l: data["lessons"].get(l.id) or {}  # noqa: E731
    done = [l for l in ls if entry(l).get("status") == progress.STATUS_DONE]
    counted = [l for l in ls if l.check_kind != "steps"]
    counted_done = [l for l in counted if entry(l).get("status") == progress.STATUS_DONE]
    nxt = next((l for l in counted if entry(l).get("status") != progress.STATUS_DONE), None) \
        or next((l for l in ls if entry(l).get("status") != progress.STATUS_DONE), None)
    complete = bool(counted) and len(counted_done) == len(counted)
    finished = max((float(entry(l).get("passed_at") or 0) for l in counted), default=0.0) if complete else 0.0
    cert = (data.get("certificates") or {}).get(track.id) or {}
    return {
        "id": track.id, "title": track.title, "role": track.role, "summary": track.summary,
        "modules": track.modules, "total": len(ls), "done": len(done),
        "counted": len(counted), "counted_done": len(counted_done),
        "percent": round(100 * len(counted_done) / len(counted)) if counted else 0,
        "started": any(entry(l).get("status") == progress.STATUS_STARTED for l in ls) or bool(done),
        "minutes": sum(l.minutes for l in counted),
        "minutes_done": sum(l.minutes for l in counted_done),
        "next": nxt.id if nxt else "", "next_title": nxt.title if nxt else "",
        "complete": complete, "finished": finished,
        "certificate": {k: cert.get(k) for k in ("code", "name", "issued", "url", "shared_at") if cert.get(k)},
    }


def all_status(data: dict | None = None) -> list[dict]:
    data = data or progress.load()
    ls = lmod.list_available()
    return [status(t, data, ls) for t in list_tracks()]


def render(data: dict | None = None) -> str:
    """`winlab tracks list`."""
    lines = []
    for s in all_status(data):
        mark = "[x]" if s["complete"] else "[~]" if s["started"] else "[ ]"
        lines.append(f"  {mark} {s['id']:<18} {s['title']}: {s['counted_done']}/{s['counted']} checked lessons"
                     f" ({s['percent']}%)")
        if s["certificate"].get("url"):
            lines.append(f"      certificate {s['certificate']['code']}, verify at {s['certificate']['url']}")
        elif s["certificate"].get("code"):
            lines.append(f"      certificate {s['certificate']['code']}")
        elif s["next"]:
            lines.append(f"      next: {s['next']}  {s['next_title']}")
    return "\n".join(lines)
