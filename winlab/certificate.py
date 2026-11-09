"""The certificate of completion: a print-ready page the student opens from
the Lab guide or the Progress window once a track (or the path, or one
module) is done. Pure HTML and CSS so the browser's print dialog makes the
PDF. Nothing leaves the PC unless the student shares a track certificate,
which puts a verification link on it (winlab/certshare.py)."""
from __future__ import annotations

import hashlib
import html
import time

from . import __version__, lessons as lmod, progress


class NotYet(Exception):
    """The path (or module) is not complete yet."""


def _code(name: str, ids: list[str], when: float) -> str:
    digest = hashlib.sha256(f"{name}|{int(when)}|{','.join(sorted(ids))}".encode()).hexdigest()
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4)).upper()


def facts(name: str, track_id: str) -> dict:
    """What a track certificate states, for the page and for sharing it."""
    from . import tracks
    name = name.strip()
    if not name:
        raise NotYet("a name is needed on the certificate")
    try:
        t = tracks.get(track_id)
    except tracks.TrackError as exc:
        raise NotYet(str(exc)) from exc
    data = progress.load()
    chosen = [l for l in tracks.lessons_in(t) if l.check_kind != "steps"]
    done = [l for l in chosen if (data["lessons"].get(l.id) or {}).get("status") == progress.STATUS_DONE]
    if not chosen or len(done) < len(chosen):
        raise NotYet(f"{len(done)} of {len(chosen)} lessons done in {t.title}")
    finished = max(float((data["lessons"].get(l.id) or {}).get("passed_at") or 0) for l in chosen) or time.time()
    ids = [l.id for l in chosen]
    return {"name": name, "track": t.id, "title": t.title, "role": t.role, "lessons": ids,
            "count": len(ids), "minutes": sum(l.minutes for l in chosen), "completed": int(finished),
            "graded": sum(1 for l in chosen if l.check_kind == "exercise"),
            "fixed": sum(1 for l in chosen if l.check_kind == "problem"),
            "modules": [{"title": m["title"], "count": len(m["lessons"])} for m in lmod.by_module(chosen)],
            "code": _code(name, ids, finished), "version": __version__}


def issue(name: str, track_id: str) -> tuple[str, dict]:
    """The track certificate's page, noting it as issued in the progress
    file (the Progress window lists it, with its code and any link)."""
    f = facts(name, track_id)
    data = progress.load()
    old = (data.get("certificates") or {}).get(track_id) or {}
    keep_link = old.get("code") == f["code"] and old.get("url")
    progress.record_certificate(track_id, {
        "code": f["code"], "name": f["name"], "title": f["title"],
        "issued": old.get("issued") if old.get("code") == f["code"] else time.time(),
        "completed": f["completed"],
        # a new name (or newer lessons) is a new certificate: the old link
        # still verifies the old one, so it is forgotten here, not withdrawn
        "url": old.get("url") if keep_link else None, "share_id": old.get("share_id") if keep_link else None,
        "shared_at": old.get("shared_at") if keep_link else None})
    progress.set_student(f["name"])
    return render(name, track=track_id, _facts=f), f


def render(name: str, module: str = "", track: str = "", _facts: dict | None = None) -> str:
    name = name.strip()
    if not name:
        raise NotYet("a name is needed on the certificate")
    if track:
        return _render_track(_facts or facts(name, track))
    data = progress.load()
    all_lessons = lmod.list_available()
    if module:
        chosen = [l for l in all_lessons if l.module == module]
        if not chosen:
            raise NotYet(f"no module named {module}")
        title = chosen[0].module_title
    else:
        # The path certificate stands on what winlab checked: a lesson done
        # by ticking its steps is self-reported and stays off it.
        chosen = [l for l in all_lessons if l.check_kind != "steps"]
        title = "the Windows Server administration path"
    done = [l for l in chosen if (data["lessons"].get(l.id) or {}).get("status") == progress.STATUS_DONE]
    if len(done) < len(chosen):
        raise NotYet(f"{len(done)} of {len(chosen)} lessons done in {title}")
    finished = max(float((data["lessons"].get(l.id) or {}).get("passed_at") or 0) for l in chosen) or time.time()
    minutes = sum(l.minutes for l in chosen)
    problems = sum(1 for p in data["problems"].values() if int(p.get("solved") or 0) > 0)
    modules = lmod.by_module(chosen)
    code = _code(name, [l.id for l in chosen], finished)
    date = time.strftime("%d %B %Y", time.localtime(finished))
    mod_rows = "".join(
        f"<li><b>{html.escape(m['title'])}</b> <span>{len(m['lessons'])} lesson{'s' if len(m['lessons']) != 1 else ''}</span></li>"
        for m in modules)
    what = (f"has completed <b>{html.escape(title)}</b> in the winlab Windows Server lab: "
            f"{len(chosen)} lessons across {len(modules)} module{'s' if len(modules) != 1 else ''}, "
            f"about {minutes // 60} hours of hands-on work on real Windows Server machines"
            f"{f', and {problems} break-and-fix problems diagnosed and repaired' if problems else ''}.")
    return _page(name, "Certificate of completion", what, mod_rows, date, code)


def _render_track(f: dict) -> str:
    from . import progress as _p
    cert = (_p.load().get("certificates") or {}).get(f["track"]) or {}
    url = cert.get("url") if cert.get("code") == f["code"] else ""
    hours = f["minutes"] / 60
    parts = []
    if f["graded"]:
        parts.append(f"{f['graded']} graded inside the machines")
    if f["fixed"]:
        parts.append(f"{f['fixed']} real faults diagnosed and fixed")
    what = (f"has completed the <b>{html.escape(f['title'])}</b> track in the winlab lab: "
            f"{f['count']} lesson{'s' if f['count'] != 1 else ''} ({', '.join(parts)}), about "
            f"{round(hours) if hours >= 1 else round(hours, 1)} hours of hands-on work on real Windows machines.")
    if f["role"]:
        what += f" <span class='role'>Track for the {html.escape(f['role'])} role.</span>"
    rows = "".join(f"<li><b>{html.escape(m['title'])}</b> <span>{m['count']} lesson{'s' if m['count'] != 1 else ''}</span></li>"
                   for m in f["modules"])
    date = time.strftime("%d %B %Y", time.localtime(f["completed"]))
    verify = (f"<div class='verify'>Verify this certificate: <b>{html.escape(url)}</b></div>" if url else
              "<div class='verify'>Graded on the holder's own PC. Not yet shared: no online verification link.</div>")
    return _page(f["name"], "Certificate of completion", what, rows, date, f["code"], verify,
                 title_suffix=f["title"])


def _page(name: str, heading: str, what: str, rows: str, date: str, code: str, verify: str = "",
          title_suffix: str = "") -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>winlab certificate: {html.escape(name)}{' · ' + html.escape(title_suffix) if title_suffix else ''}</title>
<style>{_STYLE}</style></head><body>
<div class="print"><button onclick="print()">Print or save as PDF</button></div>
<div class="sheet"><div class="in">
  <div class="brand"><i></i>winlab</div>
  <h1>{html.escape(heading)}</h1>
  <p class="sub">This certifies that</p>
  <div class="name">{html.escape(name)}</div>
  <p class="what">{what}</p>
  <ul>{rows}</ul>
  {verify}
  <div class="foot">
    <div><b>{date}</b>completed</div>
    <div><b>{code}</b>credential ID</div>
    <div class="sig"><b>winlab {__version__}</b>graded inside the lab machines</div>
  </div>
</div></div>
</body></html>"""


_STYLE = """
@page { size: A4 landscape; margin: 0 }
*{box-sizing:border-box}
body{margin:0;background:#e9ecf2;font:15px/1.5 "Segoe UI",ui-sans-serif,system-ui,sans-serif;color:#1b1b1b}
.sheet{width:297mm;height:210mm;margin:16px auto;background:#fff;padding:18mm 22mm;position:relative;
 border:1px solid #d5dae4;box-shadow:0 10px 30px rgba(0,0,0,.12)}
.sheet:before{content:"";position:absolute;inset:8mm;border:2px solid #0067c0;border-radius:4px}
.sheet:after{content:"";position:absolute;inset:10mm;border:1px solid #9ec5ff;border-radius:3px}
.in{position:relative;height:100%;display:flex;flex-direction:column;z-index:1}
.brand{display:flex;align-items:center;gap:10px;font:650 18px ui-monospace,Consolas,monospace}
.brand i{width:22px;height:22px;border-radius:5px;background:conic-gradient(#0067c0 0 25%,#4aa3ff 0 50%,#0067c0 0 75%,#4aa3ff 0)}
h1{font-size:34px;font-weight:300;letter-spacing:.08em;text-transform:uppercase;margin:26px 0 6px;color:#0067c0}
.sub{color:#596273;margin:0}
.name{font-size:44px;font-weight:600;margin:22px 0 4px;border-bottom:1px solid #d5dae4;display:inline-block;padding-bottom:4px}
.what{font-size:17px;max-width:70ch}
.what .role{color:#596273;font-size:14px}
ul{columns:2;padding-left:18px;margin:14px 0;font-size:13.5px}
ul li span{color:#596273;font-size:12px}
.verify{font-size:12.5px;color:#596273;margin:0 0 6px}.verify b{color:#0067c0;font-weight:600}
.foot{margin-top:auto;display:flex;justify-content:space-between;align-items:flex-end;font-size:12.5px;color:#596273}
.foot b{display:block;color:#1b1b1b;font-size:14px}
.sig{border-top:1px solid #1b1b1b;padding-top:6px;min-width:220px}
.print{position:fixed;top:12px;right:16px;z-index:10}
.print button{font:600 13px inherit;background:#0067c0;color:#fff;border:0;border-radius:5px;padding:8px 14px;cursor:pointer}
@media print{body{background:#fff}.sheet{margin:0;border:0;box-shadow:none}.print{display:none}}
"""
