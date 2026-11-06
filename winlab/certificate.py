"""The certificate of completion: a print-ready page the student opens from
the Lab guide once the path (or one module) is done. Pure HTML and CSS so
the browser's print dialog makes the PDF; nothing leaves the PC."""
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


def render(name: str, module: str = "") -> str:
    name = name.strip()
    if not name:
        raise NotYet("a name is needed on the certificate")
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
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>winlab certificate: {html.escape(name)}</title>
<style>
@page {{ size: A4 landscape; margin: 0 }}
*{{box-sizing:border-box}}
body{{margin:0;background:#e9ecf2;font:15px/1.5 "Segoe UI",ui-sans-serif,system-ui,sans-serif;color:#1b1b1b}}
.sheet{{width:297mm;height:210mm;margin:16px auto;background:#fff;padding:18mm 22mm;position:relative;
 border:1px solid #d5dae4;box-shadow:0 10px 30px rgba(0,0,0,.12)}}
.sheet:before{{content:"";position:absolute;inset:8mm;border:2px solid #0067c0;border-radius:4px}}
.sheet:after{{content:"";position:absolute;inset:10mm;border:1px solid #9ec5ff;border-radius:3px}}
.in{{position:relative;height:100%;display:flex;flex-direction:column}}
.brand{{display:flex;align-items:center;gap:10px;font:650 18px ui-monospace,Consolas,monospace}}
.brand i{{width:22px;height:22px;border-radius:5px;background:conic-gradient(#0067c0 0 25%,#4aa3ff 0 50%,#0067c0 0 75%,#4aa3ff 0)}}
h1{{font-size:34px;font-weight:300;letter-spacing:.08em;text-transform:uppercase;margin:26px 0 6px;color:#0067c0}}
.sub{{color:#596273;margin:0}}
.name{{font-size:44px;font-weight:600;margin:22px 0 4px;border-bottom:1px solid #d5dae4;display:inline-block;padding-bottom:4px}}
.what{{font-size:17px;max-width:70ch}}
ul{{columns:2;padding-left:18px;margin:14px 0;font-size:13.5px}}
ul li span{{color:#596273;font-size:12px}}
.foot{{margin-top:auto;display:flex;justify-content:space-between;align-items:flex-end;font-size:12.5px;color:#596273}}
.foot b{{display:block;color:#1b1b1b;font-size:14px}}
.sig{{border-top:1px solid #1b1b1b;padding-top:6px;min-width:220px}}
.print{{position:fixed;top:12px;right:16px;z-index:10}}
.print button{{font:600 13px inherit;background:#0067c0;color:#fff;border:0;border-radius:5px;padding:8px 14px;cursor:pointer}}
@media print{{body{{background:#fff}}.sheet{{margin:0;border:0;box-shadow:none}}.print{{display:none}}}}
</style></head><body>
<div class="print"><button onclick="print()">Print or save as PDF</button></div>
<div class="sheet"><div class="in">
  <div class="brand"><i></i>winlab</div>
  <h1>Certificate of completion</h1>
  <p class="sub">This certifies that</p>
  <div class="name">{html.escape(name)}</div>
  <p class="what">has completed <b>{html.escape(title)}</b> in the winlab Windows Server lab:
  {len(chosen)} lessons across {len(modules)} module{'s' if len(modules) != 1 else ''}, about {minutes // 60} hours of hands-on work
  on real Windows Server machines{f', and {problems} break-and-fix problems diagnosed and repaired' if problems else ''}.</p>
  <ul>{mod_rows}</ul>
  <div class="foot">
    <div><b>{date}</b>completed</div>
    <div><b>{code}</b>verification code</div>
    <div class="sig"><b>winlab {__version__}</b>graded inside the lab machines</div>
  </div>
</div></div>
</body></html>"""
