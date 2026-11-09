"""The skills transcript: what the student has shown they can do, as one
print-ready page. Unlike the certificate it needs nothing finished: it lists
every graded lesson passed (best score, date), every problem fixed (and how
many hints it took), every on-call shift, every company run (days run, the
SLA met, incidents) and the exam readiness, so it can
go with a job application at any point. Built from var/progress.json;
nothing leaves the PC."""
from __future__ import annotations

import hashlib
import html
import time

from . import __version__, exams, guestfaults, lessons as lmod, progress


def _date(t: float) -> str:
    return time.strftime("%d %b %Y", time.localtime(t)) if t else ""


def collect(data: dict | None = None) -> dict:
    """The transcript's facts, for the page and for `winlab transcript`."""
    data = data or progress.load()
    all_lessons = lmod.list_available()
    modules = []
    for m in lmod.by_module(all_lessons):
        rows = []
        for l in m["lessons"]:
            e = data["lessons"].get(l.id) or {}
            if e.get("status") != progress.STATUS_DONE:
                continue
            # Ticked steps are the student's own word: said so, and kept off
            # the path certificate (certificate.py).
            how = ("graded" if l.check_kind == "exercise" else
                   "problem fixed" if l.check_kind == "problem" else "self-reported (steps ticked)")
            rows.append({"id": l.id, "title": l.title, "how": how, "best": int(e.get("best") or 0),
                         "answer": bool(e.get("answer_viewed")), "gave_up": int(e.get("gave_up") or 0),
                         "attempts": int(e.get("attempts") or 0), "date": _date(float(e.get("passed_at") or 0))})
        modules.append({"id": m["id"], "title": m["title"], "total": len(m["lessons"]), "done": rows})
    problems = []
    for sid, e in sorted(data["problems"].items()):
        if int(e.get("solved") or 0) <= 0:
            continue
        f = guestfaults.SCENARIOS.get(sid)
        problems.append({"id": sid, "title": f.title if f else sid, "solved": int(e["solved"]),
                         "hints": int(e.get("hints") or 0), "date": _date(float(e.get("solved_at") or 0))})
    shifts = [{"date": _date(float(s.get("started") or 0)), "minutes": int(s.get("minutes") or 0),
               "fixed": int(s.get("fixed") or 0), "tickets": int(s.get("tickets") or 0),
               "score": int(s.get("score") or 0), "max": int(s.get("max") or 0),
               "avg_minutes": s.get("avg_minutes", 0)} for s in data.get("shifts", [])]
    helpdesk = [{"date": _date(float(h.get("ended") or h.get("started") or 0)), "handled": int(h.get("handled") or 0),
                 "tickets": int(h.get("tickets") or 0), "sla": int(h.get("sla_met_pct") or 0),
                 "ftf": int(h.get("first_fix_pct") or 0), "mttr": h.get("mttr_minutes", 0),
                 "breaches": int(h.get("breaches") or 0)} for h in data.get("helpdesk", [])]
    companies = [{"name": str(c.get("name") or c.get("lab") or ""), "lab": str(c.get("lab") or ""),
                  "date": _date(float(c.get("started") or 0)), "days": int(c.get("days") or 0),
                  "weeks": int(c.get("weeks") or 0), "resolved": int(c.get("resolved") or 0),
                  "tickets": int(c.get("tickets") or 0), "sla": int(c.get("sla_met_pct") or 0),
                  "incidents": int(c.get("incidents") or 0), "uptime": c.get("uptime", 100.0),
                  "finished": bool(c.get("finished"))}
                 for c in data.get("companies", []) if int(c.get("days") or 0) > 0]
    drills = [{"date": _date(float(b.get("started") or 0)), "topic": str(b.get("topic") or ""),
               "level": str(b.get("level") or ""), "verdict": str(b.get("verdict") or ""),
               "percent": int(b.get("percent") or 0), "minutes": b.get("minutes", 0),
               "fixed": int(b.get("faults_fixed") or 0), "faults": int(b.get("faults") or 0),
               "causes": int(b.get("causes_right") or 0)}
              for b in data.get("breakfix", []) if not b.get("gave_up")]
    interviews = [{"date": _date(float(i.get("started") or 0)), "role": str(i.get("role_title") or i.get("role") or ""),
                   "level": str(i.get("level") or ""), "verdict": str(i.get("verdict") or ""),
                   "percent": int(i.get("percent") or 0), "rounds": dict(i.get("rounds") or {})}
                  for i in data.get("interviews", [])]
    irs = [{"date": _date(float(b.get("started") or 0)), "title": str(b.get("title") or b.get("drill") or ""),
            "node": str(b.get("node") or ""), "verdict": str(b.get("verdict") or ""),
            "percent": int(b.get("percent") or 0), "minutes": b.get("minutes", 0),
            "detected": bool(b.get("detected")), "iocs": int(b.get("iocs") or 0),
            "found": int(b.get("iocs_found") or 0), "technique": bool(b.get("technique_right"))}
           for b in data.get("incidents", []) if not b.get("gave_up")]
    readiness = []
    titles = {l.id: l.title for l in all_lessons}
    for ex in exams.list_available():
        r = exams.readiness(ex, data, titles)
        readiness.append({"id": r["id"], "title": r["title"], "overall": r["overall"], "ready": r["ready"],
                          "areas": [(a["title"], a["percent"]) for a in r["areas"]]})
    done = sum(len(m["done"]) for m in modules)
    return {"student": str(data.get("student") or ""), "lessons_done": done, "lessons_total": len(all_lessons),
            "graded": sum(1 for m in modules for r in m["done"] if r["how"] == "graded"),
            "modules": modules, "problems": problems, "shifts": shifts, "helpdesk": helpdesk,
            "companies": companies, "breakfix": drills, "interviews": interviews, "incidents": irs, "exams": readiness, "game": _game(data),
            "hours": round(sum(l.minutes for l in all_lessons
                               if (data["lessons"].get(l.id) or {}).get("status") == progress.STATUS_DONE) / 60, 1)}


def _game(data: dict) -> dict | None:
    """The helpdesk ticket game (winlab/ticketgame.py): rank, points, best grade per level, badges."""
    from . import ticketgame
    c = ticketgame.career(data)
    if not c["shifts"]:
        return None
    return {"rank": ticketgame.rank(c["xp"])["title"], "xp": c["xp"], "shifts": len(c["shifts"]),
            "best": [(lv["title"], c["best"][k].get("grade", ""), int(c["best"][k].get("score") or 0))
                     for k, lv in ticketgame.LEVELS.items() if c["best"].get(k)],
            "badges": [ticketgame.BADGES[b][0] for b in c["badges"] if b in ticketgame.BADGES]}


def _code(name: str, facts: dict) -> str:
    key = "|".join([name] + [r["id"] for m in facts["modules"] for r in m["done"]]
                   + [p["id"] for p in facts["problems"]])
    d = hashlib.sha256(key.encode()).hexdigest()
    return "-".join(d[i:i + 4] for i in range(0, 16, 4)).upper()


def render_text(facts: dict | None = None) -> str:
    f = facts or collect()
    out = [f"skills transcript{': ' + f['student'] if f['student'] else ''}",
           f"{f['lessons_done']}/{f['lessons_total']} lessons ({f['graded']} graded inside the machines, "
           f"about {f['hours']} h), {len(f['problems'])} problems fixed, {len(f['shifts'])} on-call shifts", ""]
    for m in f["modules"]:
        if not m["done"]:
            continue
        out.append(f"{m['title']} ({len(m['done'])}/{m['total']})")
        for r in m["done"]:
            score = f"  {r['best']}%" if r["how"] == "graded" else f"  ({r['how']})"
            note = ", worked answer viewed" if r.get("answer") else ""
            out.append(f"  {r['date']:<12} {r['title']}{score}{note}")
    if f["problems"]:
        out += ["", "Problems fixed"]
        out += [f"  {p['date']:<12} {p['title']}  ({p['hints']} hint{'s' if p['hints'] != 1 else ''})"
                for p in f["problems"]]
    if f["shifts"]:
        out += ["", "On call"]
        out += [f"  {s['date']:<12} {s['minutes']} min, {s['fixed']}/{s['tickets']} fixed, {s['score']}/{s['max']} points"
                for s in f["shifts"]]
    if f.get("helpdesk"):
        out += ["", "Helpdesk queue"]
        out += [f"  {h['date']:<12} {h['handled']}/{h['tickets']} handled, SLA met {h['sla']}%, "
                f"first-time fix {h['ftf']}%, {h['mttr']} min to resolve, {h['breaches']} breaches"
                for h in f["helpdesk"]]
    if f.get("game"):
        g = f["game"]
        out += ["", f"Ticket game: {g['rank']}, {g['xp']} points over {g['shifts']} shift{'s' if g['shifts'] != 1 else ''}"]
        out += [f"  {t:<22} best grade {gr}, {sc} points" for t, gr, sc in g["best"]]
        if g["badges"]:
            out.append("  badges: " + ", ".join(g["badges"]))
    if f.get("companies"):
        out += ["", "Company runs"]
        out += [f"  {c['date']:<12} {c['name']} ({c['lab']}): {c['days']} days run, SLA met {c['sla']}%, "
                f"{c['incidents']} incident{'s' if c['incidents'] != 1 else ''}, {c['resolved']}/{c['tickets']} tickets"
                f"{'' if c['finished'] else ', still running'}"
                for c in f["companies"]]
    if f.get("breakfix"):
        out += ["", "Break and fix"]
        out += [f"  {b['date']:<12} {b['topic']}, {b['level']}: {b['verdict']} ({b['percent']}%), "
                f"{b['fixed']}/{b['faults']} fixed, {b['causes']} root cause{'s' if b['causes'] != 1 else ''} named, "
                f"{b['minutes']} min" for b in f["breakfix"]]
    if f.get("interviews"):
        out += ["", "Job interviews"]
        out += [f"  {i['date']:<12} {i['role']}, {i['level']}: {i['verdict']} ({i['percent']}%)" for i in f["interviews"]]
    if f.get("incidents"):
        out += ["", "Security incident drills"]
        out += [f"  {b['date']:<12} {b['node']}: {b['verdict']} ({b['percent']}%), "
                f"{'seen by the SIEM' if b['detected'] else 'not seen by the SIEM'}, "
                f"{b['found']}/{b['iocs']} indicators reported, {b['minutes']} min" for b in f["incidents"]]
    for e in f["exams"]:
        out += ["", f"{e['title']}: {e['overall']}% ready"]
    return "\n".join(out)


def render(name: str = "") -> str:
    f = collect()
    name = (name or f["student"]).strip() or "Student"
    esc = html.escape
    mods = "".join(
        f"<h3>{esc(m['title'])} <small>{len(m['done'])} of {m['total']}</small></h3>"
        "<table><tr><th>Lesson</th><th>How it was checked</th><th>Best</th><th>Date</th></tr>"
        + "".join(f"<tr><td>{esc(r['title'])}</td><td>{esc(r['how'])}"
                  f"{'; worked answer viewed' if r.get('answer') else ''}</td>"
                  f"<td>{str(r['best']) + '%' if r['how'] == 'graded' else ''}</td><td>{esc(r['date'])}</td></tr>"
                  for r in m["done"]) + "</table>"
        for m in f["modules"] if m["done"])
    probs = ("<h2>Problems diagnosed and fixed</h2><table><tr><th>Problem</th><th>Times</th><th>Hints used</th>"
             "<th>Date</th></tr>" + "".join(
                 f"<tr><td>{esc(p['title'])}</td><td>{p['solved']}</td><td>{p['hints']} of 3</td><td>{esc(p['date'])}</td></tr>"
                 for p in f["problems"]) + "</table>") if f["problems"] else ""
    shifts = ("<h2>On-call shifts</h2><table><tr><th>Date</th><th>Length</th><th>Tickets fixed</th>"
              "<th>Average time to fix</th><th>Score</th></tr>" + "".join(
                  f"<tr><td>{esc(s['date'])}</td><td>{s['minutes']} min</td><td>{s['fixed']} of {s['tickets']}</td>"
                  f"<td>{s['avg_minutes']} min</td><td>{s['score']} of {s['max']}</td></tr>"
                  for s in f["shifts"][-10:]) + "</table>") if f["shifts"] else ""
    desk = ("<h2>Helpdesk queue</h2><table><tr><th>Date</th><th>Tickets handled</th><th>SLA met</th>"
            "<th>First-time fix</th><th>Mean time to resolve</th><th>Breaches</th></tr>" + "".join(
                f"<tr><td>{esc(h['date'])}</td><td>{h['handled']} of {h['tickets']}</td><td>{h['sla']}%</td>"
                f"<td>{h['ftf']}%</td><td>{h['mttr']} min</td><td>{h['breaches']}</td></tr>"
                for h in f["helpdesk"][-10:]) + "</table>") if f.get("helpdesk") else ""
    g = f.get("game")
    game = (f"<h2>Ticket game</h2><p>{esc(g['rank'])}: {g['xp']} points over {g['shifts']} helpdesk shifts of real problems, "
            "each fix checked on the machine.</p><table><tr><th>Level</th><th>Best grade</th><th>Points</th></tr>"
            + "".join(f"<tr><td>{esc(t)}</td><td>{esc(gr)}</td><td>{sc}</td></tr>" for t, gr, sc in g["best"]) + "</table>"
            + (f"<p>Badges: {esc(', '.join(g['badges']))}</p>" if g["badges"] else "")) if g else ""
    runs = ("<h2>Company runs</h2><table><tr><th>Started</th><th>Company</th><th>Days run</th><th>Tickets resolved</th>"
            "<th>SLA met</th><th>Incidents</th><th>Uptime</th></tr>" + "".join(
                f"<tr><td>{esc(c['date'])}</td><td>{esc(c['name'])} <small>({esc(c['lab'])})</small></td>"
                f"<td>{c['days']}{'' if c['finished'] else ' (running)'}</td><td>{c['resolved']} of {c['tickets']}</td>"
                f"<td>{c['sla']}%</td><td>{c['incidents']}</td><td>{c['uptime']}%</td></tr>"
                for c in f["companies"][-10:]) + "</table>") if f.get("companies") else ""
    drills = ("<h2>Break and fix</h2><table><tr><th>Date</th><th>Topic</th><th>Level</th><th>Fixed</th>"
              "<th>Root cause</th><th>Time</th><th>Result</th></tr>" + "".join(
                  f"<tr><td>{esc(b['date'])}</td><td>{esc(b['topic'])}</td><td>{esc(b['level'])}</td>"
                  f"<td>{b['fixed']} of {b['faults']}</td><td>{b['causes']} of {b['faults']} named</td>"
                  f"<td>{b['minutes']} min</td><td>{esc(b['verdict'])} ({b['percent']}%)</td></tr>"
                  for b in f["breakfix"][-10:]) + "</table>") if f.get("breakfix") else ""
    _rt = (("screening", "Screening"), ("technical", "Technical"), ("situation", "Situations"), ("practical", "Practical"))
    ivs = ("<h2>Job interviews</h2><table><tr><th>Date</th><th>Role</th><th>Level</th>"
           + "".join(f"<th>{t}</th>" for _, t in _rt) + "<th>Result</th></tr>" + "".join(
               f"<tr><td>{esc(i['date'])}</td><td>{esc(i['role'])}</td><td>{esc(i['level'])}</td>"
               + "".join(f"<td>{int(i['rounds'].get(k) or 0)}%</td>" for k, _ in _rt)
               + f"<td>{esc(i['verdict'])} ({i['percent']}%)</td></tr>"
               for i in f["interviews"][-10:]) + "</table>") if f.get("interviews") else ""
    irs = ("<h2>Security incident drills</h2><table><tr><th>Date</th><th>Machine</th><th>Seen by the SIEM</th>"
           "<th>Indicators reported</th><th>Technique</th><th>Time</th><th>Result</th></tr>" + "".join(
               f"<tr><td>{esc(b['date'])}</td><td>{esc(b['node'])}</td><td>{'yes' if b['detected'] else 'no'}</td>"
               f"<td>{b['found']} of {b['iocs']}</td><td>{'named' if b['technique'] else 'missed'}</td>"
               f"<td>{b['minutes']} min</td><td>{esc(b['verdict'])} ({b['percent']}%)</td></tr>"
               for b in f["incidents"][-10:]) + "</table>") if f.get("incidents") else ""
    exm = "".join(
        f"<h2>{esc(e['title'])}: {e['overall']}% ready</h2><table><tr><th>Skill area</th><th>Lessons done</th></tr>"
        + "".join(f"<tr><td>{esc(t)}</td><td><span class='bar'><i style='width:{p}%'></i></span> {p}%</td></tr>"
                  for t, p in e["areas"]) + "</table>"
        for e in f["exams"])
    empty = "" if f["lessons_done"] or f["problems"] else "<p class='sub'>Nothing finished yet: pass a lesson's graded check or fix a problem and it appears here.</p>"
    return f"""<!doctype html><html lang="en" translate="no"><head><meta charset="utf-8"><meta name="google" content="notranslate">
<title>winlab skills transcript: {esc(name)}</title>
<style>
@page {{ size: A4; margin: 14mm }}
*{{box-sizing:border-box}}
body{{margin:0;background:#e9ecf2;font:13.5px/1.45 "Segoe UI",ui-sans-serif,system-ui,sans-serif;color:#1b1b1b}}
.sheet{{width:210mm;min-height:297mm;margin:16px auto;background:#fff;padding:16mm 16mm;border:1px solid #d5dae4;
 box-shadow:0 10px 30px rgba(0,0,0,.12)}}
.brand{{display:flex;align-items:center;gap:10px;font:650 16px ui-monospace,Consolas,monospace}}
.brand i{{width:20px;height:20px;border-radius:5px;background:conic-gradient(#0067c0 0 25%,#4aa3ff 0 50%,#0067c0 0 75%,#4aa3ff 0)}}
h1{{font-size:26px;font-weight:600;margin:14px 0 2px}}
.sub{{color:#596273;margin:0 0 10px}}
.sum{{display:flex;gap:10px;margin:14px 0 6px;flex-wrap:wrap}}
.sum div{{flex:1;min-width:110px;border:1px solid #d5dae4;border-radius:6px;padding:8px 10px}}
.sum b{{display:block;font-size:20px;color:#0067c0}}
h2{{font-size:15px;margin:20px 0 6px;color:#0067c0}}
h3{{font-size:13.5px;margin:14px 0 4px}} h3 small{{color:#596273;font-weight:400}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;page-break-inside:auto}}
th{{text-align:left;color:#596273;font-weight:600;border-bottom:1px solid #d5dae4;padding:4px 6px}}
td{{border-bottom:1px solid #eef0f4;padding:4px 6px;vertical-align:top}}
.bar{{display:inline-block;width:120px;height:7px;background:#e6e9ef;border-radius:4px;vertical-align:middle}}
.bar i{{display:block;height:100%;background:#0067c0;border-radius:4px}}
.foot{{margin-top:22px;display:flex;justify-content:space-between;color:#596273;font-size:12px;border-top:1px solid #d5dae4;padding-top:8px}}
.print{{position:fixed;top:12px;right:16px}}
.print button{{font:600 13px inherit;background:#0067c0;color:#fff;border:0;border-radius:5px;padding:8px 14px;cursor:pointer}}
@media print{{body{{background:#fff}}.sheet{{margin:0;border:0;box-shadow:none;padding:0}}.print{{display:none}}}}
</style></head><body>
<div class="print"><button onclick="print()">Print or save as PDF</button></div>
<div class="sheet">
  <div class="brand"><i></i>winlab</div>
  <h1>Skills transcript: {esc(name)}</h1>
  <p class="sub">Windows Server and Windows 11 administration, practised on real Windows machines. Every graded
  lesson below was checked inside the machines it ran on, and every problem was a real fault fixed and verified there.</p>
  <div class="sum">
    <div><b>{f['lessons_done']}</b>lessons of {f['lessons_total']}</div>
    <div><b>{f['graded']}</b>graded in the machines</div>
    <div><b>{len(f['problems'])}</b>problems fixed</div>
    <div><b>{len(f['shifts'])}</b>on-call shifts</div>
    <div><b>{f['hours']} h</b>hands-on</div>
  </div>
  {empty}
  {('<h2>Lessons passed</h2>' + mods) if mods else ''}
  {probs}{shifts}{drills}{ivs}{irs}{desk}{game}{runs}{exm}
  <div class="foot"><span>{time.strftime('%d %B %Y')}</span><span>reference {_code(name, f)}</span><span>winlab {__version__}</span></div>
</div></body></html>"""
