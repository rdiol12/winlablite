"""Network intrusion detection inside the lab: a Suricata sensor the student
builds on the boundary router, the rule set it reads from a stick, and the
drills that blind it.

This is defensive, blue-team content only: installing, configuring, tuning
and reading a sensor that watches the lab's own traffic.
There is no attacker machine, no scanner, no brute-force tool and no exploit
in the lab.
Every alert comes from harmless traffic the student makes on purpose:

  - the lab Internet (role inet-sites, content/roles/inet-sites.sh) serves
    /uid/index.html on every site, a plain-text page whose body is the
    well-known benign IDS test answer "uid=0(root) gid=0(root)
    groups=0(root)" (what the public "test my NIDS" pages serve). ET Open's
    stock rule 2100498 (GPL ATTACK_RESPONSE id check returned root) matches
    it, so a plain curl from a PC fires a stock alert;
  - the student's own local.rules (a web visit to games.example, a DNS query
    for a name, a ping to the DMZ server), triggered with a browser or curl,
    nslookup and ping.

The intrusion-detection lab (content/labs/intrusion-detection.toml) starts
empty:

  rt01   an Ubuntu router with three legs (the office, a DMZ, the lab
         Internet); the student turns forwarding on, installs Suricata from
         the 'suricata' pack (suricata, suricata-update, jq) and nftables
         from the 'nftables' pack, sets HOME_NET and the af-packet
         interface, reads eve.json with jq and fast.log, writes local rules,
         tunes a noisy one (threshold.config: suppress, threshold), and
         finally runs Suricata inline (NFQUEUE from an nftables forward
         chain) so the test response is dropped, not only reported.
  srv01  an Ubuntu web server in the DMZ (nginx from the 'nginx' pack), the
         $HTTP_SERVERS the rules talk about.
  dc01   AD, DNS (forwarding to the lab Internet's DNS) and DHCP.
  pc01   a Windows 11 PC that makes the traffic.
  inet01 the lab Internet (role inet-sites), somebody else's equipment that
         the lab brings up by itself.

The rules: Proofpoint's Emerging Threats Open ruleset (ET Open), fetched on
this PC from https://rules.emergingthreats.net/open/suricata-<version>/
emerging.rules.tar.gz for the Suricata version the pack carries (read from
the fetched pack, 7.0.3 on Ubuntu 24.04 when the pack is not fetched yet),
checked against the .md5 the site publishes beside it (the SHA-256 is
recorded when it publishes none), and written onto a "Suricata rules" stick
on the lab's media shelf together with its .md5 and a README. Inside rt01
the student points suricata-update at the stick as a local source
(suricata-update add-source ... file:///mnt/rules/emerging.rules.tar.gz), so
it never asks the internet. ET Open is free to use and redistribute under
its BSD-style licence (the GPL-derived rules under GPLv2); winlab carries
nothing of it in git and only writes the file the customer fetched.

Isolation: the lab never reaches the real internet, not even optionally.
suricata-update's own index and source list (update-sources, list-sources,
enable-source et/open) need the internet and are not used; neither are
GeoIP databases or ET Pro (a paid subscription). OPNsense's own intrusion
detection downloads its rule sets from the internet and cannot read them
from a stick, so the firewall labs do not use it; this lab builds the sensor
by hand instead.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
import time
from pathlib import Path

from . import debpacks, paths
from .bootstrap import BootstrapError, _download_to, _get, _sha256

PACKS = ("suricata", "nftables", "nginx")
PRODUCT = "Emerging Threats Open ruleset (ET Open)"
LICENSE = "BSD-style (Proofpoint); the GPL-derived rules GPLv2"
ET_BASE = "https://rules.emergingthreats.net/open"
PAGE = "https://rules.emergingthreats.net/OPEN_download_instructions.html"
ARCHIVE = "emerging.rules.tar.gz"
# The Suricata on Ubuntu 24.04 (suricata 1:7.0.3-1build3), used when the
# pack is not on this PC yet.
PINNED_VERSION = "7.0.3"
JOB = "idsrules-fetch"
DOWNLOAD_ID = "et-open"     # node vars downloads = ["et-open"]
STEP_LABEL = "Fetch the ET Open rules (rules.emergingthreats.net)"
SIZE_TEXT = "about 5 MB"
STICK_LABEL = "IDSRULES"
META_NAME = "etopen.json"
# The stock signature the lab Internet's test page fires, and the page.
TEST_SID = 2100498
TEST_PATH = "/uid/index.html"
TEST_BODY = "uid=0(root) gid=0(root) groups=0(root)"
LOCAL_SIDS = (1000000, 1999999)   # the range local rules use
DRILL_SID = 1000099               # the rule the rules-not-reloaded drill adds


class IdsError(Exception):
    pass


# --------------------------------------------------------- the rule set
def rules_dir() -> Path:
    return paths.RUNTIME / "idsrules"


def meta() -> dict:
    try:
        return json.loads((rules_dir() / META_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ready() -> bool:
    f = rules_dir() / ARCHIVE
    return bool(meta().get("version")) and f.is_file() and f.stat().st_size > 0


def suricata_version() -> str:
    """The Suricata version the fetched pack carries (1:7.0.3-1build3 ->
    7.0.3), else the one Ubuntu 24.04 ships."""
    for row in debpacks.manifest("suricata").get("packages") or []:
        if row.get("name") == "suricata":
            m = re.search(r"(?:^|:)(\d+\.\d+\.\d+)", str(row.get("version") or ""))
            if m:
                return m.group(1)
    return PINNED_VERSION


def candidate_urls(version: str) -> list[str]:
    """Where ET Open keeps the rules for a Suricata version: its own
    directory, then the major.minor one."""
    out = [f"{ET_BASE}/suricata-{version}/{ARCHIVE}"]
    mm = ".".join(version.split(".")[:2])
    if mm != version:
        out.append(f"{ET_BASE}/suricata-{mm}/{ARCHIVE}")
    return out


def parse_md5(text: str) -> str:
    m = re.search(r"\b([0-9a-fA-F]{32})\b", text)
    return m.group(1).lower() if m else ""


def _md5(path: Path) -> str:
    h = hashlib.md5()  # noqa: S324 - the checksum ET publishes, not a security boundary of ours
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def inspect_archive(path: Path) -> dict:
    """What is in the tarball: the number of rule files and rules, whether
    the test signature is there, the licence file's first line."""
    files = rules = 0
    has_test = False
    licence = ""
    try:
        with tarfile.open(path, "r:gz") as t:
            for m in t:
                if not m.isfile():
                    continue
                name = m.name.lstrip("./")
                if name.endswith(".rules"):
                    files += 1
                    data = t.extractfile(m).read().decode("utf-8", "replace")
                    rules += sum(1 for ln in data.splitlines() if re.match(r"\s*#?\s*(alert|drop|pass|reject)\s", ln))
                    has_test |= f"sid:{TEST_SID};" in data
                elif name.upper().endswith(("LICENSE", "LICENSE.TXT")) and not licence:
                    text = t.extractfile(m).read().decode("utf-8", "replace").strip()
                    licence = text.splitlines()[0][:120] if text else ""
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise IdsError(f"{path.name} is not a readable rules archive ({exc})") from exc
    if not files:
        raise IdsError(f"{path.name} holds no .rules files")
    return {"rule_files": files, "rules": rules, "test_sid": has_test, "licence": licence}


def fetch(progress=None, get=_get, download=_download_to) -> dict:
    """Fetches ET Open for the pack's Suricata version onto this PC, checked
    against the .md5 the site publishes beside it."""
    say = progress or (lambda _m: None)
    version = suricata_version()
    d = rules_dir()
    d.mkdir(parents=True, exist_ok=True)
    dest = d / ARCHIVE
    errors = []
    for url in candidate_urls(version):
        md5 = ""
        try:
            md5 = parse_md5(get(url + ".md5", timeout=30).decode("ascii", "replace"))
        except BootstrapError:
            md5 = ""
        say(f"ET Open for Suricata {version}: {url}" + ("" if md5 else " (no .md5 published)"))
        try:
            download(url, dest, expect_sha="", label=ARCHIVE)
        except BootstrapError as exc:
            errors.append(str(exc))
            continue
        break
    else:
        raise IdsError(f"ET Open for Suricata {version} could not be fetched: {'; '.join(errors)}")
    got = _md5(dest)
    if md5 and got != md5:
        dest.unlink(missing_ok=True)
        raise IdsError(f"{ARCHIVE} does not match the MD5 rules.emergingthreats.net publishes "
                       f"({got} against {md5}); try again later")
    info = inspect_archive(dest)
    if md5:
        (d / (ARCHIVE + ".md5")).write_text(md5 + "\n", encoding="ascii")
    else:
        (d / (ARCHIVE + ".md5")).unlink(missing_ok=True)
    m = {"name": PRODUCT, "version": version, "license": LICENSE, "source": url,
         "fetched": time.strftime("%Y-%m-%d"), "md5": got, "checksum": "published" if md5 else "recorded",
         "sha256": _sha256(dest), **info}
    (d / META_NAME).write_text(json.dumps(m, indent=1), encoding="utf-8")
    say(f"ET Open ready: {info['rules']} rules in {info['rule_files']} files"
        + ("" if info["test_sid"] else f" (sid {TEST_SID} not among them)") + f", {d}")
    return m


def readme(m: dict) -> str:
    lines = [f"{PRODUCT} for Suricata {m.get('version', '')}, {LICENSE}",
             f"fetched on the host PC {m.get('fetched', '?')} from {m.get('source', '')}",
             ("checked against the MD5 the site publishes: " if m.get("checksum") == "published"
              else "no MD5 was published: winlab recorded ") + f"MD5 {m.get('md5', '')}",
             f"SHA-256 {m.get('sha256', '')}", "",
             "On the sensor (rt01), offline, never from the internet:",
             f"  sudo mkdir -p /mnt/rules; sudo mount LABEL={STICK_LABEL} /mnt/rules",
             f"  sudo suricata-update add-source et-open-stick file:///mnt/rules/{ARCHIVE}",
             "  sudo suricata-update",
             "  -> /var/lib/suricata/rules/suricata.rules, then: sudo systemctl reload suricata",
             "Do not run suricata-update update-sources or enable-source: they ask the internet.", "",
             "The licence travels inside the archive (rules/LICENSE). Emerging Threats is a",
             "Proofpoint brand; winlab only carries the file you fetched."]
    return "\r\n".join(lines) + "\r\n"


def stick_files() -> dict[str, bytes]:
    if not ready():
        raise IdsError("the ET Open rules are not on this PC yet: fetch them in Images (Suricata rules), "
                       "or winlab ids fetch")
    d = rules_dir()
    out = {ARCHIVE: (d / ARCHIVE).read_bytes()}
    if (d / (ARCHIVE + ".md5")).is_file():
        out[ARCHIVE + ".md5"] = (d / (ARCHIVE + ".md5")).read_bytes()
    out["README.txt"] = readme(meta()).encode("utf-8")
    return out


def to_stick(lab_name: str) -> dict:
    """A new Suricata rules stick on the lab's media shelf."""
    from . import media, mediashelf
    files = stick_files()
    title = f"Suricata rules (ET Open {meta().get('fetched', '')})".replace(" )", ")")
    sid = mediashelf._new_id(lab_name, "suricata-rules")
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise IdsError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title, "files": len(files),
            "mb": sum(len(b) for b in files.values()) >> 20}


def summary() -> dict:
    m = meta()
    f = rules_dir() / ARCHIVE
    return {"id": DOWNLOAD_ID, "title": f"{PRODUCT} for Suricata", "ready": ready(),
            "version": m.get("version", ""), "fetched": m.get("fetched", ""), "license": LICENSE,
            "page": PAGE, "rules": m.get("rules", 0), "checksum": m.get("checksum", ""),
            "size_mb": round(f.stat().st_size / 1048576, 1) if f.is_file() else 0}


def render_status() -> str:
    s = summary()
    lines = ["intrusion detection lab (intrusion-detection): what this PC fetches", ""]
    for p in PACKS:
        st = debpacks.status(p)
        state = (f"ready ({st['count']} packages, {st['size_mb']} MB, fetched {st['fetched']})"
                 if st["ready"] else f"not fetched (about {st['typical_mb']} MB)")
        lines.append(f"  pack {p:<9} {state}")
    state = (f"ready (Suricata {s['version']}, {s['rules']} rules, MD5 {s['checksum']}, fetched {s['fetched']})"
             if s["ready"] else f"not fetched ({SIZE_TEXT})")
    lines += [f"  ET Open        {state}",
              f"                 {PRODUCT}, {LICENSE}, from {ET_BASE}/",
              "                 onto a stick: the media shelf's Suricata rules stick button, or winlab ids stick <lab>"]
    if not (s["ready"] and all(debpacks.ready(p) for p in PACKS)):
        lines += ["", "  then:  winlab ids fetch   (the packs and the rules)"]
    lines += ["", f"the test traffic: http://<any .example site>{TEST_PATH} on the lab Internet answers",
              f"  '{TEST_BODY}', which ET Open's sid {TEST_SID} reports; nothing in the lab attacks anything", ""]
    return "\n".join(lines)


def fetch_all(progress=None, refresh: bool = False, get=_get, download=_download_to) -> dict:
    """The packs first (the rules follow the pack's Suricata version), then
    the rules."""
    extra = {k: v for k, v in (("get", get), ("download", download)) if v is not None}
    packs = []
    for p in PACKS:
        try:
            packs.append(debpacks.fetch(p, progress=progress, refresh=refresh, **extra))
        except debpacks.PackError as exc:
            raise IdsError(f"{p}: {exc}") from exc
    return {"packs": packs, "rules": fetch(progress=progress, get=get, download=download)}


# --------------------------------------------------------------- the lab
_RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def sensor_node(lab):
    """The machine the sensor is built on (node vars packs has suricata)."""
    from .mail import hand_packs
    return next((n for n in lab.node_list() if "suricata" in hand_packs(n)), None)


def fault_params(lab) -> dict[str, str]:
    """The drills' parameters (guestfaults.lab_params): the sensor's legs
    (its address on the office segment and on the DMZ), both inside
    segments, the DMZ server's address."""
    import ipaddress
    n = sensor_node(lab)
    if n is None:
        return {}
    out: dict[str, str] = {"sensor": (n.hostname or n.id).lower()}
    inside = []
    for i, nic in enumerate(n.nics):
        net = lab.networks.get(nic.network)
        if net is None or not net.cidr:
            continue
        cidr = str(ipaddress.ip_network(net.cidr, strict=False))
        if any(ipaddress.ip_network(cidr).subnet_of(ipaddress.ip_network(r)) for r in _RFC1918):
            inside.append((i, nic, cidr))
    if inside:
        out["corpgw"], out["corpnet"] = inside[0][1].ip or "", inside[0][2]
    if len(inside) > 1:
        out["dmzgw"], out["dmznet"] = inside[1][1].ip or "", inside[1][2]
        srv = next((m for m in lab.node_list() if m is not n and m.primary_nic is not None
                    and m.primary_nic.network == inside[1][1].network and m.primary_nic.ip), None)
        if srv is not None:
            out["srvip"] = srv.primary_nic.ip
    return out


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """The Setup step for the rules when a machine names them (node vars
    downloads = ["et-open"]); the packs come through mail.setup_steps."""
    have = set(have or ())
    who = [n.id for n in lab.node_list() if DOWNLOAD_ID in (n.vars.get("downloads") or [])]
    if not who or DOWNLOAD_ID in have:
        return []
    return [{"id": DOWNLOAD_ID, "label": STEP_LABEL, "done": ready(), "blocked": False,
             "hint": f"{', '.join(who)} load{'s' if len(who) == 1 else ''} them from the Suricata rules stick "
                     f"with suricata-update: {PRODUCT}, {LICENSE}, checked against the published MD5, {SIZE_TEXT}",
             "link": PAGE, "job": JOB}]


def act(dash, action: str, params: dict) -> dict:
    """The workbench's IDS action: wb-ids-stick writes the Suricata rules
    stick onto the shelf."""
    if action == "wb-ids-stick":
        try:
            r = to_stick(dash.lab.name)
        except IdsError as exc:
            return {"ok": False, "message": str(exc), "fetch": not ready()}
        return {"ok": True, "message": f"{r['title']} is on the shelf: drag it onto the sensor", "stick": r["id"]}
    return {"ok": False, "message": f"unknown IDS action {action!r}"}


# ------------------------------------------------------------- the drills
_NEED = ("command -v suricata >/dev/null 2>&1 || { echo 'no Suricata on this machine: build the sensor first "
         "(lesson ids-sensor)'; exit 1; }; f=/etc/suricata/suricata.yaml; ")
_DUMP = "suricata --dump-config -c /etc/suricata/suricata.yaml 2>/dev/null"
# The interface that holds an address, by the address.
def _iface(ip: str) -> str:
    return ("ip -o -4 addr show | awk -v a='" + ip + "' '{split($4, p, \"/\"); if (p[1] == a) {print $2; exit}}'")


# HOME_NET covers both inside segments (python3 is on the Ubuntu image).
_HOME_OK = ("v=$(" + _DUMP + " | sed -n 's/^vars\\.address-groups\\.HOME_NET = //p'); "
            "python3 -c 'import ipaddress, sys; s = sys.argv[1].strip().strip(\"[]\"); "
            "pos = [ipaddress.ip_network(x.strip(), strict=False) for x in s.split(\",\") "
            "if x.strip() and x.strip()[0] not in \"!$\" and x.strip() != \"any\"]; "
            "need = [ipaddress.ip_network(a) for a in sys.argv[2:] if a]; "
            "print(bool(pos) and all(any(n.subnet_of(p) for p in pos) for n in need))' "
            "\"$v\" '{corpnet}' '{dmznet}' 2>/dev/null || echo False")


def _faults():
    from .guestfaults import LINUX, GuestFault
    return [
        GuestFault(
            id="ids-wrong-interface",
            images=("ubuntu",),
            title="The sensor runs and has seen nothing since the change window",
            os=LINUX,
            teaches="where Suricata listens (the af-packet section and the service's command line), "
                    "which of a router's legs sees which traffic, and proving it with stats in eve.json",
            symptom="suricata is active, but curl http://news.example/uid/index.html from pc01 raises no alert "
                    "in fast.log or eve.json any more; pings from pc01 to the DMZ server still show up",
            apply=(_NEED + "[ -f $f.winlab-iface ] || cp $f $f.winlab-iface; "
                   "to=$(" + _iface("{dmzgw}") + "); [ -n \"$to\" ] || to=eth1; "
                   "awk -v to=\"$to\" '/^[A-Za-z]/ {s = ($0 ~ /^af-packet:/)} "
                   "s && !d && /^[ \\t]*-[ \\t]*interface:/ {sub(/interface:.*/, \"interface: \" to); d = 1} {print}' "
                   "$f > $f.tmp && cat $f.tmp > $f && rm -f $f.tmp && systemctl restart suricata; echo broken"),
            clear=("f=/etc/suricata/suricata.yaml; [ -f $f.winlab-iface ] && cat $f.winlab-iface > $f && "
                   "rm -f $f.winlab-iface; systemctl restart suricata; echo ok"),
            shell="sh",
            hints=(
                "Ask the sensor what it sees before you blame the rules. jq -c 'select(.event_type==\"stats\") | "
                ".stats.capture' /var/log/suricata/eve.json | tail -n 2 shows packets still counted, so it "
                "captures somewhere. Which interface? grep -A2 '^af-packet' /etc/suricata/suricata.yaml, and "
                "systemctl cat suricata for the command line (--af-packet takes the interfaces from that section).",
                "A router's legs see different traffic. ip -br addr: the office leg holds {corpgw}, the DMZ leg "
                "{dmzgw}. A PC's visit to the lab Internet crosses the office leg and the outside leg, never the "
                "DMZ leg, and the sensor now listens on the DMZ leg only. sudo tcpdump -ni <leg> host 203.0.113.80 "
                "on each leg while pc01 runs its curl proves it.",
                "Set the first af-packet entry back to the office leg (the one with {corpgw}): - interface: <that "
                "name>, then sudo suricata -T -c /etc/suricata/suricata.yaml and sudo systemctl restart suricata. "
                "The office leg sees everything the office does, to the DMZ and to the Internet, once. Run the curl "
                "from pc01 again: sid 2100498 is in fast.log.",
            ),
            verify=("systemctl is-active -q suricata || { echo False; exit 0; }; "
                    "if pgrep -af suricata | grep -qE -- ' (-q|--nfqueue)'; then echo True; exit 0; fi; "
                    "want=$(" + _iface("{corpgw}") + "); [ -n \"$want\" ] || { echo False; exit 0; }; "
                    + _DUMP + " | sed -n 's/^af-packet\\.[0-9]*\\.interface = //p' | grep -qx \"$want\" "
                    "&& echo True || echo False"),
        ),
        GuestFault(
            id="ids-home-net",
            images=("ubuntu",),
            title="The stock test alert fires, our own rules have gone quiet",
            os=LINUX,
            teaches="HOME_NET and EXTERNAL_NET: what $HOME_NET -> $EXTERNAL_NET means in a rule's header, why a "
                    "rule written for any any still matches, and reading the running value with --dump-config",
            symptom="sid 2100498 still shows up for the uid test page, but the local rule for a visit to "
                    "games.example (and every other $HOME_NET rule) has raised nothing since the sensor's "
                    "configuration was 'aligned with the branch office'",
            apply=(_NEED + "[ -f $f.winlab-homenet ] || cp $f $f.winlab-homenet; "
                   "sed -i 's|^\\([[:space:]]*\\)HOME_NET:.*|\\1HOME_NET: \"[192.168.0.0/16]\"|' $f && "
                   "systemctl restart suricata; echo broken"),
            clear=("f=/etc/suricata/suricata.yaml; [ -f $f.winlab-homenet ] && cat $f.winlab-homenet > $f && "
                   "rm -f $f.winlab-homenet; systemctl restart suricata; echo ok"),
            shell="sh",
            hints=(
                "Compare the rule that fires with the ones that do not. grep 2100498 /var/lib/suricata/rules/"
                "suricata.rules: its header is alert ip any any -> any any. Your games.example rule says "
                "$HOME_NET any -> $EXTERNAL_NET any. Only the variables differ.",
                "Read what the engine uses, not what you remember: sudo suricata --dump-config | grep -E "
                "'HOME_NET|EXTERNAL_NET'. HOME_NET is 192.168.0.0/16 now, so pc01 ({corpnet}) is not home; the "
                "source of the visit fails $HOME_NET and the rule never matches.",
                "Set HOME_NET in /etc/suricata/suricata.yaml to the two inside segments, \"[{corpnet},{dmznet}]\", "
                "keep EXTERNAL_NET \"!$HOME_NET\", then sudo suricata -T -c /etc/suricata/suricata.yaml and sudo "
                "systemctl restart suricata (the variables are read at start, a rule reload does not change them). "
                "Open http://games.example on pc01: your rule is back in fast.log.",
            ),
            verify="systemctl is-active -q suricata || { echo False; exit 0; }; " + _HOME_OK,
        ),
        GuestFault(
            id="ids-rules-not-reloaded",
            images=("ubuntu",),
            title="A new rule went into local.rules this morning and has never fired",
            os=LINUX,
            teaches="the rules a running Suricata uses are the ones it loaded: suricata -T to test, "
                    "reload-rules (suricatasc, systemctl reload) to load, and the reload in suricata.log",
            symptom=f"local.rules has a rule for social.example (sid {DRILL_SID}) that a colleague added; users "
                    "open http://social.example all day and the rule has not raised one alert",
            apply=(_NEED + "r=$(" + _DUMP + " | sed -n 's/^rule-files\\.[0-9]* = //p' | grep 'local' | head -n 1); "
                   "case \"$r\" in '') r=/etc/suricata/rules/local.rules ;; /*) ;; *) r=\"$(" + _DUMP +
                   " | sed -n 's/^default-rule-path = //p')/$r\" ;; esac; mkdir -p \"$(dirname \"$r\")\"; "
                   "sed -i '/sid:" + str(DRILL_SID) + ";/d' \"$r\" 2>/dev/null; "
                   "printf '%s\\n' 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"LOCAL policy: "
                   "social.example visited\"; flow:established,to_server; http.host; content:\"social.example\"; "
                   "classtype:policy-violation; sid:" + str(DRILL_SID) + "; rev:1;)' >> \"$r\"; echo broken"),
            clear=("for r in /etc/suricata/rules/*.rules /var/lib/suricata/rules/local*.rules; do [ -f \"$r\" ] && "
                   "sed -i '/sid:" + str(DRILL_SID) + ";/d' \"$r\"; done; systemctl reload suricata 2>/dev/null; echo ok"),
            shell="sh",
            hints=(
                "Is the rule wrong, or is it not loaded? sudo suricata -T -c /etc/suricata/suricata.yaml -v "
                "tests the files as they are now and says how many rules load: no error. Then look at when the "
                "engine last read its rules: grep -iE 'rule reload|signatures processed' /var/log/suricata/"
                "suricata.log | tail -n 3, and ls -l --time-style=full-iso on local.rules.",
                "Suricata reads its rules at start and when told to reload, never by itself. local.rules is newer "
                "than the last load, so the engine is still running yesterday's set; the file was changed and "
                "nobody told it.",
                "sudo systemctl reload suricata (it runs suricatasc -c reload-rules), or sudo suricatasc -c "
                "reload-rules; suricata.log says rule reload complete. Then open http://social.example on pc01 "
                f"and find sid {DRILL_SID} in fast.log. Make it a habit: test with suricata -T, then reload, "
                "after every change and after every suricata-update.",
            ),
            verify=("zcat -f /var/log/suricata/eve.json* 2>/dev/null | jq -c -R 'fromjson? | select(.event_type == "
                    f"\"alert\" and .alert.signature_id == {DRILL_SID})' 2>/dev/null | head -n 1 | grep -q . "
                    "&& echo True || echo False"),
        ),
    ]


FAULT_IDS = ("ids-wrong-interface", "ids-home-net", "ids-rules-not-reloaded")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
