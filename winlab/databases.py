"""Databases inside the lab: PostgreSQL and MariaDB servers the student
builds on Ubuntu, the Windows clients they install, and the drills that
break them. It sits beside the SQL Server lessons on the every-role lab
(sql01, install-sql-server and the rest), which teach Microsoft's engine.

The servers come from the Ubuntu archive as packs (winlab/debpacks.py):
'postgresql' (PostgreSQL 16 with contrib, its client, and krb5-user for the
optional Kerberos lesson) and 'mariadb' (MariaDB 10.11 server, client and
mariadb-backup). MariaDB is the MySQL-compatible engine winlab carries: it
is Debian's and Ubuntu's community default, GPLv2 throughout, and its
replication with GTIDs is the clearest to teach. Ubuntu's archive also has
mysql-server-8.0 (Oracle's MySQL); it cannot share a machine with MariaDB
and teaches nothing the MariaDB lessons do not, so winlab has no pack for
it. A lab names the packs a machine installs by hand in its node vars
(packs = ["postgresql"]) and the part each machine plays (pg = "primary" or
"standby", maria = "primary" or "replica"), which the drills read.

The Windows clients are fetched on this PC from their projects' official
sources and written onto a "database clients" stick on the lab's media
shelf; the student installs them inside the Windows machine:

  pgAdmin 4 (PostgreSQL Licence), from ftp.postgresql.org; the current
    version is read from pgadmin.org's versions.json. The pgAdmin project
    publishes no checksum for its Windows installer, so winlab records the
    SHA-256 of the file it got and the README says to check the installer's
    signature inside the machine (Get-AuthenticodeSignature) before running
    it. pgAdmin carries psql.exe, pg_dump.exe and pg_restore.exe in its
    runtime folder, which the lessons use from Windows.
  HeidiSQL (GPLv2), the project's GitHub release: the setup .exe, checked
    against the SHA-256 GitHub publishes for each release asset.
  psqlODBC (LGPL), the PostgreSQL ODBC driver, the project's GitHub release
    (postgresql-interfaces/psqlodbc): the x64 MSI, checked the same way.

What winlab does not fetch: MySQL Workbench (GPLv2) comes from Oracle's
download pages, which steer every visitor through an Oracle account form
and give no stable file URL; it also warns on MariaDB servers. HeidiSQL
does the same job for MariaDB and PostgreSQL. A customer who wants
Workbench downloads it themselves and writes it onto a stick from the media
shelf (Write to a stick). Nothing is bundled with winlab, and nothing is
installed or configured for the student. The lab never reaches the
internet: everything above is fetched on this PC and carried in on sticks.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to, _get, _sha256

JOB = "dbclients-fetch"
STEP_LABEL = "Fetch the database clients (pgAdmin, HeidiSQL, psqlODBC)"
SIZE_TEXT = "about 230 MB"
STICK_LABEL = "DBCLIENTS"
META_NAME = "dbclients.json"
DOWNLOAD_ID = "dbclients"   # node vars downloads = ["dbclients"]
GITHUB_API = "https://api.github.com/repos"
PGADMIN_VERSIONS = "https://www.pgadmin.org/versions.json"
PGADMIN_FTP = "https://ftp.postgresql.org/pub/pgadmin/pgadmin4"
# The pgAdmin release fetched when pgadmin.org's version list cannot be asked.
PGADMIN_PINNED = "9.9"


@dataclass(frozen=True)
class Client:
    id: str
    product: str
    license: str
    page: str
    source: str        # where the file comes from, for LICENSING and status
    required: bool     # the stick is ready without it when False


CLIENTS: dict[str, Client] = {
    "pgadmin": Client("pgadmin", "pgAdmin 4", "PostgreSQL Licence", "https://www.pgadmin.org/",
                      f"{PGADMIN_FTP}/", True),
    "heidisql": Client("heidisql", "HeidiSQL", "GPL-2.0", "https://www.heidisql.com/",
                       "https://github.com/HeidiSQL/HeidiSQL/releases", True),
    "psqlodbc": Client("psqlodbc", "psqlODBC (PostgreSQL ODBC driver)", "LGPL-2.0",
                       "https://odbc.postgresql.org/",
                       "https://github.com/postgresql-interfaces/psqlodbc/releases", False),
}
REPOS = {"heidisql": "HeidiSQL/HeidiSQL", "psqlodbc": "postgresql-interfaces/psqlodbc"}
# The release asset each GitHub project's latest release is searched for,
# best first.
ASSETS = {
    "heidisql": (r"^HeidiSQL_[\d.]+_Setup\.exe$",),
    "psqlodbc": (r"(?i)^psqlodbc[^/]*(?:x64|amd64)[^/]*\.msi$", r"(?i)^psqlodbc[^/]*(?:x64|amd64)[^/]*\.zip$"),
}


class DatabaseError(Exception):
    pass


# ------------------------------------------------------------ the clients
def client_dir() -> Path:
    return paths.RUNTIME / "dbclients"


def meta() -> dict:
    try:
        return json.loads((client_dir() / META_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _have(entry: dict | None) -> bool:
    if not entry or not entry.get("file"):
        return False
    f = client_dir() / entry["file"]
    return f.is_file() and f.stat().st_size > 0


def ready() -> bool:
    files = meta().get("files") or {}
    return all(_have(files.get(c.id)) for c in CLIENTS.values() if c.required)


def pgadmin_release(get=_get) -> tuple[str, str]:
    """(version, installer URL) of pgAdmin 4 for Windows: the version from
    pgadmin.org's versions.json, the pinned one when that cannot be asked."""
    version = ""
    try:
        d = json.loads(get(PGADMIN_VERSIONS, timeout=30).decode("utf-8"))
        v = str((d.get("pgadmin4") or {}).get("version") or "")
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", v):
            version = v
    except (BootstrapError, ValueError, AttributeError):
        pass
    version = version or PGADMIN_PINNED
    return version, f"{PGADMIN_FTP}/v{version}/windows/pgadmin4-{version}-x64.exe"


def pick_asset(assets: list[dict], patterns: tuple[str, ...]) -> dict | None:
    """The first release asset a pattern matches, patterns in order."""
    for pat in patterns:
        hit = sorted((a for a in assets if re.match(pat, str(a.get("name", "")))), key=lambda a: a["name"])
        if hit:
            return hit[0]
    return None


def github_release(client_id: str, get=_get) -> tuple[str, str, str, str]:
    """(version, file name, URL, SHA-256 or '') of a project's latest
    release asset, from GitHub's API; the SHA-256 is the digest GitHub
    publishes for the asset."""
    repo = REPOS[client_id]
    try:
        rel = json.loads(get(f"{GITHUB_API}/{repo}/releases/latest", timeout=30).decode("utf-8"))
    except (BootstrapError, ValueError) as exc:
        raise DatabaseError(f"GitHub does not answer for {repo} ({exc}); try again later, or download "
                            f"it from {CLIENTS[client_id].source} yourself and write it onto a stick "
                            f"from the media shelf") from exc
    asset = pick_asset(list(rel.get("assets") or []), ASSETS[client_id])
    if asset is None:
        raise DatabaseError(f"the latest {CLIENTS[client_id].product} release lists no Windows installer")
    digest = str(asset.get("digest") or "")
    sha = digest.split(":", 1)[1].lower() if digest.lower().startswith("sha256:") else ""
    tag = str(rel.get("tag_name") or "")
    version = re.sub(r"^(?:v|REL-)", "", tag).replace("_", ".")
    return version, str(asset["name"]), str(asset["browser_download_url"]), sha


def _fetch_one(client_id: str, say, get, download) -> dict:
    d = client_dir()
    d.mkdir(parents=True, exist_ok=True)
    if client_id == "pgadmin":
        version, url = pgadmin_release(get)
        name, sha = url.rsplit("/", 1)[-1], ""
    else:
        version, name, url, sha = github_release(client_id, get)
    say(f"{CLIENTS[client_id].product} {version}: {name}")
    try:
        download(url, d / name, expect_sha=sha, label=name)
    except BootstrapError as exc:
        raise DatabaseError(str(exc)) from exc
    checked = "published" if sha else "recorded"
    if not sha:
        sha = _sha256(d / name)
    return {"file": name, "version": version, "sha256": sha, "checksum": checked, "source": url,
            "license": CLIENTS[client_id].license}


def fetch(only: str = "", progress=None, get=_get, download=_download_to) -> dict:
    """Fetches the Windows clients (or one of them) onto this PC. A client
    that fails does not throw away the others; the error names it."""
    say = progress or (lambda _m: None)
    if only and only not in CLIENTS:
        raise DatabaseError(f"no client {only!r}; known: {', '.join(CLIENTS)}")
    old = meta()
    files = dict(old.get("files") or {})
    errors = []
    for cid in ([only] if only else list(CLIENTS)):
        try:
            files[cid] = _fetch_one(cid, say, get, download)
        except DatabaseError as exc:
            errors.append(f"{CLIENTS[cid].product}: {exc}")
            say(f"{CLIENTS[cid].product}: {exc}")
    m = {"fetched": time.strftime("%Y-%m-%d"), "files": files}
    (client_dir()).mkdir(parents=True, exist_ok=True)
    (client_dir() / META_NAME).write_text(json.dumps(m, indent=1), encoding="utf-8")
    keep = {f["file"] for f in files.values()} | {META_NAME}
    for f in client_dir().iterdir():
        if f.name not in keep and not f.name.endswith(".part"):
            f.unlink()
    if errors and (only or not ready()):
        raise DatabaseError("; ".join(errors))
    say(f"database clients ready: {client_dir()}" + (f" (not fetched: {'; '.join(errors)})" if errors else ""))
    return m


def readme(m: dict) -> str:
    files = m.get("files") or {}
    lines = ["Database clients for the lab's Windows machines, fetched on the host PC "
             f"{m.get('fetched', '?')} from each project's own release.", ""]
    for cid, c in CLIENTS.items():
        f = files.get(cid)
        if not f:
            continue
        how = ("checked against the SHA-256 the project's release publishes" if f.get("checksum") == "published"
               else "no checksum is published for it: winlab recorded the SHA-256 below")
        lines += [f"{c.product} {f.get('version', '')} ({c.license}), from {f.get('source', '')}",
                  f"  {how}", f"  SHA-256 {f.get('sha256', '')}"]
        if cid == "pgadmin":
            lines += [f"  Check it first: Get-AuthenticodeSignature .\\Windows\\{f['file']} shows Status Valid,",
                      "  and Get-FileHash .\\Windows\\" + f["file"] + " gives the SHA-256 above.",
                      f"  Install: .\\Windows\\{f['file']} /VERYSILENT /ALLUSERS  (or run it and click through)",
                      "  psql.exe, pg_dump.exe and pg_restore.exe are in C:\\Program Files\\pgAdmin 4\\runtime"]
        elif cid == "heidisql":
            lines += [f"  Install: .\\Windows\\{f['file']} /VERYSILENT  (or run it and click through)"]
        elif f["file"].lower().endswith(".msi"):
            lines += [f"  Install: msiexec /i \"<stick>\\Windows\\{f['file']}\" /qn",
                      "  Then Get-OdbcDriver -Name 'PostgreSQL*' lists PostgreSQL Unicode(x64) and ANSI(x64)."]
        else:
            lines += ["  Unzip it and run the MSI inside with msiexec /i."]
        lines.append("")
    lines += ["MySQL Workbench is not on this stick: Oracle's download goes through an account form.",
              "PostgreSQL and pgAdmin are trademarks of the PostgreSQL Community Association;",
              "MariaDB is a trademark of MariaDB plc. winlab only carries the files you fetched."]
    return "\r\n".join(lines) + "\r\n"


def stick_files() -> dict[str, bytes]:
    if not ready():
        raise DatabaseError("the database clients are not on this PC yet: fetch them in Images "
                            "(Database clients), or winlab databases fetch")
    m = meta()
    out = {}
    for cid, f in (m.get("files") or {}).items():
        if _have(f):
            out[f"Windows/{f['file']}"] = (client_dir() / f["file"]).read_bytes()
    out["README.txt"] = readme(m).encode("utf-8")
    return out


def to_stick(lab_name: str) -> dict:
    """A new database clients stick on the lab's media shelf."""
    from . import media, mediashelf
    files = stick_files()
    title = "Database clients (pgAdmin, HeidiSQL" + (", psqlODBC)" if _have((meta().get("files") or {})
                                                                         .get("psqlodbc")) else ")")
    sid = mediashelf._new_id(lab_name, "db-clients")
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise DatabaseError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title, "files": len(files),
            "mb": sum(len(b) for b in files.values()) >> 20}


def summary() -> dict:
    m = meta()
    files = m.get("files") or {}
    size = sum((client_dir() / f["file"]).stat().st_size for f in files.values() if _have(f))
    return {"id": DOWNLOAD_ID, "title": "Database clients (pgAdmin 4, HeidiSQL, psqlODBC)", "ready": ready(),
            "fetched": m.get("fetched", ""), "size_mb": round(size / 1048576, 1),
            "clients": [{"id": c.id, "product": c.product, "license": c.license, "page": c.page,
                         "ready": _have(files.get(c.id)), "version": (files.get(c.id) or {}).get("version", ""),
                         "checksum": (files.get(c.id) or {}).get("checksum", "")} for c in CLIENTS.values()]}


def render_status() -> str:
    s = summary()
    lines = [f"database clients store: {client_dir()}", ""]
    for c in s["clients"]:
        cl = CLIENTS[c["id"]]
        state = (f"ready ({c['version']}, checksum {c['checksum']})" if c["ready"]
                 else "not fetched" + ("" if cl.required else " (optional)"))
        lines += [f"  {c['id']:<10} {state}", f"  {'':<10} {cl.product}, {cl.license}, from {cl.source}"]
    lines += ["", "  onto a stick: the media shelf's Database clients stick button, or winlab databases stick <lab>"]
    if not s["ready"]:
        lines.append(f"  then:         winlab databases fetch   ({SIZE_TEXT})")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------- the lab
def _node_with(lab, var: str, value: str):
    return next((n for n in lab.node_list() if str(n.vars.get(var) or "") == value), None)


def _host(lab, n, fallback: str) -> str:
    if n is None:
        return fallback
    name = (n.hostname or n.id).lower()
    return f"{name}.{lab.domain}" if lab.domain else name


def _like(cidr: str) -> str:
    """A subnet as MariaDB writes an account's host part: 10.88.0.0/24 ->
    10.88.0.%; a subnet that is not on an octet boundary as address/mask."""
    import ipaddress
    if not cidr:
        return "%"
    net = ipaddress.ip_network(cidr, strict=False)
    if net.prefixlen % 8 == 0 and 0 < net.prefixlen < 32:
        return ".".join(str(net.network_address).split(".")[: net.prefixlen // 8]) + ".%"
    return f"{net.network_address}/{net.netmask}"


def fault_params(lab) -> dict[str, str]:
    """The drills' parameters (guestfaults.lab_params): the PostgreSQL
    primary and standby, the MariaDB server, the lab's subnet."""
    import ipaddress
    prim, stby = _node_with(lab, "pg", "primary"), _node_with(lab, "pg", "standby")
    maria = _node_with(lab, "maria", "primary")
    if prim is None and maria is None:
        return {}   # no database machines: guestfaults.DEFAULTS stand
    net = ""
    anchor = prim or maria
    nic = anchor.primary_nic if anchor is not None else None
    if nic is not None and nic.network in lab.networks and lab.networks[nic.network].cidr:
        net = str(ipaddress.ip_network(lab.networks[nic.network].cidr, strict=False))
    return {"pgprimary": _host(lab, prim, "the PostgreSQL primary"),
            "pgprimaryip": nic.ip if prim is not None and nic is not None and nic.ip else "",
            "pgstandby": _host(lab, stby, "the standby"),
            "mariahost": _host(lab, maria, "the MariaDB server"),
            "dbnet": net or "0.0.0.0/0", "dbhosts": _like(net)}


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """The Setup step for the Windows clients when a machine in the lab
    names them (node vars downloads = ["dbclients"]); the packs come
    through mail.setup_steps, which lists every hand-installed pack."""
    have = set(have or ())
    who = [n.id for n in lab.node_list() if DOWNLOAD_ID in (n.vars.get("downloads") or [])]
    if not who or DOWNLOAD_ID in have:
        return []
    return [{"id": DOWNLOAD_ID, "label": STEP_LABEL, "done": ready(), "blocked": False,
             "hint": f"{', '.join(who)} install{'s' if len(who) == 1 else ''} them from the database clients "
                     f"stick: pgAdmin 4, HeidiSQL and the PostgreSQL ODBC driver from their projects' own "
                     f"releases, {SIZE_TEXT} once",
             "link": CLIENTS["pgadmin"].page, "job": JOB}]


def act(dash, action: str, params: dict) -> dict:
    """The workbench's database action: wb-db-stick writes the database
    clients stick onto the shelf."""
    if action == "wb-db-stick":
        try:
            r = to_stick(dash.lab.name)
        except DatabaseError as exc:
            return {"ok": False, "message": str(exc), "fetch": not ready()}
        return {"ok": True, "message": f"{r['title']} is on the shelf: drag it onto a Windows machine",
                "stick": r["id"]}
    return {"ok": False, "message": f"unknown database action {action!r}"}


# ------------------------------------------------------------- the drills
_PSQL = "runuser -u postgres -- psql -AtX"
_NEED_PG = ("command -v pg_lsclusters >/dev/null 2>&1 || { echo 'no PostgreSQL on this machine: build it "
            "first (lesson postgresql-install-roles)'; exit 1; }; ")
_HBA = (f"f=$({_PSQL} -c 'show hba_file' 2>/dev/null); [ -f \"$f\" ] || {{ echo 'PostgreSQL is not "
        "running: systemctl status postgresql'; exit 1; }; ")
_RELOAD = f"{_PSQL} -c 'select pg_reload_conf()' >/dev/null; "


def _faults():
    from .guestfaults import LINUX, GuestFault
    return [
        GuestFault(
            id="pg-hba-rejects-remote",
            images=("ubuntu",),
            title="PostgreSQL turns away every remote client: pg_hba.conf rejects connection",
            os=LINUX,
            teaches="how pg_hba.conf is read (top to bottom, the first line that matches decides), "
                    "pg_hba_file_rules, reloading, and reading the refusal in the server log",
            symptom="pgAdmin and psql on the Windows machine get 'FATAL: pg_hba.conf rejects connection for "
                    "host ...'; psql on {pgprimary} itself still works, and so does the standby's replication",
            apply=(_NEED_PG + _HBA + "[ -e \"$f.winlab\" ] || cp -p \"$f\" \"$f.winlab\"; "
                   "sed -i -e '1i # audit: remote logins only through the jump host' -e '1i host    all    all    "
                   "{dbnet}    reject' \"$f\" && " + _RELOAD + "echo broken"),
            clear=(_NEED_PG + _HBA + "[ -f \"$f.winlab\" ] && mv \"$f.winlab\" \"$f\"; " + _RELOAD + "echo ok"),
            shell="sh",
            hints=(
                "The client's message is exact: 'rejects connection' means a line matched and its method is "
                "reject (no line at all would say 'no pg_hba.conf entry'). The server says the same: "
                "journalctl -u postgresql@16-main -n 20, or tail /var/log/postgresql/postgresql-16-main.log.",
                "pg_hba.conf is read from the top and the first matching line wins; lines below it never get "
                "a say. runuser -u postgres -- psql -c 'table pg_hba_file_rules' lists the lines in order with "
                "their line numbers: one near the top sends all of {dbnet} to reject.",
                "Remove that line (sudoedit the file psql -c 'show hba_file' names), keep your host line with "
                "scram-sha-256 for {dbnet}, then reload: sudo systemctl reload postgresql, or select "
                "pg_reload_conf(). An edit without a reload changes nothing. Then connect again from pgAdmin.",
            ),
            verify=(f"{_PSQL} -c \"select count(*) filter (where error is not null) = 0 and count(*) filter "
                    "(where type like 'host%' and auth_method = 'reject') = 0 and count(*) filter (where type "
                    "like 'host%' and auth_method in ('scram-sha-256', 'gss')) > 0 and pg_conf_load_time() >= "
                    "(pg_stat_file(current_setting('hba_file'))).modification from pg_hba_file_rules\" "
                    "2>/dev/null | grep -qx t && echo True || echo False"),
        ),
        GuestFault(
            id="pg-listen-localhost",
            images=("ubuntu",),
            title="PostgreSQL listens on localhost only, whatever postgresql.conf says",
            os=LINUX,
            teaches="listen_addresses, where a setting really comes from (pg_settings sourcefile), "
                    "ALTER SYSTEM and postgresql.auto.conf, and which settings need a restart",
            symptom="from the Windows machine Test-NetConnection {pgprimary} -Port 5432 fails and pgAdmin "
                    "says 'Connection refused'; on the server ss -ltn shows 127.0.0.1:5432 only, although "
                    "postgresql.conf has listen_addresses = '*'",
            apply=(_NEED_PG + "d=$(" + _PSQL + " -c 'show data_directory' 2>/dev/null); [ -d \"$d\" ] || "
                   "{ echo 'PostgreSQL is not running'; exit 1; }; [ -e /var/lib/postgresql/winlab-auto.conf ] || "
                   "cp -p \"$d/postgresql.auto.conf\" /var/lib/postgresql/winlab-auto.conf; "
                   + _PSQL + " -c \"ALTER SYSTEM SET listen_addresses = 'localhost'\" >/dev/null && "
                   "systemctl restart postgresql; echo broken"),
            clear=(_NEED_PG + "d=$(" + _PSQL + " -c 'show data_directory' 2>/dev/null); "
                   "if [ -f /var/lib/postgresql/winlab-auto.conf ] && [ -d \"$d\" ]; then "
                   "mv /var/lib/postgresql/winlab-auto.conf \"$d/postgresql.auto.conf\"; "
                   "chown postgres:postgres \"$d/postgresql.auto.conf\"; else " + _PSQL
                   + " -c 'ALTER SYSTEM RESET listen_addresses' >/dev/null; fi; systemctl restart postgresql; echo ok"),
            shell="sh",
            hints=(
                "Ask the server, not the file: runuser -u postgres -- psql -c 'show listen_addresses'. Then "
                "where that value came from: select name, setting, sourcefile, sourceline from pg_settings "
                "where name = 'listen_addresses'.",
                "The value comes from postgresql.auto.conf in the data directory, which is read after "
                "postgresql.conf and wins. ALTER SYSTEM writes that file; someone ran ALTER SYSTEM SET "
                "listen_addresses = 'localhost'. Never edit postgresql.auto.conf by hand.",
                "Undo it the way it was made: ALTER SYSTEM RESET listen_addresses (as postgres in psql), then "
                "sudo systemctl restart postgresql: listen_addresses is read only at start, a reload is not "
                "enough. ss -ltn shows 0.0.0.0:5432 again; pg_hba.conf and ufw still decide who gets in.",
            ),
            verify=("ss -Hltn 'sport = :5432' | awk '{print $4}' | grep -qvE '^(127\\.0\\.0\\.1|\\[::1\\]):5432$' "
                    "&& echo True || echo False"),
        ),
        GuestFault(
            id="pg-standby-broken",
            images=("ubuntu",),
            title="The standby stopped following the primary",
            os=LINUX,
            teaches="primary_conninfo, pg_stat_wal_receiver on the standby and pg_stat_replication on the "
                    "primary, the standby's log, and when a standby has to be seeded again",
            symptom="rows written on {pgprimary} never show up on {pgstandby}; on the primary "
                    "select * from pg_stat_replication returns nothing",
            apply=(_NEED_PG + _PSQL + " -c 'select pg_is_in_recovery()' 2>/dev/null | grep -qx t || { echo 'this "
                   "machine is not a standby yet: build replication first (lesson postgresql-streaming-replication)'; "
                   "exit 1; }; d=$(" + _PSQL + " -c 'show data_directory'); a=\"$d/postgresql.auto.conf\"; "
                   "[ -e /var/lib/postgresql/winlab-standby.conf ] || cp -p \"$a\" /var/lib/postgresql/winlab-standby.conf; "
                   "sed -i -E \"/^primary_conninfo/ s/host=(''[^']*''|[^ ']+)/host=db-old.{domain}/\" \"$a\" && "
                   + _RELOAD + "echo broken"),
            clear=(_NEED_PG + "d=$(" + _PSQL + " -c 'show data_directory'); "
                   "[ -f /var/lib/postgresql/winlab-standby.conf ] && mv /var/lib/postgresql/winlab-standby.conf "
                   "\"$d/postgresql.auto.conf\" && chown postgres:postgres \"$d/postgresql.auto.conf\"; "
                   + _RELOAD + "echo ok"),
            shell="sh",
            hints=(
                "Start on the standby: runuser -u postgres -- psql -c 'select * from pg_stat_wal_receiver' is "
                "empty, so no WAL is arriving. Its log says why: tail -n 20 /var/log/postgresql/postgresql-16-main.log.",
                "The log cannot resolve db-old.{domain}: show primary_conninfo names a host that is not the "
                "primary. pg_basebackup -R wrote primary_conninfo into postgresql.auto.conf; someone changed "
                "it. The other classic in that log is 'requested WAL segment ... has already been removed': the "
                "standby was off longer than the primary kept WAL, and then only a fresh pg_basebackup (and a "
                "replication slot from then on) brings it back.",
                "Point it at the primary again: ALTER SYSTEM SET primary_conninfo = followed by the connection "
                "string with host={pgprimary} and the replication user (the password comes from ~postgres/.pgpass, "
                "never from this line), then select pg_reload_conf(). Since PostgreSQL 13 a reload is enough. "
                "pg_stat_wal_receiver shows status streaming, and pg_stat_replication on {pgprimary} shows the standby.",
            ),
            verify=(f"{_PSQL} -c \"select count(*) from pg_stat_wal_receiver where status = 'streaming'\" "
                    "2>/dev/null | grep -qx 1 && echo True || echo False"),
        ),
        GuestFault(
            id="mariadb-bind-localhost",
            images=("ubuntu",),
            title="MariaDB answers on the server and nowhere else",
            os=LINUX,
            teaches="bind-address, the order MariaDB reads its option files in, my_print_defaults, "
                    "and telling a network refusal from an account refusal",
            symptom="HeidiSQL on the Windows machine says 'Can't connect to server on {mariahost} (10061)'; "
                    "mariadb on the server itself logs in fine",
            apply=("command -v mariadb >/dev/null 2>&1 || { echo 'no MariaDB on this machine: build it first "
                   "(lesson database-remote-access)'; exit 1; }; printf '%s\\n' '# hardening baseline' '[mysqld]' "
                   "'bind-address = 127.0.0.1' > /etc/mysql/mariadb.conf.d/99-hardening.cnf && "
                   "systemctl restart mariadb; echo broken"),
            clear="rm -f /etc/mysql/mariadb.conf.d/99-hardening.cnf; systemctl restart mariadb; echo ok",
            shell="sh",
            hints=(
                "10061 is Windows for connection refused: nothing listens there, so this is not about accounts "
                "or passwords (those answer 1045 Access denied, or 1130 host is not allowed). On the server: "
                "ss -ltn | grep 3306.",
                "It listens on 127.0.0.1 only. my_print_defaults --mysqld lists every option mysqld gets, in "
                "the order it reads them, and the last one wins: grep -rn bind-address /etc/mysql finds a "
                "file read after 50-server.cnf.",
                "Delete or fix the later file (99-hardening.cnf) so bind-address is 0.0.0.0 or the server's "
                "own address, then sudo systemctl restart mariadb (bind-address is read at start). ufw and "
                "the account's host part ('app'@'{dbhosts}') still decide who gets in.",
            ),
            verify=("ss -Hltn 'sport = :3306' | awk '{print $4}' | grep -qvE '^(127\\.0\\.0\\.1|\\[::1\\]):3306$' "
                    "&& echo True || echo False"),
        ),
    ]


FAULT_IDS = ("pg-hba-rejects-remote", "pg-listen-localhost", "pg-standby-broken", "mariadb-bind-localhost")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
