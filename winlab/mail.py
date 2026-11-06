"""Mail inside the lab: the server the student builds, the clients they
install, and the drills that break it.

The server is Postfix and Dovecot on an Ubuntu machine, installed by hand
from the 'mail' pack (winlab/debpacks.py; webmail from the optional
'roundcube' pack). A lab names the packs a machine installs by hand in its
node vars (packs = ["mail"]), so Setup offers to fetch them, and the name
clients use for it (mail_name = "mail": mail.corp.lab), which the drills use.

The client is Mozilla Thunderbird (MPL-2.0), fetched from Mozilla's own
release archive onto this PC (the ESR release, verified against the
release's SHA256SUMS) and written onto a "mail client" stick on the lab's
media shelf: the Windows installer and the Linux tarball. Nothing is bundled
with winlab, and nothing is installed for the student.

What winlab does not fetch: Windows Server has no mail client and Windows
11's own (Outlook) wants a Microsoft account on the internet, so neither is
of use in the sealed lab. hMailServer, a Windows mail server, is freeware but
not open source: download its installer yourself and write it onto a stick
from the media shelf (Write to a stick). Exchange Server, from its
evaluation ISO, needs far more than a small lab has; winlab does not support
it.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to, _get

PRODUCT = "Mozilla Thunderbird"
LICENSE = "MPL-2.0"
VERSIONS_URL = "https://product-details.mozilla.org/1.0/thunderbird_versions.json"
ARCHIVE = "https://archive.mozilla.org/pub/thunderbird/releases"
PAGE = "https://www.thunderbird.net/"
# The release fetched when Mozilla's version list cannot be asked.
PINNED_VERSION = "140.0esr"
JOB = "mailclient-fetch"
STEP_LABEL = "Fetch Thunderbird (Mozilla's release archive)"
SIZE_TEXT = "about 150 MB"
STICK_LABEL = "MAILCLIENT"
META_NAME = "thunderbird.json"
# The files a release lists in its SHA256SUMS, per platform: the Windows MSI
# (msiexec /i, or a GPO software installation), else the setup .exe; the
# Linux tarball.
PATTERNS = {
    "windows": (r"^win64/en-US/Thunderbird Setup [^/]+\.msi$", r"^win64/en-US/Thunderbird Setup [^/]+\.exe$"),
    "linux": (r"^linux-x86_64/en-US/thunderbird-[^/]+\.tar\.(?:xz|bz2)$",),
}


class MailError(Exception):
    pass


# ----------------------------------------------------------- Thunderbird
def client_dir() -> Path:
    return paths.RUNTIME / "mailclient"


def meta() -> dict:
    try:
        return json.loads((client_dir() / META_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ready() -> bool:
    m = meta()
    files = m.get("files") or {}
    return bool(m.get("version")) and "windows" in files and all(
        (client_dir() / f["file"]).is_file() and (client_dir() / f["file"]).stat().st_size > 0
        for f in files.values())


def parse_sums(text: str) -> dict[str, str]:
    """A SHA256SUMS file -> {path: sha256}."""
    out = {}
    for line in text.splitlines():
        sha, _, path = line.strip().partition(" ")
        path = path.strip().lstrip("*")
        if len(sha) == 64 and path:
            out[path] = sha.lower()
    return out


def pick(sums: dict[str, str]) -> dict[str, str]:
    """{platform: path in the release} for the files winlab carries."""
    out = {}
    for platform, pats in PATTERNS.items():
        for pat in pats:
            hit = sorted(p for p in sums if re.match(pat, p))
            if hit:
                out[platform] = hit[0]
                break
    return out


def discover(get=_get) -> str:
    """The current ESR release (what organisations deploy), from Mozilla's
    version list; the pinned release when that cannot be asked."""
    try:
        d = json.loads(get(VERSIONS_URL, timeout=30).decode("utf-8"))
        v = str(d.get("THUNDERBIRD_ESR") or d.get("LATEST_THUNDERBIRD_VERSION") or "")
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)*(?:esr)?", v):
            return v
    except (BootstrapError, ValueError, AttributeError):
        pass
    return PINNED_VERSION


def fetch(progress=None, get=_get, download=_download_to) -> dict:
    """Fetches Thunderbird for Windows and Linux and records what it is."""
    say = progress or (lambda _m: None)
    version = discover(get)
    base = f"{ARCHIVE}/{version}"
    say(f"Thunderbird {version} from {base}/")
    try:
        sums = parse_sums(get(f"{base}/SHA256SUMS", timeout=60).decode("utf-8", "replace"))
    except BootstrapError as exc:
        raise MailError(str(exc)) from exc
    chosen = pick(sums)
    if "windows" not in chosen:
        raise MailError(f"Thunderbird {version} lists no Windows installer in its SHA256SUMS")
    d = client_dir()
    d.mkdir(parents=True, exist_ok=True)
    files = {}
    for platform, rel in chosen.items():
        name = rel.rsplit("/", 1)[-1]
        say(f"{platform}: {name}")
        try:
            download(f"{base}/{urllib.parse.quote(rel)}", d / name, expect_sha=sums[rel], label=name)
        except BootstrapError as exc:
            raise MailError(str(exc)) from exc
        files[platform] = {"file": name, "sha256": sums[rel], "source": f"{base}/{rel}"}
    m = {"name": PRODUCT, "version": version, "license": LICENSE, "fetched": time.strftime("%Y-%m-%d"),
         "files": files}
    (d / META_NAME).write_text(json.dumps(m, indent=1), encoding="utf-8")
    keep = {f["file"] for f in files.values()} | {META_NAME}
    for f in d.iterdir():
        if f.name not in keep:
            f.unlink()
    say(f"Thunderbird {version} ready: {d}")
    return m


def readme(m: dict) -> str:
    files = m.get("files", {})
    win = files.get("windows", {}).get("file", "")
    lin = files.get("linux", {}).get("file", "")
    lines = [f"{PRODUCT} {m.get('version', '')} ({LICENSE}), from Mozilla's release archive",
             f"fetched {m.get('fetched', '?')}, each file checked against the release's SHA256SUMS.", "",
             "Windows 11 (or Windows Server):",
             f"  run Windows\\{win}" + ("  (or: msiexec /i \"<stick>\\Windows\\" + win + "\" /qn)"
                                      if win.endswith(".msi") else ""),
             "  Then add an account: your name, alice@corp.lab, the password; Configure manually:",
             "  IMAP mail.corp.lab 993 SSL/TLS, SMTP mail.corp.lab 587 STARTTLS, Normal password.", ""]
    if lin:
        lines += ["Linux with a desktop:",
                  f"  tar -xf Linux/{lin} -C /opt   then run /opt/thunderbird/thunderbird", ""]
    lines += ["Thunderbird is a trademark of the Mozilla Foundation; winlab only carries the file you fetched."]
    return "\r\n".join(lines) + "\r\n"


def stick_files() -> dict[str, bytes]:
    if not ready():
        raise MailError("Thunderbird is not on this PC yet: fetch it in Images (Mail client), "
                        "or winlab mail fetch")
    m = meta()
    out = {}
    for platform, f in m["files"].items():
        out[f"{platform.capitalize()}/{f['file']}"] = (client_dir() / f["file"]).read_bytes()
    out["README.txt"] = readme(m).encode("utf-8")
    return out


def to_stick(lab_name: str) -> dict:
    """A new mail client stick on the lab's media shelf."""
    from . import media, mediashelf
    files = stick_files()
    title = f"Mail client (Thunderbird {meta().get('version', '')})".replace(" )", ")")
    sid = mediashelf._new_id(lab_name, "mail-client")
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise MailError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title, "files": len(files),
            "mb": sum(len(b) for b in files.values()) >> 20}


def summary() -> dict:
    m = meta()
    size = sum((client_dir() / f["file"]).stat().st_size for f in (m.get("files") or {}).values()
               if (client_dir() / f["file"]).is_file())
    return {"id": "thunderbird", "title": f"{PRODUCT} (mail client)", "ready": ready(),
            "version": m.get("version", ""), "fetched": m.get("fetched", ""), "license": LICENSE,
            "page": PAGE, "size_mb": round(size / 1048576, 1),
            "platforms": sorted((m.get("files") or {}).keys())}


def render_status() -> str:
    s = summary()
    state = (f"ready (Thunderbird {s['version']}, {', '.join(s['platforms'])}, {s['size_mb']} MB, "
             f"fetched {s['fetched']})" if s["ready"] else f"not fetched ({SIZE_TEXT})")
    return "\n".join([f"mail client store: {client_dir()}", "",
                      f"  thunderbird  {state}",
                      f"               {PRODUCT}, {LICENSE}, from {ARCHIVE}",
                      "               onto a stick: the media shelf's Mail client stick button",
                      "" if s["ready"] else "               then:    winlab mail fetch", ""])


# --------------------------------------------------------------- the lab
def hand_packs(node) -> list[str]:
    """The packs a lab says a machine installs by hand (node vars packs)."""
    from .debpacks import PACKS
    v = node.vars.get("packs") or []
    return [p for p in (v if isinstance(v, list) else [v]) if p in PACKS]


def mail_node(lab):
    """The machine the lab's mail server is built on, or None."""
    return next((n for n in lab.node_list() if "mail" in hand_packs(n)), None)


def fault_params(lab) -> dict[str, str]:
    """The drills' parameters (guestfaults.lab_params): the name clients
    use for the mail server and its address."""
    n = mail_node(lab)
    name = str(n.vars.get("mail_name") or "mail") if n is not None else "mail"
    nic = n.primary_nic if n is not None else None
    host = f"{name}.{lab.domain}" if lab.domain else name
    return {"mailhost": host, "mailip": nic.ip if nic and nic.ip else "",
            "mailserver": (n.hostname or n.id).lower() if n is not None else "the mail server"}


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """Setup steps for what a lab's machines install by hand: the packs in
    their node vars and Thunderbird for the PCs (vars downloads)."""
    from . import appliances, debpacks
    have = set(have or ())
    steps = []
    for n in lab.node_list():
        for pack_id in hand_packs(n):
            if f"pack-{pack_id}" in have:
                continue
            pk = debpacks.PACKS[pack_id]
            have.add(f"pack-{pack_id}")
            short = appliances.get_or_raise(pk.image).short if appliances.is_appliance(pk.image) else pk.image
            archive = "Debian" if pk.image.startswith("debian") else "Ubuntu"
            steps.append({"id": f"pack-{pack_id}", "label": f"Fetch the {pack_id} pack ({archive} archive)",
                          "done": debpacks.ready(pack_id),
                          "blocked": appliances.is_appliance(pk.image) and not appliances.ready(pk.image),
                          "hint": f"{pk.title}: {n.id} installs it by hand from a stick, about "
                                  f"{pk.typical_mb} MB; needs the {short} image first",
                          "pack": pack_id, "job": "pack-fetch"})
    who = [n.id for n in lab.node_list() if "thunderbird" in (n.vars.get("downloads") or [])]
    if who and "mailclient" not in have:
        steps.append({"id": "mailclient", "label": STEP_LABEL, "done": ready(), "blocked": False,
                      "hint": f"{', '.join(who)} install it from the mail client stick: {PRODUCT}, "
                              f"{LICENSE}, checked against the release's SHA256SUMS, {SIZE_TEXT} once",
                      "link": PAGE, "job": JOB})
    return steps


def act(dash, action: str, params: dict) -> dict:
    """The workbench's mail actions: wb-mail-stick writes the mail client
    stick onto the shelf."""
    if action == "wb-mail-stick":
        try:
            r = to_stick(dash.lab.name)
        except MailError as exc:
            return {"ok": False, "message": str(exc), "fetch": not ready()}
        return {"ok": True, "message": f"{r['title']} is on the shelf: drag it onto a PC", "stick": r["id"]}
    return {"ok": False, "message": f"unknown mail action {action!r}"}


# ------------------------------------------------------------- the drills
def _faults():
    from .guestfaults import LINUX, WINDOWS, GuestFault
    keep_main = "cp -n /etc/postfix/main.cf /etc/postfix/main.cf.winlab 2>/dev/null; "
    need = ("command -v postconf >/dev/null 2>&1 || { echo 'no Postfix on this machine: build the mail "
            "server first (lesson mail-server)'; exit 1; }; ")
    return [
        GuestFault(
            id="mail-wrong-mx",
            roles=("dns",),
            title="Mail for the domain goes to a server that is not there",
            os=WINDOWS,
            teaches="the MX record: what asks for it (another mail server, never your own Thunderbird), "
                    "what it must point at (a name with an A record), and reading it with Resolve-DnsName",
            symptom="mail from outside never arrives: swaks --to bob@{domain} on the mail server, which "
                    "delivers the way any other server would (by the domain's MX), cannot find a server; "
                    "Thunderbird between the PCs still works",
            apply=("$z = '{domain}'; $f = 'C:\\Windows\\Temp\\winlab-mx.xml'; "
                   "$mx = @(Get-DnsServerResourceRecord -ZoneName $z -RRType MX -ErrorAction SilentlyContinue); "
                   "if (-not (Test-Path $f)) { $mx | Select-Object HostName, @{n='Exchange';e={$_.RecordData.MailExchange}}, "
                   "@{n='Preference';e={$_.RecordData.Preference}} | Export-Clixml $f }; "
                   "$mx | Remove-DnsServerResourceRecord -ZoneName $z -Force; "
                   "Add-DnsServerResourceRecordMX -ZoneName $z -Name '.' -MailExchange 'mx1.{domain}' -Preference 10; 'broken'"),
            clear=("$z = '{domain}'; $f = 'C:\\Windows\\Temp\\winlab-mx.xml'; "
                   "Get-DnsServerResourceRecord -ZoneName $z -RRType MX -ErrorAction SilentlyContinue | "
                   "Remove-DnsServerResourceRecord -ZoneName $z -Force; "
                   "if (Test-Path $f) { foreach ($r in Import-Clixml $f) { $n = if ($r.HostName -eq '@') { '.' } else { $r.HostName }; "
                   "Add-DnsServerResourceRecordMX -ZoneName $z -Name $n -MailExchange $r.Exchange -Preference $r.Preference }; "
                   "Remove-Item $f }; 'ok'"),
            hints=(
                "Who uses the MX? Not Thunderbird: it talks to the server you typed in. Another mail server "
                "does: it asks DNS for the MX of the recipient's domain. On dc01: Resolve-DnsName {domain} "
                "-Type MX. Then resolve the name it gives: Resolve-DnsName <that name> -Type A.",
                "The MX names mx1.{domain}, and nothing in the zone has that name: an MX that points at no "
                "address is a dead end for every sender. In DNS Manager the zone's (same as parent folder) "
                "Mail Exchanger record shows it; Get-DnsServerResourceRecord -ZoneName {domain} -RRType MX "
                "lists it with its preference.",
                "Remove the wrong record (in DNS Manager, or Get-DnsServerResourceRecord -ZoneName {domain} -RRType MX | "
                "Remove-DnsServerResourceRecord -ZoneName {domain} -Force) and point the MX at the server's own A record: "
                "Add-DnsServerResourceRecordMX -ZoneName {domain} -Name '.' -MailExchange {mailhost} -Preference 10. "
                "An MX must name an A record, never a CNAME or an address. Test from {mailserver}: "
                "swaks --to bob@{domain} with no --server.",
            ),
            verify=("$mx = @(Resolve-DnsName -Name '{domain}' -Type MX -Server 127.0.0.1 -DnsOnly "
                    "-ErrorAction SilentlyContinue | Where-Object Type -eq 'MX'); $ok = $mx.Count -gt 0; "
                    "foreach ($m in $mx) { $a = @(Resolve-DnsName -Name $m.NameExchange -Type A -Server 127.0.0.1 "
                    "-DnsOnly -ErrorAction SilentlyContinue | Where-Object Type -eq 'A'); "
                    "if (-not ($a.IPAddress -contains '{mailip}')) { $ok = $false } }; $ok"),
        ),
        GuestFault(
            id="mail-relay-denied",
            images=("ubuntu",),
            title="The mail server refuses mail for its own domain: Relay access denied",
            os=LINUX,
            teaches="mydestination (the domains a Postfix server is final for), what relaying is, "
                    "smtpd_relay_restrictions, and reading the answer in the mail log",
            symptom="swaks --to bob@{domain} --server {mailhost} from another machine gets '554 5.7.1 "
                    "<bob@{domain}>: Relay access denied'; mail between logged-in users bounces with "
                    "'mail for {domain} loops back to myself'",
            apply=(need + keep_main + "postconf -e 'mydestination = localhost.localdomain, localhost' && "
                   "postfix reload >/dev/null 2>&1; echo broken"),
            clear=("[ -f /etc/postfix/main.cf.winlab ] && mv /etc/postfix/main.cf.winlab /etc/postfix/main.cf; "
                   "postfix reload >/dev/null 2>&1; echo ok"),
            shell="sh",
            hints=(
                "Read the refusal where Postfix writes it: journalctl -u postfix -n 30 (or grep 'reject' "
                "/var/log/mail.log). 'Relay access denied' is what Postfix says to a client that is not allowed "
                "to relay, for a recipient domain it does not think is its own.",
                "Relaying is passing mail on to another server. For its own domains Postfix is the final "
                "destination and nobody needs relay permission. postconf mydestination: {domain} is not in it "
                "any more, so Postfix thinks bob@{domain} lives somewhere else.",
                "Put the domain back: postconf -e 'mydestination = $myhostname, $mydomain, localhost' (postconf "
                "-x mydestination shows it expanded), then postfix reload. The relay rule itself "
                "(smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination) "
                "was right all along: never fix this by widening mynetworks.",
            ),
            verify=("{ postconf -xh mydestination; postconf -xh virtual_mailbox_domains; } 2>/dev/null | "
                    "tr ', ' '\\n\\n' | grep -qixF '{domain}' && postfix status >/dev/null 2>&1 && "
                    "! postconf -xh mynetworks | grep -qE '(^|[ ,])0\\.0\\.0\\.0/0' && echo True || echo False"),
        ),
        GuestFault(
            id="mail-cert-mismatch",
            images=("ubuntu",),
            title="Thunderbird warns about the certificate when it reads mail, not when it sends",
            os=LINUX,
            teaches="the certificate each daemon serves (Postfix and Dovecot each have their own setting), "
                    "the names in a certificate against the name clients use, and openssl s_client",
            symptom="Thunderbird asks to 'Add Security Exception' for {mailhost}:993: the certificate belongs "
                    "to a different site and is not trusted; sending on 587 is fine",
            apply=("command -v doveconf >/dev/null 2>&1 || { echo 'no Dovecot on this machine: build the mail server "
                   "first (lesson mail-server)'; exit 1; }; [ -f /etc/ssl/certs/ssl-cert-snakeoil.pem ] || "
                   "make-ssl-cert generate-default-snakeoil; "
                   "f=/etc/dovecot/local.conf; [ -e $f.winlab ] || [ -e $f.winlab-none ] || { [ -f $f ] && cp $f $f.winlab || : > $f.winlab-none; }; "
                   "printf '%s\\n' '# certificate after the reinstall' 'ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem' "
                   "'ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key' >> $f && systemctl reload dovecot; echo broken"),
            clear=("f=/etc/dovecot/local.conf; if [ -f $f.winlab ]; then mv $f.winlab $f; elif [ -f $f.winlab-none ]; "
                   "then rm -f $f $f.winlab-none; fi; systemctl reload dovecot; echo ok"),
            shell="sh",
            hints=(
                "Look at what each port serves, from the server itself: openssl s_client -connect {mailhost}:993 "
                "-servername {mailhost} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -ext "
                "subjectAltName, and the same with -starttls smtp -connect {mailhost}:587. They differ.",
                "On 993 the subject is the machine's own hostname and the issuer is the same name: a self-signed "
                "certificate (Ubuntu's snakeoil), not the one the lab CA issued for {mailhost}. Dovecot's "
                "setting decides: doveconf -n | grep ssl_cert, and grep -rn ssl_cert /etc/dovecot finds who set it.",
                "The last ssl_cert Dovecot reads wins, and local.conf is read last: remove the two lines there so "
                "ssl_cert and ssl_key in conf.d/10-ssl.conf name the lab CA's certificate and key again (the files "
                "postconf smtpd_tls_cert_file names), then systemctl reload dovecot. Check with the s_client line "
                "from the first hint, and in Thunderbird remove the exception if one was added.",
            ),
            verify=("d=$(doveconf -h ssl_cert 2>/dev/null | sed 's/^<//'); p=$(postconf -h smtpd_tls_cert_file 2>/dev/null); "
                    "[ -f \"$d\" ] && [ -f \"$p\" ] && openssl x509 -in \"$d\" -noout -checkhost {mailhost} 2>/dev/null | "
                    "grep -q 'does match' && [ \"$(openssl x509 -in \"$d\" -noout -fingerprint -sha256)\" = "
                    "\"$(openssl x509 -in \"$p\" -noout -fingerprint -sha256)\" ] && systemctl is-active -q dovecot "
                    "&& echo True || echo False"),
        ),
    ]


FAULT_IDS = ("mail-wrong-mx", "mail-relay-denied", "mail-cert-mismatch")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
