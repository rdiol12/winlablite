"""Webmin: the real management pages of the lab's Linux boxes that have no
web GUI of their own, and the other real GUIs the lab's servers already run.

Webmin (BSD-3-Clause, webmin.com) is the web console Linux admins use to run
a box from a browser: its Linux RAID, Logical Volume Management and iSCSI
TGTd modules build a storage array's RAID groups, volumes and targets; its
System Time and System Logs modules look after a time server or a log
collector. In winlab it is the firmware of the storage array (role ``san``)
and of the NTP server (role ``ntp-server``). On an Ubuntu machine (the mail
server, a log collector) the student installs it by hand from the ``webmin``
pack, like Postfix and Dovecot, when the lab names that pack.

Nothing is bundled. For the Alpine appliances the pinned release tarball is
fetched from Webmin's own GitHub release onto this PC at preparation, checked
against its SHA-256, and carried on the repository volume beside the Alpine
packages (apkrepo.build_image); the ``webmin`` role installs it from there
onto the appliance's own internal disk at its first power-on, so it is there
at every power-on after. For Ubuntu machines the same release's .deb comes in
the ``webmin`` pack (winlab/debpacks.py) with its dependencies from the
Ubuntu archive.

Factory state: Webmin installed and listening on https 10000 (its own
self-signed certificate, which the browser warns about), nothing configured.
On an appliance root signs in with the lab's password (Start > Lab password),
set as Webmin's own password for root at install; on Ubuntu Webmin's package
lets any user who may sudo sign in with their own password, which on the lab's
machines is the administrator account with the lab's password.

This module also registers the AdminGui of each (winlab/adminui.py), and of
the other real web GUIs already on the lab's servers: Roundcube webmail and
Rspamd's web interface on the mail server, the mail lab's DNS host (Webmin's
BIND module, role inet-mail), Grafana and Prometheus on the monitoring appliance.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import adminui, paths
from .adminui import AdminGui, Target
from .bootstrap import BootstrapError, _download_to

PRODUCT = "Webmin"
LICENSE = "BSD-3-Clause"
VERSION = "2.670"
PAGE = "https://webmin.com/"
RELEASE = f"https://github.com/webmin/webmin/releases/download/{VERSION}"
TARBALL = f"webmin-{VERSION}.tar.gz"
# The digest GitHub publishes for the release asset (checked against the
# downloaded file when this version was pinned).
TARBALL_SHA256 = "617af07a890bea18a83dca5c9d7168de1ad4d5f3076d8a1df3475f123748dc21"
TARBALL_SIZE = 38959343
DEB = f"webmin_{VERSION}_all.deb"
DEB_SHA256 = "9fdacf6b219a186ec5d7dbbbe0f46e9802cbd7050d91605bd0dfc48e150e47dc"
DEB_SIZE = 28094738
# The .deb's own control fields (dpkg-deb -f), so the pack resolves its
# dependencies against the Ubuntu archive like any other package.
DEB_DEPENDS = ("perl, libnet-ssleay-perl, openssl, libauthen-pam-perl, libpam-runtime, libio-pty-perl, "
               "unzip, shared-mime-info, tar, libdigest-sha-perl, libdigest-md5-perl, gzip")
PORT = 10000
# On the repository volume: <volume>/webmin/<tarball>; the role looks for it
# under Alpine's mount of the volume (/media/<device>/webmin).
VOLUME_DIR = "webmin"
# The Alpine packages Webmin needs on an appliance: Perl, Net::SSLeay for its
# https, IO::Tty for its terminal, openssl to make its certificate at install,
# and e2fsprogs for the appliance's internal disk. (Alpine has no Authen::PAM
# package and no PAM in its base; Webmin signs root in with its own password.)
APK = ("perl", "perl-net-ssleay", "perl-io-tty", "openssl", "e2fsprogs")
SIZE_TEXT = "about 37 MB"
STEP_LABEL = "Fetch Webmin (its GitHub release)"


class WebminError(Exception):
    pass


# ------------------------------------------------------------- the tarball
def store() -> Path:
    return paths.downloads_dir() / "webmin"


def tarball_path() -> Path:
    return store() / TARBALL


def ready() -> bool:
    p = tarball_path()
    return p.is_file() and p.stat().st_size == TARBALL_SIZE


def fetch(progress=None, download=_download_to) -> Path:
    """The pinned release tarball from Webmin's GitHub release onto this PC,
    verified against its SHA-256; files of other versions are removed."""
    say = progress or (lambda _m: None)
    dest = tarball_path()
    say(f"Webmin {VERSION} from {RELEASE}/{TARBALL}")
    try:
        download(f"{RELEASE}/{TARBALL}", dest, expect_sha=TARBALL_SHA256, label=TARBALL)
    except BootstrapError as exc:
        raise WebminError(str(exc)) from exc
    for f in store().iterdir():
        if f.name not in (TARBALL, "webmin.json"):
            f.unlink()
    (store() / "webmin.json").write_text(json.dumps({
        "name": PRODUCT, "version": VERSION, "license": LICENSE, "sha256": TARBALL_SHA256,
        "source": f"{RELEASE}/{TARBALL}", "fetched": time.strftime("%Y-%m-%d")}, indent=1), encoding="utf-8")
    say(f"Webmin {VERSION} ready: {dest}")
    return dest


def volume_files() -> list[tuple[str, Path]]:
    """What the repository volume carries for the appliances' Webmin: the
    tarball, when it was fetched (apkrepo.build_image)."""
    return [(f"{VOLUME_DIR}/{TARBALL}", tarball_path())] if ready() else []


def summary() -> dict:
    m = {}
    try:
        m = json.loads((store() / "webmin.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return {"id": "webmin", "title": f"{PRODUCT} {VERSION}", "ready": ready(), "version": VERSION,
            "license": LICENSE, "page": PAGE, "fetched": m.get("fetched", ""),
            "size_mb": round(TARBALL_SIZE / 1048576, 1)}


def deb_stanza() -> str:
    """The release .deb as one stanza of a Packages index, its Filename
    relative to the release (debpacks reads it as a repository of one)."""
    return "\n".join([
        "Package: webmin", f"Version: {VERSION}", "Architecture: all", "Priority: optional", "Section: admin",
        "Pre-Depends: perl", f"Depends: {DEB_DEPENDS}", "Provides: webmin",
        "Maintainer: Jamie Cameron <jcameron@webmin.com>",
        f"Filename: {DEB}", f"Size: {DEB_SIZE}", f"SHA256: {DEB_SHA256}",
        "Description: web-based administration interface for Unix systems"])


# --------------------------------------------------------------- the GUIs
APPLIANCE_SIGN_IN = "root, with the lab's password (Start > Lab password)"


def ubuntu_sign_in() -> str:
    from . import appliances
    user = appliances.get_or_raise("ubuntu").user
    return f"{user} (any account that may sudo), with the lab's password (Start > Lab password)"


def webmin_gui(note: str, sign_in: str = APPLIANCE_SIGN_IN) -> AdminGui:
    return AdminGui(software=f"{PRODUCT} {VERSION}", scheme="https", port=PORT, path="/", sign_in=sign_in,
                    license=LICENSE, note=note)


ROUNDCUBE = AdminGui(software="Roundcube Webmail", scheme="http", port=80, path="/roundcube/",
                     sign_in="a mailbox user (alice@corp.lab) with that mailbox's password",
                     license="GPL-3.0-or-later",
                     note="Webmail on the mail server, once you install the roundcube pack and enable its "
                          "Alias in /etc/roundcube/apache.conf.")
RSPAMD = AdminGui(software="Rspamd", scheme="http", port=11334, path="/",
                  sign_in="the controller password you set (rspamadm pw, in local.d/worker-controller.inc)",
                  license="Apache-2.0",
                  note="The mail filter's own web interface, once you install the mailfilter pack and bind its "
                       "controller to the server's address: History shows each message's score and symbols.")
# The mail lab's Internet (role inet-mail): the DNS host's control panel.
DNS_HOST_NOTE = ("The DNS host's control panel: its BIND DNS Server module shows the one zone the company may "
                 "edit, corp.lab; add records, then Apply Configuration.")
GRAFANA_NOTE = "Dashboards over what Prometheus scrapes; viewing needs no sign-in."
PROMETHEUS = AdminGui(software="Prometheus", scheme="http", port=9090, path="/targets",
                      sign_in="nobody: Prometheus has no sign-in", license="Apache-2.0",
                      note="Its Targets page: every machine it scrapes, up or down, and the last error.")


def _node_gui(lab, node):
    roles = set(getattr(node, "roles", ()) or ())
    image = getattr(node, "image", "")
    if image == "alpine" and "san" in roles:
        return webmin_gui("Linux RAID builds the RAID groups from the drives in its bays, Logical Volume "
                          "Management carves volumes out of them, iSCSI TGTd makes the targets that offer them.")
    if image == "alpine" and "ntp-server" in roles:
        return webmin_gui("System Time shows and sets its clock and Bootup and Shutdown restarts chronyd; "
                          "System Logs reads what chronyd says.")
    if "inet-mail" in roles:
        return webmin_gui(DNS_HOST_NOTE, "corp (the company's account at the DNS host), with the lab's "
                                         "password (Start > Lab password)")
    if "grafana" in roles:
        from . import metrics
        return AdminGui(software="Grafana", scheme="http", port=metrics.GRAFANA_PORT, path="/",
                        sign_in="admin, with the lab's password (Start > Lab password)", license="AGPL-3.0",
                        note=GRAFANA_NOTE)
    packs = _hand_packs(node)
    if "webmin" in packs:
        if "syslog-server" in roles:
            what = "its System Logs module reads the files rsyslog writes, /var/log/remote/<host> among them."
        else:
            what = "its Postfix Mail Server and Dovecot IMAP/POP3 Server modules read the same files you edit."
        return webmin_gui("Once you install it from the webmin pack: " + what, ubuntu_sign_in())
    if "roundcube" in packs:
        return ROUNDCUBE
    return None


def _hand_packs(node) -> list[str]:
    v = (getattr(node, "vars", None) or {}).get("packs") or []
    return [str(p) for p in (v if isinstance(v, list) else [v])]


def target_key(node_id: str, what: str) -> str:
    """A second page on a machine whose own page is another one: the page
    draws the Targets whose key is '<machine>#<what>' in its panel."""
    return f"{node_id}#{what}"


def _targets(lab) -> list[Target]:
    out = []
    for node in lab.node_list():
        host = _address(lab, node)
        if "grafana" in (node.roles or []):
            out.append(Target(target_key(node.id, "prometheus"), "Prometheus", host, PROMETHEUS))
        packs = _hand_packs(node)
        if "webmin" in packs and "roundcube" in packs:
            out.append(Target(target_key(node.id, "webmail"), "Webmail", host, ROUNDCUBE))
        if "mailfilter" in packs:
            out.append(Target(target_key(node.id, "rspamd"), "Mail filter", host, RSPAMD))
    return out


def _address(lab, node) -> str:
    nic = node.primary_nic
    if nic is not None and nic.ip:
        return nic.ip
    return (node.hostname or node.id).lower()


adminui.register(node_gui=_node_gui, targets=_targets)


# ------------------------------------------------------------------ Setup
APPLIANCE_ROLES = ("san", "ntp-server")


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """A Setup step when a lab has an appliance that runs Webmin and the
    tarball is not on this PC (a fabric prepared before it was added)."""
    who = [n.id for n in lab.node_list() if n.image == "alpine" and set(n.roles or ()) & set(APPLIANCE_ROLES)]
    if not who or "webmin" in set(have or ()):
        return []
    return [{"id": "webmin", "label": STEP_LABEL, "done": ready(), "blocked": False,
             "hint": f"the management pages of {', '.join(who)}: {PRODUCT} {VERSION} ({LICENSE}), checked "
                     f"against its SHA-256, {SIZE_TEXT} once, carried on the Alpine repository volume",
             "link": PAGE, "job": "webmin-fetch"}]


def fetch_onto_volume(progress=None) -> Path:
    """Fetch the tarball, then rebuild the repository volume around it."""
    from . import apkrepo
    fetch(progress)
    cache = apkrepo.cached()
    if cache is None:
        raise WebminError("the Alpine packages are not fetched yet: prepare the fabric first "
                          "(winlab images prepare fabric), which fetches Webmin too")
    img = apkrepo.build_image(cache)
    (progress or (lambda _m: None))(f"repository volume rebuilt with Webmin: {img}")
    return img
