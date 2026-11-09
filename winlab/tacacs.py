"""A TACACS+ server for the lab: tac_plus-ng, built by the student from its
source on a lab Linux machine, the way it is installed at work.

The router and the switches speak TACACS+ (winlab/aaa.py: login, exec
authorization, command authorization and accounting). Nothing in Ubuntu
24.04's or Debian 12's archive is a TACACS+ server any more (the old
shrubbery ``tacacs+`` package left with Python 2), so a lab needs one from
elsewhere. tac_plus-ng (Marc Huber's Event-Driven-Servers, a BSD-style
licence with the advertising clause, its own LICENSE) is the maintained
open-source one, and it has no binary releases and no distribution
packages: admins build it from source with ``./configure tac_plus-ng``,
``make`` and ``make install``. That is what the student does here, on the
machine the lesson names, offline.

The ``tacacs`` pack (winlab/debpacks.py) carries the compiler and the
libraries the build needs from the Ubuntu archive (build-essential,
libpcre2-dev, libssl-dev, libc-ares-dev; each .deb checked against the
archive's index) and, as its extra file, the source of one pinned commit of
the project, fetched on this PC from GitHub's archive of that commit.

How the source is checked. The project publishes no tarballs and no
checksums, so the commit itself is the pin: COMMIT is a full git commit id,
GitHub's API says which tree that commit holds, and the tarball is accepted
only when the git tree computed from its files (every blob hashed as git
hashes it, every directory as a git tree) is that tree. The repository
expands ``$Id$`` keywords on export (.gitattributes ``ident``), so each
``$Id: <blob> $`` is folded back to ``$Id$`` before hashing, as git does
when it checks a file in. A tarball that differs by one byte from the
commit is refused; nothing is built from it.

Nothing is bundled with winlab, and winlab compiles nothing: the source
travels on the stick and the student builds it inside the lab machine.
"""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
import time
from pathlib import Path

PRODUCT = "tac_plus-ng"
PROJECT = "Event-Driven-Servers"
LICENSE = "BSD-style (Marc Huber's licence, with the advertising clause; see LICENSE in the source)"
REPO = "MarcJHuber/event-driven-servers"
# The commit pinned (master on 7 Nov 2026: "Merge pull request #318"). The
# project has no tags or releases; a newer commit is a new pin.
COMMIT = "1904ec4a1f8adaf48bab9b98e328374628cdfff0"
TARBALL_URL = f"https://codeload.github.com/{REPO}/tar.gz/{COMMIT}"
COMMIT_API = f"https://api.github.com/repos/{REPO}/git/commits/{COMMIT}"
TARBALL = f"event-driven-servers-{COMMIT[:12]}.tar.gz"
PAGE = "https://projects.pro-bono-publico.de/event-driven-servers/doc/tac_plus-ng.html"
_IDENT = re.compile(rb"\$Id: [0-9a-f]{40} \$")


class TacacsError(Exception):
    pass


# debpacks.fetch catches a pack's extra-files error by this name.
ExtraError = TacacsError


# ------------------------------------------------------------ git's hashes
def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def _tree_sha(entries: list[tuple[str, str, str]]) -> str:
    """entries: (mode, name, sha hex). Git sorts names as bytes, a tree's
    name as if it ended in '/'."""
    def key(e):
        return e[1].encode() + (b"/" if e[0] == "40000" else b"")
    body = b"".join(m.encode() + b" " + n.encode() + b"\0" + bytes.fromhex(s) for m, n, s in sorted(entries, key=key))
    return hashlib.sha1(b"tree %d\0" % len(body) + body).hexdigest()


def tree_of_tar(path: Path) -> tuple[str, str]:
    """(git tree id, top directory) of a `git archive` tarball, with each
    expanded $Id$ folded back."""
    files: dict[str, tuple[str, str]] = {}   # path inside the top dir -> (mode, blob sha)
    top = ""
    try:
        with tarfile.open(path, "r:*") as tf:
            for m in tf.getmembers():
                if m.type in (tarfile.XGLTYPE, tarfile.XHDTYPE) or m.isdir():
                    continue
                head, _, rest = m.name.partition("/")
                if not rest:
                    raise TacacsError(f"{path.name}: {m.name} is outside the archive's top directory")
                if top and head != top:
                    raise TacacsError(f"{path.name}: more than one top directory")
                top = head
                if m.issym():
                    files[rest] = ("120000", blob_sha(m.linkname.encode()))
                elif m.isfile():
                    data = tf.extractfile(m).read()
                    data = _IDENT.sub(b"$Id$", data)
                    files[rest] = ("100755" if m.mode & 0o111 else "100644", blob_sha(data))
                else:
                    raise TacacsError(f"{path.name}: {m.name} is neither a file nor a link")
    except (tarfile.TarError, OSError) as exc:
        raise TacacsError(f"{path.name} is not a readable tarball ({exc})") from exc
    if not files:
        raise TacacsError(f"{path.name} is empty")

    def build(prefix: str) -> str:
        entries: dict[str, tuple[str, str]] = {}
        for p, (mode, sha) in files.items():
            if not p.startswith(prefix):
                continue
            name, sep, _ = p[len(prefix):].partition("/")
            if sep:
                if name not in entries:
                    entries[name] = ("40000", build(prefix + name + "/"))
            else:
                entries[name] = (mode, sha)
        return _tree_sha([(m, n, s) for n, (m, s) in entries.items()])

    return build(""), top


def commit_tree(get) -> str:
    """The tree the pinned commit holds, as GitHub's API says."""
    try:
        doc = json.loads(get(COMMIT_API, timeout=30).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - any failure: no pin to check against, so no fetch
        raise TacacsError(f"GitHub does not answer for {REPO} ({exc}); try again later") from exc
    sha = str(((doc or {}).get("tree") or {}).get("sha", ""))
    if str(doc.get("sha", "")) != COMMIT or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise TacacsError(f"GitHub did not describe commit {COMMIT} of {REPO}")
    return sha


# ------------------------------------------------------------ the pack's extra file
def fetch_extra(pack, d: Path, closure, get, download, say) -> dict:
    """After the tacacs pack's .debs (debpacks.fetch): the source."""
    from .bootstrap import BootstrapError
    want = commit_tree(get)
    dest = d / TARBALL
    say(f"{PRODUCT} source, commit {COMMIT[:12]}, from {TARBALL_URL}")
    try:
        download(TARBALL_URL, dest, expect_sha="", label=TARBALL)
    except BootstrapError as exc:
        raise TacacsError(str(exc)) from exc
    got, top = tree_of_tar(dest)
    if got != want:
        dest.unlink(missing_ok=True)
        raise TacacsError(f"{TARBALL} is not commit {COMMIT[:12]}: its files make git tree {got[:12]}, "
                          f"the commit holds {want[:12]}. Nothing was kept.")
    sha256 = hashlib.sha256(dest.read_bytes()).hexdigest()
    rec = {"name": PRODUCT, "version": f"commit {COMMIT[:12]}", "license": LICENSE, "file": TARBALL,
           "sha256": sha256, "tree": want, "commit": COMMIT, "top": top, "source": TARBALL_URL,
           "files": [TARBALL, "BUILD.txt"]}
    (d / "BUILD.txt").write_text(build_text(rec), encoding="utf-8", newline="\r\n")
    return rec


def extra_ready(d: Path, man: dict) -> bool:
    rec = man.get("extra") or {}
    files = rec.get("files") or []
    return (rec.get("commit") == COMMIT and bool(files)
            and all((d / f).is_file() and (d / f).stat().st_size > 0 for f in files))


def build_text(rec: dict) -> str:
    """The note beside the source on the stick: how to build it, never its
    configuration (the lesson aaa-tacacs-plus walks through that)."""
    return "\n".join([
        f"{PRODUCT} ({PROJECT}), {rec['version']}, {rec['license']}",
        f"from {rec['source']}, fetched {time.strftime('%Y-%m-%d')};",
        f"checked: its files make git tree {rec['tree']}, the tree of commit {rec['commit']} on GitHub.",
        f"SHA-256 of this tarball: {rec['sha256']}",
        "",
        "First install the build tools from this stick (README.txt). Then, as your own user:",
        f"  tar xzf /mnt/winlab-pack/{rec['file']} -C ~",
        f"  cd ~/{rec.get('top') or 'event-driven-servers-' + rec['commit']}",
        "  ./configure tac_plus-ng",
        "  make",
        "  sudo make install        (puts tac_plus-ng in /usr/local/sbin, its libraries in /usr/local/lib)",
        "  sudo ldconfig",
        "  ls -l /usr/local/sbin/tac_plus-ng",
        "",
        f"Its documentation: {PAGE}",
        "",
    ])
