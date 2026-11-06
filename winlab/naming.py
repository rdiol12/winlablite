"""The names a student gives the machines and services they build.

Every machine keeps a stable id (`dc01`): the key its disks, MAC addresses,
checkpoints, firewall rules and lessons hang off. What the student calls it is
its computer name (`hostname`), which Windows takes at install, the desktop
shows everywhere, and the command line accepts in place of the id. The same
split holds for services: the domain and NetBIOS name live on the lab, and the
file server's main share, the AD sites and the DHCP scopes carry the student's
names in the lab's [names] table, keyed by what winlab would otherwise call
them.

Lessons and exercises are written once, against winlab's own names (corp.lab,
CORP, DC01, the Company share, the HQ and Branch sites). `Localizer` rewrites
their text, scripts and expected output into the student's names, in one pass
so that swapped names cannot chain, so a lab called contoso.test with a file
server called FILES grades exactly like the shipped one.
"""

from __future__ import annotations

import re
from dataclasses import replace

from . import paths
from .model import Lab, Node

# What the lessons and exercises are written against.
AUTHORED_DOMAIN = "corp.lab"
AUTHORED_NETBIOS = "CORP"
AUTHORED_SHARE = "Company"

# A computer name: what Windows accepts and NetBIOS can carry.
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$")
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NETBIOS = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$")
_SHARE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9 _.-]{0,38}[A-Za-z0-9_-])?$")
_SITE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SCOPE = re.compile(r"^[^'\"`$\r\n\t]{1,60}$")
MAX_DOMAIN = 64   # what dcpromo accepts for a domain's DNS name


# --------------------------------------------------------------------------
# Defaults and lookups
# --------------------------------------------------------------------------


def default_hostname(node_id: str) -> str:
    return node_id.upper()[:15]


def hostname_of(node: Node) -> str:
    return node.hostname or default_hostname(node.id)


def renamed(node: Node) -> bool:
    return hostname_of(node).upper() != default_hostname(node.id)


def share_name(lab: Lab) -> str:
    """The file server's main share (winlab's default: Company)."""
    return lab.names.share or AUTHORED_SHARE


def site_keys(lab: Lab) -> list[str]:
    """The AD sites machines are placed in, by the `site` var they carry."""
    out: list[str] = []
    for n in lab.node_list():
        s = str((n.vars or {}).get("site") or "")
        if s and s not in out:
            out.append(s)
    return out


def site_name(lab: Lab, key: str) -> str:
    return lab.names.sites.get(key) or key


def scope_name(lab: Lab, network_id: str) -> str:
    return lab.names.scopes.get(network_id) or f"{lab.name}-{network_id}"


def scoped_networks(lab: Lab) -> list[str]:
    """The networks a Windows DHCP server hands out addresses on: its own,
    and those whose machines ask for one and the fabric does not serve."""
    servers = [n for n in lab.node_list() if "dhcp" in n.roles]
    if not servers:
        return []
    out = {s.primary_nic.network for s in servers if s.primary_nic}
    for n in lab.nodes.values():
        for nic in n.nics:
            net = lab.networks.get(nic.network)
            if nic.dhcp and net and not net.dhcp and not net.wan:
                out.add(nic.network)
    return sorted(out)


def resolve(lab: Lab, name: str) -> str:
    """A machine's id from its id or its computer name (any case); the name
    unchanged when nothing matches, so callers report it as they do today."""
    if name in lab.nodes:
        return name
    for n in lab.node_list():
        if hostname_of(n).lower() == name.lower() or n.id.lower() == name.lower():
            return n.id
    return name


def display(lab: Lab, node_id: str) -> str:
    n = lab.nodes.get(node_id)
    return hostname_of(n) if n else node_id


def installed(lab_name: str, node_id: str) -> bool:
    """Has the machine been built: its system disk exists."""
    return (paths.lab_dir(lab_name) / node_id / "system.qcow2").exists()


def keeps_its_name(node: Node) -> str:
    """Why an installed machine cannot be renamed in place, or ''. Microsoft's
    own rule: a domain controller is renamed with netdom in several reboots,
    and a certification authority not at all, since its name is in every
    certificate it issued."""
    if "adcs" in node.roles:
        return "it is a certification authority, and a CA's name is in every certificate it issued"
    if "ad-ds" in node.roles:
        return "it is a domain controller, which keeps the name it was promoted with"
    return ""


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def check_hostname(name: str) -> str:
    if not _HOSTNAME.match(name):
        return (f"computer name {name!r}: 1 to 15 letters, digits and hyphens, "
                f"not starting or ending with a hyphen")
    if name.isdigit():
        return f"computer name {name!r}: cannot be only digits"
    return ""


def check_domain(domain: str) -> str:
    labels = domain.split(".")
    if (len(labels) < 2 or len(domain) > MAX_DOMAIN
            or not all(_LABEL.match(x) for x in labels) or labels[-1].isdigit()):
        return (f"domain {domain!r}: a DNS name in lower case with at least two parts, "
                f"like contoso.lab or ad.example.com, at most {MAX_DOMAIN} characters")
    return ""


def check_netbios(netbios: str) -> str:
    if not _NETBIOS.match(netbios) or netbios.isdigit():
        return (f"NetBIOS name {netbios!r}: 1 to 15 letters, digits and hyphens, "
                f"not only digits")
    return ""


def check_share(share: str) -> str:
    if not _SHARE.match(share):
        return (f"share name {share!r}: 1 to 40 letters, digits, spaces, dots, hyphens "
                f"and underscores, starting with a letter or digit")
    return ""


def check_site(site: str) -> str:
    if not _SITE.match(site):
        return (f"site name {site!r}: letters, digits and hyphens, no spaces "
                f"(AD site names end up in DNS)")
    return ""


def check_scope(scope: str) -> str:
    if not _SCOPE.match(scope) or scope != scope.strip():
        return f"scope name {scope!r}: 1 to 60 characters, no quotes, $ or tabs"
    return ""


def validate(lab: Lab) -> list[str]:
    """Every name the lab carries, and the clashes between them."""
    errs: list[str] = []
    has_domain = any("ad-ds" in n.roles for n in lab.nodes.values())
    if has_domain:
        for e in (check_domain(lab.domain), check_netbios(lab.netbios)):
            if e:
                errs.append(e)
    seen: dict[str, str] = {}
    ids = {n.id.lower(): n.id for n in lab.nodes.values()}
    for n in lab.node_list():
        host = hostname_of(n)
        e = check_hostname(host)
        if e:
            errs.append(f"node '{n.id}': {e}")
            continue
        low = host.lower()
        if low in seen:
            errs.append(f"node '{n.id}': computer name {host} is already {seen[low]}'s")
        seen[low] = n.id
        other = ids.get(low)
        if other and other != n.id:
            errs.append(f"node '{n.id}': computer name {host} is another machine's id ({other})")
        if has_domain and host.upper() == lab.netbios.upper():
            errs.append(f"node '{n.id}': computer name {host} is the domain's NetBIOS name")
    if lab.names.share:
        e = check_share(lab.names.share)
        if e:
            errs.append(e)
    known = set(site_keys(lab))
    for key, name in lab.names.sites.items():
        if key not in known:
            errs.append(f"[names.sites]: no machine is in a site {key!r}")
        e = check_site(name)
        if e:
            errs.append(e)
    if len({v.lower() for v in lab.names.sites.values()}) < len(lab.names.sites):
        errs.append("[names.sites]: two sites have the same name")
    for key, name in lab.names.scopes.items():
        if key not in lab.networks:
            errs.append(f"[names.scopes]: no network {key!r}")
        e = check_scope(name)
        if e:
            errs.append(e)
    return errs


# --------------------------------------------------------------------------
# Lessons and exercises in the student's names
# --------------------------------------------------------------------------


def _dn(domain: str) -> str:
    return ",".join(f"DC={x}" for x in domain.split("."))


def _like(matched: str, new: str) -> str:
    """The new name as the student typed it, or in capitals where the text
    has the old one in capitals (DC01 -> FILES, dc01 -> Files)."""
    if matched.isupper() and not matched.islower():
        return new.upper()
    return new


class Localizer:
    """Rewrites text written against winlab's names into this lab's."""

    def __init__(self, lab: Lab) -> None:
        self.lab = lab
        prose: list[tuple[str, str, str, bool]] = []   # (group, pattern, new, ignore case)
        if lab.domain.lower() != AUTHORED_DOMAIN:
            prose += [
                ("dn", re.escape(_dn(AUTHORED_DOMAIN)), _dn(lab.domain), True),
                ("dom", re.escape(AUTHORED_DOMAIN), lab.domain, True),
                ("domrx", re.escape(AUTHORED_DOMAIN.replace(".", "\\.")),
                 lab.domain.replace(".", "\\."), True),
            ]
        if lab.netbios != AUTHORED_NETBIOS:
            prose.append(("nb", AUTHORED_NETBIOS, lab.netbios, False))
        for n in lab.node_list():
            if renamed(n):
                prose.append((f"h{len(prose)}", re.escape(n.id), hostname_of(n), True))
        for key, name in lab.names.sites.items():
            if name != key:
                prose.append((f"site{len(prose)}", re.escape(key), name, False))
        share = share_name(lab)
        code = list(prose)
        if share != AUTHORED_SHARE:
            prose.append(("sh", AUTHORED_SHARE, share, False))
            # In a script or a pattern the share is matched in any case.
            code.append(("sh", AUTHORED_SHARE, share, True))
        self.changes = bool(code)
        self._prose = self._compile(prose)
        self._code = self._compile(code)

    @staticmethod
    def _compile(tokens):
        if not tokens:
            return None
        news = {g: new for g, _, new, _ in tokens}
        alts = [f"(?P<{g}>{'(?i:' + pat + ')' if ci else pat})"
                for g, pat, _, ci in sorted(tokens, key=lambda t: -len(t[1]))]
        rx = re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(alts) + r")(?![A-Za-z0-9_])")
        return rx, news

    @staticmethod
    def _sub(compiled, text: str) -> str:
        if not compiled or not text:
            return text
        rx, news = compiled

        def one(m: re.Match) -> str:
            g = m.lastgroup or ""
            new = news[g]
            if g in ("dn",):
                return new if m.group(0)[:2] == "DC" else new.lower()
            if g == "nb" or g.startswith("site"):
                return new
            return _like(m.group(0), new)
        return rx.sub(one, text)

    def text(self, s: str) -> str:
        return self._sub(self._prose, s)

    def code(self, s: str) -> str:
        return self._sub(self._code, s)

    def lesson(self, lesson):
        if not self.changes:
            return lesson
        t = self.text
        return replace(
            lesson, title=t(lesson.title), summary=t(lesson.summary), why=t(lesson.why),
            concepts=[t(x) for x in lesson.concepts], steps=[t(x) for x in lesson.steps],
            pitfalls=[t(x) for x in lesson.pitfalls], further=list(lesson.further),
            verify=[replace(v, label=t(v.label), cmd=self.code(v.cmd)) for v in lesson.verify])

    def exercise(self, ex):
        if not self.changes:
            return ex
        t = self.text
        return replace(
            ex, title=t(ex.title), brief=t(ex.brief), tasks=[t(x) for x in ex.tasks],
            checks=[replace(c, name=t(c.name), script=self.code(c.script),
                            expect=self.code(c.expect), hint=t(c.hint)) for c in ex.checks])


_CACHE: dict[str, tuple[tuple[int, int], Localizer]] = {}


def for_lab(lab_name: str) -> Localizer:
    """The localizer for a lesson's lab, read from its file (and read again
    when the file changes); winlab's own names when there is no such lab."""
    from . import schema
    from . import content
    path = paths.LABS / f"{lab_name}.toml"
    try:
        st = path.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        if not content.exists(path):   # no such lab, or a locked one
            return Localizer(Lab(name=lab_name))
        stamp = ("pack", content.mode())
    hit = _CACHE.get(lab_name)
    if hit and hit[0] == stamp:
        return hit[1]
    try:
        loc = Localizer(schema.load(path))
    except schema.LabError:
        loc = Localizer(Lab(name=lab_name))
    _CACHE[lab_name] = (stamp, loc)
    return loc


def as_lab_names(lab: Lab) -> dict:
    """The names panel: every name winlab lets the student choose, with what
    winlab would call it."""
    return {
        "domain": lab.domain, "netbios": lab.netbios,
        "share": share_name(lab), "share_default": AUTHORED_SHARE,
        "sites": [{"key": k, "name": site_name(lab, k)} for k in site_keys(lab)],
        "scopes": [{"network": nid, "name": scope_name(lab, nid),
                    "default": f"{lab.name}-{nid}"} for nid in scoped_networks(lab)],
        "machines": [{"id": n.id, "name": hostname_of(n), "default": default_hostname(n.id),
                      "kind": n.kind} for n in lab.node_list()],
        "has_domain": any("ad-ds" in n.roles for n in lab.nodes.values()),
    }


# --------------------------------------------------------------------------
# Renaming a running Windows machine
# --------------------------------------------------------------------------

_RENAME_PS = r"""$new = '__NEW__'
if ($env:COMPUTERNAME -ieq $new) { 'same'; return }
$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.PartOfDomain) {
__CRED__    Rename-Computer -NewName $new -DomainCredential $cred -Force -ErrorAction Stop
} else {
    Rename-Computer -NewName $new -Force -ErrorAction Stop
}
Start-Process -FilePath shutdown.exe -ArgumentList '/r', '/t', '10', '/c', 'winlab: new computer name'
'renamed'
"""


def rename_live(lab: Lab, node_id: str) -> tuple[bool, str]:
    """Renames the running Windows machine to the computer name the lab gives
    it, over the winlab agent (a member renames its domain account too) and
    restarts it. (False, why) when that cannot happen now; the next
    Configure renames it then."""
    from . import state
    from .dsc import _LAB_CRED
    from .guestctl import GuestChannel, GuestError

    node = lab.nodes[node_id]
    new = hostname_of(node)
    st = state.load(lab.name)
    ns = st.nodes.get(node_id) if st else None
    if not node.is_windows:
        return False, "only Windows machines run the agent that renames them"
    if not ns or not ns.serial_port or not state.pid_alive(ns.pid):
        return False, "it is not running"
    if ns.phase == "installing":
        return False, "it is still installing, and takes the name when it finishes"
    cred = "".join("    " + line + "\n" for line in _LAB_CRED.strip().splitlines())
    script = _RENAME_PS.replace("__NEW__", new).replace("__CRED__", cred)
    try:
        ch = GuestChannel(ns.serial_port).connect(retries=3, delay=2)
    except (GuestError, OSError) as exc:
        return False, f"its agent does not answer ({exc})"
    try:
        res = ch.run(script, timeout=180)
    except GuestError as exc:
        return False, str(exc)
    finally:
        ch.close()
    out = (res.out or "").strip().splitlines()
    if res.ok and out and out[-1] == "same":
        return True, f"Windows is already called {new}"
    if res.ok and out and out[-1] == "renamed":
        return True, f"Windows renamed itself {new} and restarts in 10 seconds"
    detail = (res.err or res.out or "").strip().splitlines()
    return False, f"Windows refused: {detail[-1][:200] if detail else f'rc={res.rc}'}"
