"""Web filtering inside the lab: the proxy the student builds, the router
that makes it the only way out, the Internet it filters, and the drills that
break each of them.

The web-proxy lab (content/labs/web-proxy.toml) starts empty. The student
builds every part inside the machines, lesson by lesson (web-proxy-* in the
workloads module):

  rt01   an Ubuntu router between the office and the outside segment:
         forwarding on, nftables rules that let only the proxy (and the
         DC's DNS) out. Its nftables and conntrack come on the 'nftables' pack.
  px01   Squid on Ubuntu, from the 'squid' pack (squid-openssl, squidclient,
         krb5-user, ldap-utils): an explicit proxy on 3128, allow and block
         lists by domain, a time rule, Kerberos logins with a keytab from AD,
         a rule for one AD group (ext_ldap_group_acl), HTTPS filtered by the
         SNI it peeks at, without decrypting anything (peek, splice,
         terminate).
  dc01   AD, DNS (forwarding to the lab Internet's DNS) and the Group Policy
         that sets the proxy for the users, and the Internet's root CA for
         the PCs.

Both packs come from the Ubuntu archive onto this PC (winlab/debpacks.py,
`winlab webproxy fetch` or Setup, which lists the packs a lab's machines
install by hand), and plug into the machine as a stick apt reads.

Isolation: the lab never reaches the real internet, not even optionally. The
"Internet" is inet01, an Alpine host on the outside segment running the role
inet-sites (content/roles/inet-sites.sh): made-up web sites under RFC 2606
.example names (news, wiki, games, shop, social, video, pki), HTTP and HTTPS
by name on one address, and the Internet's DNS on a second one. It is
somebody else's equipment, so the lab brings it up by itself; its nginx and
openssl come from the Alpine mirror with the rest of the lab's Alpine
packages (winlab/apkrepo.py). Its HTTPS certificate is issued by "Example
Trust Services Root", a CA that plays the public CAs a real PC trusts out of
the box: the student puts it in the PCs' trusted roots with Group Policy.

What is not here, and why: squidGuard and ufdbGuard (URL filter plug-ins)
are left out: squidGuard is unmaintained upstream, and Squid's own ACL files
teach the same thing with nothing extra. Commercial category lists (the
"block all gambling" kind) are subscriptions fetched from the internet, so a
sealed lab cannot have them; the student writes the lists by hand. Full TLS
interception (bumping) is explained, not built: it needs a CA of the
proxy's own trusted by every PC, which the HTTPS lesson discusses and the
exercise does not require.
"""

from __future__ import annotations

from . import debpacks

PACKS = ("squid", "nftables")
# The lab Internet (content/roles/inet-sites.sh): name -> what the lessons
# do with it.
SITES = {
    "news.example": "on the allow list",
    "wiki.example": "on the allow list",
    "pki.example": "on the allow list: the sites' CA publishes its root here (/root.crt)",
    "games.example": "on the block list, with play.games.example under it",
    "shop.example": "allowed at lunch time only (12:00-13:00, Monday to Friday)",
    "social.example": "allowed for the AD group Web-Social only",
    "video.example": "on no list: the proxy's last rule decides",
}
INTERNET_ROLE = "inet-sites"
ROOT_CA = "Example Trust Services Root"
DEFAULT_PORT = 3128


class WebProxyError(Exception):
    pass


# --------------------------------------------------------------- the lab
def proxy_node(lab):
    """The machine the lab's proxy is built on (node vars packs has squid)."""
    from .mail import hand_packs
    return next((n for n in lab.node_list() if "squid" in hand_packs(n)), None)


def internet_node(lab):
    return next((n for n in lab.node_list() if INTERNET_ROLE in n.roles), None)


def fault_params(lab) -> dict[str, str]:
    """The drills' parameters (guestfaults.lab_params): the proxy's name,
    address and port, the office segment it serves, the Internet's sites."""
    out: dict[str, str] = {}
    n = proxy_node(lab)
    if n is not None:
        host = (n.hostname or n.id).lower()
        out["proxyhost"] = f"{host}.{lab.domain}" if lab.domain else host
        nic = n.primary_nic
        if nic is not None and nic.ip:
            out["proxyip"] = nic.ip
        net = lab.networks.get(nic.network) if nic is not None else None
        if net is not None:
            out["corpnet"] = str(net.net)
        out["proxyport"] = str(n.vars.get("proxy_port") or DEFAULT_PORT)
    i = internet_node(lab)
    if i is not None and i.primary_nic is not None and i.primary_nic.ip:
        out["inetip"] = i.primary_nic.ip
    return out


# ----------------------------------------------------------- the packs
def status() -> list[dict]:
    return [debpacks.status(p) for p in PACKS]


def fetch(progress=None, refresh: bool = False, get=None, download=None) -> list[dict]:
    """Fetches both packs from the Ubuntu archive (the Ubuntu image first),
    each .deb against the SHA-256 the archive's index gives (debpacks)."""
    extra = {k: v for k, v in (("get", get), ("download", download)) if v is not None}
    out = []
    for p in PACKS:
        try:
            out.append(debpacks.fetch(p, progress=progress, refresh=refresh, **extra))
        except debpacks.PackError as exc:
            raise WebProxyError(f"{p}: {exc}") from exc
    return out


def render_status() -> str:
    lines = ["web filtering lab (web-proxy): what this PC fetches, what the lab plays", ""]
    for st in status():
        state = (f"ready ({st['count']} packages, {st['size_mb']} MB, fetched {st['fetched']})"
                 if st["ready"] else f"not fetched (about {st['typical_mb']} MB)")
        lines.append(f"  pack {st['id']:<9} {state}")
        lines.append(f"  {'':<14} {st['title']}")
    if not all(st["ready"] for st in status()):
        lines += ["", "  then:  winlab webproxy fetch   (or winlab packs fetch squid / nftables)"]
    lines += ["", "the lab Internet (inet01, role inet-sites; never the real internet):",
              "  203.0.113.80  web sites, HTTP and HTTPS by name; 203.0.113.53  their DNS"]
    for name, what in SITES.items():
        lines.append(f"  {name:<16} {what}")
    lines += [f"  HTTPS certificates from '{ROOT_CA}', published at http://pki.example/root.crt", ""]
    return "\n".join(lines)


# ------------------------------------------------------------- the drills
def _faults():
    from .guestfaults import LINUX, WINDOWS, GuestFault
    key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    find_pref = (f"$k = '{key}'; "
                 "$hits = @(foreach ($g in Get-GPO -All) { $v = Get-GPPrefRegistryValue -Name $g.DisplayName "
                 "-Context User -Key $k -ValueName ProxyServer -ErrorAction SilentlyContinue; "
                 "if ($v) { [pscustomobject]@{ Gpo = $g.DisplayName; Value = @($v)[0].Value } } }); ")
    need_squid = ("command -v squid >/dev/null 2>&1 || { echo 'no Squid on this machine: build the proxy first "
                  "(lesson web-proxy-squid)'; exit 1; }; ")
    return [
        GuestFault(
            id="proxy-direct-out",
            images=("ubuntu",),
            title="Users reach blocked sites by switching the proxy off",
            os=LINUX,
            teaches="why a proxy only filters what is forced through it: the router's forward rules, "
                    "the difference between the running nftables ruleset and /etc/nftables.conf, and "
                    "proving a path with the Internet's own log",
            symptom="games.example shows Squid's Access Denied page through the proxy, but a user who turns "
                    "the proxy off in Settings, Network and internet, Proxy, gets the site directly; the "
                    "Internet's log shows visits from PC addresses, not only from {proxyip}",
            apply=("command -v nft >/dev/null 2>&1 || { echo 'no nftables on this machine: build the router first "
                   "(lesson web-proxy-boundary)'; exit 1; }; "
                   "c=$(nft list ruleset 2>/dev/null | awk '/^table /{t=$2\" \"$3} /^[ \\t]*chain /{ch=$2} "
                   "/hook forward/{print t\" \"ch}'); "
                   "[ -n \"$c\" ] || { echo 'no forward chain on this machine: build the router first "
                   "(lesson web-proxy-boundary)'; exit 1; }; "
                   "echo \"$c\" | while read fam tbl ch; do nft insert rule \"$fam\" \"$tbl\" \"$ch\" ip saddr "
                   "{corpnet} accept comment '\"vendor remote support, temporary\"'; done; echo broken"),
            clear=("nft -a list ruleset 2>/dev/null | awk '/^table /{t=$2\" \"$3} /^[ \\t]*chain /{ch=$2} "
                   "/vendor remote support, temporary/{print t\" \"ch\" \"$NF}' | while read fam tbl ch h; do "
                   "nft delete rule \"$fam\" \"$tbl\" \"$ch\" handle \"$h\"; done; echo ok"),
            shell="sh",
            hints=(
                "Prove the path before you touch anything. On inet01's side every visit is logged with its "
                "source; from rt01 you can watch the crossing itself: conntrack -L | grep 203.0.113 (or "
                "tcpdump -ni eth1 host {inetip}) while a PC with the proxy switched off opens "
                "http://games.example. A PC address in there means the router let it out.",
                "Read the rules the kernel is using, not the file: nft -a list ruleset. In the forward chain, "
                "above your rules, there is an accept for the whole office ({corpnet}) with a comment about "
                "vendor support. Compare with /etc/nftables.conf: the file does not have it, so somebody "
                "added it by hand and it would vanish at the next reboot, or worse, get saved.",
                "Delete it by its handle: nft delete rule <family> <table> forward handle <n>, using the "
                "family, table and handle nft -a printed. Only the proxy ({proxyip}) may go out on 80 and 443, "
                "and the DC ({dns}) on 53; everything else from the office is dropped. Check that the file "
                "still says the same (nft -c -f /etc/nftables.conf), then retry the PC without the proxy: "
                "the connection times out.",
            ),
            verify=("command -v nft >/dev/null 2>&1 || { echo False; exit 0; }; "
                    "[ \"$(sysctl -n net.ipv4.ip_forward 2>/dev/null)\" = 1 ] || { echo False; exit 0; }; "
                    "nft list ruleset 2>/dev/null | awk -v px='{proxyip}' -v dc='{dns}' '"
                    "/^[ \\t]*chain /{fwd=0; next} "
                    "/hook forward/{fwd=1; if ($0 ~ /policy drop/) drop=1; next} "
                    "fwd && /^[ \\t]*}/{fwd=0; next} "
                    "fwd {l=$0; gsub(/counter packets [0-9]+ bytes [0-9]+/, \"\", l); gsub(/^[ \\t]+|[ \\t]+$/, \"\", l); "
                    "if (l == \"drop\") drop=1} "
                    "fwd && / accept|^[ \\t]*accept/ {"
                    "if ($0 ~ /ct state/ && $0 ~ /established/ && $0 !~ /new/) next; "
                    "if ($0 ~ /icmp/) next; "
                    "if (px != \"\" && $0 ~ (\"saddr \" px \"([ \\t]|$)\")) next; "
                    "if (dc != \"\" && $0 ~ (\"saddr \" dc \"([ \\t]|$)\") && $0 ~ /dport (53|domain)/) next; "
                    "bad=1} "
                    "END {print (drop && !bad) ? \"True\" : \"False\"}'"),
        ),
        GuestFault(
            id="squid-acl-order",
            images=("ubuntu",),
            title="The proxy lets a blocked site through, and the log no longer says who",
            os=LINUX,
            teaches="http_access is read top to bottom and the first line that matches decides; where "
                    "Ubuntu's squid.conf includes conf.d; and reading the decision in access.log",
            symptom="http://games.example loads through the proxy on every PC; /var/log/squid/access.log "
                    "shows TCP_MISS/200 for games.example with - where the user name used to be",
            apply=(need_squid + "f=/etc/squid/squid.conf; [ -f $f.winlab ] || cp $f $f.winlab; "
                   "n=$(grep -n '^[[:space:]]*http_access' $f | head -n 1 | cut -d: -f1); "
                   "[ -n \"$n\" ] || { echo 'no http_access lines in squid.conf'; exit 1; }; "
                   "sed -i \"${n}i http_access allow helpdesk_pcs\" $f && "
                   "sed -i \"${n}i # helpdesk: let the PCs browse while the filter is reviewed\" $f && "
                   "sed -i \"${n}i acl helpdesk_pcs src {corpnet}\" $f && "
                   "squid -k reconfigure >/dev/null 2>&1; echo broken"),
            clear=("f=/etc/squid/squid.conf; [ -f $f.winlab ] && mv $f.winlab $f; "
                   "squid -k reconfigure >/dev/null 2>&1; echo ok"),
            shell="sh",
            hints=(
                "Let the log tell you which rule decided. tail -f /var/log/squid/access.log while a PC opens "
                "http://games.example: TCP_MISS/200 means Squid fetched it, and the user column is - , so no "
                "login was asked for. Something allowed the request before your block list and before the "
                "login rule were ever read.",
                "Squid reads http_access lines top to bottom, across the include of /etc/squid/conf.d/*.conf "
                "in the middle of squid.conf, and stops at the first line whose ACLs all match. "
                "grep -n -E '^(http_access|include|acl)' /etc/squid/squid.conf /etc/squid/conf.d/*.conf "
                "lists them in order: an allow for the whole office ({corpnet}) now sits above everything.",
                "Remove the two helpdesk lines (the acl and its http_access) from squid.conf, then squid -k parse "
                "and squid -k reconfigure. Order rules from narrow to wide: deny the blocked list first, then "
                "require the login, then the allows, and http_access deny all last. Retry games.example: "
                "TCP_DENIED/403.",
            ),
            verify=("systemctl is-active -q squid || { echo False; exit 0; }; "
                    "c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 --interface {proxyip} "
                    "-x http://{proxyip}:{proxyport} http://games.example/); "
                    "if [ \"$c\" = 403 ] || [ \"$c\" = 407 ]; then echo True; else echo False; fi"),
        ),
        GuestFault(
            id="gpo-proxy-wrong-port",
            roles=("ad-ds",),
            title="After a policy change, no PC can open any web site",
            os=WINDOWS,
            teaches="where the PCs' proxy setting comes from (a Group Policy registry preference in User "
                    "Configuration), reading it with gpresult and the registry, and testing the proxy's port "
                    "before blaming the proxy",
            symptom="Edge on every PC says 'No internet: there is something wrong with the proxy server' "
                    "after gpupdate or the next logon; Squid on {proxyhost} runs and its log shows nothing "
                    "from the PCs",
            apply=(find_pref + "$f = 'C:\\Windows\\Temp\\winlab-proxy.xml'; "
                   "if (-not $hits) { 'nothing to break: set the proxy with a Group Policy registry preference "
                   "first (lesson web-proxy-gpo)' } else { "
                   "if (-not (Test-Path $f)) { $hits | Export-Clixml $f }; "
                   "foreach ($h in $hits) { Remove-GPPrefRegistryValue -Name $h.Gpo -Context User -Key $k "
                   "-ValueName ProxyServer -ErrorAction SilentlyContinue; Set-GPPrefRegistryValue -Name $h.Gpo "
                   "-Context User -Key $k -ValueName ProxyServer -Value '{proxyhost}:8080' -Type String "
                   "-Action Update | Out-Null }; 'broken' }"),
            clear=(f"$k = '{key}'; $f = 'C:\\Windows\\Temp\\winlab-proxy.xml'; "
                   "if (Test-Path $f) { foreach ($h in Import-Clixml $f) { Remove-GPPrefRegistryValue -Name $h.Gpo "
                   "-Context User -Key $k -ValueName ProxyServer -ErrorAction SilentlyContinue; "
                   "Set-GPPrefRegistryValue -Name $h.Gpo -Context User -Key $k -ValueName ProxyServer "
                   "-Value $h.Value -Type String -Action Update | Out-Null }; Remove-Item $f }; 'ok'"),
            hints=(
                "Start on a PC, as the user: Settings, Network and internet, Proxy shows the address and port "
                "Windows uses (reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet "
                "Settings\" /v ProxyServer says the same). Then test that exact port: Test-NetConnection "
                "{proxyhost} -Port 8080 fails, and -Port {proxyport} succeeds.",
                "The PC did not invent the port: gpresult /r /scope user names the GPO that set it. On dc01, "
                "in Group Policy Management, that GPO's User Configuration, Preferences, Windows Settings, "
                "Registry holds ProxyServer = {proxyhost}:8080. Squid listens on {proxyport} "
                "(grep http_port /etc/squid/squid.conf on the proxy).",
                "Edit the registry item back to {proxyhost}:{proxyport} (or Set-GPPrefRegistryValue -Name "
                "<the GPO> -Context User -Key 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet "
                "Settings' -ValueName ProxyServer -Value {proxyhost}:{proxyport} -Type String -Action Update, "
                "after removing the wrong item). On a PC: gpupdate /force, then open a site; Squid's "
                "access.log shows the visit again.",
            ),
            verify=(f"$k = '{key}'; "
                    "$vals = @(foreach ($g in Get-GPO -All) { Get-GPPrefRegistryValue -Name $g.DisplayName "
                    "-Context User -Key $k -ValueName ProxyServer -ErrorAction SilentlyContinue | "
                    "ForEach-Object { $_.Value } }); "
                    "$vals.Count -gt 0 -and -not ($vals | Where-Object { $_ -notmatch "
                    "'(^|[=;])(http://)?{proxyhost}:{proxyport}(;|$)' })"),
        ),
    ]


FAULT_IDS = ("proxy-direct-out", "squid-acl-order", "gpo-proxy-wrong-port")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
