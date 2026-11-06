"""Remote access: a home worker dialling into the office, built by hand, and
the drills that break it.

The remote-access lab (content/labs/remote-access.toml) starts empty. The
student builds every part inside the machines, lesson by lesson
(remote-access-* in the network module):

  dc01      AD, DNS and DHCP (the foundation), then the enterprise CA (CORP
            Root CA) with a CRL distribution point the Internet can reach,
            the certificate templates for the VPN server and the users, and
            NPS, the RADIUS server whose network policy lets the AD group
            Remote-Workers dial in.
  vpn01     Windows Server with two cards, the office's gateway: Routing and
            Remote Access with SSTP and IKEv2, a certificate for its public
            name (vpn.corp.example), RADIUS to dc01, a static address pool,
            and IIS serving the CRL on its public address (pki.corp.example).
  laptop01  Alice's Windows 11 laptop at home: joined and enrolled at the
            office (its cable moved onto corp in the workbench), then a VPN
            connection from home, split or full tunnel, and Always On VPN
            from a ProfileXML the student pushes through the MDM bridge (WMI)
            with PowerShell, as SYSTEM, with no MDM server.
  wg01      the open-source option: WireGuard on Ubuntu, from the
            'wireguard' pack (wireguard-tools, qrencode) and the 'nftables'
            pack, both from the Ubuntu archive (winlab/debpacks.py).

No download is needed for the Windows side: RRAS, NPS, AD CS and IIS are
roles of Windows Server. For WireGuard the laptop needs WireGuard for
Windows (MIT), fetched on this PC from WireGuard's own download server: the
signed list https://download.wireguard.com/windows-client/latest.sig is
checked against WireGuard LLC's release key (the Ed25519 key the Windows
client's own updater pins, in signify format), and the amd64 MSI it names
is checked against the BLAKE2b-256 hash in that list. The media shelf
writes it onto a "VPN client" stick; the student installs it inside the
laptop. Nothing is bundled with winlab.

Why WireGuard and not OpenVPN: one small MSI from one signed list (OpenVPN's
Windows installer has no signed hash list to check it against, and its
server needs a PKI of its own on top of the lab's), a configuration of a few
lines on each side, and a kernel module Ubuntu already carries. OpenVPN
teaches nothing the SSTP lesson does not (TLS on 443 through any firewall).

Isolation: the lab never reaches the real internet, not even optionally.
Its three segments are cut off from the lab router (routed = false). The
"Internet" is one flat subnet in the lab (203.0.113.0/24) holding vpn01's
and wg01's public legs, inet01 (role inet-sites: the Internet's DNS, which
also answers the company's public names, and a few web sites) and the
public side of homegw, the home worker's broadband router (role
home-router: NAT, DHCP and DNS for the house). From home the laptop reaches
only what the company publishes on that Internet.

What is not here, and why: DirectAccess (deprecated by Microsoft in favour
of Always On VPN), the Remote Access Gateway in front of Remote Desktop
(the remote-desktop lessons cover RDP), and Azure VPN or Entra ID
conditional access (cloud services, never reachable from a sealed lab).
Intune is replaced by the MDM bridge script Microsoft documents for
deploying a ProfileXML without an MDM server. PPTP and L2TP/IPsec with a
pre-shared key are explained as what not to deploy, not built.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from pathlib import Path

from . import debpacks, paths
from .bootstrap import BootstrapError, _download_to, _get

PRODUCT = "WireGuard for Windows"
LICENSE = "MIT"
PAGE = "https://www.wireguard.com/install/"
SERVER = "https://download.wireguard.com/windows-client"
LIST_URL = f"{SERVER}/latest.sig"
# WireGuard LLC's release key for the Windows client, as its updater pins it
# (wireguard-windows, updater/constants.go: releasePublicKeyBase64). signify
# format: "Ed", an 8-byte key number, the 32-byte Ed25519 public key.
RELEASE_SIGNER = "RWRNqGKtBXftKTKPpBPGDMe8jHLnFQ0EdRy8Wg0apV6vTDFLAODD83G4"
MSI_RE = re.compile(r"^wireguard-amd64-(\d+(?:\.\d+){1,3})\.msi$")
JOB = "wireguard-fetch"
STEP_LABEL = "Fetch WireGuard for Windows (download.wireguard.com)"
SIZE_TEXT = "about 4 MB"
STICK_LABEL = "VPNCLIENT"
META_NAME = "wireguard.json"
DOWNLOAD_ID = "wireguard"   # node vars downloads = ["wireguard"]
PACKS = ("wireguard", "nftables")

CA_NAME = "CORP Root CA"
GROUP = "Remote-Workers"
POLICY = "Remote-Workers VPN"
CONNECTION = "Corp VPN"
DEVICE_TUNNEL = "CorpDeviceTunnel"


class RemoteAccessError(Exception):
    pass


# ------------------------------------------------- the signed release list
def parse_signed_list(text: bytes, key_b64: str = "") -> dict[str, str]:
    """latest.sig -> {file name: BLAKE2b-256 hex}, after checking its
    signify signature against the release key: the same checks the Windows
    client's updater makes (updater/signify.go). Raises on anything else."""
    from .licensing import ed25519
    try:
        key = base64.b64decode(key_b64 or RELEASE_SIGNER, validate=True)
    except ValueError as exc:
        raise RemoteAccessError("the WireGuard release key is not valid base64") from exc
    if len(key) != 42 or key[:2] != b"Ed":
        raise RemoteAccessError("the WireGuard release key is not a signify Ed25519 key")
    parts = text.split(b"\n", 2)
    if len(parts) != 3 or not parts[0].startswith(b"untrusted comment: "):
        raise RemoteAccessError("WireGuard's latest.sig is not a signify signed file")
    try:
        sig = base64.b64decode(parts[1].strip(), validate=True)
    except ValueError as exc:
        raise RemoteAccessError("WireGuard's latest.sig has no valid signature line") from exc
    if len(sig) != 74 or sig[:10] != key[:10]:
        raise RemoteAccessError("WireGuard's latest.sig is signed with another key")
    if not ed25519.verify(sig[10:], parts[2], key[10:]):
        raise RemoteAccessError("WireGuard's latest.sig does not verify against WireGuard LLC's release key")
    out = {}
    lines = parts[2].decode("utf-8", "replace").split("\n")
    for i, line in enumerate(lines):
        if not line and i == len(lines) - 1:
            break
        digest, sep, name = line.partition("  ")
        if not sep or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RemoteAccessError(f"WireGuard's latest.sig has a bad line: {line[:80]!r}")
        out[name] = digest
    if not out:
        raise RemoteAccessError("WireGuard's latest.sig lists no files")
    return out


def _vkey(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


def pick_msi(files: dict[str, str]) -> tuple[str, str, str]:
    """(file, version, BLAKE2b-256) of the newest amd64 MSI in the list."""
    found = [(m.group(1), name) for name in files if (m := MSI_RE.match(name))]
    if not found:
        raise RemoteAccessError("WireGuard's signed list names no amd64 MSI")
    version, name = max(found, key=lambda f: _vkey(f[0]))
    return name, version, files[name]


def blake2b_256(path: Path) -> str:
    h = hashlib.blake2b(digest_size=32)
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# ------------------------------------------------------- the client stick
def client_dir() -> Path:
    return paths.RUNTIME / "vpnclient"


def meta() -> dict:
    try:
        return json.loads((client_dir() / META_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def ready() -> bool:
    m = meta()
    f = client_dir() / str(m.get("file") or "-")
    return bool(m.get("version")) and f.is_file() and f.stat().st_size > 0


def fetch_client(progress=None, get=_get, download=_download_to) -> dict:
    """Fetches the WireGuard for Windows MSI named by the signed list."""
    say = progress or (lambda _m: None)
    say(f"WireGuard's signed release list: {LIST_URL}")
    try:
        files = parse_signed_list(get(LIST_URL, timeout=30))
    except BootstrapError as exc:
        raise RemoteAccessError(f"{exc}; try again later, or download WireGuard for Windows from {PAGE} "
                                f"yourself and write it onto a stick from the media shelf") from exc
    name, version, digest = pick_msi(files)
    d = client_dir()
    d.mkdir(parents=True, exist_ok=True)
    dest = d / name
    say(f"{PRODUCT} {version}: {name} (signature good)")
    if not (dest.is_file() and blake2b_256(dest) == digest):
        try:
            download(f"{SERVER}/{name}", dest, label=name)
        except BootstrapError as exc:
            raise RemoteAccessError(str(exc)) from exc
        got = blake2b_256(dest)
        if got != digest:
            dest.unlink(missing_ok=True)
            raise RemoteAccessError(f"{name} does not match the BLAKE2b-256 in WireGuard's signed list "
                                    f"({got[:16]}... against {digest[:16]}...); it was deleted")
    m = {"name": PRODUCT, "version": version, "license": LICENSE, "file": name, "blake2b_256": digest,
         "source": f"{SERVER}/{name}", "list": LIST_URL, "fetched": time.strftime("%Y-%m-%d")}
    (d / META_NAME).write_text(json.dumps(m, indent=1), encoding="utf-8")
    for f in d.iterdir():
        if f.name not in (name, META_NAME) and not f.name.endswith(".part"):
            f.unlink()
    say(f"{PRODUCT} {version} ready: {d}")
    return m


def fetch(what: str = "all", progress=None, refresh: bool = False, get=None, download=None) -> dict:
    """what = client (the MSI), packs (wireguard and nftables from the Ubuntu
    archive, which need the Ubuntu image first) or all."""
    if what not in ("all", "client", "packs"):
        raise RemoteAccessError(f"fetch what? client, packs or all, not {what!r}")
    extra = {k: v for k, v in (("get", get), ("download", download)) if v is not None}
    out: dict = {}
    if what in ("all", "client"):
        out["client"] = fetch_client(progress, **extra)
    if what in ("all", "packs"):
        out["packs"] = []
        for p in PACKS:
            try:
                out["packs"].append(debpacks.fetch(p, progress=progress, refresh=refresh, **extra))
            except debpacks.PackError as exc:
                raise RemoteAccessError(f"{p}: {exc}") from exc
    return out


def readme(m: dict) -> str:
    f = m.get("file", "")
    lines = [f"{PRODUCT} {m.get('version', '')} ({LICENSE}), from {m.get('source', SERVER)}",
             f"fetched {m.get('fetched', '?')}; WireGuard's signed list ({m.get('list', LIST_URL)}) was checked",
             "against WireGuard LLC's release key, and this file against the BLAKE2b-256 it lists:",
             f"  {m.get('blake2b_256', '')}", "",
             "Check it inside the machine too: Get-AuthenticodeSignature .\\Windows\\" + f,
             "shows Status Valid and the signer WireGuard LLC.", "",
             "Install (Windows 10 or 11, as an administrator):",
             f"  msiexec /i \"<stick>\\Windows\\{f}\" /qn DO_NOT_LAUNCH=1",
             "  then start WireGuard from the Start menu, Add Tunnel > Add empty tunnel...", "",
             "The lab has no internet, so WireGuard's own update check finds nothing; that is expected.",
             "WireGuard is a registered trademark of Jason A. Donenfeld; winlab only carries the file you fetched."]
    return "\r\n".join(lines) + "\r\n"


def stick_files() -> dict[str, bytes]:
    if not ready():
        raise RemoteAccessError("WireGuard for Windows is not on this PC yet: fetch it in Images (VPN client), "
                                "or winlab remoteaccess fetch client")
    m = meta()
    return {f"Windows/{m['file']}": (client_dir() / m["file"]).read_bytes(), "README.txt": readme(m).encode("utf-8")}


def to_stick(lab_name: str) -> dict:
    """A new VPN client stick on the lab's media shelf."""
    from . import media, mediashelf
    files = stick_files()
    title = f"VPN client (WireGuard {meta().get('version', '')})".replace(" )", ")")
    sid = mediashelf._new_id(lab_name, "vpn-client")
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABEL)
    except media.MediaError as exc:
        raise RemoteAccessError(str(exc)) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title, "files": len(files), "mb": sum(len(b) for b in files.values()) >> 20}


def summary() -> dict:
    m = meta()
    f = client_dir() / str(m.get("file") or "-")
    return {"id": DOWNLOAD_ID, "title": f"{PRODUCT} (VPN client)", "ready": ready(),
            "version": m.get("version", ""), "fetched": m.get("fetched", ""), "license": LICENSE, "page": PAGE,
            "size_mb": round(f.stat().st_size / 1048576, 1) if f.is_file() else 0}


def render_status() -> str:
    s = summary()
    state = (f"ready ({s['version']}, {s['size_mb']} MB, fetched {s['fetched']})" if s["ready"]
             else f"not fetched ({SIZE_TEXT})")
    lines = ["remote access lab (remote-access): what this PC fetches, what the lab plays", "",
             f"  wireguard-windows  {state}",
             f"  {'':<17}  {PRODUCT}, {LICENSE}, from {SERVER} (signed list checked)"]
    for p in PACKS:
        st = debpacks.status(p)
        pstate = (f"ready ({st['count']} packages, {st['size_mb']} MB, fetched {st['fetched']})"
                  if st["ready"] else f"not fetched (about {st['typical_mb']} MB)")
        lines.append(f"  pack {p:<12}  {pstate}")
    lines += ["", "  onto a stick: the media shelf's VPN client stick button, or winlab remoteaccess stick <lab>"]
    if not s["ready"] or not all(debpacks.ready(p) for p in PACKS):
        lines.append("  then:         winlab remoteaccess fetch   (client, packs or all)")
    lines += ["", "the Windows side downloads nothing: RRAS, NPS, AD CS and IIS are Windows Server roles",
              "the lab Internet (never the real internet): vpn.corp.example and pki.corp.example 203.0.113.10,",
              "  wg.corp.example 203.0.113.20, the home router 203.0.113.30, the Internet's DNS 203.0.113.53", ""]
    return "\n".join(lines)


# --------------------------------------------------------------- the lab
def edge_node(lab):
    """The Windows VPN edge: the machine whose vars name a public_name."""
    return next((n for n in lab.node_list() if n.vars.get("public_name")), None)


def fault_params(lab) -> dict[str, str]:
    """The drills' parameters (guestfaults.lab_params): the edge's public
    name and address, the CRL's public name, the office subnet, the file
    server, the address pool, the CA, the connection and policy names."""
    import ipaddress
    edge = edge_node(lab)
    if edge is None:
        return {}   # no VPN edge: guestfaults.DEFAULTS stand
    out = {"vpnname": str(edge.vars["public_name"]), "crlname": str(edge.vars.get("crl_name") or ""),
           "vpnhost": (edge.hostname or edge.id).lower(), "caname": CA_NAME, "vpnconn": CONNECTION,
           "rapolicy": POLICY, "ragroup": GROUP}
    for nic in edge.nics:
        net = lab.networks.get(nic.network)
        if net is None or not nic.ip:
            continue
        if net.default_gateway == nic.ip or nic is edge.nics[0]:
            out["officenet"] = str(ipaddress.ip_network(net.cidr, strict=False))
        else:
            out["vpnpublic"] = nic.ip
    office = out.get("officenet", "")
    for n in lab.node_list():
        if n.id.startswith("fs") and n.primary_nic is not None and n.primary_nic.ip:
            out["fsip"] = n.primary_nic.ip
            name = (n.hostname or n.id).lower()
            out["fshost"] = f"{name}.{lab.domain}" if lab.domain else name
            break
    pool = str(edge.vars.get("vpn_pool") or "")
    if pool:
        first = pool.split("-")[0]
        out["poolnet"] = str(ipaddress.ip_network(f"{first}/24", strict=False))
    if not office:
        out.pop("officenet", None)
    return out


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    """The Setup step for WireGuard for Windows when a machine names it
    (node vars downloads = ["wireguard"]); the packs come through
    mail.setup_steps, which lists every hand-installed pack."""
    have = set(have or ())
    who = [n.id for n in lab.node_list() if DOWNLOAD_ID in (n.vars.get("downloads") or [])]
    if not who or DOWNLOAD_ID in have:
        return []
    return [{"id": DOWNLOAD_ID, "label": STEP_LABEL, "done": ready(), "blocked": False,
             "hint": f"{', '.join(who)} install{'s' if len(who) == 1 else ''} it from the VPN client stick: "
                     f"{PRODUCT}, {LICENSE}, checked against WireGuard's signed release list, {SIZE_TEXT} once",
             "link": PAGE, "job": JOB}]


def act(dash, action: str, params: dict) -> dict:
    """The workbench's remote-access action: wb-ra-stick writes the VPN
    client stick onto the shelf."""
    if action == "wb-ra-stick":
        try:
            r = to_stick(dash.lab.name)
        except RemoteAccessError as exc:
            return {"ok": False, "message": str(exc), "fetch": not ready()}
        return {"ok": True, "message": f"{r['title']} is on the shelf: drag it onto the laptop", "stick": r["id"]}
    return {"ok": False, "message": f"unknown remote-access action {action!r}"}


# ------------------------------------------------------------- the drills
# NPS's policies as netsh lists them: name, state, processing order.
_NPS_POLICIES = ("$P = @(); $o = $null; foreach ($l in @(netsh nps show np)) { "
                 "if ($l -match '^\\s*Name\\s+=\\s*(.+?)\\s*$') { $o = [pscustomobject]@{ Name = $Matches[1]; "
                 "State = ''; Order = 0 }; $P += $o } "
                 "elseif ($o -and $l -match '^\\s*State\\s+=\\s*(\\S+)') { $o.State = $Matches[1] } "
                 "elseif ($o -and $l -match '^\\s*Processing order\\s+=\\s*(\\d+)') { $o.Order = [int]$Matches[1] } }; ")
_NPS_DENY = "Connections to Microsoft Routing and Remote Access server"
_PBK = "$pbk = Join-Path $env:ProgramData 'Microsoft\\Network\\Connections\\Pbk\\rasphone.pbk'; "
_IP2N = ("$toN = { param($a) $b = ([ipaddress]$a).GetAddressBytes(); "
         "[int64]$b[0] * 16777216 + [int64]$b[1] * 65536 + [int64]$b[2] * 256 + [int64]$b[3] }; ")


def _faults():
    from .guestfaults import WINDOWS, GuestFault
    need_edge = ("if (-not (Get-Service RemoteAccess -ErrorAction SilentlyContinue) -or "
                 "-not (Get-Command Get-RemoteAccess -ErrorAction SilentlyContinue)) { 'nothing to break: build "
                 "the VPN edge first (lessons remote-access-edge and remote-access-sstp)' } else { ")
    return [
        GuestFault(
            id="vpn-crl-offline",
            roles=("domain-join",),
            title="Home workers cannot connect: the revocation server is offline",
            os=WINDOWS,
            teaches="why a VPN client must reach the CRL of the server's certificate from outside the office, "
                    "where the CDP points, certutil -verify -urlfetch from the client's side, and an edge "
                    "firewall rule that blocks the CRL with the web",
            symptom="from home, the SSTP connection fails with error 0x80092013 (the revocation function was "
                    "unable to check revocation because the revocation server was offline) and IKEv2 with 13801; "
                    "inside the office everything works. A laptop that still holds a cached CRL connects until "
                    "it runs out (certutil -urlcache crl delete shows it now)",
            apply=(need_edge + "if (-not (Get-Service W3SVC -ErrorAction SilentlyContinue)) { 'nothing to break: "
                   "publish the CRL on vpn01 first (lesson remote-access-pki)' } else { "
                   "if (-not (Get-NetFirewallRule -Name 'WINLAB-EDGE-HTTP' -ErrorAction SilentlyContinue)) { "
                   "New-NetFirewallRule -Name 'WINLAB-EDGE-HTTP' -DisplayName 'Edge hardening: no plain HTTP from "
                   "the Internet' -Description 'Only the VPN on the public address' -Direction Inbound "
                   "-Protocol TCP -LocalPort 80 -LocalAddress {vpnpublic} -Action Block | Out-Null }; 'broken' } }"),
            clear=("Remove-NetFirewallRule -Name 'WINLAB-EDGE-HTTP' -ErrorAction SilentlyContinue; 'ok'"),
            hints=(
                "Start on the laptop, at home: certutil -urlcache crl delete, then copy the server's certificate "
                "out of the failed handshake (or export it on vpn01 to a file the laptop can read through "
                "another connection) and run certutil -verify -urlfetch on it. The CDP section lists "
                "http://{crlname}/crl/... and says the fetch failed. Invoke-WebRequest on that URL times out.",
                "The name resolves to {vpnpublic} (Resolve-DnsName {crlname}), and port 443 there answers "
                "(SSTP), but Test-NetConnection {crlname} -Port 80 fails. On vpn01 IIS is running and serves "
                "the file locally. Something between the Internet and IIS drops port 80: "
                "Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True.",
                "A block rule for TCP 80 on {vpnpublic} (\"Edge hardening: no plain HTTP from the Internet\") "
                "sits on vpn01. Block wins over allow in Windows Firewall, so the IIS rule cannot help. Remove "
                "it (Remove-NetFirewallRule -DisplayName ...). A CRL must stay on plain HTTP: a client cannot "
                "check the revocation of the very certificate the HTTPS would need. On the laptop: "
                "certutil -urlcache crl delete, then connect again.",
            ),
            verify=("Import-Module WebAdministration -ErrorAction SilentlyContinue; "
                    "$bad = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Block -ErrorAction "
                    "SilentlyContinue | Where-Object { $pf = $_ | Get-NetFirewallPortFilter; "
                    "($pf.Protocol -eq 'TCP' -or $pf.Protocol -eq 'Any') -and "
                    "($pf.LocalPort -contains '80' -or $pf.LocalPort -contains 'Any') }); "
                    "$vd = Get-WebVirtualDirectory -Site 'Default Web Site' -Name crl -ErrorAction SilentlyContinue; "
                    "$crl = @(); if ($vd) { $crl = @(Get-ChildItem (Join-Path "
                    "([Environment]::ExpandEnvironmentVariables($vd.PhysicalPath)) '*.crl') -ErrorAction "
                    "SilentlyContinue | Where-Object { $_.Name -notmatch '\\+' }) }; $web = $false; "
                    "if ($crl.Count -gt 0) { try { $web = (Invoke-WebRequest ('http://{vpnpublic}/crl/' + "
                    "[uri]::EscapeDataString($crl[0].Name)) -UseBasicParsing -TimeoutSec 10).StatusCode -eq 200 } "
                    "catch { $web = $false } }; $bad.Count -eq 0 -and $web"),
        ),
        GuestFault(
            id="vpn-cert-name-mismatch",
            roles=("domain-join",),
            title="After a certificate change, SSTP says the name does not match",
            os=WINDOWS,
            teaches="the certificate SSTP presents (one per server, chosen in RRAS), the name in it against the "
                    "name the client dials, and reading it from the client's side",
            symptom="from home the SSTP connection fails with error 0x800B010F (the certificate's CN name does "
                    "not match the passed value); the certificate is trusted and not revoked, and IKEv2 may "
                    "still connect",
            apply=(need_edge + "$ra = Get-RemoteAccess -ErrorAction SilentlyContinue; "
                   "if (-not $ra -or -not $ra.SslCertificate) { 'nothing to break: give SSTP its certificate first "
                   "(lesson remote-access-sstp)' } else { $f = 'C:\\Windows\\Temp\\winlab-sstp.txt'; "
                   "if (-not (Test-Path $f)) { $ra.SslCertificate.Thumbprint | Set-Content $f }; "
                   "$me = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName; "
                   "$c = Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { $_.HasPrivateKey -and "
                   "$_.Subject -eq ('CN=' + $me) -and $_.NotAfter -gt (Get-Date) -and $_.Issuer -ne $_.Subject } | "
                   "Select-Object -First 1; "
                   "if (-not $c) { try { $c = (Get-Certificate -Template Machine -CertStoreLocation "
                   "Cert:\\LocalMachine\\My -ErrorAction Stop).Certificate } catch { $c = $null } }; "
                   "if (-not $c) { $c = New-SelfSignedCertificate -DnsName $me -CertStoreLocation "
                   "Cert:\\LocalMachine\\My }; Set-RemoteAccess -SslCertificate $c; "
                   "Restart-Service RemoteAccess -Force; 'broken' } }"),
            clear=("$f = 'C:\\Windows\\Temp\\winlab-sstp.txt'; if (Test-Path $f) { $t = (Get-Content $f | "
                   "Select-Object -First 1).Trim(); $c = Get-Item ('Cert:\\LocalMachine\\My\\' + $t) -ErrorAction "
                   "SilentlyContinue; if ($c) { Set-RemoteAccess -SslCertificate $c; Restart-Service RemoteAccess "
                   "-Force }; Remove-Item $f }; 'ok'"),
            hints=(
                "Read the error literally: the name the laptop dialled ({vpnname}) is not in the certificate the "
                "server presented. On vpn01: (Get-RemoteAccess).SslCertificate | Format-List Subject, "
                "DnsNameList, Thumbprint, NotAfter.",
                "It is the machine's own certificate (CN={vpnhost}...), not the one issued for {vpnname}. "
                "In rrasmgmt.msc: the server's Properties, Security, SSL Certificate Binding shows the same. The "
                "right one is still in Cert:\\LocalMachine\\My: Get-ChildItem Cert:\\LocalMachine\\My | "
                "Where-Object { $_.DnsNameList.Unicode -contains '{vpnname}' }.",
                "Bind it back: $c = <that certificate>; Set-RemoteAccess -SslCertificate $c; Restart-Service "
                "RemoteAccess (or pick it in the Security tab and restart the service). Check with "
                "Test-Certificate $c -Policy SSL -DNSName {vpnname}, then connect from home. Use Default "
                "(Use HTTP) unticked in the console only when you know why.",
            ),
            verify=("$c = (Get-RemoteAccess -ErrorAction SilentlyContinue).SslCertificate; "
                    "[bool]($c -and (@($c.DnsNameList | ForEach-Object { $_.Unicode }) -contains '{vpnname}') -and "
                    "(Test-Certificate -Cert $c -Policy SSL -DNSName '{vpnname}' -ErrorAction SilentlyContinue "
                    "-WarningAction SilentlyContinue))"),
        ),
        GuestFault(
            id="nps-policy-order",
            roles=("ad-ds",),
            title="Every home worker is refused, with the right group and the right password",
            os=WINDOWS,
            teaches="NPS network policies are read in processing order and the first whose conditions match "
                    "decides, deny included; the default policies; reading the decision in event 6273",
            symptom="the VPN asks for credentials and then fails with error 812 (the connection was prevented "
                    "because of a policy configured on your RAS/VPN server); Alice is in {ragroup}; dc01's "
                    "Security log has event 6273 for her, naming a policy that is not {rapolicy}",
            apply=("if (-not (Get-Service IAS -ErrorAction SilentlyContinue)) { 'nothing to break: install NPS "
                   "first (lesson remote-access-sstp)' } else { " + _NPS_POLICIES +
                   "$mine = $P | Where-Object { $_.Name -match '{ragroup}' } | Select-Object -First 1; "
                   f"$deny = $P | Where-Object {{ $_.Name -eq '{_NPS_DENY}' }} | Select-Object -First 1; "
                   "if (-not $mine -or -not $deny) { 'nothing to break: the policy {rapolicy} and the default "
                   f"policy {_NPS_DENY} must both be there' }} else {{ "
                   "$f = 'C:\\Windows\\Temp\\winlab-nps.txt'; if (-not (Test-Path $f)) { $deny.Order | "
                   "Set-Content $f }; $s = 'C:\\Windows\\Temp\\winlab-nps.netsh'; "
                   "Set-Content $s ('nps set np name=\"' + $deny.Name + '\" state=enable processingorder=1') "
                   "-Encoding ASCII; netsh -f $s | Out-Null; Remove-Item $s; 'broken' } }"),
            clear=("$f = 'C:\\Windows\\Temp\\winlab-nps.txt'; if (Test-Path $f) { $n = (Get-Content $f | "
                   "Select-Object -First 1).Trim(); $s = 'C:\\Windows\\Temp\\winlab-nps.netsh'; "
                   f"Set-Content $s ('nps set np name=\"{_NPS_DENY}\" processingorder=' + $n) -Encoding ASCII; "
                   "netsh -f $s | Out-Null; Remove-Item $s, $f }; 'ok'"),
            hints=(
                "Let NPS tell you which policy decided. On dc01: Get-WinEvent -FilterHashtable @{LogName='Security'; "
                "Id=6273} -MaxEvents 3 | Format-List TimeCreated, Message. Read Network Policy Name and Reason "
                "Code: it is not {rapolicy}.",
                "Open nps.msc, Policies, Network Policies, and look at the Processing Order column (or netsh nps "
                f"show np). {_NPS_DENY}, a default policy that denies every RRAS request, now sits at the top. "
                "NPS stops at the first policy whose conditions match, so your policy is never read.",
                f"Move it back below yours: in nps.msc right-click {_NPS_DENY}, Move Down until {{rapolicy}} is "
                "first (or netsh nps set np name=\"<the policy>\" processingorder=<n>). Keep the two default "
                "deny policies last, where they catch everything nobody allowed. Connect again: event 6272, "
                "granted by {rapolicy}.",
            ),
            verify=(_NPS_POLICIES + "$mine = $P | Where-Object { $_.Name -match '{ragroup}' -and $_.State -eq "
                    "'Enabled' } | Sort-Object Order | Select-Object -First 1; "
                    "[bool]$mine -and -not ($P | Where-Object { $_.Name -like 'Connections to *' -and $_.State -eq "
                    "'Enabled' -and $_.Order -lt $mine.Order })"),
        ),
        GuestFault(
            id="vpn-split-no-route",
            title="The VPN connects, but the file server is unreachable",
            os=WINDOWS,
            teaches="split tunnelling: only the routes the connection carries go through the tunnel; the "
                    "class-based route Windows adds by itself and why it is turned off; Add-VpnConnectionRoute",
            symptom="on the laptop at home '{vpnconn}' says Connected and has an address from the pool, but "
                    "\\\\{fshost} and Test-NetConnection {fsip} -Port 445 fail; the Internet's web sites still "
                    "load",
            apply=("$n = '{vpnconn}'; $c = Get-VpnConnection -AllUserConnection -Name $n -ErrorAction "
                   "SilentlyContinue; if (-not $c) { 'nothing to break: make the {vpnconn} connection for all "
                   "users first (lesson remote-access-sstp)' } else { " + _PBK +
                   "$f = 'C:\\Windows\\Temp\\winlab-split.xml'; if (-not (Test-Path $f)) { [pscustomobject]@{ "
                   "Routes = @($c.Routes | ForEach-Object { $_.DestinationPrefix }); Pbk = "
                   "[IO.File]::ReadAllText($pbk) } | Export-Clixml $f }; "
                   "if ($c.ConnectionStatus -eq 'Connected') { rasdial $n /disconnect | Out-Null }; "
                   "foreach ($r in @($c.Routes)) { Remove-VpnConnectionRoute -AllUserConnection -ConnectionName $n "
                   "-DestinationPrefix $r.DestinationPrefix -ErrorAction SilentlyContinue }; "
                   "Set-VpnConnection -AllUserConnection -Name $n -SplitTunneling $true -Force -ErrorAction "
                   "SilentlyContinue; "
                   "$out = New-Object System.Collections.Generic.List[string]; $sect = $false; $done = $false; "
                   "foreach ($l in [IO.File]::ReadAllLines($pbk)) { if ($l -match '^\\[(.*)\\]$') { "
                   "if ($sect -and -not $done) { $out.Add('DisableClassBasedDefaultRoute=1'); $done = $true }; "
                   "$sect = ($Matches[1] -eq $n) }; if ($sect -and $l -match '^DisableClassBasedDefaultRoute=') { "
                   "$l = 'DisableClassBasedDefaultRoute=1'; $done = $true }; $out.Add($l) }; "
                   "if ($sect -and -not $done) { $out.Add('DisableClassBasedDefaultRoute=1') }; "
                   "[IO.File]::WriteAllLines($pbk, $out); 'broken' }"),
            clear=("$n = '{vpnconn}'; $f = 'C:\\Windows\\Temp\\winlab-split.xml'; " + _PBK +
                   "if (Test-Path $f) { $s = Import-Clixml $f; [IO.File]::WriteAllText($pbk, $s.Pbk); "
                   "foreach ($r in @($s.Routes)) { Add-VpnConnectionRoute -AllUserConnection -ConnectionName $n "
                   "-DestinationPrefix $r -ErrorAction SilentlyContinue }; Remove-Item $f }; 'ok'"),
            hints=(
                "Ask Windows which way it would send a packet to the file server: Find-NetRoute -RemoteIPAddress "
                "{fsip} | Select-Object InterfaceAlias, NextHop, DestinationPrefix. It picks the home Wi-Fi's "
                "default route, not the tunnel, and the home router has never heard of the office.",
                "Get-VpnConnection -AllUserConnection -Name '{vpnconn}' | Format-List SplitTunneling, Routes: split "
                "tunnelling is on and the connection carries no route. Windows would normally add a class-based "
                "route from the pool address ({poolnet} is in class A, so 10.0.0.0/8), but this connection has "
                "DisableClassBasedDefaultRoute=1 in the all-users phonebook (rasphone.pbk under "
                "%ProgramData%\\Microsoft\\Network\\Connections\\Pbk), as a well-run one should.",
                "Give the tunnel the office's subnet: Add-VpnConnectionRoute -AllUserConnection -ConnectionName "
                "'{vpnconn}' -DestinationPrefix {officenet} (or turn split tunnelling off for a full tunnel). Do "
                "not re-enable the class-based route: it works by accident and grabs every 10.x network, the "
                "home's too if it is one. Disconnect, connect, and Find-NetRoute again.",
            ),
            verify=("$c = Get-VpnConnection -AllUserConnection -Name '{vpnconn}' -ErrorAction SilentlyContinue; "
                    "if (-not $c) { $false } else { " + _IP2N + "$x = & $toN '{fsip}'; "
                    "$hit = @($c.Routes | Where-Object { $_.DestinationPrefix -notmatch ':' } | Where-Object { "
                    "$p = $_.DestinationPrefix.Split('/'); $len = [int]$p[1]; "
                    "$m = (1L -shl 32) - (1L -shl (32 - $len)); ((& $toN $p[0]) -band $m) -eq ($x -band $m) }); "
                    "(-not $c.SplitTunneling) -or $hit.Count -gt 0 }"),
        ),
    ]


FAULT_IDS = ("vpn-crl-offline", "vpn-cert-name-mismatch", "nps-policy-order", "vpn-split-no-route")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
