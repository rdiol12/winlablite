"""Your own CA, actually in use.

The lab's enterprise CA (role adcs) issues the certificates real services
then serve, end to end inside the lab: HTTPS on IIS, LDAPS on the domain
controllers, the Remote Desktop listener, with every member trusting the
root through AD. Then the lifecycle: expiry on the lab clock, renewal by
autoenrollment, revocation and the CRL the CA publishes over HTTP on its own
IIS (http://<ca>/CertEnroll/), and what breaks when any of it is missing.

The student wires it, inside the machines, with the lessons (pki-* in the
workloads module); the app never configures it for them. For the CLI's
`winlab roles apply`, CI and the career game, three vars on the CA machine
do it as desired state instead, like every other role option:

  pki_https  a v2 Web Server template (LabWebServer) Domain Computers
             autoenrol, and every IIS machine bound to its certificate
  pki_ldaps  Kerberos Authentication and Domain Controller published, so
             the DCs autoenrol and answer LDAPS on 636
  pki_rdp    a Remote Desktop Authentication template (LabRDP) and the
             policy that puts its certificate on every RDP listener

Any of them adds the "winlab PKI autoenrollment" GPO at the domain root and
a CRL schedule short enough for the lab clock (crl_days, 7). Templates are
duplicated in AD the way the console does it (a copy of WebServer with its
own OID, schema version 2, autoenrol rights), so the student who opens
certtmpl.msc sees what a person would have made.

Four graded faults register with guestfaults; `winlab pki check <lab>`
runs read-only probes (what 636, 443 and 3389 present, whether the CRL
answers) on the running machines over the agent, and changes nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .dsc import NodeConfig

# (var on the CA machine, label, what DSC does)
WIRES = (
    ("pki_https", "HTTPS on IIS",
     "A Web Server template every domain computer autoenrols (LabWebServer), and each IIS "
     "machine's https binding moved to its certificate."),
    ("pki_ldaps", "LDAPS on the domain controllers",
     "Kerberos Authentication published and autoenrolment on: every DC gets a certificate and "
     "answers LDAPS on 636 with a chain to the lab root."),
    ("pki_rdp", "Remote Desktop certificate",
     "A Remote Desktop Authentication template (LabRDP) and the policy that puts its certificate "
     "on every RDP listener instead of the self-signed one."),
)
WEB_TEMPLATE = "LabWebServer"
RDP_TEMPLATE = "LabRDP"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
RDP_AUTH = "1.3.6.1.4.1.311.54.1.2"      # Remote Desktop Authentication
TEMPLATE_EXT = "1.3.6.1.4.1.311.21.7"    # the v2 template information extension
GPO_NAME = "winlab PKI autoenrollment"
AE_KEY = "HKLM\\Software\\Policies\\Microsoft\\Cryptography\\AutoEnrollment"
TS_KEY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
# Enroll and AutoEnroll, the two extended rights on a template.
ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
HTTPS = "'IIS:\\SslBindings\\0.0.0.0!443'"
CERTENROLL = "'IIS:\\Sites\\Default Web Site\\CertEnroll'"


# ----------------------------------------------------------------- the lab's CA
def lab_ca(lab):
    """(node, CA common name) of the lab's enterprise CA, or (None, '')."""
    for n in lab.node_list():
        if "adcs" in n.roles:
            return n, str(n.vars.get("ca_common_name") or f"{lab.netbios} Issuing CA")
    return None, ""


def wired(lab, var: str) -> bool:
    ca, _ = lab_ca(lab)
    return bool(ca is not None and ca.vars.get(var))


def _ca_fqdn(lab) -> str:
    from .naming import hostname_of
    ca, _ = lab_ca(lab)
    return f"{hostname_of(ca).lower()}.{lab.domain}" if ca is not None and lab.domain else ""


# ----------------------------------------------------------------- templates
_TEMPLATE_BASE = (
    "$cfgNc = ([ADSI]'LDAP://RootDSE').configurationNamingContext\n"
    "$base = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,' + $cfgNc\n"
    "$name = __NAME__\n"
)

# A duplicate of WebServer, as certtmpl.msc's Duplicate Template makes it:
# its own OID registered under the forest's OID container, schema version 2,
# subject and DNS name built from AD, autoenrolment, then Enroll and
# AutoEnroll for Domain Computers (515) and Domain Controllers (516).
_TEMPLATE_SET = _TEMPLATE_BASE + (
    "$display = __DISPLAY__\n"
    "$ekus = @(__EKUS__)\n"
    "$src = [ADSI]('LDAP://CN=WebServer,' + $base)\n"
    "if (-not $src.Properties['cn'].Count) { throw 'no WebServer template in AD: is the enterprise CA installed?' }\n"
    "$oidc = [ADSI]('LDAP://CN=OID,CN=Public Key Services,CN=Services,' + $cfgNc)\n"
    "$forest = [string]$oidc.Properties['msPKI-Cert-Template-OID'].Value\n"
    "$rnd = New-Object System.Random\n"
    "$a = $rnd.Next(10000000, 99999999); $b = $rnd.Next(10000000, 99999999)\n"
    "$oid = '{0}.{1}.{2}' -f $forest, $a, $b\n"
    "$hex = -join (1..32 | ForEach-Object { '{0:X}' -f $rnd.Next(16) })\n"
    "$o = $oidc.Create('msPKI-Enterprise-Oid', ('CN={0}.{1}' -f $b, $hex))\n"
    "$o.Put('displayName', $display); $o.Put('flags', 1); $o.Put('msPKI-Cert-Template-OID', $oid); $o.SetInfo()\n"
    "$t = ([ADSI]('LDAP://' + $base)).Create('pKICertificateTemplate', 'CN=' + $name)\n"
    "$t.Put('displayName', $display)\n"
    "$t.Put('revision', 100)\n"
    # Not a default template any more, modified, autoenrolled, for machines.
    "$t.Put('flags', ((([int]$src.Properties['flags'].Value) -band (-bnot 0x10000)) -bor 0x20060))\n"
    "$t.Put('pKIDefaultKeySpec', 1)\n"
    "$t.Put('pKIKeyUsage', [byte[]]$src.Properties['pKIKeyUsage'].Value)\n"
    "$t.Put('pKIMaxIssuingDepth', 0)\n"
    "foreach ($m in @('pKICriticalExtensions', 'pKIDefaultCSPs')) {\n"
    "    $v = @($src.Properties[$m] | ForEach-Object { [string]$_ })\n"
    "    if ($v.Count) { $t.PutEx(2, $m, $v) }\n"
    "}\n"
    "$t.PutEx(2, 'pKIExtendedKeyUsage', $ekus)\n"
    "$t.PutEx(2, 'msPKI-Certificate-Application-Policy', $ekus)\n"
    "$t.Put('pKIExpirationPeriod', [byte[]][BitConverter]::GetBytes([int64](-864000000000 * __DAYS__)))\n"
    "$t.Put('pKIOverlapPeriod', [byte[]][BitConverter]::GetBytes([int64](-864000000000 * __RENEW__)))\n"
    "$t.Put('msPKI-RA-Signature', 0)\n"
    "$t.Put('msPKI-Enrollment-Flag', 32)\n"
    "$t.Put('msPKI-Private-Key-Flag', 0)\n"
    # DNS name in the subject alternative name and as the CN, both from AD.
    "$t.Put('msPKI-Certificate-Name-Flag', 402653184)\n"
    "$t.Put('msPKI-Minimal-Key-Size', 2048)\n"
    "$t.Put('msPKI-Template-Schema-Version', 2)\n"
    "$t.Put('msPKI-Template-Minor-Revision', 1)\n"
    "$t.Put('msPKI-Cert-Template-OID', $oid)\n"
    "$t.SetInfo()\n"
    "Import-Module ActiveDirectory\n"
    "$dom = (Get-ADDomain).DomainSID.Value\n"
    "$t = [ADSI]('LDAP://CN=' + $name + ',' + $base)\n"
    "foreach ($rid in @(515, 516)) {\n"
    "    $sid = New-Object System.Security.Principal.SecurityIdentifier(('{0}-{1}' -f $dom, $rid))\n"
    "    $t.psbase.ObjectSecurity.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule("
    "$sid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, [System.Security.AccessControl.AccessControlType]::Allow)))\n"
    f"    foreach ($g in @('{ENROLL}', '{AUTOENROLL}')) {{\n"
    "        $t.psbase.ObjectSecurity.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule("
    "$sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [System.Security.AccessControl.AccessControlType]::Allow, [guid]$g)))\n"
    "    }\n"
    "}\n"
    "$t.psbase.CommitChanges()"
)


def template_scripts(name: str, display: str, ekus: list[str], days: int, renew: int) -> tuple[str, str]:
    """(test, set) for one duplicated v2 template in AD."""
    from .dsc import ps_quote
    fill = {"__NAME__": ps_quote(name), "__DISPLAY__": ps_quote(display),
            "__EKUS__": ", ".join(ps_quote(e) for e in ekus),
            "__DAYS__": str(int(days)), "__RENEW__": str(int(renew))}
    test, set_ = _TEMPLATE_BASE + "[ADSI]::Exists('LDAP://CN=' + $name + ',' + $base)", _TEMPLATE_SET
    for k, v in fill.items():
        test, set_ = test.replace(k, v), set_.replace(k, v)
    return test, set_


def templates_wanted(lab) -> list[str]:
    """The templates the CA must offer for what is wired."""
    out: list[str] = []
    if wired(lab, "pki_https"):
        out.append(WEB_TEMPLATE)
    if wired(lab, "pki_ldaps"):
        out += ["KerberosAuthentication", "DomainController"]
    if wired(lab, "pki_rdp"):
        out.append(RDP_TEMPLATE)
    return out


# ----------------------------------------------------------------- DSC: the CA side
def build_ca(cfg: NodeConfig, root_id: str, web_id: str) -> None:
    """On the CA machine, after the CA itself: what the switches wire."""
    from .dscroles import gpo
    lab = cfg.lab
    wanted = templates_wanted(lab)
    if not wanted:
        return
    days = int(cfg.vars.get("pki_cert_days") or 28)
    renew = int(cfg.vars.get("pki_renew_days") or 7)
    made: list[str] = []
    for var, name, display, ekus in (("pki_https", WEB_TEMPLATE, "Lab Web Server", [SERVER_AUTH]),
                                     ("pki_rdp", RDP_TEMPLATE, "Lab Remote Desktop", [RDP_AUTH])):
        if wired(lab, var):
            test, set_ = template_scripts(name, display, ekus, days, renew)
            made.append(cfg.script(f"PkiTemplate_{name}", test, set_, depends=[root_id], run_as=True))
    arr = "@(" + ", ".join(f"'{t}'" for t in wanted) + ")"
    published = cfg.script(
        "PkiPublishedTemplates",
        f"Import-Module ADCSAdministration\n$want = {arr}\n"
        "$have = @(Get-CATemplate | ForEach-Object { $_.Name })\n"
        "@($want | Where-Object { $have -notcontains $_ }).Count -eq 0",
        f"Import-Module ADCSAdministration\n$want = {arr}\n"
        "$have = @(Get-CATemplate | ForEach-Object { $_.Name })\n"
        "foreach ($n in $want) { if ($have -notcontains $n) { Add-CATemplate -Name $n -Force } }",
        depends=[root_id] + made, run_as=True)
    crl = int(cfg.vars.get("crl_days") or 7)
    reg = ("$ca = (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration').Active\n"
           "$k = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\' + $ca\n")
    cfg.script(
        "PkiCrlSchedule",
        reg + "$p = Get-ItemProperty -Path $k\n"
        f"[bool]($p.CRLPeriodUnits -eq {crl} -and $p.CRLPeriod -eq 'Days' -and $p.CRLDeltaPeriodUnits -eq 1)",
        reg + f"Set-ItemProperty -Path $k -Name CRLPeriodUnits -Value {crl}\n"
        "Set-ItemProperty -Path $k -Name CRLPeriod -Value 'Days'\n"
        "Set-ItemProperty -Path $k -Name CRLDeltaPeriodUnits -Value 1\n"
        "Set-ItemProperty -Path $k -Name CRLDeltaPeriod -Value 'Days'\n"
        "Restart-Service -Name CertSvc\n"
        "certutil -crl | Out-Null",
        depends=[root_id])
    # A delta CRL's name ends in '+', which IIS refuses by default (404.11).
    cfg.script(
        "PkiCdpDoubleEscaping",
        "Import-Module WebAdministration\n"
        "[bool](Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/CertEnroll' "
        "-Filter 'system.webServer/security/requestFiltering' -Name allowDoubleEscaping).Value",
        "Import-Module WebAdministration\n"
        "Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/CertEnroll' "
        "-Filter 'system.webServer/security/requestFiltering' -Name allowDoubleEscaping -Value $true",
        depends=[web_id])
    values: list[tuple[str, str, str, object]] = [(AE_KEY, "AEPolicy", "DWord", 7)]
    if wired(lab, "pki_rdp"):
        values.append((TS_KEY, "CertTemplateName", "String", RDP_TEMPLATE))
    gpo(cfg, GPO_NAME, values, [cfg.base_dn], depends=[published])
    what = [w[1] for w in WIRES if wired(lab, w[0])]
    cfg.notes.append(f"pki: {', '.join(what)} wired from this CA; templates {', '.join(wanted)}; "
                     f"GPO '{GPO_NAME}' at the domain root; CRL every {crl} days at http://{_ca_fqdn(lab)}/CertEnroll/")


# ----------------------------------------------------------------- DSC: an IIS machine
def build_iis(cfg: NodeConfig, binding_id: str) -> None:
    """Moves the https binding to the autoenrolled LabWebServer certificate,
    when the lab's CA has pki_https on and this machine is in the domain."""
    from .dsc import ps_quote
    lab = cfg.lab
    if not wired(lab, "pki_https") or not ({"domain-join", "ad-ds"} & set(cfg.node.roles)):
        return
    _, cn = lab_ca(lab)
    head = ("Import-Module WebAdministration\n"
            f"$ca = {ps_quote(cn)}\n$fqdn = {ps_quote(cfg.fqdn.lower())}\n")
    find = ("$c = Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { $_.Issuer -like ('CN=' + $ca + '*') -and "
            "$_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(1) -and "
            f"($_.EnhancedKeyUsageList.ObjectId -contains '{SERVER_AUTH}') -and ($_.DnsNameList.Unicode -contains $fqdn) }} | "
            "Sort-Object NotAfter -Descending | Select-Object -First 1\n")
    deps = [binding_id] + (["[Script]PkiPublishedTemplates"] if cfg.has("[Script]PkiPublishedTemplates") else [])
    cfg.script(
        "HttpsFromLabCa",
        head + f"$b = Get-Item {HTTPS} -ErrorAction SilentlyContinue\n"
        "if (-not $b) { return $false }\n"
        "$c = Get-Item -Path ('Cert:\\LocalMachine\\My\\' + $b.Thumbprint) -ErrorAction SilentlyContinue\n"
        "[bool]($c -and $c.Issuer -like ('CN=' + $ca + '*') -and $c.NotAfter -gt (Get-Date))",
        head + "certutil -pulse | Out-Null\n"
        "for ($i = 0; $i -lt 24; $i++) {\n    " + find.replace("\n", "\n    ").rstrip() + "\n"
        "    if ($c) { break }\n    Start-Sleep -Seconds 5\n}\n"
        "if (-not $c) {\n"
        f"    $r = Get-Certificate -Template '{WEB_TEMPLATE}' -Url 'ldap:' -CertStoreLocation 'Cert:\\LocalMachine\\My'\n"
        "    if ($r.Status -ne 'Issued') { throw ('the lab CA did not issue a web certificate: {0}' -f $r.Status) }\n"
        "    " + find.rstrip() + "\n"
        "}\n"
        "if (-not $c) { throw ('no certificate from ' + $ca + ' for ' + $fqdn + ' in LocalMachine\\My') }\n"
        f"Remove-Item {HTTPS} -ErrorAction SilentlyContinue\n"
        f"New-Item {HTTPS} -Value $c | Out-Null",
        depends=deps)
    cfg.notes.append(f"iis: https bound to the {WEB_TEMPLATE} certificate from {cn} (autoenrolled)")


# ----------------------------------------------------------------- probes
# One line each, "OK ..." or "NO ...": the Check the PKI job prints them, and
# the faults' verify reads the same tests as True/False.
def _chain(var: str) -> str:
    return ("$ch = New-Object System.Security.Cryptography.X509Certificates.X509Chain\n"
            "$ch.ChainPolicy.RevocationMode = 'Online'\n"
            f"$ok = $ch.Build({var})\n"
            "$root = $ch.ChainElements[$ch.ChainElements.Count - 1].Certificate\n"
            "$why = ($ch.ChainStatus | ForEach-Object { $_.Status }) -join ', '\n")


def probe_ldaps(host: str, ca: str, verdict: bool = False) -> str:
    """TLS on 636 to host (a PowerShell expression): the certificate it
    presents and its chain, to the lab root named ca (any trusted root when
    ca is ''). verdict: print True or False instead of the OK/NO line."""
    good = f"$root.Subject -like 'CN={ca}*'" if ca else "$root.Issuer -eq $root.Subject"
    yes, no, down = (("'True'", "'False'", "'False'") if verdict else
                     ("'OK LDAPS {0}: {1}, chain to {2}' -f $h, $cert.Subject, $root.Subject",
                      "'NO LDAPS {0}: {1} issued by {2} ({3})' -f $h, $cert.Subject, $cert.Issuer, $why",
                      "'NO LDAPS {0}: no TLS on 636 ({1})' -f $h, $_.Exception.Message"))
    return ("try {\n"
            f"$h = {host}\n"
            "$tcp = New-Object System.Net.Sockets.TcpClient\n$tcp.Connect($h, 636)\n"
            "$cb = [System.Net.Security.RemoteCertificateValidationCallback]{ param($s, $c, $x, $e) $true }\n"
            "$ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)\n"
            "$ssl.AuthenticateAsClient($h)\n"
            "$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)\n"
            "$tcp.Close()\n" + _chain("$cert") +
            f"if ($ok -and {good}) {{ {yes} }} else {{ {no} }}\n"
            f"}} catch {{ {down} }}")


def probe_https(ca: str) -> str:
    """The certificate IIS's https binding serves, on that machine."""
    return ("Import-Module WebAdministration\n"
            f"$b = Get-Item {HTTPS} -ErrorAction SilentlyContinue\n"
            "if (-not $b) { 'NO HTTPS: no https binding on 443' } else {\n"
            "$c = Get-Item -Path ('Cert:\\LocalMachine\\My\\' + $b.Thumbprint) -ErrorAction SilentlyContinue\n"
            "if (-not $c) { 'NO HTTPS: the binding points at a certificate that is not in the store' } "
            f"elseif ($c.Issuer -notlike 'CN={ca}*') {{ 'NO HTTPS: {{0}} is issued by {{1}}' -f $c.Subject, $c.Issuer }} "
            "elseif ($c.NotAfter -lt (Get-Date)) { 'NO HTTPS: {0} expired {1}' -f $c.Subject, $c.NotAfter } "
            "else { 'OK HTTPS: {0} from the lab CA until {1}' -f $c.Subject, $c.NotAfter } }")


_RDP_CERT = ("$ts = Get-CimInstance -Namespace root\\cimv2\\TerminalServices -ClassName Win32_TSGeneralSetting "
             "-Filter \"TerminalName='RDP-tcp'\"\n"
             "$t = [string]$ts.SSLCertificateSHA1Hash\n"
             "$c = Get-ChildItem -Path Cert:\\LocalMachine\\My, 'Cert:\\LocalMachine\\Remote Desktop' -ErrorAction "
             "SilentlyContinue | Where-Object { $_.Thumbprint -eq $t } | Select-Object -First 1\n")


def probe_rdp(ca: str) -> str:
    """The certificate this machine's RDP listener presents."""
    return (_RDP_CERT +
            "if (-not $c) { 'NO RDP: the listener has no certificate yet' } "
            f"elseif ($c.Issuer -like 'CN={ca}*') {{ 'OK RDP: {{0}} from the lab CA until {{1}}' -f $c.Subject, $c.NotAfter }} "
            "else { 'NO RDP: {0} is issued by {1}' -f $c.Subject, $c.Issuer }")


def probe_crl(ca_fqdn: str, ca: str) -> str:
    """The CA's base CRL over HTTP, fetched from this machine."""
    url = f"http://{ca_fqdn}/CertEnroll/{ca.replace(' ', '%20')}.crl"
    return ("try {\n"
            f"$r = Invoke-WebRequest -Uri '{url}' -UseBasicParsing -TimeoutSec 15\n"
            f"'OK CRL: {url} answers ({{0}} bytes)' -f $r.RawContentLength\n"
            f"}} catch {{ 'NO CRL: {url}: {{0}}' -f $_.Exception.Message }}")


def checks(lab, running: list[str]) -> list[tuple[str, str, str]]:
    """(node, label, command) for every probe that fits the running machines."""
    from .naming import hostname_of
    ca, cn = lab_ca(lab)
    if ca is None or not lab.domain:
        return []
    out: list[tuple[str, str, str]] = []
    member = [n for n in lab.node_list() if n.id in running and n.is_windows
              and ({"domain-join", "ad-ds"} & set(n.roles))]
    for n in member:
        if "ad-ds" in n.roles:
            out.append((n.id, "LDAPS", probe_ldaps(f"'{hostname_of(n).lower()}.{lab.domain}'", cn)))
        if "iis" in n.roles:
            out.append((n.id, "HTTPS", probe_https(cn)))
        out.append((n.id, "RDP", probe_rdp(cn)))
    client = next((n for n in member if n.id != ca.id), None) or (ca if ca.id in running else None)
    if client is not None:
        out.append((client.id, "CRL", probe_crl(_ca_fqdn(lab), cn)))
    return out


def run_checks(lab, emit, runner=None, running: list[str] | None = None) -> dict:
    """Runs the probes over the agent on the running machines; counts the OKs."""
    from . import labclock
    run = runner or labclock.guest_runner(lab.name, timeout=60)
    todo = checks(lab, list(labclock._running(lab.name)) if running is None else running)
    if not todo:
        emit("nothing to check: start the CA and a domain machine first")
        return {"ok": 0, "total": 0}
    good = 0
    for node, label, cmd in todo:
        ok, out = run(node, cmd, "powershell")
        line = next((ln.strip() for ln in reversed(out.splitlines()) if ln.strip()), "") if ok else ""
        good += line.startswith("OK ")
        emit(f"{node}: {line or 'NO ' + label + ': ' + (out.strip()[-200:] or 'no answer')}")
    emit(f"{good} of {len(todo)} checks pass")
    return {"ok": good, "total": len(todo)}


# ----------------------------------------------------------------- guest faults
def _faults():
    from .guestfaults import WINDOWS, GuestFault
    cdp_dir = "$env:SystemRoot\\System32\\CertSrv\\CertEnroll"
    return [
        GuestFault(
            id="pki-cdp-unreachable",
            roles=("adcs",),
            title="Certificates fail revocation checks: the CRL cannot be fetched",
            os=WINDOWS,
            teaches="the CRL distribution point in every certificate, publishing the CRL over HTTP, and reading "
                    "certutil -verify -urlfetch",
            symptom="clients take long to connect to HTTPS and LDAPS, some apps say 'the revocation function was "
                    "unable to check revocation because the revocation server was offline'; the CA itself runs",
            apply=("Import-Module WebAdministration; New-Item -ItemType Directory -Path C:\\winlab\\CertEnroll-moved -Force | Out-Null; "
                   f"Set-Content -Path 'C:\\winlab\\cdp-path.txt' -Value (Get-ItemProperty {CERTENROLL}).physicalPath; "
                   f"Set-ItemProperty {CERTENROLL} -Name physicalPath -Value 'C:\\winlab\\CertEnroll-moved'"),
            clear=("Import-Module WebAdministration; $p = Get-Content -Path 'C:\\winlab\\cdp-path.txt' -ErrorAction SilentlyContinue; "
                   f"if (-not $p) {{ $p = '%windir%\\system32\\CertSrv\\CertEnroll' }}; Set-ItemProperty {CERTENROLL} -Name physicalPath -Value $p"),
            hints=(
                "Take a certificate the CA issued and ask Windows to fetch everything it names: certutil -verify -urlfetch "
                "<file.cer> (export one from certlm.msc, or certutil -ca.cert ca.cer). Read the 'CRL Distribution Points' "
                "section: the HTTP URL says 'Error retrieving URL: Not found (404)'. pkiview.msc on the CA shows the same in red.",
                "The CA writes its CRLs to %windir%\\System32\\CertSrv\\CertEnroll (dir it: the .crl files are there and "
                "current). IIS serves that folder as the CertEnroll virtual directory, so look at what IIS really maps: "
                "Get-ItemProperty 'IIS:\\Sites\\Default Web Site\\CertEnroll' physicalPath, or IIS Manager > CertEnroll > Basic Settings.",
                "Point the virtual directory back at the folder the CA publishes to: Set-ItemProperty 'IIS:\\Sites\\Default Web "
                "Site\\CertEnroll' -Name physicalPath -Value '%windir%\\system32\\CertSrv\\CertEnroll'. Then certutil -verify "
                "-urlfetch shows 'Verified' on the CDP line. Clients that cached the failure retry later; certutil -urlcache "
                "* delete clears it on one.",
            ),
            verify=("Import-Module WebAdministration; "
                    f"$want = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty {CERTENROLL}).physicalPath); "
                    f"$crl = @(Get-ChildItem -Path \"{cdp_dir}\" -Filter *.crl | Where-Object {{ $_.Name -notlike '*+*' }}); "
                    f"$ok = $want.TrimEnd('\\') -eq [Environment]::ExpandEnvironmentVariables(\"{cdp_dir}\") -and $crl.Count -gt 0; "
                    "foreach ($f in $crl) { try { $r = Invoke-WebRequest -Uri ('http://localhost/CertEnroll/' + "
                    "[uri]::EscapeDataString($f.Name)) -UseBasicParsing -TimeoutSec 15; if ($r.StatusCode -ne 200) { $ok = $false } } "
                    "catch { $ok = $false } }; [bool]$ok"),
        ),
        GuestFault(
            id="pki-root-untrusted",
            roles=("domain-join",),
            title="This PC no longer trusts the company's certificates",
            os=WINDOWS,
            teaches="how an enterprise root reaches members (AD's Certification Authorities container, pulled by the "
                    "autoenrollment policy), the enterprise and machine Root stores, and gpupdate / certutil -pulse",
            symptom="on this machine only, every internal HTTPS site warns 'not trusted', LDAPS refuses, Remote Desktop "
                    "warns about the server's identity; the other PCs are fine",
            apply=("New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null; "
                   "$k = 'HKLM:\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates'; "
                   "$th = @(Get-ChildItem -Path $k -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }); "
                   "Set-Content -Path 'C:\\winlab\\pki-roots.txt' -Value $th; "
                   "reg export 'HKLM\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root' C:\\winlab\\pki-roots.reg /y | Out-Null; "
                   "$ae = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\AutoEnrollment'; "
                   "$old = (Get-ItemProperty -Path $ae -ErrorAction SilentlyContinue).AEPolicy; "
                   "Set-Content -Path 'C:\\winlab\\pki-aepolicy.txt' -Value ([string]$old); "
                   "New-Item -Path $ae -Force | Out-Null; Set-ItemProperty -Path $ae -Name AEPolicy -Value 32768 -Type DWord; "
                   "foreach ($t in $th) { Remove-Item -Path (Join-Path $k $t) -Recurse -Force; "
                   "Remove-Item -Path ('Cert:\\LocalMachine\\Root\\' + $t) -ErrorAction SilentlyContinue }"),
            clear=("reg import C:\\winlab\\pki-roots.reg 2>$null; "
                   "$ae = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\AutoEnrollment'; "
                   "$old = Get-Content -Path 'C:\\winlab\\pki-aepolicy.txt' -ErrorAction SilentlyContinue; "
                   "if ($old) { Set-ItemProperty -Path $ae -Name AEPolicy -Value ([int]$old) -Type DWord } "
                   "else { Remove-ItemProperty -Path $ae -Name AEPolicy -ErrorAction SilentlyContinue }; certutil -pulse | Out-Null"),
            hints=(
                "Read the chain, not the browser: certutil -verify on a certificate the CA issued (or open it, "
                "Certification Path) ends in 'A certificate chain processed, but terminated in a root certificate which "
                "is not trusted by the trust provider'. Compare with a PC that works: the root is there, here it is not.",
                "Enterprise roots are not installed by hand: the autoenrollment policy copies them from AD (CN=Certification "
                "Authorities in the Configuration partition) into the enterprise Root store at every policy refresh. "
                "certutil -enterprise -viewstore Root is empty here. Why did refresh not bring it back? Read "
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\AutoEnrollment: AEPolicy is 32768 (0x8000), "
                "'Certificate Services Client - Auto-Enrollment: Disabled', set locally on this machine.",
                "Remove the local override (Remove-ItemProperty that AEPolicy, or set it to 7 as the domain policy does), "
                "then gpupdate /force and certutil -pulse. certutil -enterprise -viewstore Root lists the lab root again and "
                "certutil -verify ends in 'Verified'. If a GPO set the 0x8000, fix the GPO instead: the next refresh would undo you.",
            ),
            verify=("$th = @(Get-Content -Path 'C:\\winlab\\pki-roots.txt' -ErrorAction SilentlyContinue | Where-Object { $_ }); "
                    "$ae = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\AutoEnrollment' "
                    "-ErrorAction SilentlyContinue).AEPolicy; "
                    "$miss = @($th | Where-Object { -not (Test-Path -Path ('Cert:\\LocalMachine\\Root\\' + $_)) }); "
                    "[bool]($th.Count -gt 0 -and $miss.Count -eq 0 -and -not (([int]$ae) -band 32768))"),
        ),
        GuestFault(
            id="rdp-cert-self-signed",
            roles=("domain-join", "ad-ds"),
            title="Remote Desktop warns that the server's identity cannot be verified",
            os=WINDOWS,
            teaches="the RDP listener's certificate (Win32_TSGeneralSetting), the self-signed fallback, and the "
                    "Remote Desktop certificate template policy",
            symptom="mstsc to this machine shows 'The identity of the remote computer cannot be verified' with a "
                    "certificate issued by the machine itself; last week it connected without a prompt",
            apply=("New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null; " + _RDP_CERT.replace("\n", "; ") +
                   "Set-Content -Path 'C:\\winlab\\rdp-thumb.txt' -Value $t; "
                   f"$k = '{TS_KEY.replace('HKLM', 'HKLM:')}'; "
                   "$old = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).CertTemplateName; "
                   "Set-Content -Path 'C:\\winlab\\rdp-template.txt' -Value ([string]$old); "
                   "Remove-ItemProperty -Path $k -Name CertTemplateName -ErrorAction SilentlyContinue; "
                   "$self = Get-ChildItem -Path 'Cert:\\LocalMachine\\Remote Desktop' -ErrorAction SilentlyContinue | "
                   "Where-Object { $_.Issuer -eq $_.Subject } | Select-Object -First 1; "
                   "if ($self) { Set-CimInstance -InputObject $ts -Property @{ SSLCertificateSHA1Hash = $self.Thumbprint } } "
                   "else { Set-CimInstance -InputObject $ts -Property @{ SSLCertificateSHA1Hash = '' } }"),
            clear=(_RDP_CERT.replace("\n", "; ") +
                   f"$k = '{TS_KEY.replace('HKLM', 'HKLM:')}'; "
                   "$old = Get-Content -Path 'C:\\winlab\\rdp-template.txt' -ErrorAction SilentlyContinue; "
                   "if ($old) { New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name CertTemplateName -Value $old }; "
                   "$t0 = Get-Content -Path 'C:\\winlab\\rdp-thumb.txt' -ErrorAction SilentlyContinue; "
                   "if ($t0 -and (Test-Path -Path ('Cert:\\LocalMachine\\My\\' + $t0))) { "
                   "Set-CimInstance -InputObject $ts -Property @{ SSLCertificateSHA1Hash = $t0 } }"),
            hints=(
                "Look at what the listener presents, not at the store: (Get-CimInstance -Namespace root\\cimv2\\TerminalServices "
                "Win32_TSGeneralSetting -Filter \"TerminalName='RDP-tcp'\").SSLCertificateSHA1Hash, then find that thumbprint "
                "in Cert:\\LocalMachine\\My and Cert:\\LocalMachine\\'Remote Desktop'. It is the self-signed one in Remote "
                "Desktop, issued by the machine to itself, so no client can chain it.",
                "A CA-issued RDP certificate comes from the policy Computer Configuration > Administrative Templates > "
                "Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > 'Server "
                "authentication certificate template', which is HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal "
                "Services CertTemplateName. It is missing here (gpresult /h shows whether the GPO still sets it).",
                "Bring the policy back (gpupdate /force when the GPO sets it; or set CertTemplateName to the template's name), "
                "then certutil -pulse; the Remote Desktop Configuration service enrols and moves the listener to the new "
                "certificate. To bind one by hand: Set-CimInstance on that Win32_TSGeneralSetting with "
                "@{SSLCertificateSHA1Hash='<thumbprint of a CA-issued cert in LocalMachine\\My>'}.",
            ),
            verify=(_RDP_CERT.replace("\n", "; ") +
                    "$ok = $false; if ($c -and $c.Issuer -ne $c.Subject) { $ch = New-Object "
                    "System.Security.Cryptography.X509Certificates.X509Chain; $ch.ChainPolicy.RevocationMode = 'NoCheck'; "
                    "$ok = $ch.Build($c) }; [bool]$ok"),
        ),
        GuestFault(
            id="ldaps-no-cert",
            roles=("ad-ds",),
            title="LDAPS on a domain controller stopped answering",
            os=WINDOWS,
            teaches="where a DC gets its LDAPS certificate (autoenrolment from the enterprise CA), Schannel's events, "
                    "ldp.exe on 636 and asking the DC to reload its certificate",
            symptom="applications that bind with LDAPS (ldp.exe, port 636 with SSL) fail with 'Cannot open connection'; "
                    "plain LDAP on 389 and logons work, port 636 answers a TCP connect",
            apply=("New-Item -Path Cert:\\LocalMachine\\WinlabParked -Force | Out-Null; "
                   f"Get-ChildItem Cert:\\LocalMachine\\My | Where-Object {{ $_.Issuer -ne $_.Subject -and "
                   f"$_.EnhancedKeyUsageList.ObjectId -contains '{SERVER_AUTH}' }} | "
                   "Move-Item -Destination Cert:\\LocalMachine\\WinlabParked; "
                   "$r = [ADSI]'LDAP://localhost/RootDSE'; $r.Put('renewServerCertificate', 1); $r.SetInfo()"),
            clear=("Get-ChildItem Cert:\\LocalMachine\\WinlabParked -ErrorAction SilentlyContinue | "
                   "Move-Item -Destination Cert:\\LocalMachine\\My; certutil -pulse | Out-Null; "
                   "$r = [ADSI]'LDAP://localhost/RootDSE'; $r.Put('renewServerCertificate', 1); $r.SetInfo()"),
            hints=(
                "Separate the port from TLS: Test-NetConnection <dc> -Port 636 succeeds, so something listens. ldp.exe, "
                "Connection > Connect, port 636, SSL ticked, fails. On the DC, the System log has Schannel event 36886: "
                "'No suitable default server credential exists on this system'.",
                "LDAPS uses a certificate in the DC's LocalMachine\\My with Server Authentication and the DC's name, normally "
                "autoenrolled from the Kerberos Authentication or Domain Controller template. certlm.msc > Personal > "
                "Certificates (or Get-ChildItem Cert:\\LocalMachine\\My) has none any more.",
                "Enrol one: certutil -pulse (autoenrolment), or Get-Certificate -Template KerberosAuthentication -Url ldap: "
                "-CertStoreLocation Cert:\\LocalMachine\\My. The DC picks a new certificate up on its own within minutes; to "
                "make it now, write renewServerCertificate=1 to the RootDSE (ldp.exe Browse > Modify, DN empty). ldp.exe on 636 "
                "then shows the RootDSE, and from a member the chain ends in the lab root.",
            ),
            verify=probe_ldaps("[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName", "", verdict=True),
        ),
    ]


FAULT_IDS = ("pki-cdp-unreachable", "pki-root-untrusted", "rdp-cert-self-signed", "ldaps-no-cert")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
