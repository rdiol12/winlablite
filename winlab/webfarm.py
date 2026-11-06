"""Web servers by hand: IIS sites by host name, nginx in front of them, the
intranet's names in AD DNS, HTTPS from the lab's own CA, and Kerberos for a
site that two servers answer under one name.

The web-farm lab (content/labs/web-farm.toml) starts empty and the student
builds every part inside the machines, lesson by lesson (web-* in the
workloads module); nginx reaches lb01 as the nginx pack
(winlab/debpacks.py), plugged in as a stick. The app connects, starts and
grades; it configures nothing. The web-proxy role is the nginx lesson's
model answer for `winlab roles apply` and CI only.

The names the lessons build (written against winlab's own, localized by
winlab/naming.py like every lesson):

  intranet.<domain>  A record: web01 first, then lb01 once nginx fronts the farm
  wiki.<domain>      CNAME to web01, then to intranet
  HTTP/intranet.<domain>  the SPN on CORP\\svc-intranet, the farm's pool account

Four graded drills register with guestfaults, each the way it breaks in a
real web team: a second site holding the intranet's binding, the SPN gone
(Kerberos falls back to NTLM, which a reverse proxy cannot carry), a
certificate for the wrong name on the SNI binding, and a stale A record
left by a server that is gone.
"""

from __future__ import annotations

SITE = "Intranet"
HOST = "intranet"
SPN = "HTTP/intranet.{domain}"
SNI = "'IIS:\\SslBindings\\!443!intranet.{domain}'"

FAULT_IDS = ("iis-binding-clash", "kerberos-spn-missing", "web-cert-name-mismatch", "dns-stale-record")


def _faults():
    from .guestfaults import WINDOWS, GuestFault
    keep = "New-Item -ItemType Directory -Path C:\\winlab -Force | Out-Null; "
    chain = ("$ch = New-Object System.Security.Cryptography.X509Certificates.X509Chain; "
             "$ch.ChainPolicy.RevocationMode = 'NoCheck'; ")
    return [
        GuestFault(
            id="iis-binding-clash",
            roles=("iis",),
            title="The intranet site is stopped and will not start again",
            os=WINDOWS,
            teaches="what a binding is, why two sites cannot listen on the same IP, port and host name, "
                    "and reading the site's state and its error instead of restarting IIS",
            symptom="intranet.corp.lab shows an old page (or, through the proxy, the old page on every other "
                    "request); in IIS Manager the Intranet site is Stopped and Start answers 'Cannot create a "
                    "file when that file already exists'",
            apply=("Import-Module WebAdministration; " + keep +
                   f"$s = Get-Website -Name '{SITE}' -ErrorAction SilentlyContinue; "
                   "if (-not $s) { 'nothing to break: build the Intranet site first' } else { "
                   "$b = @($s.bindings.Collection | Where-Object { $_.protocol -eq 'http' })[0].bindingInformation; "
                   "$p = $b.Split(':'); "
                   f"Stop-Website -Name '{SITE}'; "
                   "New-Item -ItemType Directory -Path C:\\inetpub\\intranet-old -Force | Out-Null; "
                   "Set-Content -Path C:\\inetpub\\intranet-old\\index.html -Value '<h1>Intranet (old copy, 2019)</h1>'; "
                   "New-Website -Name 'Intranet-old' -IPAddress $p[0] -Port $p[1] -HostHeader $p[2] "
                   "-PhysicalPath C:\\inetpub\\intranet-old -Force | Out-Null; "
                   "Start-Website -Name 'Intranet-old'; 'broken' }"),
            clear=("Import-Module WebAdministration; Remove-Website -Name 'Intranet-old' -ErrorAction SilentlyContinue; "
                   f"Start-Website -Name '{SITE}' -ErrorAction SilentlyContinue"),
            hints=(
                "Look at the server, not the browser: Get-IISSite (or IIS Manager's Sites) lists every site with "
                "its state and bindings. The Intranet site is Stopped, and another site you did not build is Started.",
                "Start-Website Intranet fails with 'Cannot create a file when that file already exists' "
                "(0x800700B7): a running site already holds the same binding, protocol, address, port and host "
                "name. Get-WebBinding | Format-Table protocol, bindingInformation, ItemXPath shows two sites "
                "with *:80:intranet.corp.lab. Only one of them can listen.",
                "Retire the old copy: Stop-Website Intranet-old; Remove-Website Intranet-old (or change its "
                "binding), then Start-Website Intranet and browse it from pc01. Next time a site will not start, "
                "netsh http show servicestate and the System log's WAS events name the clash.",
            ),
            verify=("Import-Module WebAdministration; "
                    f"$s = Get-Website -Name '{SITE}' -ErrorAction SilentlyContinue; "
                    "$mine = @($s.bindings.Collection | ForEach-Object { $_.bindingInformation }); "
                    f"$clash = @(Get-Website | Where-Object {{ $_.Name -ne '{SITE}' -and $_.State -eq 'Started' }} | "
                    "ForEach-Object { $_.bindings.Collection } | Where-Object { $mine -contains $_.bindingInformation }); "
                    "[bool]($s -and $s.State -eq 'Started' -and $clash.Count -eq 0)"),
        ),
        GuestFault(
            id="kerberos-spn-missing",
            roles=("ad-ds",),
            title="The intranet asks for a password, or refuses everyone, after a cleanup",
            os=WINDOWS,
            teaches="how a browser finds the service account for a web site (the SPN), what happens when it "
                    "cannot (NTLM fallback), and why NTLM does not survive a reverse proxy",
            symptom="pc01 gets 401 from https://intranet.corp.lab through the proxy (Edge keeps prompting for "
                    "credentials); klist on pc01 shows no HTTP/intranet.corp.lab ticket after klist purge",
            apply=("Import-Module ActiveDirectory; " + keep + f"$spn = '{SPN}'; "
                   "$o = @(Get-ADObject -LDAPFilter \"(servicePrincipalName=$spn)\"); "
                   "if ($o.Count -eq 0) { 'nothing to break: put the SPN on the pool account first (setspn -S)' } else { "
                   "$o | ForEach-Object { $_.DistinguishedName } | Set-Content -Path C:\\winlab\\web-spn.txt; "
                   "foreach ($x in $o) { Set-ADObject -Identity $x.DistinguishedName -Remove @{servicePrincipalName = $spn} }; "
                   "'broken' }"),
            clear=("Import-Module ActiveDirectory; " + f"$spn = '{SPN}'; "
                   "Get-Content -Path C:\\winlab\\web-spn.txt -ErrorAction SilentlyContinue | "
                   "ForEach-Object { Set-ADObject -Identity $_ -Add @{servicePrincipalName = $spn} }"),
            hints=(
                "Start on pc01: klist purge, then Invoke-WebRequest https://intranet.corp.lab -UseDefaultCredentials "
                "-UseBasicParsing, then klist. A working site leaves a ticket for HTTP/intranet.corp.lab; here there "
                "is none, so Kerberos never happened and the client fell back to NTLM.",
                "A client asks the KDC for a ticket to HTTP/<the name in the URL>. The KDC finds the account by "
                "that SPN: setspn -Q HTTP/intranet.corp.lab on dc01 says 'No such SPN found'. The System log on "
                "pc01 has a Kerberos event KDC_ERR_S_PRINCIPAL_UNKNOWN. NTLM is a three-step handshake on one "
                "connection, and nginx opens a new connection to the backend for each request, so it fails.",
                "Put the SPN back on the account the application pool runs as, on both servers: setspn -S "
                "HTTP/intranet.corp.lab CORP\\svc-intranet (-S refuses a duplicate). Then klist purge on pc01 and "
                "browse again: klist shows the HTTP/intranet.corp.lab ticket. Never put it on WEB01$ as well: a "
                "duplicate SPN breaks Kerberos for everyone (setspn -X lists duplicates).",
            ),
            verify=("Import-Module ActiveDirectory; "
                    f"$o = @(Get-ADObject -LDAPFilter '(servicePrincipalName={SPN})'); "
                    "[bool]($o.Count -eq 1 -and $o[0].ObjectClass -ne 'computer')"),
        ),
        GuestFault(
            id="web-cert-name-mismatch",
            roles=("iis",),
            title="The browser warns that the intranet's certificate is for another site",
            os=WINDOWS,
            teaches="what a certificate's names are for, the SAN list a browser checks (not the subject), "
                    "SNI bindings, and testing one backend directly with its real name",
            symptom="https://intranet.corp.lab on web01 gives NET::ERR_CERT_COMMON_NAME_INVALID in Edge and "
                    "'The remote certificate is invalid' from Invoke-WebRequest; HTTP works",
            apply=("Import-Module WebAdministration; " + keep + f"$p = {SNI}; "
                   "$b = Get-Item $p -ErrorAction SilentlyContinue; "
                   "if (-not $b) { 'nothing to break: bind https for intranet.{domain} first' } else { "
                   "Set-Content -Path C:\\winlab\\web-sni-thumb.txt -Value $b.Thumbprint; $c = $null; "
                   "try { $c = (Get-Certificate -Template LabWebSAN -SubjectName 'CN=staging.{domain}' "
                   "-DnsName 'staging.{domain}' -CertStoreLocation Cert:\\LocalMachine\\My -ErrorAction Stop).Certificate } catch { }; "
                   "if (-not $c) { $c = New-SelfSignedCertificate -DnsName 'staging.{domain}' "
                   "-CertStoreLocation Cert:\\LocalMachine\\My }; "
                   "Remove-Item $p; New-Item $p -Value $c -SSLFlags 1 | Out-Null; 'broken' }"),
            clear=("Import-Module WebAdministration; " + f"$p = {SNI}; "
                   "$t = Get-Content -Path C:\\winlab\\web-sni-thumb.txt -ErrorAction SilentlyContinue; "
                   "$c = $null; if ($t) { $c = Get-Item -Path \"Cert:\\LocalMachine\\My\\$t\" -ErrorAction SilentlyContinue }; "
                   "if ($c) { Remove-Item $p -ErrorAction SilentlyContinue; New-Item $p -Value $c -SSLFlags 1 | Out-Null }"),
            hints=(
                "Read what the site really presents. From pc01, certutil -url https://intranet.corp.lab is "
                "interactive; quicker: on web01, (Get-Item 'IIS:\\SslBindings\\!443!intranet.corp.lab').Thumbprint, "
                "then Get-Item Cert:\\LocalMachine\\My\\<thumbprint> | Format-List Subject, DnsNameList, Issuer, NotAfter.",
                "The certificate is valid and may chain to the lab CA, but its names (DnsNameList, the SAN "
                "extension) do not include intranet.corp.lab. A browser checks the name in the URL against the "
                "SAN list only; the subject's CN no longer counts. Someone bound a staging certificate to the "
                "intranet's SNI binding.",
                "Bind the certificate whose SAN names intranet.corp.lab: Get-ChildItem Cert:\\LocalMachine\\My | "
                "Where-Object { $_.DnsNameList.Unicode -contains 'intranet.corp.lab' } finds it; then "
                "Remove-Item 'IIS:\\SslBindings\\!443!intranet.corp.lab' and New-Item it again with -Value <that "
                "certificate> -SSLFlags 1 (or IIS Manager > Intranet > Bindings > https > the certificate). No "
                "certificate with the name? Request one: Get-Certificate -Template LabWebSAN -DnsName "
                "intranet.corp.lab,wiki.corp.lab -SubjectName CN=intranet.corp.lab -CertStoreLocation Cert:\\LocalMachine\\My.",
            ),
            verify=("Import-Module WebAdministration; " + f"$t = (Get-Item {SNI} -ErrorAction SilentlyContinue).Thumbprint; "
                    "$c = $null; if ($t) { $c = Get-Item -Path \"Cert:\\LocalMachine\\My\\$t\" -ErrorAction SilentlyContinue }; "
                    + chain +
                    "[bool]($c -and (@($c.DnsNameList | ForEach-Object { $_.Unicode }) -contains 'intranet.{domain}') "
                    "-and $c.NotAfter -gt (Get-Date) -and $ch.Build($c))"),
        ),
        GuestFault(
            id="dns-stale-record",
            roles=("dns",),
            title="The intranet times out for everyone since this morning",
            os=WINDOWS,
            teaches="reading a name's records at the DNS server, static against dynamic records, TTLs and "
                    "the caches between a client and the zone",
            symptom="pc01 gets 'Unable to connect' (a timeout) from intranet.corp.lab; ping intranet.corp.lab gets no "
                    "reply; web01, web02 and lb01 all run and answer by their own names",
            apply=("Import-Module DnsServer; " + keep + "$z = '{domain}'; "
                   f"$r = @(Get-DnsServerResourceRecord -ZoneName $z -Name {HOST} -RRType A -ErrorAction SilentlyContinue); "
                   "if ($r.Count -eq 0) { 'nothing to break: add the intranet record first' } else { "
                   "$r | ForEach-Object { $_.RecordData.IPv4Address.IPAddressToString } | Set-Content -Path C:\\winlab\\web-dns.txt; "
                   "$ip = $r[0].RecordData.IPv4Address.IPAddressToString; $stale = ($ip.Split('.')[0..2] -join '.') + '.199'; "
                   "$r | Remove-DnsServerResourceRecord -ZoneName $z -Force; "
                   f"Add-DnsServerResourceRecordA -ZoneName $z -Name {HOST} -IPv4Address $stale -TimeToLive 01:00:00; "
                   "Set-Content -Path C:\\winlab\\web-dns-stale.txt -Value $stale; Clear-DnsServerCache -Force; 'broken' }"),
            clear=("Import-Module DnsServer; $z = '{domain}'; "
                   f"Get-DnsServerResourceRecord -ZoneName $z -Name {HOST} -RRType A -ErrorAction SilentlyContinue | "
                   "Remove-DnsServerResourceRecord -ZoneName $z -Force; "
                   "Get-Content -Path C:\\winlab\\web-dns.txt -ErrorAction SilentlyContinue | "
                   f"ForEach-Object {{ Add-DnsServerResourceRecordA -ZoneName $z -Name {HOST} -IPv4Address $_ }}; "
                   "Clear-DnsServerCache -Force"),
            hints=(
                "Separate the name from the servers. From pc01, Resolve-DnsName intranet.corp.lab gives an "
                "address; Test-NetConnection <that address> -Port 443 fails, while Test-NetConnection lb01 -Port 443 "
                "(by the machine's own address) succeeds. So the servers are fine and the name points somewhere else.",
                "Ask the zone itself, not a cache: on dc01, Get-DnsServerResourceRecord -ZoneName corp.lab -Name "
                "intranet shows an A record for an address no machine has, a leftover of a server that was "
                "retired. Its TTL is an hour, so clients keep the wrong answer that long (ipconfig /displaydns on pc01).",
                "Remove the stale record and add the right one: Remove-DnsServerResourceRecord -ZoneName corp.lab "
                "-Name intranet -RRType A -RecordData <stale address>, then Add-DnsServerResourceRecordA -ZoneName "
                "corp.lab -Name intranet -IPv4Address <the proxy's address>. Then Clear-DnsServerCache on dc01 and "
                "ipconfig /flushdns on pc01. Static records never age out: aging and scavenging only remove "
                "dynamic ones, so a retired server's static record stays until someone deletes it.",
            ),
            verify=("Import-Module DnsServer; "
                    "$want = @(Get-Content -Path C:\\winlab\\web-dns.txt -ErrorAction SilentlyContinue); "
                    "$stale = Get-Content -Path C:\\winlab\\web-dns-stale.txt -ErrorAction SilentlyContinue; "
                    f"$have = @(Get-DnsServerResourceRecord -ZoneName '{{domain}}' -Name {HOST} -RRType A -ErrorAction SilentlyContinue | "
                    "ForEach-Object { $_.RecordData.IPv4Address.IPAddressToString }); "
                    "[bool]($have.Count -gt 0 -and -not ($stale -and $have -contains $stale) -and "
                    "@($want | Where-Object { $have -notcontains $_ }).Count -eq 0)"),
        ),
    ]


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
