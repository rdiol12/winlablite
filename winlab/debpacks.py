"""Packs: Debian packages for a Linux appliance, fetched from the
distribution's own archive onto this PC and plugged into the machine as a
stick that apt reads as a repository.

The lab has no internet, so `apt install` inside a machine has nothing to
talk to. A pack is the dependency closure of a few packages (realmd and SSSD
for joining the domain, say), resolved here against the archive's Packages
index minus what the appliance image already carries (its publisher's
manifest), every .deb verified against the SHA-256 the index gives, and laid
out as a flat repository (the .debs plus a Packages file). The role that
needs it mounts the stick and installs from it with apt, offline. Nothing is
bundled with winlab; the archive's own licences travel inside each package
(/usr/share/doc/<pkg>/copyright).
"""

from __future__ import annotations

import gzip
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import paths
from .bootstrap import BootstrapError, _download_to, _get


class PackError(Exception):
    pass


@dataclass(frozen=True)
class Pack:
    id: str
    title: str
    image: str                 # the appliance it is resolved for
    packages: tuple[str, ...]  # what to install; dependencies are resolved
    roles: tuple[str, ...] = ()
    typical_mb: int = 30
    note: str = ""
    # Repositories beyond the distribution's archive the pack resolves
    # against, as (root url, suite, components): a vendor's own apt
    # repository, read the same way (its Packages index, its SHA-256s).
    repos: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    # A module (winlab/<extra>.py) that adds files beside the .debs after
    # they are fetched: fetch_extra(pack, dir, closure, get, download, say)
    # returns what the manifest records, extra_ready(dir, manifest) says
    # whether they are all there (the FreePBX tarball, Sangoma's signed index).
    extra: str = ""
    # Check each fetched index against the SHA-256 its suite's Release file
    # lists (both read over HTTPS from the publisher), as apt does before it
    # trusts a Packages file.
    verify_release: bool = False
    # (package, version prefix): the release a pack is pinned to; a fetch
    # that resolves another major version is refused.
    pins: tuple[tuple[str, str], ...] = ()
    # Packages a publisher releases as a single .deb, not from an apt
    # repository: (one Packages stanza with its Filename, Size and SHA-256,
    # the release URL it is relative to). Resolved and verified like the rest.
    release_debs: tuple[tuple[str, str], ...] = ()
    # The least memory the machine needs once the student has installed and
    # started what the pack carries (0: nothing beyond the OS). `winlab lab
    # up` never trims a machine below it when the host is short
    # (membudget.floor): a JVM or a database killed for memory is not a lesson.
    min_mb: int = 0
    # Kernel module packages that must match the image's own kernel, named
    # without their ABI ("linux-modules-extra"): the fetch adds
    # <name>-<the image's kernel release> (from its manifest) to the roots.
    kernel_modules: tuple[str, ...] = ()


FLAT = "/"   # the suite of a flat repository (a sources line ending in " /")


def _webmin_release() -> tuple[tuple[str, str], ...]:
    from . import webmin
    return ((webmin.deb_stanza(), webmin.RELEASE),)


PACKS: dict[str, Pack] = {
    "sssd": Pack(
        id="sssd",
        title="Domain member: SSSD, realmd, adcli and Kerberos",
        image="ubuntu",
        packages=("realmd", "sssd-ad", "sssd-tools", "adcli", "krb5-user",
                  "libnss-sss", "libpam-sss"),
        roles=("linux-member",),
        typical_mb=40,
        note="what an Ubuntu server needs to join Active Directory and log domain users in",
    ),
    "grafana": Pack(
        id="grafana",
        title="Monitoring: Grafana, Prometheus and the node exporter",
        image="ubuntu",
        packages=("grafana", "prometheus", "prometheus-node-exporter"),
        roles=("grafana",),
        typical_mb=230,
        note="Grafana from Grafana Labs' own apt repository (AGPLv3), Prometheus and its node "
             "exporter from the Ubuntu archive (Apache-2.0)",
        repos=(("https://apt.grafana.com", "stable", ("main",)),),
    ),
    # No role installs it: the student does, inside the machine (apt install
    # freeradius from the stick), for 802.1X on the switches (winlab/dot1x.py).
    "freeradius": Pack(
        id="freeradius",
        title="RADIUS server: FreeRADIUS and radtest",
        image="ubuntu",
        packages=("freeradius", "freeradius-utils"),
        typical_mb=15,
        note="FreeRADIUS (GPLv2) from the Ubuntu archive: a RADIUS server for the switches' 802.1X, "
             "set up by hand in /etc/freeradius/3.0",
    ),
    # The web-farm lab's proxy: the student installs it by hand (apt install
    # nginx from the stick); the web-proxy role does the same for the CLI.
    "nginx": Pack(
        id="nginx",
        title="Web server and reverse proxy: nginx",
        image="ubuntu",
        packages=("nginx",),
        roles=("web-proxy",),
        typical_mb=2,
        note="nginx (BSD-2-Clause) from the Ubuntu archive: virtual hosts, a reverse proxy and an "
             "upstream load balancer in front of IIS, set up by hand in /etc/nginx",
    ),
    # The certificate-authority lab's Linux issuing CA (winlab/calab.py, lesson
    # pki-step-ca-acme): Smallstep's step-ca and step CLI from Smallstep's own
    # apt repository, certbot as the ACME client and nginx to serve what it
    # fetches, both from the Ubuntu archive. Installed by hand from the stick.
    "stepca": Pack(
        id="stepca",
        title="Private CA with ACME: step-ca, step CLI, certbot and nginx",
        image="ubuntu",
        packages=("step-ca", "step-cli", "certbot", "nginx"),
        roles=("step-ca",),
        typical_mb=75,
        note="step-ca and step CLI (Apache-2.0) from Smallstep's own apt repository; certbot "
             "(Apache-2.0) and nginx (BSD-2-Clause) from the Ubuntu archive",
        repos=(("https://packages.smallstep.com/stable/debian", "debs", ("main",)),),
    ),
    # The lab's mail server, built by hand (winlab/mail.py, lesson mail-server):
    # Postfix for SMTP, Dovecot for IMAP and the SASL logins Postfix asks it
    # about, swaks (with the Perl modules for its TLS, logins and MX lookups) and
    # s-nail to test from the server itself.
    "mail": Pack(
        id="mail",
        title="Mail server: Postfix, Dovecot IMAP, swaks and s-nail",
        image="ubuntu",
        packages=("postfix", "dovecot-imapd", "swaks", "s-nail", "libnet-dns-perl",
                  "libio-socket-ssl-perl", "libauthen-sasl-perl"),
        typical_mb=6,
        note="Postfix (EPL-2.0 / IPL-1.0) and Dovecot (MIT / LGPL-2.1) from the Ubuntu archive: SMTP on "
             "25 and 587, IMAP on 993, set up by hand in /etc/postfix and /etc/dovecot",
    ),
    # Optional webmail beside it: Roundcube on Apache and PHP, SQLite for its
    # own settings, talking IMAP and SMTP to the server above.
    "roundcube": Pack(
        id="roundcube",
        title="Webmail: Roundcube on Apache and PHP (SQLite)",
        image="ubuntu",
        packages=("roundcube", "roundcube-sqlite3", "roundcube-plugins", "apache2", "libapache2-mod-php"),
        typical_mb=16,
        note="Roundcube (GPLv3+), Apache (Apache-2.0) and PHP (PHP-3.01) from the Ubuntu archive: "
             "optional webmail for the mail server, at http://<server>/roundcube",
    ),
    # The mail server's filter (lessons mail-auth-records, mail-spam-filter):
    # Rspamd as Postfix's milter (spam scores, DNS blocklists, SPF, DKIM and
    # DMARC checks, DKIM signing), Dovecot's LMTP and Sieve so delivery can
    # file spam into Junk (with ManageSieve for Roundcube's filters), and dig.
    "mailfilter": Pack(
        id="mailfilter",
        title="Mail filter: Rspamd, Dovecot LMTP and Sieve, dig",
        image="ubuntu",
        packages=("rspamd", "dovecot-lmtpd", "dovecot-sieve", "dovecot-managesieved", "bind9-dnsutils"),
        typical_mb=20,
        note="Rspamd (Apache-2.0) and Dovecot's LMTP, Sieve and ManageSieve (MIT / LGPL-2.1) from the Ubuntu "
             "archive: spam filtering and DKIM signing as Postfix's milter, spam filed into Junk at delivery",
    ),
    # The mail lab's Internet (role inet-mail, content/roles/inet-mail.sh):
    # BIND for the public zones, Webmin as the DNS host's control panel,
    # Postfix and Rspamd for Example Mail, swaks for the spam sender.
    "inetmail": Pack(
        id="inetmail",
        title="The mail lab's Internet: BIND, Postfix, Rspamd, swaks and Webmin",
        image="ubuntu",
        packages=("postfix", "bind9", "bind9-utils", "bind9-dnsutils", "rspamd", "swaks",
                  "libnet-dns-perl", "webmin"),
        roles=("inet-mail",),
        typical_mb=75,
        note="BIND 9 (MPL-2.0), Postfix (EPL-2.0 / IPL-1.0), Rspamd (Apache-2.0) and swaks (GPLv2) from the "
             "Ubuntu archive, Webmin (BSD-3-Clause) from its GitHub release: the in-lab Internet's DNS "
             "host, a mail provider and a spam sender, which the lab brings up by itself",
        release_debs=_webmin_release(),
    ),
    # The phone system's firmware (winlab/voip.py): what Sangoma's own
    # installer (sng_freepbx_debian_install.sh) puts on Debian 12 for the open
    # source FreePBX 17, less what an office PBX without modem cards, fax or
    # commercial modules needs (no DAHDI, no sysadmin, no ionCube loader).
    # Debian 12 has no Asterisk: Asterisk 22 comes from Sangoma's signed apt
    # repository, FreePBX itself as Sangoma's tarball (the extra files).
    "freepbx": Pack(
        id="freepbx",
        title="Phone system: FreePBX 17 with Asterisk 22, Apache, MariaDB and PHP 8.2",
        image="debian12",
        packages=("apache2", "libapache2-mod-php8.2", "mariadb-server", "mariadb-client",
                  "php8.2", "php8.2-cli", "php8.2-common", "php8.2-curl", "php8.2-mysql", "php8.2-gd",
                  "php8.2-mbstring", "php8.2-intl", "php8.2-xml", "php8.2-bz2", "php8.2-zip",
                  "php8.2-ldap", "php8.2-sqlite3", "php8.2-bcmath", "php8.2-soap", "php-pear",
                  "nodejs", "sox", "mpg123", "lame", "flite", "sqlite3", "uuid", "unixodbc", "odbc-mariadb",
                  "sudo", "cron", "incron", "at", "curl", "wget", "gnupg", "net-tools",
                  "asterisk22", "asterisk22-core", "asterisk22-addons", "asterisk22-addons-core",
                  "asterisk22-addons-mysql", "asterisk22-curl", "asterisk22-odbc", "asterisk22-sqlite3",
                  "asterisk22-voicemail", "asterisk22.0-freepbx-asterisk-modules"),
        roles=("pbx",),
        typical_mb=420,
        note="FreePBX 17 (framework GPLv2+, core GPLv3+, open-source modules only) from "
             "mirror.freepbx.org, Asterisk 22 (GPL-2.0) from Sangoma's signed repository deb.freepbx.org, "
             "the rest from the Debian archive (flite, the BSD-style speech synthesiser the lab's callers "
             "speak with); installed offline by the phone system at its first power-on",
        repos=(("http://deb.freepbx.org/freepbx17-prod", "bookworm", ("main",)),),
        verify_release=True,
        extra="voip",
    ),
    # The NAS's firmware (content/roles/nas.sh): OpenMediaVault 8
    # "Synchrony", the current stable release, from the project's own apt
    # repository, on Debian 13 trixie from the Debian archive. Installed at
    # the NAS's first start; everything else is done in its web UI.
    "omv": Pack(
        id="omv",
        title="NAS firmware: OpenMediaVault 8 (Synchrony)",
        image="debian13-cloud",
        packages=("openmediavault-keyring", "openmediavault"),
        roles=("nas",),
        typical_mb=320,
        note="OpenMediaVault (GPL-3.0) from packages.openmediavault.org, its dependencies (Samba, NFS, "
             "nginx, PHP, Salt) from the Debian and OpenMediaVault archives: the NAS's web UI on port 80",
        repos=(("https://packages.openmediavault.org/public", "synchrony", ("main",)),),
        verify_release=True,
        pins=(("openmediavault", "8."),),
    ),
    # Webmin, the web console of a Linux server (winlab/webmin.py): no role
    # installs it; the student does, by hand, on the mail server or the log
    # collector (a lab names it in the machine's packs).
    "webmin": Pack(
        id="webmin",
        title="Web console: Webmin",
        image="ubuntu",
        packages=("webmin",),
        typical_mb=45,
        note="Webmin (BSD-3-Clause), the .deb from its own GitHub release (SHA-256 pinned), its Perl "
             "dependencies from the Ubuntu archive: https on port 10000, sign in as any user who may sudo",
        release_debs=_webmin_release(),
    ),
    # Docker on Ubuntu, installed by hand (winlab/containers.py, lesson
    # docker-basics): the engine, containerd and runc, Compose v2 and buildx.
    # The images come on their own stick, pulled on this PC from the registries.
    "docker": Pack(
        id="docker",
        title="Containers: Docker Engine, containerd, Compose v2 and buildx",
        image="ubuntu",
        packages=("docker.io", "docker-compose-v2", "docker-buildx"),
        typical_mb=90,
        note="Docker Engine (Apache-2.0), containerd and runc (Apache-2.0) from the Ubuntu archive: "
             "docker run, build, compose and a registry of your own inside the lab",
    ),
    # The kubeadm nodes of the containers lab (winlab/kubeadm.py): what
    # kubeadm's preflight and kube-proxy want from the OS beside the
    # binaries on the kubeadm stick.
    "kubeadm": Pack(
        id="kubeadm",
        title="Kubernetes node tools: conntrack and socat",
        image="ubuntu",
        packages=("conntrack", "socat"),
        typical_mb=1,
        note="conntrack-tools (GPLv2) and socat (GPLv2) from the Ubuntu archive: kube-proxy's connection "
             "tracking and kubectl port-forward on a kubeadm node",
    ),
    # The databases lab (winlab/databases.py): PostgreSQL 16 installed by hand
    # on the primary and the standby, its contrib modules and client, and
    # krb5-user (kinit, klist -k) for the optional Kerberos lesson.
    "postgresql": Pack(
        id="postgresql",
        title="Database server: PostgreSQL 16, contrib and the psql client",
        image="ubuntu",
        packages=("postgresql", "postgresql-contrib", "postgresql-client", "krb5-user"),
        typical_mb=45,
        note="PostgreSQL (PostgreSQL Licence) from the Ubuntu archive: a cluster in /etc/postgresql/16/main, "
             "pg_hba.conf, streaming replication and pg_dump, all set up by hand",
    ),
    # MariaDB, the MySQL-compatible engine the lab carries (Ubuntu's archive
    # also has mysql-server-8.0; it cannot share a machine with MariaDB, and
    # winlab has no pack for it): server, client and mariadb-backup.
    "mariadb": Pack(
        id="mariadb",
        title="Database server: MariaDB 10.11, its client and mariadb-backup",
        image="ubuntu",
        packages=("mariadb-server", "mariadb-client", "mariadb-backup"),
        typical_mb=25,
        note="MariaDB (GPLv2) from the Ubuntu archive: bind-address, accounts by host, mariadb-dump and "
             "GTID replication, set up by hand in /etc/mysql/mariadb.conf.d",
    ),
    # The Linux track (winlab/linuxdomain.py, lab linux-in-the-domain): a
    # Samba file server that is a member of the Windows domain (winbind,
    # Windows ACLs kept in extended attributes, the recycle module from
    # samba-vfs-modules), BIND 9 as a second DNS server beside the domain
    # controllers, and a Linux client that mounts the share with Kerberos.
    # All three are installed and set up by hand inside the machines.
    "samba": Pack(
        id="samba",
        title="File server in the domain: Samba with winbind, its VFS modules and the ACL tools",
        image="ubuntu",
        packages=("samba", "samba-vfs-modules", "winbind", "libnss-winbind", "libpam-winbind", "krb5-user",
                  "smbclient", "acl", "attr"),
        typical_mb=45,
        note="Samba (GPLv3) from the Ubuntu archive: joined to Active Directory with net ads join, users "
             "and groups through winbind, shares whose permissions are set from Windows, set up by hand in "
             "/etc/samba/smb.conf",
    ),
    "bind": Pack(
        id="bind",
        title="DNS server: BIND 9 and its tools (named-checkconf, rndc, dig)",
        image="ubuntu",
        packages=("bind9", "bind9-utils", "bind9-dnsutils"),
        typical_mb=6,
        note="BIND 9 (MPL-2.0) from the Ubuntu archive: a secondary of the domain's DNS zones and a "
             "primary for a delegated subdomain, set up by hand in /etc/bind",
    ),
    "cifs": Pack(
        id="cifs",
        title="SMB client: cifs-utils, keyutils and smbclient",
        image="ubuntu",
        packages=("cifs-utils", "keyutils", "smbclient"),
        typical_mb=8,
        note="cifs-utils (GPLv3) and smbclient (GPLv3) from the Ubuntu archive: a Windows or Samba share "
             "mounted on Linux with Kerberos (sec=krb5, multiuser)",
    ),
    # Linux identity (winlab/linuxidentity.py): a FreeIPA client on Ubuntu
    # (the server is Rocky's, from its own DVD), and Keycloak with the two
    # applications it signs people in to. Both installed and set up by hand.
    "ipaclient": Pack(
        id="ipaclient",
        title="FreeIPA client: ipa-client-install, SSSD, sssctl and the LDAP tools",
        image="ubuntu",
        packages=("freeipa-client", "sssd-tools", "ldap-utils"),
        typical_mb=60,
        note="the FreeIPA client (GPLv3) with SSSD (GPLv3), its tools and OpenLDAP's ldapsearch (OpenLDAP "
             "Public License) from the Ubuntu archive: lx02 enrolled in ipa.lab by hand with ipa-client-install",
    ),
    "keycloak": Pack(
        id="keycloak",
        title="Single sign-on: Keycloak 26 on OpenJDK 21 and PostgreSQL, Grafana, Apache with mod_auth_mellon, oathtool",
        image="ubuntu",
        packages=("openjdk-21-jre-headless", "postgresql", "grafana", "apache2", "libapache2-mod-auth-mellon",
                  "oathtool", "sqlite3"),
        typical_mb=480,
        note="Keycloak (Apache-2.0) from its release on Maven Central (pinned by SHA-256, its LICENSE.txt beside "
             "it); OpenJDK 21 (GPLv2 with the Classpath Exception), PostgreSQL (PostgreSQL Licence), Apache "
             "(Apache-2.0), mod_auth_mellon (GPLv2+), oathtool (GPLv3+) and sqlite3 (public domain) from the "
             "Ubuntu archive; Grafana (AGPLv3) from Grafana Labs' own apt repository: an identity provider, "
             "an OpenID Connect and a SAML application, set up by hand",
        repos=(("https://apt.grafana.com", "stable", ("main",)),),
        extra="linuxidentity",
        # Keycloak's JVM, PostgreSQL and Grafana on one machine.
        min_mb=2048,
    ),
    # The dynamic-routing lab's routers, built by hand (winlab/routing.py):
    # FRRouting's zebra, ospfd and bgpd with the vtysh shell, frr-reload.py
    # (frr-pythontools) so systemctl reload frr applies a changed frr.conf,
    # and traceroute to watch the path move.
    "frr": Pack(
        id="frr",
        title="Router: FRRouting (OSPF, BGP, vtysh) and traceroute",
        image="ubuntu",
        packages=("frr", "frr-pythontools", "traceroute"),
        typical_mb=5,
        note="FRRouting (GPL-2.0-or-later) from the Ubuntu archive: OSPF and BGP set up by hand in vtysh, "
             "daemons switched on in /etc/frr/daemons",
    ),
    # The web-proxy lab's filter, built by hand (winlab/webproxy.py): Squid
    # built with OpenSSL (Ubuntu's plain squid uses GnuTLS and cannot peek at
    # a TLS handshake for its SNI), squidclient to ask it from the shell, the
    # Kerberos tools for its keytab and ldapsearch to test its group lookups.
    # Its Kerberos (negotiate_kerberos_auth) and AD group (ext_ldap_group_acl)
    # helpers ship inside Squid itself.
    "squid": Pack(
        id="squid",
        title="Web proxy: Squid (with OpenSSL), squidclient, Kerberos and LDAP tools",
        image="ubuntu",
        packages=("squid-openssl", "squidclient", "krb5-user", "ldap-utils"),
        typical_mb=12,
        note="Squid (GPLv2+) from the Ubuntu archive: an explicit web proxy on 3128 with allow and block "
             "lists, Kerberos logins and AD group rules, HTTPS filtered by SNI, set up by hand in /etc/squid",
    ),
    # The router in front of it: nftables for the forwarding rules that let
    # only the proxy out, conntrack to watch the connections crossing it.
    "nftables": Pack(
        id="nftables",
        title="Router firewall: nftables and conntrack",
        image="ubuntu",
        packages=("nftables", "conntrack"),
        typical_mb=1,
        note="nftables (GPLv2) and conntrack-tools (GPLv2) from the Ubuntu archive: the forwarding rules of "
             "a Linux router, set up by hand in /etc/nftables.conf",
    ),
    # The ipv6-dual-stack lab's IPv6 routers, built by hand (winlab/ipv6.py):
    # FRRouting's zebra sends the router advertisements (ipv6 nd) and ospf6d
    # runs OSPFv3 between the two routers; ndisc6 (rdisc6, ndisc6) asks for an
    # RA or a neighbour by hand, traceroute -6 shows the path.
    "ipv6-router": Pack(
        id="ipv6-router",
        title="IPv6 router: FRRouting (router advertisements, OSPFv3), ndisc6 and traceroute",
        image="ubuntu",
        packages=("frr", "frr-pythontools", "ndisc6", "traceroute"),
        typical_mb=5,
        note="FRRouting (GPL-2.0-or-later) and ndisc6 (GPL-2.0-or-later) from the Ubuntu archive: RAs and "
             "OSPFv3 set up by hand in vtysh",
    ),
    # The Linux machine on the lab's IPv6 LANs: rdisc6 to watch the router
    # advertisements arrive, traceroute for the path.
    "ipv6-tools": Pack(
        id="ipv6-tools",
        title="IPv6 tools: ndisc6 (rdisc6, ndisc6, rltraceroute6) and traceroute",
        image="ubuntu",
        packages=("ndisc6", "traceroute"),
        typical_mb=1,
        note="ndisc6 (GPL-2.0-or-later) and traceroute (GPL-2.0-or-later) from the Ubuntu archive",
    ),
    # The intrusion-detection lab's sensor, built by hand on the boundary
    # router (winlab/ids.py): Suricata (built with NFQUEUE and af-packet),
    # suricata-update to merge the ET Open rules from the rules stick (a
    # Recommends of suricata, which a pack does not follow, so it is named),
    # and jq to read eve.json.
    # The print-support lab's CUPS print server, built by hand
    # (winlab/printing.py, lesson cups-print-server): CUPS and its filters,
    # the BSD commands (lpr, lpq, lprm) and nc to test a printer's port.
    "cups": Pack(
        id="cups",
        title="Print server: CUPS, cups-filters and the lp and lpr commands",
        image="ubuntu",
        packages=("cups", "cups-client", "cups-bsd", "cups-filters", "netcat-openbsd", "snmp"),
        typical_mb=42,
        note="CUPS (Apache-2.0) and cups-filters (Apache-2.0 / GPL-2.0+ / MIT) from the Ubuntu archive: "
             "queues, drivers and sharing over IPP on port 631, set up by hand with lpadmin and cupsctl "
             "or the web pages; net-snmp's snmpget and snmpwalk (BSD-style) to read a printer's status",
    ),
    "suricata": Pack(
        id="suricata",
        title="Network IDS/IPS: Suricata, suricata-update and jq",
        image="ubuntu",
        packages=("suricata", "suricata-update", "jq"),
        typical_mb=30,
        note="Suricata (GPLv2), suricata-update (GPLv2) and jq (MIT) from the Ubuntu archive: a sensor on the "
             "router watching the lab's own traffic, set up by hand in /etc/suricata; its rules come from the "
             "Suricata rules stick (ET Open, winlab ids fetch), never from the internet",
    ),
    # The remote-access lab's open-source VPN edge (winlab/remoteaccess.py):
    # wg and wg-quick (the kernel module is in Ubuntu's own kernel), qrencode
    # to show a peer's configuration as a QR code for a phone.
    "wireguard": Pack(
        id="wireguard",
        title="VPN edge: WireGuard tools and qrencode",
        image="ubuntu",
        packages=("wireguard-tools", "qrencode"),
        typical_mb=1,
        note="wireguard-tools (GPLv2) and qrencode (LGPLv2.1+) from the Ubuntu archive: a WireGuard VPN "
             "server for home workers, set up by hand in /etc/wireguard",
    ),
    # The automation lab's control node (winlab/automation.py): Ubuntu's
    # ansible package is the full community bundle, so ansible.windows,
    # community.windows and microsoft.ad come with it and nothing is pulled
    # from Ansible Galaxy; pywinrm with Kerberos and NTLM for the Windows
    # servers, krb5-user for kinit. No sshpass, since the lessons use SSH keys.
    # The far end of the lab router's site-to-site IPsec tunnel (winlab/vti.py):
    # strongSwan's charon run by systemd with the swanctl tool, and the
    # standard plugins (AES-GCM among them). The XFRM interface the tunnel
    # uses is in Ubuntu's own kernel.
    # Flow export and collection (winlab/advnet.py, lesson netflow-ipfix-export):
    # softflowd watches a router's card and exports NetFlow v9 or IPFIX, nfcapd
    # (the nfdump package) collects it into files that nfdump reads.
    "netflow": Pack(
        id="netflow",
        title="Flow export and collector: softflowd and nfdump (nfcapd)",
        image="ubuntu",
        packages=("softflowd", "nfdump"),
        typical_mb=2,
        note="softflowd (BSD-3-Clause) and nfdump (BSD-3-Clause) from the Ubuntu archive: a router exports "
             "NetFlow v9 or IPFIX, a collector stores and queries it, set up by hand in /etc/softflowd and "
             "/etc/nfdump",
    ),
    # The web farm's load-balancing pair (winlab/advnet.py, lesson
    # haproxy-keepalived-pair): HAProxy in front of the IIS servers, keepalived
    # moving one virtual address between the two machines with VRRP.
    "haproxy": Pack(
        id="haproxy",
        title="Load balancer pair: HAProxy and keepalived (VRRP)",
        image="ubuntu",
        packages=("haproxy", "keepalived"),
        typical_mb=4,
        note="HAProxy (GPL-2.0-or-later) and keepalived (GPL-2.0-or-later) from the Ubuntu archive: a TCP and "
             "HTTP load balancer and the VRRP daemon that keeps its address alive, set up by hand in "
             "/etc/haproxy and /etc/keepalived",
    ),
    # The web-farm lab's other way to keep a service up on ha01 and ha02
    # (lesson linux-pacemaker-cluster): Corosync for membership and quorum,
    # Pacemaker to place the resources, pcs (with pcsd) to set it up, and the
    # OCF resource agents (IPaddr2 for the floating address). No fence agent
    # is fetched: the lab has nothing a fence agent could power off, which
    # the lesson says out loud.
    "pacemaker": Pack(
        id="pacemaker",
        title="High-availability cluster: Pacemaker, Corosync, pcs and the resource agents",
        image="ubuntu",
        packages=("pacemaker", "corosync", "pcs", "resource-agents-base"),
        typical_mb=60,
        note="Pacemaker (GPL-2.0-or-later), Corosync (BSD-3-Clause), pcs (GPL-2.0-only) and resource-agents "
             "(GPL-2.0-or-later) from the Ubuntu archive: a two-node cluster set up by hand with pcs",
    ),
    # The ipv6-dual-stack lab's NAT64 and DNS64 on rtr01 (lesson
    # ipv6-nat64-dns64): TAYGA translates between an IPv6 prefix and an IPv4
    # pool in user space (a TUN device), Unbound synthesises AAAA records
    # from A records with its dns64 module.
    "nat64": Pack(
        id="nat64",
        title="NAT64 and DNS64: TAYGA and Unbound",
        image="ubuntu",
        packages=("tayga", "unbound", "bind9-dnsutils"),
        typical_mb=8,
        note="TAYGA (GPL-2.0-or-later), Unbound (BSD-3-Clause) and dig (bind9-dnsutils, MPL-2.0) from the Ubuntu "
             "archive: stateless NAT64 on a TUN device and a DNS64 resolver, set up by hand in /etc/tayga.conf "
             "and /etc/unbound",
    ),
    "strongswan": Pack(
        id="strongswan",
        title="IPsec VPN: strongSwan (charon-systemd, swanctl)",
        image="ubuntu",
        packages=("charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins"),
        typical_mb=3,
        note="strongSwan (GPL-2.0-or-later) from the Ubuntu archive: the branch end of an IKEv2 "
             "site-to-site tunnel to the lab router, set up by hand in /etc/swanctl",
    ),
    "ansible": Pack(
        id="ansible",
        title="Automation: Ansible with its collections, pywinrm and Kerberos",
        image="ubuntu",
        packages=("ansible", "python3-winrm", "python3-requests-kerberos", "krb5-user"),
        typical_mb=18,
        note="Ansible 9 / ansible-core 2.16 (GPLv3+) with the ansible.windows, community.windows and "
             "microsoft.ad collections, pywinrm (MIT) and requests-kerberos (ISC) from the Ubuntu archive: "
             "the control node, set up by hand",
    ),
    # The network automation control node (winlab/netauto.py): Ansible (Ubuntu's
    # full bundle carries cisco.ios and ansible.netcommon), Netmiko, paramiko for
    # network_cli (Ubuntu has no ansible-pylibssh), jq, and what NAPALM imports;
    # NAPALM itself and the four modules Ubuntu lacks are pinned PyPI wheels
    # fetched beside the .debs (the extra files).
    "netauto": Pack(
        id="netauto",
        title="Network automation: Ansible (cisco.ios), Netmiko, NAPALM, jq",
        image="ubuntu",
        packages=("ansible", "python3-netmiko", "python3-paramiko", "python3-venv", "jq", "python3-jmespath",
                  "python3-ncclient", "python3-pyeapi", "python3-lxml", "python3-netaddr", "python3-jinja2",
                  "python3-requests", "python3-yaml", "python3-scp", "python3-serial", "python3-six",
                  "python3-yamlordereddictloader", "python3-pyparsing", "python3-transitions",
                  "python3-typing-extensions", "python3-textfsm", "python3-ntc-templates", "python3-setuptools"),
        typical_mb=35,
        note="Ansible 9 (GPLv3+, with cisco.ios and ansible.netcommon), Netmiko (MIT), paramiko (LGPL-2.1+) and "
             "jq (MIT) from the Ubuntu archive; NAPALM 5.0 (Apache-2.0), junos-eznc (Apache-2.0), netutils "
             "(Apache-2.0), ttp and ttp-templates (MIT) as PyPI wheels pinned by SHA-256, for a venv: the "
             "control node that drives the router and the switches over SSH",
        extra="netauto",
    ),
    # What the student's playbook installs on the managed Ubuntu servers. The
    # stick goes into ctl01, which serves it to them as the lab's own apt
    # repository over HTTP: the servers never get a stick of their own.
    "baseline": Pack(
        id="baseline",
        title="Managed servers' baseline: nginx and chrony, for the lab repository",
        image="ubuntu",
        packages=("nginx", "chrony"),
        typical_mb=1,
        note="nginx (BSD-2-Clause) and chrony (GPLv2) from the Ubuntu archive: copied onto ctl01 and "
             "served as an apt repository the playbook points the managed servers at",
    ),
    # A VM host built by hand on the Ubuntu appliance (winlab/nestedvirt.py:
    # VT-x in its firmware): QEMU/KVM and libvirt with its QEMU driver,
    # virt-install, Cockpit with its Virtual machines page, and xorriso /
    # genisoimage to make ISOs inside the lab. A pack does not follow
    # Recommends, so what they recommend and a VM host needs is named: OVMF
    # (UEFI VMs), dnsmasq-base (libvirt's default network), cpu-checker
    # (kvm-ok), libosinfo's bindings (Cockpit's Create VM dialog lists
    # operating systems through them). virt-manager is left out: the
    # appliance has no desktop to show it on.
    "kvm": Pack(
        id="kvm",
        title="VM host: QEMU/KVM, libvirt, virt-install, Cockpit with its Virtual machines page, xorriso",
        image="ubuntu",
        packages=("qemu-system-x86", "qemu-utils", "ovmf", "cpu-checker", "libvirt-daemon-system",
                  "libvirt-daemon-driver-qemu", "libvirt-clients", "dnsmasq-base", "virtinst", "cockpit",
                  "cockpit-machines", "python3-gi", "gir1.2-libosinfo-1.0", "xorriso", "genisoimage"),
        typical_mb=100,
        note="QEMU (GPL-2.0), libvirt (LGPL-2.1+), virt-install (GPL-2.0+), Cockpit and cockpit-machines "
             "(LGPL-2.1+), xorriso (GPL-3.0+) and genisoimage (GPL-2.0) from the Ubuntu archive: a KVM host "
             "built by hand, its VMs in Cockpit on https port 9090 (Virtual machines) or with virsh, ISOs "
             "made with xorriso -as mkisofs",
    ),
    # The admin's documentation tools on the Admin tools server (winlab/doctools.py),
    # Debian 12: installed by hand, each pack carrying its application beside
    # the .debs (the extra files): GLPI's release tarball, DokuWiki's stable
    # tarball, the Vaultwarden image pulled from Docker Hub.
    "glpi": Pack(
        id="glpi",
        title="Asset inventory: GLPI 11 on Apache, PHP 8.2 and MariaDB",
        image="debian12",
        packages=("apache2", "libapache2-mod-php8.2", "php8.2-cli", "mariadb-server", "mariadb-client",
                  "php8.2-mysql", "php8.2-curl", "php8.2-gd", "php8.2-intl", "php8.2-xml", "php8.2-mbstring",
                  "php8.2-zip", "php8.2-bz2", "php8.2-ldap", "php8.2-bcmath", "php8.2-opcache"),
        typical_mb=120,
        note="GLPI (GPL-3.0-or-later) from its GitHub release (SHA-256 GitHub publishes), Apache, PHP 8.2 and "
             "MariaDB 10.11 from the Debian archive: the web installer at http://<server>/, set up by hand",
        extra="doctools",
    ),
    "dokuwiki": Pack(
        id="dokuwiki",
        title="Runbook wiki: DokuWiki on Apache and PHP 8.2",
        image="debian12",
        packages=("apache2", "libapache2-mod-php8.2", "php8.2-xml", "php8.2-gd", "php8.2-mbstring", "php8.2-intl"),
        typical_mb=25,
        note="DokuWiki (GPL-2.0-or-later) from download.dokuwiki.org (SHA-256 recorded: it publishes none), "
             "Apache and PHP from the Debian archive: flat-file pages at http://<server>/dokuwiki/",
        extra="doctools",
    ),
    "vaultwarden": Pack(
        id="vaultwarden",
        title="Password vault: Vaultwarden on Docker",
        image="debian12",
        packages=("docker.io",),
        typical_mb=150,
        note="Vaultwarden (AGPL-3.0) and the Bitwarden web vault (GPL-3.0) as the image Docker Hub serves "
             "(pinned by digest), Docker from the Debian archive (Apache-2.0): docker load, then run it with TLS",
        extra="doctools",
    ),
    # The network team's tools on the Network operations server (winlab/netops.py),
    # Debian 12: installed by hand, each pack carrying its application's image
    # (pulled from Docker Hub by digest) beside the .debs.
    "librenms": Pack(
        id="librenms",
        title="SNMP monitoring: LibreNMS on Docker, MariaDB, Net-SNMP",
        image="debian12",
        packages=("docker.io", "mariadb-server", "mariadb-client", "snmpd", "snmp"),
        typical_mb=300,
        note="LibreNMS (GPL-3.0) as the image its project publishes on Docker Hub (pinned by digest), Docker, "
             "MariaDB 10.11 and Net-SNMP from the Debian archive: web UI on port 8000 and a poller container, "
             "set up by hand",
        extra="netops",
    ),
    "oxidized": Pack(
        id="oxidized",
        title="Configuration backup: Oxidized on Docker, git",
        image="debian12",
        packages=("docker.io", "git"),
        typical_mb=160,
        note="Oxidized and oxidized-web (Apache-2.0) as the image Docker Hub serves (pinned by digest), Docker "
             "and git from the Debian archive: device configurations kept in git, web UI on port 8888",
        extra="netops",
    ),
    "uptime-kuma": Pack(
        id="uptime-kuma",
        title="Uptime checks: Uptime Kuma on Docker",
        image="debian12",
        packages=("docker.io",),
        typical_mb=230,
        note="Uptime Kuma (MIT) as the slim image Docker Hub serves (pinned by digest), Docker from the Debian "
             "archive: monitors and a status page on port 3001, SQLite for its data",
        extra="netops",
    ),
    # The network's documentation on the same kind of server (winlab/netdocs.py):
    # phpIPAM's release tarball, pinned, on Apache, PHP 8.2 and MariaDB; NetBox
    # as netbox-docker runs it, its three images pulled from Docker Hub by digest,
    # run by Debian's docker.io and docker-compose.
    "phpipam": Pack(
        id="phpipam",
        title="IP address management: phpIPAM 1.8 on Apache, PHP 8.2 and MariaDB",
        image="debian12",
        packages=("apache2", "libapache2-mod-php8.2", "php8.2-cli", "mariadb-server", "mariadb-client",
                  "php8.2-mysql", "php8.2-gmp", "php8.2-curl", "php8.2-gd", "php8.2-xml", "php8.2-mbstring",
                  "php8.2-ldap"),
        typical_mb=110,
        note="phpIPAM 1.8.3 (GPL-3.0) from its GitHub release (SHA-256 pinned), Apache, PHP 8.2 and MariaDB 10.11 "
             "from the Debian archive: its installer at http://<server>/, set up by hand",
        extra="netdocs",
    ),
    "netbox": Pack(
        id="netbox",
        title="Racks, cables and IPs: NetBox 4.7 on Docker (netbox-docker, PostgreSQL, Valkey)",
        image="debian12",
        packages=("docker.io", "docker-compose"),
        typical_mb=460,
        note="NetBox (Apache-2.0) as the netbox-docker 5.1.1 image, PostgreSQL 18 and Valkey 9.1, pulled from "
             "Docker Hub by digest, netbox-docker's compose files (SHA-256 pinned), Docker and Compose from the "
             "Debian archive: docker load, docker-compose up, NetBox on port 8000",
        extra="netdocs",
    ),
    # The security-ops lab's SIEM (winlab/secops.py), installed by hand the
    # way Wazuh's step-by-step guide does it: the manager, the indexer and the
    # dashboard from Wazuh's own signed apt repository, Filebeat (OSS) from the
    # same, every component on one 4.x release; the extra files are the
    # Windows agent MSI of that release (checked against Wazuh's published
    # SHA-512), the certificate tool and Filebeat's Wazuh module and template.
    "wazuh": Pack(
        id="wazuh",
        title="SIEM: Wazuh manager, indexer and dashboard, Filebeat, and the Windows agent",
        image="ubuntu",
        packages=("wazuh-manager", "wazuh-indexer", "wazuh-dashboard", "filebeat"),
        typical_mb=900,
        note="Wazuh (GPLv2), its indexer and dashboard (Apache-2.0, OpenSearch-based) and Filebeat OSS "
             "(Apache-2.0) from packages.wazuh.com, one 4.x release for all of them and the Windows agent: "
             "installed by hand on the SIEM server, agents installed by hand or by GPO on the Windows machines",
        repos=(("https://packages.wazuh.com/4.x/apt", "stable", ("main",)),),
        verify_release=True,
        pins=(("wazuh-manager", "4."), ("wazuh-indexer", "4."), ("wazuh-dashboard", "4.")),
        extra="secops",
        # Wazuh's own minimum for the three parts on one server, with the
        # indexer's heap at 1 GB (lesson wazuh-siem): 4 GB.
        min_mb=4096,
    ),
    # The security-ops lab's incident-response server ir01 (winlab/irtools.py):
    # YARA, the tools to reach a Windows share, jq, and the Python modules
    # sigma-cli needs from the Ubuntu archive; Velociraptor (server binary and
    # the Windows client MSI, from its GitHub release, GitHub's SHA-256) and
    # the sigma-cli wheels (PyPI, pinned by SHA-256) are the extra files.
    "dfir": Pack(
        id="dfir",
        title="Incident response: Velociraptor (server and Windows client), YARA and sigma-cli",
        image="ubuntu",
        packages=("yara", "cifs-utils", "smbclient", "jq", "unzip", "python3-venv", "python3-yaml",
                  "python3-pyparsing", "python3-requests", "python3-packaging", "python3-jinja2", "python3-click",
                  "python3-prettytable", "python3-colorama"),
        typical_mb=120,
        note="Velociraptor (AGPL-3.0, its own program) from Velocidex's GitHub release, checked against GitHub's "
             "SHA-256; YARA (BSD-3-Clause), cifs-utils and smbclient (GPLv3) and jq (MIT) from the Ubuntu archive; "
             "sigma-cli and pySigma (LGPL) as PyPI wheels pinned by SHA-256: the incident-response server, set "
             "up by hand",
        extra="irtools",
        min_mb=1024,
    ),
    # The intrusion-detection lab's second sensor on rt01: Zeek and zeekctl
    # from the Zeek project's own Ubuntu 24.04 repository (Ubuntu's archive
    # has no Zeek), a flat repository on the openSUSE Build Service, its
    # Release file checked. Installed under /opt/zeek.
    "zeek": Pack(
        id="zeek",
        title="Network security monitor: Zeek and zeekctl",
        image="ubuntu",
        packages=("zeek-core", "zeekctl"),
        typical_mb=60,
        note="Zeek and zeekctl (BSD-3-Clause) from the Zeek project's own repository on the openSUSE Build "
             "Service (download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04): conn, dns, http and "
             "ssl logs and notices from the sensor, set up by hand under /opt/zeek",
        repos=(("https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04", FLAT, ()),),
        verify_release=True,
    ),
    # The real helpdesk (winlab/servicedesk.py): osTicket on the same LAMP
    # stack as GLPI, Debian 12, installed by hand; Postfix so the staff's
    # mail reaches it (an alias piped into osTicket's api/pipe.php), cron for
    # its scheduled tasks, unzip for its release zip (the extra file).
    "osticket": Pack(
        id="osticket",
        title="Helpdesk: osTicket 1.18 on Apache, PHP 8.2 and MariaDB, with Postfix",
        image="debian12",
        packages=("apache2", "libapache2-mod-php8.2", "php8.2-cli", "mariadb-server", "mariadb-client",
                  "php8.2-mysql", "php8.2-gd", "php8.2-intl", "php8.2-xml", "php8.2-mbstring", "php8.2-curl",
                  "php8.2-zip", "php-apcu", "postfix", "cron", "unzip"),
        typical_mb=110,
        note="osTicket (GPL-2.0) from its GitHub release (pinned by SHA-256, its LICENSE.txt beside it), "
             "Apache, PHP 8.2, MariaDB 10.11 and Postfix from the Debian archive: the web installer at "
             "http://<server>/osticket/setup/, staff mail piped in by Postfix, set up by hand",
        extra="servicedesk",
        min_mb=1024,
    ),
    # The IT ops server's alerting (winlab/itops.py): the student installs
    # Prometheus, Alertmanager and the node exporter from this stick, writes
    # the scrape targets and rules, and has Alertmanager mail the helpdesk.
    "monitoring": Pack(
        id="monitoring",
        title="Alerting: Prometheus, Alertmanager, the node exporter and NUT's upsmon",
        image="debian12",
        packages=("prometheus", "prometheus-alertmanager", "prometheus-node-exporter", "nut-client"),
        typical_mb=115,
        note="Prometheus, Alertmanager and the node exporter (Apache-2.0) and NUT's client, upsmon "
             "(GPL-2.0-or-later), from the Debian archive: scrape targets, alert rules, the UPS's monitor "
             "and the mail route to the helpdesk set up by hand",
        min_mb=512,
    ),
    # The monitoring-dashboards lab's IT ops server (winlab/dashlab.py):
    # Grafana beside the monitoring pack's Prometheus and Alertmanager, and
    # the blackbox exporter that probes the intranet the way a user does.
    # The student installs both, writes the data source, builds the
    # dashboards and provisions them by hand.
    "dashboards": Pack(
        id="dashboards",
        title="Dashboards: Grafana and the blackbox exporter",
        image="debian12",
        packages=("grafana", "prometheus-blackbox-exporter"),
        typical_mb=140,
        note="Grafana from Grafana Labs' own apt repository (AGPLv3) and the Prometheus blackbox exporter "
             "(Apache-2.0) from the Debian archive: the data source, the dashboards, their provisioning files "
             "and the HTTP probes set up by hand",
        repos=(("https://apt.grafana.com", "stable", ("main",)),),
        min_mb=512,
    ),
    # The helpdesk's remote support (winlab/remotesupport.py): MeshCentral,
    # built by hand on the IT ops server. Debian's archive has neither a
    # Node.js new enough for it (bookworm: 18, MeshCentral wants 20) nor
    # MeshCentral, so the pack is mostly its extra files: Node.js's own
    # release tarball, MeshCentral and its npm dependencies as npm ci reads
    # them offline, and the Mesh Agent releases MeshCentral pins. From the
    # archive only setcap (libcap2-bin), so node may bind port 443 without
    # running as root, and xz to unpack Node.js.
    "meshcentral": Pack(
        id="meshcentral",
        title="Remote support: MeshCentral 1.3 on Node.js 22, with the Mesh Agent for Windows and Linux",
        image="debian12",
        packages=("libcap2-bin", "xz-utils"),
        typical_mb=125,
        note="MeshCentral (Apache-2.0) and its npm dependencies (MIT, ISC, BSD, Apache-2.0) from the npm registry, "
             "each checked against the integrity its lockfile pins; Node.js 22 (MIT) from nodejs.org (SHA-256 "
             "pinned); the Mesh Agent (Apache-2.0) from its GitHub release (the SHA-384 MeshCentral pins): "
             "npm ci offline, a systemd service, the web console on https://<server>/",
        extra="remotesupport",
        min_mb=512,
    ),
    # A Linux machine that answers the switches' LLDP (winlab/lldp.py): the
    # student installs lldpd by hand and the switch's show lldp neighbors
    # lists the machine, and lldpcli on the machine lists the switch.
    "lldpd": Pack(
        id="lldpd",
        title="LLDP: lldpd and lldpcli",
        image="ubuntu",
        packages=("lldpd",),
        typical_mb=1,
        note="lldpd (ISC) from the Ubuntu archive: the machine announces itself to the switch port it is "
             "cabled to (LLDP, and CDP with -c), and lldpcli shows what the switch announces",
    ),
    # The disaster-recovery lab's backup system (winlab/bareos.py), installed
    # by hand on the backup server, the recovery site's server and the Linux
    # clients: the Director with its PostgreSQL catalog, the Storage and File
    # Daemons, bconsole, the volume tools (bls, bextract, bscan: what rebuilds
    # a catalog from volumes alone) and the WebUI on Apache. Bareos's own
    # community packages from its flat apt repository; the extra file is the
    # File Daemon installer for Windows of the same release.
    "bareos": Pack(
        id="bareos",
        title="Backup: Bareos Director, Storage and File Daemons, bconsole, WebUI, PostgreSQL catalog",
        image="ubuntu",
        packages=("bareos-director", "bareos-storage", "bareos-filedaemon", "bareos-bconsole",
                  "bareos-database-postgresql", "bareos-database-tools", "bareos-tools", "bareos-webui",
                  "postgresql"),
        typical_mb=140,
        note="Bareos (AGPL-3.0) from its community repository download.bareos.org (a flat apt repository), "
             "PostgreSQL (PostgreSQL Licence) and Apache with PHP from the Ubuntu archive, and the Bareos File "
             "Daemon for Windows of the same release: set up by hand in /etc/bareos and bconsole",
        repos=(("https://download.bareos.org/current/xUbuntu_24.04", FLAT, ()),),
        verify_release=True,
        extra="bareos",
        min_mb=1536,
    ),
    # The AI data center (winlab/aidc.py, lab ai-datacenter), installed by the
    # roles when the student hands the data center over. hpc: Slurm (the
    # controller on the head node, slurmd on the GPU nodes), MUNGE, the NFS
    # client, chrony and the node exporter, all from the Debian archive.
    "hpc": Pack(
        id="hpc",
        title="GPU cluster: Slurm (slurmctld, slurmd), MUNGE, the NFS client, chrony",
        image="debian12",
        packages=("slurmctld", "slurmd", "slurm-client", "munge", "nfs-common", "chrony",
                  "prometheus-node-exporter"),
        roles=("aidc-head", "aidc-gpu"),
        typical_mb=40,
        note="Slurm (GPL-2.0-or-later), MUNGE (GPL-3.0-or-later), nfs-utils (GPL-2.0), chrony (GPL-2.0) and the "
             "Prometheus node exporter (Apache-2.0) from the Debian archive: the scheduler, its authentication, "
             "shared storage and time for the AI data center",
    ),
    "nfs-server": Pack(
        id="nfs-server",
        title="Shared storage: the NFS server, chrony and the node exporter",
        image="debian12",
        packages=("nfs-kernel-server", "chrony", "prometheus-node-exporter"),
        roles=("aidc-storage",),
        typical_mb=15,
        note="nfs-utils's kernel NFS server (GPL-2.0), chrony (GPL-2.0) and the Prometheus node exporter "
             "(Apache-2.0) from the Debian archive: the datasets, models and checkpoints of the AI data center",
    ),
    # The model server: nginx and what llama.cpp's build needs from the
    # archive; llama.cpp itself (its GitHub release build for Linux x86-64)
    # and the model (Qwen2.5 0.5B Instruct, GGUF, from Hugging Face) are the
    # extra files, each checked against the SHA-256 its publisher gives.
    "inference": Pack(
        id="inference",
        title="Inference: llama.cpp's llama-server, Qwen2.5 0.5B Instruct, nginx",
        image="debian12",
        packages=("nginx", "libgomp1", "libcurl4", "nfs-common", "chrony", "prometheus-node-exporter", "unzip"),
        roles=("aidc-infer",),
        typical_mb=560,
        note="llama.cpp (MIT) from its GitHub release, Qwen2.5 0.5B Instruct (Apache-2.0) from Hugging Face, nginx "
             "(BSD-2-Clause) and the rest from the Debian archive: an OpenAI-compatible model server behind a "
             "gateway with API keys",
        extra="aidc",
        min_mb=1024,
    ),
    "aiops": Pack(
        id="aiops",
        title="Cluster monitoring: Prometheus, Alertmanager, the node exporter and Grafana",
        image="debian12",
        packages=("prometheus", "prometheus-alertmanager", "prometheus-node-exporter", "grafana", "chrony"),
        roles=("aidc-ops",),
        typical_mb=200,
        note="Prometheus, Alertmanager and the node exporter (Apache-2.0) from the Debian archive and Grafana "
             "(AGPLv3) from Grafana Labs' apt repository: the AI data center's targets, alert rules and dashboard",
        repos=(("https://apt.grafana.com", "stable", ("main",)),),
        min_mb=1024,
    ),
    # winlab's own UniFi Network-style controller (winlab/unifi.py,
    # winlab/apos/controller.py), the server that adopts a lab's UniFi
    # access points. Ubiquiti's controller is not used: its licence ties it
    # to Ubiquiti hardware. The stick carries winlab's unifi .deb (built
    # when it is plugged) beside what it needs from the Ubuntu archive, so
    # the student installs it the way the real one goes in: apt-get install
    # unifi.
    "unifi": Pack(
        id="unifi",
        title="UniFi Network-style Wi-Fi controller (winlab's own), installed with apt",
        image="ubuntu",
        packages=("python3", "openssl", "adduser"),
        typical_mb=1,
        note="winlab's own controller in a Debian package (unifi), with Python 3 and OpenSSL from the "
             "Ubuntu archive: apt-get install unifi, then https://<server>:8443 adopts the UniFi access points",
        extra="unifi",
        min_mb=1024,
    ),
    # OpenWISP (winlab/openwisp.py), the open-source controller of the
    # lab's OpenWrt access points, the way its project publishes it:
    # docker-openwisp's Compose file and images (all pinned), Docker and
    # Compose from the Ubuntu archive; installed and started by hand.
    "openwisp": Pack(
        id="openwisp",
        title="Wi-Fi controller: OpenWISP on Docker Compose (docker-openwisp)",
        image="ubuntu",
        packages=("docker.io", "docker-compose-v2"),
        typical_mb=2200,
        note="OpenWISP (GPL-3.0) as docker-openwisp's images on Docker Hub (pinned by digest) with its "
             "docker-compose.yml and .env (pinned by SHA-256), PostgreSQL/PostGIS, InfluxDB and Redis images, "
             "Docker and Compose from the Ubuntu archive: set up by hand, then the OpenWrt access points' "
             "openwisp-config agent registers them",
        extra="openwisp",
        # Its Django workers, Celery, PostgreSQL and InfluxDB together.
        min_mb=4096,
    ),
    # The server the router's and switches' configurations are backed up to
    # (winlab/tftpcopy.py: copy running-config tftp:), set up by hand:
    # tftpd-hpa with the tftp-hpa client to test it from the machine itself.
    "tftpd": Pack(
        id="tftpd",
        title="TFTP server: tftpd-hpa and the tftp client",
        image="ubuntu",
        packages=("tftpd-hpa", "tftp-hpa"),
        typical_mb=1,
        note="tftp-hpa (BSD-style licence) from the Ubuntu archive: a TFTP server for device configurations, "
             "set up by hand in /etc/default/tftpd-hpa (--create, a directory the tftp user may write)",
    ),
    # The TACACS+ server the router's and switches' logins, commands and
    # accounting go to (winlab/aaa.py, lesson aaa-tacacs-plus): tac_plus-ng,
    # which no distribution packages, built from source by the student. The
    # stick carries the compiler and the libraries from the Ubuntu archive
    # and, as the extra file, the source of one pinned commit, checked
    # against the tree GitHub says that commit holds (winlab/tacacs.py).
    "tacacs": Pack(
        id="tacacs",
        title="TACACS+ server: tac_plus-ng's source and the tools to build it",
        image="ubuntu",
        packages=("build-essential", "libpcre2-dev", "libssl-dev", "libc-ares-dev"),
        typical_mb=95,
        note="tac_plus-ng (Event-Driven-Servers, BSD-style licence) as the source of a pinned commit from GitHub, "
             "checked against that commit's tree; gcc, make and the PCRE2, OpenSSL and c-ares headers "
             "(GPL, LGPL, Apache-2.0 and MIT) from the Ubuntu archive: built and set up by hand",
        extra="tacacs",
    ),
    # The FTP server the router's and switches' configurations are copied to
    # with copy running-config ftp: (winlab/ftpscp.py), set up by hand;
    # SCP needs nothing more than the OpenSSH server Ubuntu already runs.
    "ftpd": Pack(
        id="ftpd",
        title="FTP server: vsftpd and the ftp client",
        image="ubuntu",
        packages=("vsftpd", "ftp"),
        typical_mb=1,
        note="vsftpd (GPLv2) and the tnftp client (BSD) from the Ubuntu archive: an FTP server for device "
             "configurations, set up by hand in /etc/vsftpd.conf (local users, write_enable)",
    ),
    # The network team's measuring tools on a Debian 12 server (lessons
    # net-tools-iperf-mtr, nmap-inventory-check, tcp-handshake-capture):
    # all from the Debian archive, installed by hand. Alpine machines take
    # the same tools from the lab's package volume (apk add).
    "nettools": Pack(
        id="nettools",
        title="Network tools: iperf3, mtr, nmap, tshark and termshark",
        image="debian12",
        packages=("iperf3", "mtr-tiny", "nmap", "tshark", "termshark", "tcpdump"),
        typical_mb=60,
        note="iperf3 (BSD-3-Clause), mtr (GPLv2), nmap (Nmap Public Source License), tshark (GPLv2), "
             "termshark (MIT) and tcpdump (BSD) from the Debian archive: throughput, per-hop latency and loss, "
             "host and port discovery, and reading packets on a server",
    ),
    # The Linux administration lessons on linux-by-hand's practice server
    # (winlab/linuxadmin.py): the NFS client and autofs for rocky01's export,
    # the ACL tools, LVM and XFS for the empty second disk. Installed by hand.
    "sysadmin": Pack(
        id="sysadmin",
        title="Linux administration: NFS client, autofs, ACL tools, LVM, XFS and mdadm",
        image="ubuntu",
        packages=("nfs-common", "autofs", "acl", "lvm2", "xfsprogs", "mdadm"),
        typical_mb=7,
        note="nfs-common (GPLv2), autofs (GPLv2), acl (GPLv2+ and LGPLv2.1+), lvm2 (GPLv2 and LGPLv2.1), "
             "xfsprogs (GPLv2 and LGPLv2.1) and mdadm (GPLv2) from the Ubuntu archive: what the Linux "
             "administration and RAID lessons install by hand on the practice server",
    ),
    # The second half of the Linux administration lessons on lx01 (module
    # linux, orders 300 to 349, winlab/linuxplus.py): rootless Podman with
    # its user-namespace and network helpers (the images come on the images
    # stick), Flatpak with a static BusyBox to build a local runtime from,
    # TuneD, dpkg-dev to build an apt repository, the SSSD LDAP client, zstd,
    # and the kernel's extra modules for the image's own kernel (dummy and
    # the module lessons). Installed by hand.
    "sysadmin-plus": Pack(
        id="sysadmin-plus",
        title="Linux administration, part two: Podman, Flatpak, TuneD, dpkg-dev, the SSSD LDAP client and the kernel's extra modules",
        image="ubuntu",
        packages=("podman", "uidmap", "slirp4netns", "passt", "fuse-overlayfs", "catatonit",
                  "flatpak", "busybox-static", "tuned", "dpkg-dev", "sssd-ldap", "libnss-sss",
                  "libpam-sss", "ldap-utils", "zstd"),
        typical_mb=180,
        note="Podman, uidmap, slirp4netns, passt, fuse-overlayfs and catatonit (Apache-2.0, GPLv2 and others), "
             "Flatpak (LGPLv2.1+), BusyBox (GPLv2), TuneD (GPLv2+), dpkg-dev (GPLv2+), SSSD (GPLv3+), the "
             "OpenLDAP clients (OpenLDAP Public License), zstd (BSD) and the kernel's linux-modules-extra for "
             "the image's own kernel (GPLv2) from the Ubuntu archive: installed by hand on the practice server",
        kernel_modules=("linux-modules-extra",),
    ),
    # The Linux network services and disk lessons on lx02 (LPIC-2 style,
    # winlab/linuxplus.py): an OpenLDAP server, Kea's DHCPv4 server for the
    # branch switch, Apache with mod_ssl, mdadm for software RAID and the
    # quota tools, with the kernel's extra modules (the quota format
    # modules). Installed and configured by hand.
    "lpic2": Pack(
        id="lpic2",
        title="Linux network services: OpenLDAP, Kea DHCP, Apache with TLS, mdadm RAID and disk quotas",
        image="ubuntu",
        packages=("slapd", "ldap-utils", "kea-dhcp4-server", "kea-admin", "apache2", "mdadm", "quota"),
        typical_mb=150,
        note="OpenLDAP's slapd and clients (OpenLDAP Public License), ISC Kea (MPL-2.0), Apache httpd "
             "(Apache-2.0), mdadm (GPLv2+), the quota tools (GPLv2+) and the kernel's linux-modules-extra for "
             "the image's own kernel (GPLv2) from the Ubuntu archive: installed and configured by hand on the "
             "services server",
        kernel_modules=("linux-modules-extra",),
    ),
    # The devops-pipeline lab (winlab/devops.py): the Git forge, the CI
    # runner and OpenTofu, each its own binary fetched from the project's
    # release beside what it needs from the Ubuntu archive (the extra files);
    # installed, configured and started by hand.
    "forgejo": Pack(
        id="forgejo",
        title="Git server: Forgejo (repositories, pull requests, Actions, package registry)",
        image="ubuntu",
        packages=("git",),
        typical_mb=105,
        note="Forgejo (GPL-3.0-or-later) from its release on Codeberg, checked against its published SHA-256, "
             "and git (GPLv2) from the Ubuntu archive: the lab's own Git forge, CI server and container registry",
        extra="devops",
        min_mb=1024,
    ),
    "forgejo-runner": Pack(
        id="forgejo-runner",
        title="CI runner: Forgejo Runner (host executor) and git",
        image="ubuntu",
        packages=("git",),
        typical_mb=25,
        note="Forgejo Runner (GPL-3.0-or-later; MIT before 7.0) from its release on code.forgejo.org, checked "
             "against its published SHA-256, and git (GPLv2) from the Ubuntu archive: runs the workflows' steps "
             "on the build machine",
        extra="devops",
    ),
    "opentofu": Pack(
        id="opentofu",
        title="Infrastructure as code: OpenTofu with the docker and local providers",
        image="ubuntu",
        packages=("unzip",),
        typical_mb=60,
        note="OpenTofu (MPL-2.0) from its GitHub release and the kreuzwerker/docker and hashicorp/local providers "
             "(MPL-2.0) from the OpenTofu registry, each checked against its published SHA-256, for a filesystem "
             "mirror; unzip from the Ubuntu archive",
        extra="devops",
    ),
    # The aws-cloud lab's admin box: OpenTofu again, with the hashicorp/aws
    # provider for the lab's own AWS (moto); a pack of its own because the
    # provider is about 175 MB.
    "opentofu-aws": Pack(
        id="opentofu-aws",
        title="Infrastructure as code for the lab's AWS: OpenTofu with the hashicorp/aws provider",
        image="ubuntu",
        packages=("unzip",),
        typical_mb=210,
        note="OpenTofu (MPL-2.0) from its GitHub release and the hashicorp/aws provider (MPL-2.0) from the "
             "OpenTofu registry, each checked against its published SHA-256, for a filesystem mirror; unzip "
             "from the Ubuntu archive",
        extra="devops",
        # tofu plan with the aws provider peaks near 900 MB (its schema alone)
        min_mb=1536,
    ),
    # A Linux laptop on the real air (winlab/vwifi.py, role wifi-laptop):
    # NetworkManager and wpa_supplicant as on any Ubuntu laptop, iw and
    # tcpdump to look at the radio, the kernel's extra modules for its
    # software radio (mac80211_hwsim is not in the cloud image's own module
    # set), and winlab's vwifi build beside them (the programs, licence and
    # complete source), which links the radio to the router's vwifi-server.
    "wifi": Pack(
        id="wifi",
        title="Laptop Wi-Fi: NetworkManager, wpa_supplicant, iw, tcpdump, the kernel's software radio and vwifi",
        image="ubuntu",
        packages=("network-manager", "wpasupplicant", "iw", "tcpdump", "wireless-regdb"),
        roles=("wifi-laptop",),
        typical_mb=140,
        note="NetworkManager (GPLv2+), wpa_supplicant (BSD-3-Clause), iw (ISC), tcpdump (BSD) and the kernel's "
             "linux-modules-extra for the image's own kernel (GPLv2) from the Ubuntu archive, and vwifi (LGPL-3.0, "
             "winlab's build with its complete source) from winlab's release: a laptop that really scans, "
             "associates and runs WPA2's handshake with the lab's OpenWrt access point",
        extra="vwifi",
        kernel_modules=("linux-modules-extra",),
    ),
    # The company phone's MDM (winlab/hmdm.py, the mobile-devices lab):
    # Headwind MDM Community Edition built by hand on the Ubuntu server. The
    # archive has the Java it runs on, its database, aapt and adb; Ubuntu
    # 24.04 has no Tomcat 9 (tomcat10 is Jakarta EE), so Tomcat 9 is
    # Apache's own tarball, and the panel, the launcher and the app it pushes
    # are the extra files.
    "hmdm": Pack(
        id="hmdm",
        title="Mobile device management: Headwind MDM on Tomcat 9, PostgreSQL and OpenJDK 11, with adb",
        image="ubuntu",
        packages=("openjdk-11-jre-headless", "postgresql", "aapt", "adb"),
        typical_mb=200,
        note="Headwind MDM Community Edition (Apache-2.0): its web panel (.war) and launcher (.apk) from "
             "h-mdm.com/files (SHA-256 recorded: it publishes none) with both projects' LICENSE files; Apache "
             "Tomcat 9 (Apache-2.0) from archive.apache.org (Apache's SHA-512); Fossify Calculator (GPL-3.0) "
             "from its GitHub release (SHA-256 pinned) for the MDM to push; OpenJDK 11 (GPL-2.0 with the "
             "Classpath exception), PostgreSQL 16 (PostgreSQL licence), aapt and adb (Apache-2.0) from the "
             "Ubuntu archive: built by hand, the phone enrolled over adb",
        extra="hmdm",
        # Tomcat's JVM with the panel, and PostgreSQL beside it.
        min_mb=2048,
    ),
}

STICK_LABEL = "WLPACK"
MOUNT = "/mnt/winlab-pack"


@dataclass
class Deb:
    name: str
    version: str = ""
    filename: str = ""
    sha256: str = ""
    size: int = 0
    depends: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    base: str = ""             # the archive root its Filename is relative to
    stanza: str = ""
    priority: str = ""

    @property
    def basename(self) -> str:
        return self.filename.rsplit("/", 1)[-1]


# ------------------------------------------------------------ dpkg versions
def _order(c: str) -> int:
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """dpkg's verrevcmp: alternating non-digit and digit runs, '~' lowest."""
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoch, up, rev


def compare_versions(a: str, b: str) -> int:
    """Negative, zero or positive as dpkg --compare-versions would order a and b."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return ea - eb
    c = _verrevcmp(ua, ub)
    if c:
        return c
    return _verrevcmp(ra, rb)


# ----------------------------------------------------------------- the index
def _dep_name(dep: str) -> str:
    """'libc6 (>= 2.34)' -> 'libc6'; 'python3:any' -> 'python3'."""
    name = dep.strip().split("(", 1)[0].split("[", 1)[0].strip()
    return name.split(":", 1)[0]


def parse_index(text: str, base: str = "") -> dict[str, Deb]:
    """A Packages file -> {name: newest Deb}."""
    out: dict[str, Deb] = {}
    for stanza in text.split("\n\n"):
        if not stanza.strip():
            continue
        fields: dict[str, str] = {}
        key = ""
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t") and key:
                fields[key] += "\n" + line.strip()
            elif ":" in line:
                key, _, val = line.partition(":")
                key = key.strip()
                fields[key] = val.strip()
        name = fields.get("Package", "")
        if not name:
            continue
        deps = []
        for k in ("Pre-Depends", "Depends"):
            if fields.get(k):
                deps += [d.strip() for d in fields[k].replace("\n", " ").split(",") if d.strip()]
        provides = [_dep_name(p) for p in fields.get("Provides", "").split(",") if p.strip()]
        deb = Deb(name=name, version=fields.get("Version", ""), filename=fields.get("Filename", ""),
                  sha256=fields.get("SHA256", "").lower(), size=int(fields.get("Size", "0") or 0),
                  depends=deps, provides=provides, base=base, stanza=stanza.strip(),
                  priority=fields.get("Priority", "").lower())
        have = out.get(name)
        if have is None or compare_versions(deb.version, have.version) > 0:
            out[name] = deb
    return out


def index_urls(app, extra: tuple[tuple[str, str, tuple[str, ...]], ...] = ()) -> list[tuple[str, str]]:
    """(archive root, Packages.gz url) for the suite, its updates and
    security, then any extra repositories a pack names."""
    out = []
    for suite, root in ((app.series, app.archive), (f"{app.series}-updates", app.archive),
                        (f"{app.series}-security", app.security)):
        for comp in app.components:
            out.append((root, f"{root}/dists/{suite}/{comp}/binary-amd64/Packages.gz"))
    for root, suite, comps in extra:
        root = root.rstrip("/")
        if suite == FLAT:
            # A flat repository (deb <root> /): its Packages and Release sit
            # in the root itself, as Bareos publishes its community builds.
            out.append((root, f"{root}/Packages.gz"))
            continue
        for comp in comps:
            out.append((root, f"{root}/dists/{suite}/{comp}/binary-amd64/Packages.gz"))
    return out


def split_index_url(url: str) -> tuple[str, str]:
    """(the folder its Release file is in, the index's path under it):
    <root>/dists/<suite> and main/binary-amd64/Packages.gz, or for a flat
    repository <root> and Packages.gz."""
    if "/dists/" in url:
        root, rest = url.split("/dists/", 1)
        suite, rel = rest.split("/", 1)
        return f"{root}/dists/{suite}", rel
    base, _, rel = url.rpartition("/")
    return base, rel


def _cache_name(root: str, url: str) -> str:
    """The cache file for an index: the suite path, prefixed with the host
    for a repository that is not the distribution's own."""
    host = root.split("://", 1)[-1].split("/", 1)[0]
    if "/dists/" not in url:
        return url.split("://", 1)[-1].replace("/", "_")
    tail = url.split("/dists/", 1)[1].replace("/", "_")
    return tail if host.endswith("ubuntu.com") else f"{host}_{tail}"


XZ_MAGIC = b"\xfd7zXZ\x00"


def _fetch_index(get, url: str) -> bytes:
    """An index, gzip, plain or xz: a repository that publishes no
    Packages.gz answers for Packages, or for Packages.xz (the only form some
    Debian suites keep)."""
    try:
        return get(url)
    except BootstrapError:
        if not url.endswith(".gz"):
            raise
    try:
        return get(url[:-3])
    except BootstrapError:
        return get(url[:-3] + ".xz")


def _unpack_index(raw: bytes) -> str:
    """An index's text, whatever it was compressed with (told by its magic)."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    elif raw[:6] == XZ_MAGIC:
        import lzma
        raw = lzma.decompress(raw)
    return raw.decode("utf-8", "replace")


def release_hashes(text: str) -> dict[str, str]:
    """A Release file's SHA256 section: {path under the suite: sha256}."""
    out: dict[str, str] = {}
    inside = False
    for line in text.splitlines():
        if line[:1] and not line[:1].isspace():
            inside = line.strip() == "SHA256:"
            continue
        parts = line.split()
        if inside and len(parts) == 3 and len(parts[0]) == 64:
            out[parts[2]] = parts[0].lower()
    return out


def check_release(release: str, url: str, raw: bytes) -> None:
    """The index fetched from url is the one its suite's Release lists: the
    SHA-256 of the file as fetched, or of its text, matches the entry for
    <component>/binary-amd64/Packages (plain, .gz or .xz)."""
    import hashlib
    hashes = release_hashes(release)
    base, rel = split_index_url(url)                           # main/binary-amd64/Packages.gz
    if not hashes:
        raise PackError(f"the Release file for {base} lists no SHA256 hashes")
    stem = rel[:-3] if rel.endswith((".gz", ".xz")) else rel
    want = {hashes[k] for k in (stem, stem + ".gz", stem + ".xz") if k in hashes}
    if not want:
        raise PackError(f"{stem} is not listed in its suite's Release file ({url})")
    have = {hashlib.sha256(raw).hexdigest(), hashlib.sha256(_unpack_index(raw).encode("utf-8")).hexdigest()}
    if not want & have:
        raise PackError(f"the package index {url} does not match its suite's Release file: refused")


def _cache_dir() -> Path:
    return paths.RUNTIME / "cache" / "packs"


def load_index(app, refresh: bool = False, get=_get, progress=None,
               extra: tuple[tuple[str, str, tuple[str, ...]], ...] = (),
               verify_release: bool = False) -> dict[str, Deb]:
    """The merged index for an appliance's suites (and a pack's extra
    repositories), newest version per package, cached on this PC for a day.
    With verify_release each index fetched is checked against its suite's
    Release file before it is kept."""
    say = progress or (lambda _m: None)
    cache = _cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    merged: dict[str, Deb] = {}
    for root, url in index_urls(app, extra):
        name = _cache_name(root, url)
        f = cache / name
        if refresh or not f.exists() or time.time() - f.stat().st_mtime > 86400:
            base, rel = split_index_url(url)
            shown = url.split("://", 1)[-1]
            say("fetching the package index " + (" ".join(shown.split("/dists/", 1)) if "/dists/" in shown
                                                 else f"{base.split('://', 1)[-1]} {rel}"))
            try:
                raw = _fetch_index(get, url)
                if verify_release:
                    release = get(f"{base}/Release")
                    check_release(release.decode("utf-8", "replace"), url, raw)
                f.write_bytes(raw)
            except BootstrapError as exc:
                raise PackError(str(exc)) from exc
        try:
            raw = f.read_bytes()
            text = _unpack_index(raw)
        except (OSError, EOFError, ValueError) as exc:
            f.unlink(missing_ok=True)
            raise PackError(f"the package index {name} is unreadable ({exc}); run the fetch again") from exc
        for deb_name, deb in parse_index(text, root).items():
            have = merged.get(deb_name)
            if have is None or compare_versions(deb.version, have.version) > 0:
                merged[deb_name] = deb
    return merged


# --------------------------------------------------------------- resolution
def resolve(index: dict[str, Deb], roots: list[str] | tuple[str, ...],
            installed: set[str] | None = None) -> list[Deb]:
    """The packages to fetch so that `roots` install on a machine that already
    has `installed`: dependencies and pre-dependencies, first satisfiable
    alternative, virtual packages through Provides. Raises when a root or a
    needed dependency is nowhere."""
    installed = set(installed or ())
    provided: dict[str, list[str]] = {}
    for deb in index.values():
        for p in deb.provides:
            provided.setdefault(p, []).append(deb.name)
    out: dict[str, Deb] = {}
    missing: list[str] = []
    queue = [(r, "") for r in roots]

    def satisfied(name: str) -> bool:
        if name in installed or name in out:
            return True
        return any(p in installed for p in provided.get(name, []))

    def pick(name: str) -> Deb | None:
        if name in index:
            return index[name]
        for p in provided.get(name, []):
            return index[p]
        return None

    while queue:
        dep, wanted_by = queue.pop(0)
        alts = [_dep_name(a) for a in dep.split("|")]
        if any(satisfied(a) for a in alts):
            continue
        chosen = next((pick(a) for a in alts if pick(a) is not None), None)
        if chosen is None:
            missing.append(f"{dep}" + (f" (needed by {wanted_by})" if wanted_by else ""))
            continue
        if chosen.name in out:
            continue
        out[chosen.name] = chosen
        for d in chosen.depends:
            queue.append((d, chosen.name))
    if missing:
        raise PackError("not in the archive index: " + "; ".join(missing[:8]))
    return list(out.values())


# -------------------------------------------------------------------- store
def pack_dir(pack_id: str) -> Path:
    return paths.RUNTIME / "packs" / pack_id


def manifest_path(pack_id: str) -> Path:
    return pack_dir(pack_id) / "pack.json"


def manifest(pack_id: str) -> dict:
    p = manifest_path(pack_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _extra(pack: Pack):
    import importlib
    return importlib.import_module(f"{__package__}.{pack.extra}")


def ready(pack_id: str) -> bool:
    man = manifest(pack_id)
    # A pack whose few .debs the image already has is all extra files
    # (meshcentral: Node.js and MeshCentral beside libcap2-bin).
    if not man.get("packages") and not man.get("extra"):
        return False
    d = pack_dir(pack_id)
    pack = PACKS.get(pack_id)
    if pack is not None and pack.extra and not _extra(pack).extra_ready(d, man):
        return False
    # Each .deb was verified against the index's SHA-256 when it arrived
    # (bootstrap._download_to writes it whole or not at all).
    return all((d / p["file"]).exists() and (d / p["file"]).stat().st_size > 0
               for p in man["packages"]) and (d / "Packages").exists()


def get_or_raise(pack_id: str) -> Pack:
    pack = PACKS.get(pack_id)
    if pack is None:
        raise PackError(f"no pack '{pack_id}'; known: {', '.join(PACKS)}")
    return pack


def fetch(pack_id: str, progress=None, refresh: bool = False, get=_get,
          download=_download_to) -> dict:
    """Resolves and fetches the pack for its appliance image, which must be
    fetched first (its manifest says what the image already has)."""
    from . import appliances
    pack = get_or_raise(pack_id)
    say = progress or (lambda _m: None)
    app = appliances.get_or_raise(pack.image)
    if not appliances.ready(pack.image):
        raise PackError(f"fetch the {app.short} image first (winlab images fetch {pack.image}); "
                        f"the pack is resolved against what that image already has")
    installed = appliances.installed_packages(pack.image)
    index = load_index(app, refresh=refresh, get=get, progress=say, extra=pack.repos,
                       verify_release=pack.verify_release)
    for stanza, base in pack.release_debs:
        index.update(parse_index(stanza, base.rstrip("/")))
    if not installed:
        # No package list for the image: count only what every Debian system
        # has (Priority: required) and carry the rest; apt skips what is there.
        installed = {d.name for d in index.values() if d.priority == "required"}
    roots = list(pack.packages) + kernel_roots(pack, installed, index)
    closure = resolve(index, roots, installed)
    for name, prefix in pack.pins:
        got = next((d for d in closure if d.name == name), None) or index.get(name)
        if got is None or not got.version.split(":", 1)[-1].startswith(prefix):
            raise PackError(f"{pack_id} is pinned to {name} {prefix}x; the repository offers "
                            f"{got.version if got else 'none'}")
    closure.sort(key=lambda d: d.name)
    total = sum(d.size for d in closure)
    say(f"{pack_id}: {len(closure)} packages to fetch ({total >> 20} MB); "
        f"{len(installed)} already in the image")
    d = pack_dir(pack_id)
    d.mkdir(parents=True, exist_ok=True)
    rows = []
    for i, deb in enumerate(closure, 1):
        dest = d / deb.basename
        say(f"{i}/{len(closure)} {deb.name} {deb.version}")
        try:
            download(f"{deb.base}/{deb.filename.removeprefix('./')}", dest, expect_sha=deb.sha256, label=deb.basename)
        except BootstrapError as exc:
            raise PackError(str(exc)) from exc
        rows.append({"name": deb.name, "version": deb.version, "file": deb.basename,
                     "sha256": deb.sha256, "size": deb.size})
    (d / "Packages").write_text(render_packages(closure), encoding="utf-8")
    man = {"id": pack_id, "image": pack.image, "title": pack.title,
           "fetched": time.strftime("%Y-%m-%d"), "packages": rows, "size": total,
           "install": roots}
    extra_files: list[str] = []
    if pack.extra:
        mod = _extra(pack)
        try:
            man["extra"] = mod.fetch_extra(pack, d, closure, get, download, say)
        except getattr(mod, "ExtraError", None) or mod.VoipError as exc:
            raise PackError(str(exc)) from exc
        extra_files = list(man["extra"].get("files", []))
        man["install"] += [p for p in man["extra"].get("install", []) if p not in man["install"]]
    manifest_path(pack_id).write_text(json.dumps(man, indent=1), encoding="utf-8")
    # Anything from an earlier fetch that is no longer in the closure.
    keep = {r["file"] for r in rows} | {"Packages", "pack.json"} | set(extra_files)
    for f in d.iterdir():
        if f.name not in keep:
            f.unlink()
    say(f"{pack_id} ready: {d}")
    return man


def kernel_release(installed: set[str]) -> str:
    """The image's kernel release from its package list ("6.8.0-48-generic"
    from linux-image-6.8.0-48-generic); the newest when it carries several."""
    import re
    found = [m.group(1) for name in installed
             if (m := re.fullmatch(r"linux-image-(\d+\.\d+\.\d+-\d+-[a-z0-9]+)", name))]
    return max(found, key=lambda r: [int(x) for x in re.findall(r"\d+", r)]) if found else ""


def kernel_roots(pack: Pack, installed: set[str], index: dict) -> list[str]:
    """The pack's kernel module packages for the image's own kernel. Raises
    when the image's kernel is not known or the archive no longer has its
    modules (a newer image fetch brings both in step again)."""
    if not pack.kernel_modules:
        return []
    rel = kernel_release(installed)
    if not rel:
        raise PackError(f"{pack.id}: the {pack.image} image's package list names no kernel, so its "
                        f"{', '.join(pack.kernel_modules)} cannot be matched to it")
    out = [f"{m}-{rel}" for m in pack.kernel_modules]
    gone = [n for n in out if n not in index]
    if gone:
        raise PackError(f"{pack.id}: the archive no longer has {', '.join(gone)} for the image's kernel {rel}: "
                        f"fetch the {pack.image} image again (its newer kernel's modules are in the archive), "
                        f"then this pack")
    return out


def render_packages(debs: list[Deb]) -> str:
    """The Packages file of the flat repository on the stick: each stanza as
    the archive gave it, its Filename pointing at the file beside it."""
    out = []
    for deb in debs:
        lines = []
        for line in deb.stanza.splitlines():
            if line.startswith("Filename:"):
                line = f"Filename: ./{deb.basename}"
            lines.append(line)
        out.append("\n".join(lines))
    return "\n\n".join(out) + "\n"


def pack_files(pack_id: str) -> dict[str, bytes]:
    """What goes on the stick: the .debs, the Packages file and a note."""
    if not ready(pack_id):
        pack = get_or_raise(pack_id)
        raise PackError(f"pack '{pack_id}' is not on this PC yet: winlab packs fetch {pack_id} "
                        f"(it needs the {pack.image} image fetched first)")
    d = pack_dir(pack_id)
    man = manifest(pack_id)
    files = {f.name: f.read_bytes() for f in d.iterdir() if f.name != "pack.json"}
    files.update(own_tools(pack_id))   # winlab's own programs beside the packages (its own code, not fetched)
    if pack_id == "unifi":               # winlab's controller as a .deb, listed in the stick's index
        from . import unifi
        files.update(unifi.stick_files(files.get("Packages", b"").decode("utf-8", "replace")))
    files["README.txt"] = (
        f"winlab pack '{pack_id}': {man.get('title', '')}\r\n"
        f"A flat apt repository fetched from the distribution's archive on {man.get('fetched', '?')}.\r\n"
        f"Install from it offline:\r\n"
        f"  mount LABEL={STICK_LABEL} {MOUNT}\r\n"
        f"  echo 'deb [trusted=yes] file:{MOUNT} ./' > /etc/apt/sources.list.d/winlab-pack.list\r\n"
        f"  apt-get -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/winlab-pack.list "
        f"-o Dir::Etc::sourceparts=- update\r\n"
        f"  apt-get install -y {' '.join(man.get('install', []))}\r\n"
    ).encode()
    return files


# Winlab's own programs that go on a pack's stick beside the fetched packages:
# the HSRP and GLBP speakers for the routers that install FRRouting
# (winlab/hsrpd.py, winlab/glbpd.py).
OWN_TOOLS = {"frr": "hsrp", "tftpd": "images"}


def own_tools(pack_id: str) -> dict[str, bytes]:
    if OWN_TOOLS.get(pack_id) == "images":
        from . import iosimage   # winlab's stand-in device images and their MD5 list
        return iosimage.stick_files()
    if OWN_TOOLS.get(pack_id) != "hsrp":
        return {}
    from . import hsrpd
    src = Path(hsrpd.__file__).read_bytes()
    unit = ("[Unit]\nDescription=winlab-hsrpd, winlab's HSRP speaker\nAfter=network-online.target\n\n"
            "[Service]\nExecStart=/usr/bin/python3 /usr/local/sbin/winlab-hsrpd -c /etc/winlab-hsrp.conf\n"
            "ExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n")
    note = ("winlab-hsrpd: winlab's own HSRP speaker (HSRP versions 1 and 2), MIT like the rest of winlab.\r\n"
            "No open-source router speaks HSRP, so winlab wrote one; on real gear both ends are Cisco routers.\r\n"
            "Install it from this stick (it needs only Python 3, which Ubuntu has):\r\n"
            "  sudo install -m 755 /mnt/winlab-pack/winlab-hsrpd /usr/local/sbin/\r\n"
            "  sudo install -m 644 /mnt/winlab-pack/winlab-hsrpd.service /etc/systemd/system/\r\n"
            "Write /etc/winlab-hsrp.conf in IOS's own lines under the Linux interface, for example\r\n"
            "  interface eth1\r\n   standby version 2\r\n   standby 1 ip 10.80.0.1\r\n"
            "then: sudo winlab-hsrpd check, sudo systemctl enable --now winlab-hsrpd,\r\n"
            "sudo winlab-hsrpd show brief. After a change: sudo systemctl reload winlab-hsrpd.\r\n")
    from . import glbpd
    gunit = ("[Unit]\nDescription=winlab-glbpd, winlab's GLBP speaker\nAfter=network-online.target\n\n"
             "[Service]\nExecStart=/usr/bin/python3 /usr/local/sbin/winlab-glbpd -c /etc/winlab-glbp.conf\n"
             "ExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n")
    gnote = ("winlab-glbpd: winlab's own GLBP speaker, MIT like the rest of winlab.\r\n"
             "No open-source router speaks GLBP, so winlab wrote one; on real gear the members are Cisco routers.\r\n"
             "Install it from this stick (it needs only Python 3, which Ubuntu has):\r\n"
             "  sudo install -m 755 /mnt/winlab-pack/winlab-glbpd /usr/local/sbin/\r\n"
             "  sudo install -m 644 /mnt/winlab-pack/winlab-glbpd.service /etc/systemd/system/\r\n"
             "Write /etc/winlab-glbp.conf in IOS's own lines under the Linux interface, for example\r\n"
             "  interface eth1\r\n   glbp 1 ip 10.80.0.1\r\n"
             "then: sudo winlab-glbpd check, sudo systemctl enable --now winlab-glbpd,\r\n"
             "sudo winlab-glbpd show brief. After a change: sudo systemctl reload winlab-glbpd.\r\n")
    return {"winlab-hsrpd": src, "winlab-hsrpd.service": unit.encode(), "HSRP.txt": note.encode(),
            "winlab-glbpd": Path(glbpd.__file__).read_bytes(), "winlab-glbpd.service": gunit.encode(),
            "GLBP.txt": gnote.encode()}


def status(pack_id: str) -> dict:
    pack = get_or_raise(pack_id)
    man = manifest(pack_id)
    return {"id": pack.id, "title": pack.title, "image": pack.image, "roles": list(pack.roles),
            "install": list(pack.packages), "ready": ready(pack_id),
            "fetched": man.get("fetched", ""), "count": len(man.get("packages", [])),
            "size_mb": round(man.get("size", 0) / 1048576, 1), "typical_mb": pack.typical_mb,
            "note": pack.note, "repos": [r[0] for r in pack.repos] + [b for _, b in pack.release_debs]}


def render_status() -> str:
    lines = [f"pack store: {paths.RUNTIME / 'packs'}", ""]
    for pack_id in PACKS:
        st = status(pack_id)
        state = (f"ready ({st['count']} packages, {st['size_mb']} MB, fetched {st['fetched']})"
                 if st["ready"] else f"not fetched (about {st['typical_mb']} MB)")
        lines.append(f"  {pack_id:<12} {state}")
        who = f"role(s) {', '.join(st['roles'])}" if st["roles"] else "installed by hand inside the machine"
        lines.append(f"  {'':<12} {st['title']}; for the {st['image']} image, {who}")
        lines.append(f"  {'':<12} installs {', '.join(st['install'])}")
        if st["repos"]:
            lines.append(f"  {'':<12} also from {', '.join(st['repos'])}")
        if not st["ready"]:
            lines.append(f"  {'':<12} then:    winlab packs fetch {pack_id}")
        lines.append("")
    return "\n".join(lines)
