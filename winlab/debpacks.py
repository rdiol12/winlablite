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
        packages=("roundcube", "roundcube-sqlite3", "apache2", "libapache2-mod-php"),
        typical_mb=16,
        note="Roundcube (GPLv3+), Apache (Apache-2.0) and PHP (PHP-3.01) from the Ubuntu archive: "
             "optional webmail for the mail server, at http://<server>/roundcube",
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
                  "nodejs", "sox", "mpg123", "lame", "sqlite3", "uuid", "unixodbc", "odbc-mariadb",
                  "sudo", "cron", "incron", "at", "curl", "wget", "gnupg", "net-tools",
                  "asterisk22", "asterisk22-core", "asterisk22-addons", "asterisk22-addons-core",
                  "asterisk22-addons-mysql", "asterisk22-curl", "asterisk22-odbc", "asterisk22-sqlite3",
                  "asterisk22-voicemail", "asterisk22.0-freepbx-asterisk-modules"),
        roles=("pbx",),
        typical_mb=420,
        note="FreePBX 17 (framework GPLv2+, core GPLv3+, open-source modules only) from "
             "mirror.freepbx.org, Asterisk 22 (GPL-2.0) from Sangoma's signed repository deb.freepbx.org, "
             "the rest from the Debian archive; installed offline by the phone system at its first power-on",
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
        for comp in comps:
            out.append((root, f"{root}/dists/{suite}/{comp}/binary-amd64/Packages.gz"))
    return out


def _cache_name(root: str, url: str) -> str:
    """The cache file for an index: the suite path, prefixed with the host
    for a repository that is not the distribution's own."""
    tail = url.split("/dists/", 1)[1].replace("/", "_")
    host = root.split("://", 1)[-1].split("/", 1)[0]
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
    if not hashes:
        raise PackError(f"the Release file for {url.split('/dists/', 1)[0]} lists no SHA256 hashes")
    rel = url.split("/dists/", 1)[1].split("/", 1)[1]          # main/binary-amd64/Packages.gz
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
            say(f"fetching the package index {url.split('://', 1)[-1].split('/dists/', 1)[0]} "
                f"{url.split('/dists/', 1)[1]}")
            try:
                raw = _fetch_index(get, url)
                if verify_release:
                    suite = url.split("/dists/", 1)[1].split("/", 1)[0]
                    release = get(f"{url.split('/dists/', 1)[0]}/dists/{suite}/Release")
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
    if not man.get("packages"):
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
    closure = resolve(index, pack.packages, installed)
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
            download(f"{deb.base}/{deb.filename}", dest, expect_sha=deb.sha256, label=deb.basename)
        except BootstrapError as exc:
            raise PackError(str(exc)) from exc
        rows.append({"name": deb.name, "version": deb.version, "file": deb.basename,
                     "sha256": deb.sha256, "size": deb.size})
    (d / "Packages").write_text(render_packages(closure), encoding="utf-8")
    man = {"id": pack_id, "image": pack.image, "title": pack.title,
           "fetched": time.strftime("%Y-%m-%d"), "packages": rows, "size": total,
           "install": list(pack.packages)}
    extra_files: list[str] = []
    if pack.extra:
        mod = _extra(pack)
        try:
            man["extra"] = mod.fetch_extra(pack, d, closure, get, download, say)
        except getattr(mod, "ExtraError", None) or mod.VoipError as exc:
            raise PackError(str(exc)) from exc
        extra_files = list(man["extra"].get("files", []))
    manifest_path(pack_id).write_text(json.dumps(man, indent=1), encoding="utf-8")
    # Anything from an earlier fetch that is no longer in the closure.
    keep = {r["file"] for r in rows} | {"Packages", "pack.json"} | set(extra_files)
    for f in d.iterdir():
        if f.name not in keep:
            f.unlink()
    say(f"{pack_id} ready: {d}")
    return man


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
