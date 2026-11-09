"""Generate an Alpine apkovl overlay for the fabric/probe base.

An apkovl is a gzipped tar of a filesystem subtree that Alpine's init restores
very early at boot (the diskless/data-disk model). Dropping one on a disk whose
label Alpine recognises turns a stock Alpine ISO into the winlab fabric:
networking tools present, the serial agent installed and started, no manual
setup-alpine run required.

This builds the overlay deterministically with the stdlib tarfile module, so it
is verifiable without booting.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from . import paths

# Packages the fabric and the Alpine nodes need beyond alpine-base. They are
# fetched from the Alpine mirror on the customer's PC at preparation
# (apkrepo.fetch) and carried on the repository volume, where Alpine's init
# installs them offline at boot from the overlay's /etc/apk/world. Every name
# must be a real package of the ISO's release: the bridge command is part of
# iproute2, and ISC dhcp (dhcrelay) left Alpine with 3.21, so the fabric
# relays DHCP with dnsmasq.
FABRIC_PACKAGES = [
    "iproute2", "bridge-utils", "iptables", "nftables",
    "dnsmasq", "iputils", "arping", "tcpdump", "nmap",
    "ethtool", "iperf3", "tshark", "openrc", "util-linux",
    "strongswan",   # the cloud site's IKEv2 gateway (hybrid-cloud lab)
    "hostapd",      # 802.1X on the switches' ports: the wired driver as authenticator (winlab/dot1x.py)
    "conntrack-tools",  # show ip nat translations: the router's NAT table (winlab/iosl3.py)
    "dropbear",     # SSH to the router's and the switches' consoles from lab machines (winlab/iosssh.py)
]
# On the package volume too, installed only on the Alpine appliances whose
# roles name them (the manifest's `apk`): the network printer, the SAN, the
# IP phones (GNOME Calls, a SIP softphone, full screen in the cage kiosk
# compositor, with what it needs to draw and keep its account), the Admin
# workstation, the NTP server and Linux time clients (chrony). The phone
# system is not here: it is FreePBX on Debian 12, from the freepbx pack
# (winlab/voip.py). The router takes net-snmp, its tools (snmptrap) and
# chrony from here when its console asks for them (winlab/nms.py); a Linux
# machine the student makes a collector installs rsyslog and snmptrapd.
PHONE_PACKAGES = ["calls", "cage", "seatd", "gnome-keyring", "dbus", "eudev", "gst-plugins-base",
                  "gst-plugins-good", "adwaita-icon-theme", "font-dejavu"]
APPLIANCE_PACKAGES = ["net-snmp", "busybox-extras", "e2fsprogs",
                      "chrony", "scsi-tgt", "mdadm", "net-snmp-tools", "rsyslog",
                      # the printer's CUPS (content/roles/netprinter.sh)
                      "cups", "cups-doc", "cups-filters",
                      # the Admin workstation's desktop (content/roles/admin-desktop.sh)
                      "xorg-server", "xf86-input-libinput", "xf86-video-vesa", "eudev", "xauth", "openbox",
                      "tint2", "xterm", "firefox-esr", "font-dejavu", "dbus-x11",
                      # Webmin on the storage array and the NTP server (winlab/webmin.py):
                      # Perl and the modules its pages need, openssl for its certificate;
                      # tgt-admin (what Webmin's iSCSI TGTd module applies targets.conf
                      # with) and LVM for the array's volumes.
                      "perl", "perl-net-ssleay", "perl-io-tty", "openssl", "scsi-tgt-scripts", "lvm2",
                      "nginx",  # the lab Internet's web sites (role inet-sites, winlab/webproxy.py)
                      # the router's OSPF, BGP and VRRP when its console asks for them (winlab/iosrouting.py)
                      "frr",
                      # CDP and LLDP on the router and the switches (winlab/lldp.py), and the IP phones'
                      # LLDP-MED (content/roles/ipphone.sh): installed where they are needed
                      "lldpd",
                      # the entra-hybrid lab's cloud: Lab Cloud's service (content/roles/cloud-tenant.sh)
                      # Python 3 for winlab's own HSRP speaker on the router when its console
                      # configures standby (winlab/ioshsrp.py, winlab/hsrpd.py)
                      "python3",
                      # copy running-config ftp: and scp: on the router's and switches' consoles
                      # (winlab/ftpscp.py): curl for FTP, Dropbear's scp and its client for SCP
                      "curl", "dropbear-scp", "dropbear-dbclient",
                      # mtr for the network tools lessons on the lab's Alpine machines (apk add iperf3 mtr:
                      # iperf3 is on the volume already, with the fabric's packages)
                      "mtr",
                      # the azure-hybrid lab's Azure Files on cloud01 (content/roles/cloud-azure.sh)
                      "samba-server", "samba-common-tools"]
# the IP phones' softphone (content/roles/ipphone.sh)
APPLIANCE_PACKAGES += [p for p in PHONE_PACKAGES if p not in APPLIANCE_PACKAGES]


def _tarinfo(name: str, data: bytes, mode: int = 0o644) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = mode
    ti.mtime = 1735689600  # fixed stamp (2025-01-01) so the overlay is reproducible
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    return ti


def _agent_script(hostname: str = "fabric") -> bytes:
    p = paths.CONTENT / "agent" / "fabric-agent.sh"
    if p.exists():
        text = p.read_bytes()
        if hostname != "fabric":
            # The same agent answers for a Linux node under its own name.
            text = text.replace(b"HOST=fabric\n", b"HOST=" + hostname.encode() + b"\n", 1)
        return text
    return b"#!/bin/sh\necho 'fabric agent missing' >&2\n"


def build_apkovl(dest: Path | None = None, hostname: str = "fabric",
                 packages: list[str] | None = None, serial_login: bool = False) -> Path:
    """Write <hostname>.apkovl.tar.gz. Alpine restores the overlay named after
    the hostname (or the only one) from any volume it can mount at init.
    `packages` is what /etc/apk/world lists and local.d installs (the fabric
    set by default); a caller with an offline repository passes the names it
    really carries, since apk add is all-or-nothing."""
    dest = dest or (paths.bases_dir() / "fabric.apkovl.tar.gz")
    dest.parent.mkdir(parents=True, exist_ok=True)
    packages = list(FABRIC_PACKAGES if packages is None else packages)

    files: dict[str, tuple[bytes, int]] = {}

    # Hostname.
    files["etc/hostname"] = (hostname.encode() + b"\n", 0o644)

    # The agent and its init service.
    files["usr/local/bin/winlab-fabric-agent"] = (_agent_script(hostname), 0o755)
    files["usr/local/bin/winlab-fabric-setup"] = (_fabric_setup_runner(), 0o755)

    files["etc/init.d/winlab-agent"] = (_openrc_service(), 0o755)

    # local.d runs at boot after networking; installs packages then applies the
    # generated fabric config (delivered on the config disk) and starts the agent.
    files["etc/local.d/winlab.start"] = (_locald_start(packages), 0o755)

    # Enable the services we rely on.
    files["etc/runlevels/default/local"] = (b"", 0o777)  # symlink target placeholder
    files["etc/runlevels/default/winlab-agent"] = (b"", 0o777)

    # apk world: record the package set so a cached rebuild is reproducible.
    files["etc/apk/world"] = (("\n".join(["alpine-base"] + packages) + "\n").encode(), 0o644)

    # A lab machine (not the fabric) gets a login prompt on ttyS0 as well as
    # on its screen: the desktop's Terminal window. ttyS1 stays the agent's.
    if serial_login:
        files["etc/inittab"] = (_INITTAB_SERIAL, 0o644)

    # Serial console + agent both want ttyS1 free of a getty; disable it.
    files["etc/winlab/README"] = (
        b"winlab fabric overlay. Agent on ttyS1. Config disk provides fabric.sh.\n",
        0o644,
    )

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, (data, mode) in files.items():
            tar.addfile(_tarinfo(name, data, mode), io.BytesIO(data))
    dest.write_bytes(buf.getvalue())
    return dest


def overlay_disk(dest: Path, hostname: str, packages: list[str] | None = None) -> Path:
    """A FAT volume holding <hostname>.apkovl.tar.gz, attached to a Linux node
    that boots the Alpine ISO diskless: Alpine's init mounts the volume,
    finds the overlay and restores it, so the node comes up with its own
    hostname and the winlab agent on ttyS1 (the same way as the fabric)."""
    from . import fatfs
    tar = build_apkovl(dest.with_name(f"{hostname}.apkovl.tar.gz"), hostname=hostname, packages=packages,
                       serial_login=True)
    img = fatfs.disk(16, "WLOVL")
    img.add_file(tar.name, tar.read_bytes())
    img.add_file("README.txt", (f"winlab overlay volume for {hostname}: Alpine restores the "
                                f"apkovl at boot.\r\n").encode())
    dest.parent.mkdir(parents=True, exist_ok=True)
    return img.write(dest)


# Alpine's stock inittab with the serial getty switched on.
_INITTAB_SERIAL = b"""::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default
tty1::respawn:/sbin/getty 38400 tty1
tty2::respawn:/sbin/getty 38400 tty2
ttyS0::respawn:/sbin/getty -L 115200 ttyS0 xterm
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
"""


def _openrc_service() -> bytes:
    return b"""#!/sbin/openrc-run
name="winlab-agent"
description="winlab fabric serial agent"
command="/usr/local/bin/winlab-fabric-agent"
command_background=true
pidfile="/run/winlab-agent.pid"
depend() { need net; after bootmisc; }
"""


def _locald_start(packages: list[str] | None = None) -> bytes:
    pkgs = " ".join(FABRIC_PACKAGES if packages is None else packages)
    return (
        "#!/bin/sh\n"
        "# winlab fabric bootstrap. Alpine's init has already installed\n"
        "# /etc/apk/world from the boot repositories it found (the ISO and the\n"
        "# winlab repository volume); this catches up when a package was left\n"
        "# out, without the network the lab does not have and without failing\n"
        "# the whole set over one unknown name. Then apply the fabric config\n"
        "# delivered on the config disk and ensure the agent.\n"
        "set -e\n"
        f"apk add --no-network --force-broken-world {pkgs} 2>/dev/null || true\n"
        "# Find the winlab config disk (label WLFAB) and run fabric.sh from it.\n"
        "for d in /dev/vd* /dev/sd*; do\n"
        "  mp=/mnt/wlfab\n"
        "  mkdir -p $mp\n"
        "  if mount -o ro $d $mp 2>/dev/null; then\n"
        "    if [ -f $mp/fabric.sh ]; then\n"
        "      cp $mp/fabric.sh /run/fabric.sh; chmod +x /run/fabric.sh\n"
        "      sh /run/fabric.sh || true\n"
        "      umount $mp; break\n"
        "    fi\n"
        "    umount $mp 2>/dev/null || true\n"
        "  fi\n"
        "done\n"
        "rc-service winlab-agent restart 2>/dev/null || "
        "/usr/local/bin/winlab-fabric-agent &\n"
    ).encode()


def _fabric_setup_runner() -> bytes:
    return b"#!/bin/sh\nexec /etc/local.d/winlab.start\n"


def verify(path: Path) -> dict:
    """Read the overlay back and report its contents, for testing."""
    out = {"files": [], "has_agent": False, "has_service": False, "packages": 0}
    with tarfile.open(path, "r:gz") as tar:
        for m in tar.getmembers():
            out["files"].append(m.name)
            if m.name.endswith("winlab-fabric-agent"):
                out["has_agent"] = True
            if m.name.endswith("init.d/winlab-agent"):
                out["has_service"] = True
            if m.name == "etc/apk/world":
                out["packages"] = len(
                    tar.extractfile(m).read().decode().strip().splitlines()
                )
    return out
