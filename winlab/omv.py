"""The NAS runs OpenMediaVault: a real NAS operating system, managed from
its own web pages, as a small office's NAS is.

The NAS on the workbench shelf is a Debian 13 machine (Debian's own cloud
image, winlab/appliances.py ``debian13-cloud``) whose firmware is
OpenMediaVault 8 "Synchrony", the project's current stable release, built
on Debian 13 trixie. The packages come as the ``omv`` pack
(winlab/debpacks.py): OpenMediaVault from its own apt repository
(packages.openmediavault.org), everything under it from the Debian archive,
fetched on this PC and plugged into the NAS as a stick. The ``nas`` role
(content/roles/nas.sh) installs it at the NAS's first start.

Out of the box it is what a freshly installed OpenMediaVault is: the web UI
on port 80 and its administrator account ``admin``, with the lab's password
(Start > Lab password) instead of the project's well-known default. No file
system on the data disk, no shared folder, no SMB or NFS service, no users:
the student builds those in the web UI (Storage > File Systems, Shared
Folders, Users, Services > SMB/CIFS and NFS), from a browser on a lab PC,
the way it is done at work. The data disk stays in the NAS's drive bay.

Graders read what OpenMediaVault wrote on the device, over the agent:
its database (/etc/openmediavault/config.xml) and the Samba configuration
it deploys (/etc/samba/smb.conf). Shared folders live where OpenMediaVault
mounts file systems, /srv/dev-disk-by-uuid-<uuid>/<folder>, so a grader
finds a share's folder by its name in smb.conf, never by a fixed path.
"""

from __future__ import annotations

from . import adminui

SOFTWARE = "OpenMediaVault 8 (Synchrony)"
IMAGE = "debian13-cloud"
PACK = "omv"
PORT = 80
CONFIG_XML = "/etc/openmediavault/config.xml"
SMB_CONF = "/etc/samba/smb.conf"
LICENSE = "GPL-3.0"
SIGN_IN = "admin, with the lab's password (Start > Lab password)"
# The NAS's own account Windows Server Backup signs in with: the student
# creates it in OpenMediaVault (Users), the lessons name it.
BACKUP_USER = "svc-backup"


def share_path_sh(share: str) -> str:
    """sh that prints the folder an SMB share serves, read from the Samba
    configuration OpenMediaVault deployed ('' when there is no such share).
    The share name is matched without regard to case, as Samba does."""
    want = share.lower()
    return ("awk -v want='[" + want + "]' '"
            "{ l = tolower($0); gsub(/^[ \\t]+|[ \\t]+$/, \"\", l) } "
            "substr(l, 1, 1) == \"[\" { on = (l == want); next } "
            "on && $1 == \"path\" { sub(/^[^=]*=[ \\t]*/, \"\"); sub(/\\/+$/, \"\"); print; exit }' "
            + SMB_CONF + " 2>/dev/null")


def _nas_gui(lab, node):
    from . import appliance
    if appliance.device_of(node) != "nas":
        return None
    return adminui.AdminGui(
        software=SOFTWARE, scheme="http", port=PORT, path="/", sign_in=SIGN_IN, license=LICENSE,
        note="Factory state: no file system, no shared folder, no user.")


adminui.register(node_gui=_nas_gui)
