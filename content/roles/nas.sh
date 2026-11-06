#!/bin/sh
# The NAS's firmware: OpenMediaVault 8 (Synchrony) on Debian 13 (winlab/omv.py).
# The packages come from the 'omv' pack (winlab packs fetch omv:
# OpenMediaVault from packages.openmediavault.org, the rest from the Debian
# archive), plugged in as a USB stick before this runs. It installs them the
# way OpenMediaVault's own guide does on a plain Debian, offline, at the
# NAS's first start; the done marker on the system disk keeps it installed
# from then on, like a NAS's firmware.
#
# Factory state, as a freshly installed OpenMediaVault: the web UI on port 80
# and its administrator account admin, whose password is the lab's password
# (Start > Lab password; the runner passes it as WINLAB_ADMIN_PASSWORD)
# instead of the project's well-known default. Nothing else: no file system
# on the data disk, no shared folder, no users, SMB and NFS off. The student
# builds those in the web UI from a browser on a lab PC.

role=nas
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }
export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none LANG=C.UTF-8

[ -f "$done_dir/$role" ] && { log 'OpenMediaVault already installed'; exit 0; }
[ -f /etc/debian_version ] || { echo 'the NAS runs on Debian (image debian13-cloud); this machine is something else' >&2; exit 1; }
[ -n "$WINLAB_ADMIN_PASSWORD" ] || { echo 'no lab password passed to the role' >&2; exit 1; }

installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

if ! installed openmediavault; then
    # ---- 1. the pack stick: a flat apt repository --------------------------
    mp="${WINLAB_PACK_MOUNT:-/mnt/winlab-pack}"
    mkdir -p "$mp"
    mountpoint -q "$mp" || mount -o ro "LABEL=${WINLAB_PACK_LABEL:-WLPACK}" "$mp" 2>/dev/null ||
        { echo "the omv pack stick is not plugged in (winlab packs fetch omv, then power the NAS on again)" >&2; exit 1; }
    [ -f "$mp/Packages" ] || { echo "no Packages index on the pack stick at $mp" >&2; exit 1; }

    # Postfix (OpenMediaVault's mail notifications) asks how to send mail:
    # not at all until the student sets it up in the web UI.
    echo 'postfix postfix/main_mailer_type select No configuration' | debconf-set-selections 2>/dev/null || true

    # ---- 2. install it as OpenMediaVault's guide does, from the stick only --
    list=/etc/apt/sources.list.d/winlab-pack.list
    echo "deb [trusted=yes] file:$mp ./" > "$list"
    apt_pack() {
        apt-get -q -o Dir::Etc::sourcelist="$list" -o Dir::Etc::sourceparts=- "$@"
    }
    log "installing OpenMediaVault from the pack at $mp (this takes a while)"
    apt_pack update >/dev/null || { echo 'apt could not read the pack' >&2; exit 1; }
    apt_pack --yes --auto-remove --show-upgraded --allow-downgrades --allow-change-held-packages \
        --no-install-recommends \
        -o DPkg::Options::=--force-confdef -o DPkg::Options::=--force-confold \
        install openmediavault-keyring openmediavault ||
        { rm -f "$list"; echo 'OpenMediaVault did not install from the pack' >&2; exit 1; }
    rm -f "$list"
    umount "$mp" 2>/dev/null || true
fi

# ---- 3. its database, then the services behind the web UI ------------------
command -v omv-confdbadm >/dev/null 2>&1 || { echo 'omv-confdbadm missing: the install is incomplete' >&2; exit 1; }
omv-confdbadm populate >/dev/null 2>&1 || { echo 'omv-confdbadm populate failed' >&2; exit 1; }
# The network stays as cloud-init set it from the lab (the student may take
# it over in Network > Interfaces); only the web UI is deployed here.
systemctl is-active -q nginx 2>/dev/null ||
    omv-salt deploy run nginx phpfpm >/dev/null 2>&1 ||
    { echo 'the web UI (nginx, php-fpm) did not deploy; see journalctl -u nginx' >&2; exit 1; }

# ---- 4. the administrator: admin, with the lab's password -----------------
id admin >/dev/null 2>&1 || { echo 'OpenMediaVault created no admin account' >&2; exit 1; }
printf 'admin:%s\n' "$WINLAB_ADMIN_PASSWORD" | chpasswd || { echo 'could not set the admin password' >&2; exit 1; }

mkdir -p "$done_dir"
date -Iseconds > "$done_dir/$role"
host=${WINLAB_HOSTNAME:-$(hostname)}
log "ready: OpenMediaVault on http://$host/ (admin, the lab password); no file systems, shares or users yet"
