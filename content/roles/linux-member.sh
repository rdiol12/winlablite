#!/bin/sh
# Join an Ubuntu appliance to the lab's Active Directory domain with realmd
# and SSSD, the way a Linux server joins a Windows domain at work: discover
# the domain through DNS, create the computer account with adcli, log domain
# users in with SSSD (home directory made on first login), Domain Admins get
# sudo. The runner prepends WINLAB_* variables (roles.sh_env): the domain,
# its DNS servers, the lab's one password, and where the pack stick mounts.
#
# The lab has no internet, so the packages come from the 'sssd' pack
# (winlab packs fetch sssd), plugged in as a USB stick before this runs.

role=linux-member
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }
export DEBIAN_FRONTEND=noninteractive

[ -f "$done_dir/$role" ] && { log 'already configured'; exit 0; }
[ -n "$WINLAB_DOMAIN" ] || { echo 'WINLAB_DOMAIN is empty: the runner needs the lab' >&2; exit 1; }
[ -n "$WINLAB_ADMIN_PASSWORD" ] || { echo 'WINLAB_ADMIN_PASSWORD is empty' >&2; exit 1; }

# ---- 1. packages from the pack stick (a flat apt repository, offline) ----
if ! command -v realm >/dev/null 2>&1; then
    mp="${WINLAB_PACK_MOUNT:-/mnt/winlab-pack}"
    mkdir -p "$mp"
    mountpoint -q "$mp" || mount -o ro "LABEL=${WINLAB_PACK_LABEL:-WLPACK}" "$mp" 2>/dev/null ||
        { echo "the sssd pack stick is not plugged in (winlab packs fetch sssd, then apply the role again)" >&2; exit 1; }
    [ -f "$mp/Packages" ] || { echo "no Packages index on the pack stick at $mp" >&2; exit 1; }
    log "installing realmd, sssd, adcli and Kerberos from the pack at $mp"
    echo "deb [trusted=yes] file:$mp ./" > /etc/apt/sources.list.d/winlab-pack.list
    apt-get -q -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/winlab-pack.list \
            -o Dir::Etc::sourceparts=- update >/dev/null || { echo 'apt could not read the pack' >&2; exit 1; }
    apt-get -q -y --no-install-recommends \
            -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/winlab-pack.list \
            -o Dir::Etc::sourceparts=- \
            install realmd sssd-ad sssd-tools adcli krb5-user libnss-sss libpam-sss ||
        { echo 'package installation from the pack failed' >&2; exit 1; }
    rm -f /etc/apt/sources.list.d/winlab-pack.list
    umount "$mp" 2>/dev/null || true
fi

# ---- 2. name resolution and time: the domain's DNS servers, the DC's clock --
dns1=$(printf '%s' "$WINLAB_DNS" | awk '{print $1}')
if [ -n "$dns1" ]; then
    mkdir -p /etc/systemd/timesyncd.conf.d
    printf '[Time]\nNTP=%s\n' "$dns1" > /etc/systemd/timesyncd.conf.d/winlab.conf
    systemctl restart systemd-timesyncd 2>/dev/null || true
fi
realm=$(printf '%s' "$WINLAB_DOMAIN" | tr '[:lower:]' '[:upper:]')

# ---- 3. discover and join -------------------------------------------------
cat > /etc/realmd.conf <<CONF
[users]
default-home = /home/%U
default-shell = /bin/bash

[active-directory]
default-client = sssd
os-name = Ubuntu Server
os-version = 24.04

[service]
automatic-install = no

[$WINLAB_DOMAIN]
fully-qualified-names = no
automatic-id-mapping = yes
manage-system = no
CONF

for i in 1 2 3 4 5 6; do
    realm discover "$WINLAB_DOMAIN" >/tmp/realm-discover.txt 2>&1 && break
    log "domain $WINLAB_DOMAIN not found yet (try $i); waiting for DNS and the DC"
    sleep 20
done
grep -q 'type: kerberos' /tmp/realm-discover.txt || {
    echo "realm discover found no domain '$WINLAB_DOMAIN'; the machine's DNS must point at a domain controller" >&2
    cat /tmp/realm-discover.txt >&2; exit 1; }

if ! realm list 2>/dev/null | grep -q "^$WINLAB_DOMAIN"; then
    log "joining $realm as Administrator (adcli creates the computer account)"
    # --unattended reads the password from stdin instead of a terminal.
    realm join --unattended --user=Administrator --membership-software=adcli \
               --client-software=sssd "$WINLAB_DOMAIN" 2>/tmp/realm-join.err <<PW
$WINLAB_ADMIN_PASSWORD
PW
    realm list 2>/dev/null | grep -q "^$WINLAB_DOMAIN" ||
        { echo 'realm join failed:' >&2; cat /tmp/realm-join.err >&2; exit 1; }
fi

# ---- 4. logins: short names, home directories, who may log in, sudo -------
sed -i 's/^use_fully_qualified_names *=.*/use_fully_qualified_names = False/' /etc/sssd/sssd.conf
grep -q '^use_fully_qualified_names' /etc/sssd/sssd.conf ||
    sed -i "/^\[domain\/$WINLAB_DOMAIN\]/a use_fully_qualified_names = False" /etc/sssd/sssd.conf
sed -i 's|^fallback_homedir *=.*|fallback_homedir = /home/%u|' /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
pam-auth-update --enable mkhomedir >/dev/null 2>&1 || true
realm permit --all >/dev/null 2>&1 || true
printf '%%domain\\ admins ALL=(ALL:ALL) ALL\n' > /etc/sudoers.d/winlab-domain-admins
chmod 440 /etc/sudoers.d/winlab-domain-admins
systemctl enable sssd >/dev/null 2>&1 || true
systemctl restart sssd || { echo 'sssd failed to start; see journalctl -u sssd' >&2; exit 1; }

for i in 1 2 3 4 5 6; do
    id Administrator >/dev/null 2>&1 && break
    sleep 5
done
id Administrator >/dev/null 2>&1 || log 'warning: sssd does not resolve Administrator yet (id Administrator); check /var/log/sssd'

mkdir -p "$done_dir"
date -Iseconds > "$done_dir/$role"
log "done: $(hostname) is a member of $WINLAB_DOMAIN; domain users log in by short name, Domain Admins have sudo"
