#!/bin/sh
# The office phone system: FreePBX 17 on Asterisk 22, on Debian 12, the way
# Sangoma's own installer sets it up (sng_freepbx_debian_install.sh), but
# offline: the lab has no internet, so everything comes from the 'freepbx'
# pack (winlab packs fetch freepbx), plugged in as a USB stick: Debian's
# packages, Asterisk 22 from Sangoma's signed repository with that
# repository's InRelease, index and key, and Sangoma's FreePBX tarball.
#
# Factory state, as a new FreePBX: the web pages on port 80, no extension,
# no trunk, and no administrator. The first visit to http://<this machine>/
# shows FreePBX's Initial Setup, where the student creates the admin
# account; everything after that is done in FreePBX.
#
# The device runs this at every power-on: it is the phone system's firmware.
# The first power-on installs (several minutes); later ones only make sure
# FreePBX is running.

role=pbx
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }
die() { echo "$*" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
mkdir -p "$done_dir"

# ---- 0. installed already: start it, as the appliance does at every boot ---
if [ -f /etc/freepbx.conf ] && command -v fwconsole >/dev/null 2>&1; then
    # A phone system installed before the lab's callers spoke (flite) takes
    # it from a newer pack stick when one is plugged in; nothing else changes.
    if ! command -v flite >/dev/null 2>&1; then
        mp="${WINLAB_PACK_MOUNT:-/mnt/winlab-pack}"; mkdir -p "$mp"
        if mountpoint -q "$mp" || mount -o ro "LABEL=${WINLAB_PACK_LABEL:-WLPACK}" "$mp" 2>/dev/null; then
            if ls "$mp"/flite_*.deb >/dev/null 2>&1; then
                l=/etc/apt/sources.list.d/winlab-pack.list
                echo "deb [trusted=yes] file:$mp ./" > "$l"
                apt-get -q -o Dir::Etc::sourcelist="$l" -o Dir::Etc::sourceparts=- update >/dev/null 2>&1 &&
                    apt-get -q -y --no-install-recommends -o Dir::Etc::sourcelist="$l" -o Dir::Etc::sourceparts=- \
                        install flite >/dev/null 2>&1 &&
                    log 'flite installed from the pack: the helpdesk callers can speak'
                rm -f "$l"
            fi
            umount "$mp" 2>/dev/null || true
        fi
    fi
    systemctl start mariadb apache2 >/dev/null 2>&1
    systemctl start freepbx >/dev/null 2>&1 || fwconsole start -q >/dev/null 2>&1
    date -Iseconds > "$done_dir/$role"
    log 'FreePBX is running: http://'"$(hostname -I 2>/dev/null | cut -d' ' -f1)"'/'
    exit 0
fi

# ---- 1. the pack stick ------------------------------------------------------
mp="${WINLAB_PACK_MOUNT:-/mnt/winlab-pack}"
mkdir -p "$mp"
mountpoint -q "$mp" || mount -o ro "LABEL=${WINLAB_PACK_LABEL:-WLPACK}" "$mp" 2>/dev/null ||
    die 'the freepbx pack stick is not plugged in (winlab packs fetch freepbx, then power the phone system on again)'
tarball=freepbx-17.0-latest.tgz
for f in Packages "$tarball" "$tarball.sha256" freepbx-InRelease freepbx-Packages freepbx-archive.gpg; do
    [ -s "$mp/$f" ] || die "the pack stick has no $f: fetch the freepbx pack again"
done

# ---- 2. the publisher's signatures, before anything is installed -----------
work=/var/lib/winlab/freepbx
rm -rf "$work"; mkdir -p "$work"
gpgv --keyring "$mp/freepbx-archive.gpg" --output "$work/Release" "$mp/freepbx-InRelease" 2>"$work/gpgv.log" ||
    { cat "$work/gpgv.log" >&2; die "Sangoma's InRelease does not carry a good signature from its key"; }
want=$(awk '/^SHA256:/ {s=1; next} /^[^ ]/ {s=0} s && $3 == "main/binary-amd64/Packages" {print $1}' "$work/Release")
got=$(sha256sum "$mp/freepbx-Packages" | cut -d' ' -f1)
[ -n "$want" ] && [ "$want" = "$got" ] || die "Sangoma's package index is not the one its signed InRelease names"
# Every Sangoma .deb on the stick against the signed index.
awk 'BEGIN {RS = ""; FS = "\n"} {
        f = ""; s = ""
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^Filename:/) { f = $i; sub(/^Filename: */, "", f); sub(/.*\//, "", f) }
            if ($i ~ /^SHA256:/) { s = $i; sub(/^SHA256: */, "", s) }
        }
        if (f != "" && s != "") print s, f
    }' "$mp/freepbx-Packages" | while read -r sha f; do
    [ -f "$mp/$f" ] && printf '%s  %s\n' "$sha" "$mp/$f"
done > "$work/sangoma.sha256"
[ -s "$work/sangoma.sha256" ] || die 'no Sangoma package from the signed index is on the stick'
sha256sum -c --quiet "$work/sangoma.sha256" >&2 || die "a Sangoma package on the stick is not the one it signed"
log "Sangoma's signature is good: $(wc -l < "$work/sangoma.sha256") packages checked"
(cd "$mp" && sha256sum -c --quiet "$tarball.sha256") >&2 ||
    die 'the FreePBX tarball on the stick is not the one this PC fetched'

# ---- 3. Debian's packages and Asterisk 22, from the stick ------------------
pkgs="apache2 libapache2-mod-php8.2 mariadb-server mariadb-client
php8.2 php8.2-cli php8.2-common php8.2-curl php8.2-mysql php8.2-gd
php8.2-mbstring php8.2-intl php8.2-xml php8.2-bz2 php8.2-zip
php8.2-ldap php8.2-sqlite3 php8.2-bcmath php8.2-soap php-pear
nodejs sox mpg123 lame flite sqlite3 uuid unixodbc odbc-mariadb
sudo cron incron at curl wget gnupg net-tools
asterisk22 asterisk22-core asterisk22-addons asterisk22-addons-core
asterisk22-addons-mysql asterisk22-curl asterisk22-odbc asterisk22-sqlite3
asterisk22-voicemail asterisk22.0-freepbx-asterisk-modules"
log 'installing Apache, MariaDB, PHP 8.2, Node.js and Asterisk 22 from the pack'
list=/etc/apt/sources.list.d/winlab-pack.list
echo "deb [trusted=yes] file:$mp ./" > "$list"
apt_pack() { apt-get -q -o Dir::Etc::sourcelist="$list" -o Dir::Etc::sourceparts=- "$@"; }
apt_pack update >/dev/null || die 'apt could not read the pack'
# shellcheck disable=SC2086
apt_pack -y --no-install-recommends -o DPkg::Options::=--force-confnew install $pkgs >"$work/apt.log" 2>&1 ||
    { tail -n 20 "$work/apt.log" >&2; die 'package installation from the pack failed'; }
rm -f "$list"

# ---- 4. Asterisk runs as its own user; Apache serves FreePBX as it --------
id asterisk >/dev/null 2>&1 || adduser --system --group --home /var/lib/asterisk --no-create-home \
    --gecos 'Asterisk PBX' asterisk >/dev/null
mkdir -p /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /var/run/asterisk /var/lib/php/session
[ -f /etc/asterisk/asterisk.conf ] || printf '[options]\nrunuser = asterisk\nrungroup = asterisk\n' \
    > /etc/asterisk/asterisk.conf
for f in extconfig_custom extensions_override_freepbx extensions_additional extensions_custom; do
    touch "/etc/asterisk/$f.conf"
done
chown -R asterisk:asterisk /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk \
    /var/run/asterisk /var/lib/php/session
ini=/etc/php/8.2/apache2/php.ini
sed -i 's/^\(upload_max_filesize = \).*/\1120M/; s/^\(memory_limit = \).*/\1256M/;
        s/^\(expose_php = \).*/\1Off/; s/^;\?max_input_vars = .*/max_input_vars = 2000/' "$ini"
sed -i 's/^export APACHE_RUN_USER=.*/export APACHE_RUN_USER=asterisk/;
        s/^export APACHE_RUN_GROUP=.*/export APACHE_RUN_GROUP=asterisk/' /etc/apache2/envvars
sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf
a2enmod rewrite expires >/dev/null
rm -f /var/www/html/index.html
systemctl enable mariadb apache2 >/dev/null 2>&1
systemctl restart mariadb || die 'MariaDB did not start'

# ---- 5. FreePBX, from Sangoma's tarball, with its own installer ------------
log "unpacking $tarball"
rm -rf /usr/src/freepbx
tar -xzf "$mp/$tarball" -C /usr/src || die 'the FreePBX tarball did not unpack'
umount "$mp" 2>/dev/null || true
cd /usr/src/freepbx || die 'no /usr/src/freepbx after unpacking'
log 'starting Asterisk as the asterisk user'
if [ -x ./start_asterisk ]; then
    ./start_asterisk start >/dev/null 2>&1
else
    asterisk -U asterisk -G asterisk >/dev/null 2>&1
fi
sleep 3
asterisk -rx 'core show version' >/dev/null 2>&1 || die 'Asterisk did not start'
log 'running the FreePBX installer (framework, then the open-source modules in the tarball)'
./install -n --dbuser root --webroot /var/www/html >"$work/install.log" 2>&1 ||
    { tail -n 25 "$work/install.log" >&2; die 'the FreePBX installer failed (see /var/lib/winlab/freepbx/install.log)'; }
fwconsole ma list 2>/dev/null | grep -Eq '^\| core +\|.*Enabled' ||
    die 'FreePBX installed but its core module is not enabled (see /var/lib/winlab/freepbx/install.log)'

# ---- 6. started at every boot, as Sangoma's appliance does ------------------
cat > /etc/systemd/system/freepbx.service <<'UNIT'
[Unit]
Description=FreePBX VoIP Server
After=mariadb.service
Wants=mariadb.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/fwconsole start -q
ExecStop=/usr/sbin/fwconsole stop -q

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable freepbx >/dev/null 2>&1
fwconsole chown >/dev/null 2>&1
fwconsole reload >/dev/null 2>&1
systemctl restart apache2 || die 'Apache did not start'
systemctl start freepbx >/dev/null 2>&1

# Factory state: no administrator yet (FreePBX's Initial Setup creates it), no
# extensions, no trunks. winlab creates none of them.
date -Iseconds > "$done_dir/$role"
log 'FreePBX 17 is installed: open http://'"$(hostname -I 2>/dev/null | cut -d' ' -f1)"'/ from a lab PC and create the administrator'
