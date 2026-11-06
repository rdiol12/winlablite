#!/bin/sh
# Webmin (BSD-3-Clause, webmin.com) on an Alpine appliance: the management
# pages of a box that has no web GUI of its own (the storage array, the NTP
# server), on https 10000, served on the lab network only.
#
# The appliance boots Alpine diskless, so what lives in /etc is gone at the
# next power-on. Like a real appliance it keeps its software and its
# settings on an internal disk: its own small system disk, formatted at the
# first power-on (label WLFLASH) and mounted on /flash. Webmin is installed
# there once, from the release tarball winlab fetched from Webmin's GitHub
# release onto this PC and carried on the repository volume
# (winlab/webmin.py), and its configuration (/etc/webmin, /var/webmin) is
# kept there too. winlab-keep, installed here, keeps any other directory or
# file there the same way (the array's /etc/tgt, say).
#
# Factory state: Webmin installed and listening, root signs in with the
# lab's password (WINLAB_ADMIN_PASSWORD, hashed here into Webmin's own user
# file), nothing else configured. The device runs this at every power-on.

role=webmin
done_dir=/var/lib/winlab/done
FLASH=/flash
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }
mkdir -p "$done_dir"

# ---- 1. the internal disk -------------------------------------------------
flash_dev() {
    d=$(blkid -L WLFLASH 2>/dev/null)
    [ -n "$d" ] && { echo "$d"; return 0; }
    for s in /sys/block/vd* /sys/block/sd*; do
        [ -e "$s/size" ] || continue
        n=${s##*/}
        [ "$(cat "$s/ro" 2>/dev/null)" = 0 ] || continue
        case "$(cat "$s/serial" 2>/dev/null)" in SANBAY*) continue ;; esac   # a storage array's drive bays
        [ "$(cat "$s/size")" -ge 4194304 ] || continue                       # 2 GB or more
        ls "$s" | grep -q "^$n[0-9]" && continue                             # partitioned: somebody's disk
        [ -z "$(blkid -p -o value -s TYPE "/dev/$n" 2>/dev/null)" ] || continue   # never format a disk that holds something
        echo "/dev/$n"
        return 0
    done
    return 1
}

if ! mountpoint -q "$FLASH" 2>/dev/null; then
    dev=$(flash_dev) || dev=""
    if [ -n "$dev" ]; then
        if [ "$(blkid -o value -s LABEL "$dev" 2>/dev/null)" != WLFLASH ]; then
            log "first power-on: formatting the internal disk $dev"
            mkfs.ext4 -q -F -L WLFLASH "$dev" || { echo "could not format $dev" >&2; exit 1; }
        fi
        mkdir -p "$FLASH"
        mount -t ext4 "$dev" "$FLASH" || { echo "could not mount the internal disk $dev" >&2; exit 1; }
    else
        log 'no internal disk found: settings last until the next power-off'
        mkdir -p "$FLASH"
    fi
fi

mkdir -p /usr/local/sbin
cat > /usr/local/sbin/winlab-keep <<'KEEP'
#!/bin/sh
# winlab-keep <path>...: keep a directory or a file on the appliance's
# internal disk (/flash/keep), so it survives a power-off. The first time,
# what the packages put there is copied over; after that the kept copy wins.
for p in "$@"; do
    k=/flash/keep$p
    if mountpoint -q "$p" 2>/dev/null; then continue; fi
    if [ -d "$p" ] || { [ ! -e "$p" ] && [ "${p%/}" != "$p" ]; }; then
        p=${p%/}; k=/flash/keep$p
        mkdir -p "$p"
        [ -d "$k" ] || { mkdir -p "$k" && cp -a "$p/." "$k/" 2>/dev/null; }
    else
        mkdir -p "${p%/*}" "${k%/*}"
        [ -e "$k" ] || { if [ -e "$p" ]; then cp -a "$p" "$k"; else : > "$k"; fi; }
        [ -e "$p" ] || : > "$p"
    fi
    mount --bind "$k" "$p" || echo "winlab-keep: could not keep $p" >&2
done
KEEP
chmod 755 /usr/local/sbin/winlab-keep
mountpoint -q "$FLASH" && /usr/local/sbin/winlab-keep /etc/webmin/ /var/webmin/

# ---- 2. Webmin itself -----------------------------------------------------
tarball() {
    for f in /media/*/webmin/webmin-*.tar.gz; do [ -f "$f" ] && echo "$f"; done | sort | tail -n 1
}
tgz=$(tarball)
if [ -z "$tgz" ]; then
    # The repository volume, when Alpine's init did not leave it mounted.
    d=$(blkid -L WLAPK 2>/dev/null)
    if [ -n "$d" ]; then
        mkdir -p /media/wlapk
        mountpoint -q /media/wlapk || mount -o ro "$d" /media/wlapk 2>/dev/null
        tgz=$(tarball)
    fi
fi

wadir=$FLASH/webmin
have=$(cat "$wadir/version" 2>/dev/null)
want=$(basename "${tgz:-none}" .tar.gz | sed 's/^webmin-//')
if [ -n "$tgz" ] && [ "$have" != "$want" ]; then
    log "installing Webmin $want from $tgz onto the internal disk"
    src=$FLASH/webmin-src
    rm -rf "$src"
    mkdir -p "$src"
    tar -xzf "$tgz" -C "$src" || { echo "the Webmin tarball would not unpack" >&2; exit 1; }
    hash=$(WL_SECRET="$WINLAB_ADMIN_PASSWORD" perl -e '
        my @c = ("a".."z", "A".."Z", 0..9, ".", "/");
        my $salt = join("", map { $c[int(rand(@c))] } 1..16);
        print crypt($ENV{WL_SECRET}, "\$6\$$salt\$");')
    [ -n "$hash" ] || { echo "could not hash the lab password for Webmin's root user" >&2; exit 1; }
    # Webmin's own non-interactive install (setup.sh reads its answers from
    # the environment): https on 10000, user root, no start at boot (this
    # role starts it), nothing else.
    ( cd "$src/webmin-$want" &&
      env config_dir=/etc/webmin var_dir=/var/webmin perl=/usr/bin/perl port=10000 \
          login=root crypt="$hash" ssl=1 atboot=0 nostart=1 nouninstall=1 \
          ./setup.sh "$wadir" </dev/null >"$FLASH/webmin-setup.log" 2>&1 ) ||
        { echo "Webmin's setup.sh failed: see $FLASH/webmin-setup.log" >&2; tail -n 20 "$FLASH/webmin-setup.log" >&2; exit 1; }
    echo "$want" > "$wadir/version"
    rm -rf "$src"
elif [ -z "$tgz" ] && [ -z "$have" ]; then
    log 'Webmin is not on the repository volume (fetch it: winlab images prepare fabric); the device runs without its pages'
    date -Iseconds > "$done_dir/$role"
    exit 0
fi

# ---- 3. start it ----------------------------------------------------------
listening() { grep -qi ":2710 " /proc/net/tcp /proc/net/tcp6 2>/dev/null; }   # 10000 in hex
if ! listening; then
    /etc/webmin/start >/dev/null 2>&1 || { echo 'Webmin did not start (/etc/webmin/start)' >&2; exit 1; }
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do listening && break; sleep 1; done
fi
listening || { echo 'Webmin is not listening on 10000' >&2; exit 1; }

date -Iseconds > "$done_dir/$role"
log "ready: Webmin $(cat "$wadir/version" 2>/dev/null) on https://$(ip -o -4 addr show | awk '$2 != "lo" {sub(/\/.*/, "", $4); print $4; exit}'):10000 (root, the lab's password)"
