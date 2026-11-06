#!/bin/sh
# An iSCSI storage array (a SAN) on the Alpine appliance: drive bays (its
# data disks, each reporting its bay as its serial number SANBAY<n>), two
# iSCSI ports, Linux md for RAID groups, LVM for volumes and tgt (the Linux
# SCSI target framework) for the targets.
#
# Its management pages are Webmin (the webmin role runs first): the student
# builds the RAID groups in Hardware > Linux RAID, carves volumes out of
# them in Hardware > Logical Volume Management and offers them on targets in
# Hardware > iSCSI TGTd, which writes /etc/tgt/targets.conf and applies it
# with tgt-admin. Out of the box there is nothing: no group, no volume, no
# target.
#
# What the student builds survives a power-off the way it does on a real
# array: the md superblocks and the LVM metadata are on the drives; the
# targets, mdadm.conf and LVM's backups are kept on the array's internal disk
# (winlab-keep, from the webmin role). This script brings it all back at
# every power-on: it is the array's firmware. sanctl status, installed here,
# is what the front panel and the graders read.

role=san
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }
mkdir -p "$done_dir"

for tool in tgtd tgtadm tgt-admin mdadm udhcpc; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool missing from the appliance (run winlab images prepare again)" >&2; exit 1; }
done

# Its two ports: port 1 is the first network card, port 2 the second.
n=0
for ifc in $(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | cut -d@ -f1); do
    eval "ip=\${WINLAB_NIC${n}_IP:-} pfx=\${WINLAB_NIC${n}_PREFIX:-24} gw=\${WINLAB_NIC${n}_GW:-} wired=\${WINLAB_NIC${n}_PREFIX+x}"
    ip link set "$ifc" up
    if [ -n "$ip" ]; then
        log "port $((n + 1)) ($ifc): $ip/$pfx"
        ip addr replace "$ip/$pfx" dev "$ifc" || exit 1
        [ -n "$gw" ] && [ "$n" = 0 ] && ip route replace default via "$gw"
    elif [ -n "$wired" ]; then
        log "port $((n + 1)) ($ifc): asking for an address (DHCP)"
        udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" >/dev/null 2>&1 &
    fi
    n=$((n + 1))
done

# ---- what the student builds, kept on the internal disk ------------------
command -v winlab-keep >/dev/null 2>&1 && winlab-keep /etc/tgt/ /etc/lvm/ /etc/winlab-san/ /etc/mdadm.conf
mkdir -p /etc/tgt/conf.d /etc/winlab-san
if ! grep -q 'default-driver' /etc/tgt/targets.conf 2>/dev/null; then
    # The factory file: no targets, the conf.d directory included.
    printf '%s\n' '# iSCSI targets of this array: Webmin (Hardware > iSCSI TGTd) writes them here.' \
        'default-driver iscsi' 'include /etc/tgt/conf.d/*.conf' > /etc/tgt/targets.conf
fi
grep -q '^DEVICE' /etc/mdadm.conf 2>/dev/null ||
    printf '%s\n' '# RAID groups of this array: Webmin (Hardware > Linux RAID) adds ARRAY lines here.' \
        'DEVICE partitions' >> /etc/mdadm.conf

# ---- bring back what is on the drives ------------------------------------
mdadm --assemble --scan --run >/dev/null 2>&1
command -v vgchange >/dev/null 2>&1 && vgchange -ay >/dev/null 2>&1

# ---- tgt: the daemon, then the targets the student made ------------------
tgt() { tgtadm --lld iscsi "$@"; }
if ! tgt --op show --mode sys >/dev/null 2>&1; then
    rc-service tgtd start >/dev/null 2>&1 || tgtd
    for _ in 1 2 3 4 5 6 7 8 9 10; do tgt --op show --mode sys >/dev/null 2>&1 && break; sleep 1; done
fi
tgt --op show --mode sys >/dev/null 2>&1 || { echo 'tgtd did not start' >&2; exit 1; }
tgt-admin -e -c /etc/tgt/targets.conf >/dev/null 2>&1 || log 'tgt-admin did not take every target in targets.conf (Webmin shows them)'
tgt --op update --mode sys --name State -v ready >/dev/null 2>&1

# ---- Webmin's iSCSI TGTd module, set for this array ----------------------
# Its defaults are for other distributions (/etc/tgt/tgtd.conf, systemd);
# this is Alpine's layout, with tgt-admin applying targets.conf, the way a
# vendor ships Webmin set for its own box. Keys the admin changed are kept.
m=/etc/webmin/iscsi-tgtd/config
if [ -d /etc/webmin/iscsi-tgtd ]; then
    set_key() { sed -i "/^$1=/d" "$m" 2>/dev/null; echo "$1=$2" >> "$m"; }
    if ! grep -q '^winlab=1' "$m" 2>/dev/null; then
        set_key config_file /etc/tgt/targets.conf
        set_key add_file /etc/tgt/targets.conf
        set_key tgtd tgtd
        set_key tgtadm tgtadm
        set_key tgtadmin tgt-admin
        set_key init_name tgtd
        set_key start_cmd "rc-service tgtd start; tgt-admin -e -c /etc/tgt/targets.conf; tgtadm --lld iscsi --op update --mode sys --name State -v ready"
        set_key stop_cmd "tgt-admin --offline ALL; tgt-admin --update ALL -c /dev/null -f; rc-service tgtd stop"
        set_key restart_cmd "tgt-admin --update ALL -c /etc/tgt/targets.conf && tgtadm --lld iscsi --op update --mode sys --name State -v ready"
        echo winlab=1 >> "$m"
    fi
    r=/etc/webmin/raid/config
    [ -f "$r" ] && sed -i 's|^mdadm=.*|mdadm=/etc/mdadm.conf|' "$r"
fi

# ---- sanctl: what the front panel and the graders read -------------------
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/sanctl <<'SANCTL'
#!/bin/sh
# sanctl: the storage array's status (winlab SAN firmware): its bays and
# their drives, md's RAID groups, LVM's volumes, the ports and tgt's
# targets. Read-only, except `drop <tid>`, which closes a target's sessions
# so its initiators log on again (what a drill does after a change).
die() { echo "$*" >&2; exit 1; }
tgt() { tgtadm --lld iscsi "$@"; }
dev_bay() { s=$(cat "/sys/block/$1/serial" 2>/dev/null); case $s in SANBAY*) echo "${s#SANBAY}";; esac; }

drop() {
    tgt --op show --mode target | awk -v t="$1" '
        /^Target / {on = ($2 == t ":")} on && /I_T nexus: / {s = $3} on && /Connection: / {print s, $2}' |
    while read -r s c; do tgt --op delete --mode conn --tid "$1" --sid "$s" --cid "$c" >/dev/null 2>&1; done
}

status() {
    echo "#bays"
    for f in /sys/block/*/serial; do
        d=${f%/serial}; d=${d##*/}; b=$(dev_bay "$d")
        [ -n "$b" ] && echo "bay $b $d $(( $(cat "/sys/block/$d/size") / 2048 ))"
    done
    echo "#pools"
    for m in /sys/block/md*; do
        [ -d "$m/md" ] || continue
        md=${m##*/}
        echo "pool $md $md $(cat "$m/md/level") $(cat "$m/md/array_state") $(cat "$m/md/degraded" 2>/dev/null || echo 0)" \
             "$(cat "$m/md/raid_disks") $(cat "$m/md/sync_action" 2>/dev/null || echo idle)" \
             "$(cat "$m/md/sync_completed" 2>/dev/null | tr -d ' ' || echo none)"
        for dv in "$m"/md/dev-*; do
            [ -d "$dv" ] || continue
            x=${dv##*/dev-}
            echo "member $md $(dev_bay "$x") $x $(cat "$dv/state") $(cat "$dv/slot" 2>/dev/null)"
        done
    done
    echo "#lvs"
    command -v lvs >/dev/null 2>&1 &&
        lvs --noheadings --units g --nosuffix -o vg_name,lv_name,lv_size,devices 2>/dev/null |
        awk '{sub(/\(.*/, "", $4); print $1, $2, int($3 + 0.5), $4}'
    echo "#ports"
    n=1
    for ifc in $(ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | cut -d@ -f1); do
        echo "port $n $ifc $(cat "/sys/class/net/$ifc/carrier" 2>/dev/null || echo 0)" \
             "$(ip -o -4 addr show dev "$ifc" | awk '{print $4}' | head -n 1)"
        n=$((n + 1))
    done
    echo "#tgt"
    tgt --op show --mode target 2>/dev/null
}

case $1 in
    status) status ;;
    drop) [ -n "$2" ] || die "sanctl drop <tid>"; drop "$2" ;;
    drop-all) for t in $(tgt --op show --mode target 2>/dev/null | awk '/^Target / {sub(/:/, "", $2); print $2}'); do drop "$t"; done ;;
    *) die "sanctl: status | drop <tid> | drop-all" ;;
esac
SANCTL
chmod 755 /usr/local/sbin/sanctl

date -Iseconds > "$done_dir/$role"
log "ready: iSCSI on port 3260 of both ports; build it in Webmin, https on port 10000"
