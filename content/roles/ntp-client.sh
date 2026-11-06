#!/bin/sh
# A Linux machine's time client: chrony against the lab's NTP server, or the
# domain controller when the lab has none (WINLAB_NTP_SOURCE, chosen by
# winlab/timesync.py). Never a public pool: the lab has no way out.
#
# On Alpine it is chrony; on Ubuntu chrony when it is installed, else
# systemd-timesyncd, which Ubuntu brings with it. In a lab the student
# configures the client by hand; the role brings chrony onto an Alpine
# machine (its apk) and is the model answer for `winlab roles apply` and CI.

role=ntp-client
done_dir=/var/lib/winlab/done
conf=/etc/chrony/chrony.conf
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

src=$WINLAB_NTP_SOURCE
[ -n "$src" ] || { echo 'no time source in this lab: add an NTP server or a domain controller' >&2; exit 1; }

ifc=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1)
if [ -n "$ifc" ] && [ -n "$WINLAB_NIC0_IP" ] && ! ip -4 addr show dev "$ifc" | grep -q "$WINLAB_NIC0_IP/"; then
    ip link set "$ifc" up
    ip addr replace "$WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX" dev "$ifc" || exit 1
    [ -n "$WINLAB_NIC0_GW" ] && ip route replace default via "$WINLAB_NIC0_GW"
fi

if command -v chronyd >/dev/null 2>&1; then
    [ -d /etc/chrony ] || mkdir -p /etc/chrony
    [ -f /etc/chrony/chrony.conf ] || conf=/etc/chrony.conf
    {
        echo "# winlab: the lab's time, from inside the lab only."
        echo "server $src iburst"
        echo "driftfile /var/lib/chrony/chrony.drift"
        echo "makestep 1 3"
    } > "$conf"
    rm -f "$conf.winlab"
    mkdir -p /var/lib/chrony
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart chrony 2>/dev/null || systemctl restart chronyd 2>/dev/null
    else
        rc-service chronyd stop >/dev/null 2>&1; pkill -x chronyd 2>/dev/null; sleep 1
        rc-service chronyd start >/dev/null 2>&1 || chronyd -f "$conf" || { echo 'chronyd did not start' >&2; exit 1; }
    fi
    log "chrony asks $src"
elif command -v timedatectl >/dev/null 2>&1; then
    mkdir -p /etc/systemd/timesyncd.conf.d
    printf '[Time]\nNTP=%s\nFallbackNTP=\n' "$src" > /etc/systemd/timesyncd.conf.d/winlab.conf
    timedatectl set-ntp true 2>/dev/null
    systemctl restart systemd-timesyncd 2>/dev/null || true
    log "systemd-timesyncd asks $src"
else
    echo 'no time client on this machine (chrony or systemd-timesyncd)' >&2; exit 1
fi

mkdir -p "$done_dir"
date -Iseconds > "$done_dir/$role"
