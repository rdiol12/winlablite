#!/bin/sh
# An NTP server on the Alpine appliance, the way a time server sits on the
# office rack: chrony serves its own clock to the lab's networks. It has no
# upstream at all: its clock is the RTC, which winlab starts at lab time, so
# what it serves is lab time (winlab/timesync.py). It never asks this PC or
# the internet, and nothing in its configuration names a server or a pool.
#
# The runner prepends WINLAB_NTP_STRATUM (what it reports itself as) and
# WINLAB_NTP_ALLOW (the networks it answers), set on its workbench panel.
# The PDC emulator syncs from it:
#   w32tm /config /manualpeerlist:"<this address>,0x8" /syncfromflags:manual /reliable:yes /update
#
# The device runs this at every power-on: it is the time server's firmware.

role=ntp-server
done_dir=/var/lib/winlab/done
conf=/etc/chrony/chrony.conf
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

command -v chronyd >/dev/null 2>&1 || { echo 'chrony missing from the appliance (prepare the router again in Setup)' >&2; exit 1; }

ifc=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1)
[ -n "$ifc" ] || { echo 'no network interface found' >&2; exit 1; }
ip link set "$ifc" up
if [ -n "$WINLAB_NIC0_IP" ]; then
    log "address $WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX"
    ip addr replace "$WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX" dev "$ifc" || exit 1
    [ -n "$WINLAB_NIC0_GW" ] && ip route replace default via "$WINLAB_NIC0_GW"
elif ! ip -4 addr show dev "$ifc" | grep -q 'inet '; then
    log "asking for an address (DHCP) as $WINLAB_HOSTNAME"
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" -q -t 10 -T 2 >/dev/null 2>&1 ||
        log 'no DHCP answer yet; it keeps asking in the background'
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" >/dev/null 2>&1 &
fi

stratum=${WINLAB_NTP_STRATUM:-3}
mkdir -p /etc/chrony /etc/winlab-ntp /var/lib/chrony "$done_dir"
{
    echo "# winlab NTP server: serves its own clock (lab time), no upstream."
    echo "local stratum $stratum"
    echo "driftfile /var/lib/chrony/chrony.drift"
    echo "manual"
} > "$conf"
: > /etc/winlab-ntp/allow
for net in $WINLAB_NTP_ALLOW; do echo "allow $net" >> /etc/winlab-ntp/allow; done
[ -s /etc/winlab-ntp/allow ] || echo 'allow' > /etc/winlab-ntp/allow
cat /etc/winlab-ntp/allow >> "$conf"
rm -f "$conf.winlab"

rc-service chronyd stop >/dev/null 2>&1
pkill -x chronyd 2>/dev/null
sleep 1
rc-service chronyd start >/dev/null 2>&1 || chronyd -f "$conf" || { echo 'chronyd did not start' >&2; exit 1; }

date -Iseconds > "$done_dir/$role"
log "ready: stratum $stratum on UDP 123 for $(tr '\n' ' ' < /etc/winlab-ntp/allow | sed 's/allow //g')"
