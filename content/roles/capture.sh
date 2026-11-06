#!/bin/sh
# Packet-capture probe on the Alpine node: address the native NIC, add a
# passive VLAN sub-interface for every VLAN its trunk carries, and check the
# capture tools are present. The runner prepends WINLAB_NIC<i>_* variables
# (see roles.sh_env), because Linux nodes get no facts.json disk.
#
# After this, `tcpdump -i eth0.10 -nn port 53` on the probe shows DNS on the
# HQ server VLAN, tagged frames and all.

role=capture
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

[ -f "$done_dir/$role" ] && { log 'already configured'; exit 0; }

for tool in tcpdump tshark nmap; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool missing from the probe image" >&2; exit 1; }
done

# First non-loopback interface carries NIC 0.
ifc=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1)
[ -n "$ifc" ] || { echo 'no network interface found' >&2; exit 1; }
ip link set "$ifc" up

if [ -n "$WINLAB_NIC0_IP" ]; then
    log "addressing $ifc as $WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX via $WINLAB_NIC0_GW"
    ip addr replace "$WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX" dev "$ifc" || exit 1
    ip route replace default via "$WINLAB_NIC0_GW" || exit 1
fi

if [ -n "$WINLAB_NIC0_TRUNK_VIDS" ]; then
    modprobe 8021q 2>/dev/null
    for vid in $WINLAB_NIC0_TRUNK_VIDS; do
        sub="$ifc.$vid"
        ip link show "$sub" >/dev/null 2>&1 ||
            ip link add link "$ifc" name "$sub" type vlan id "$vid" || exit 1
        ip link set "$sub" up
        log "listening sub-interface $sub (vlan $vid, no address)"
    done
fi

mkdir -p /var/lib/winlab/captures "$done_dir"
date -Iseconds > "$done_dir/$role"
log 'done; captures go in /var/lib/winlab/captures'
