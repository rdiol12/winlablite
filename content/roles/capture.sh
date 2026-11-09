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

# Termshark (MIT), Wireshark's packet view in a terminal, from the repository
# volume when it was fetched (winlab/termshark.py). It drives the tshark above.
ts=$(for f in /media/*/termshark/termshark; do [ -f "$f" ] && echo "$f"; done | head -n 1)
if [ -z "$ts" ] && d=$(blkid -L WLAPK 2>/dev/null) && [ -n "$d" ]; then
    mkdir -p /media/wlapk
    mountpoint -q /media/wlapk || mount -o ro "$d" /media/wlapk 2>/dev/null
    ts=$(for f in /media/*/termshark/termshark; do [ -f "$f" ] && echo "$f"; done | head -n 1)
fi
if [ -n "$ts" ]; then
    install -m 755 "$ts" /usr/local/bin/termshark.bin
    mkdir -p /usr/share/licenses/termshark
    cp "$(dirname "$ts")/LICENSE" /usr/share/licenses/termshark/LICENSE 2>/dev/null
    # The serial console says vt100; Termshark draws its panes with colour.
    cat > /usr/local/bin/termshark <<'EOF'
#!/bin/sh
case "$TERM" in ''|vt100|vt102|linux|dumb) export TERM=xterm-256color ;; esac
exec /usr/local/bin/termshark.bin "$@"
EOF
    chmod 755 /usr/local/bin/termshark
    log 'termshark ready: termshark -i <interface>, or termshark -r <file>'
else
    log 'termshark not on the repository volume (winlab images prepare fabric fetches it)'
fi

mkdir -p /var/lib/winlab/captures "$done_dir"
date -Iseconds > "$done_dir/$role"
log 'done; captures go in /var/lib/winlab/captures'
