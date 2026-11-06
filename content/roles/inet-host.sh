#!/bin/sh
# A host on the Internet side of a lab (the ISP segment), for testing a
# firewall from the inside: it answers HTTP on port 80 and on port 8080, and
# writes down where each connection came from. A PC behind the firewall that
# opens http://<this host>/ reads back the address it arrived from, which is
# the firewall's WAN address when outbound NAT works; port 8080 is the port
# the lesson blocks, so a refused 8080 means the firewall, not a dead service.
# The log is /var/log/inet-host.log, one line per connection: time, port,
# source address.
#
# It plays somebody else's equipment (the Internet), so the lab brings it up
# by itself at start.

role=inet-host
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

command -v tcpsvd >/dev/null 2>&1 || { echo 'tcpsvd missing from the probe (prepare the router again in Setup)' >&2; exit 1; }

ifc=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1)
[ -n "$ifc" ] || { echo 'no network interface found' >&2; exit 1; }
ip link set "$ifc" up
if [ -n "$WINLAB_NIC0_IP" ]; then
    log "address $WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX"
    ip addr replace "$WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX" dev "$ifc" || exit 1
    [ -n "$WINLAB_NIC0_GW" ] && ip route replace default via "$WINLAB_NIC0_GW"
fi

mkdir -p "$done_dir"
touch /var/log/inet-host.log
cat > /usr/local/bin/winlab-inet-answer <<'ANSWER'
#!/bin/sh
# One HTTP answer per connection (tcpsvd sets TCPREMOTEIP and TCPLOCALPORT).
read -r _line
echo "$(date -Iseconds) $TCPLOCALPORT $TCPREMOTEIP" >> /var/log/inet-host.log
body="you reached $(hostname) on port $TCPLOCALPORT from $TCPREMOTEIP"
printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
    "${#body}" "$body"
ANSWER
chmod 755 /usr/local/bin/winlab-inet-answer
for port in 80 8080; do
    pkill -f "[t]cpsvd .* $port " 2>/dev/null  # [t]: not this script's own text
    tcpsvd -E 0.0.0.0 "$port" /usr/local/bin/winlab-inet-answer >/dev/null 2>&1 &
    log "answering HTTP on port $port"
done

date -Iseconds > "$done_dir/$role"
