#!/bin/sh
# A home worker's broadband router, on a small Alpine host: the house's
# network on one side (NIC 0, eth0), one public address on the lab Internet
# on the other (NIC 1, eth1), as an ISP's box gives a house. It does what
# every home router does and nothing more:
#
#   - routes the house out to the Internet behind NAT (masquerade on eth1),
#     so the company's VPN edge sees the house's one public address;
#   - lets nothing in from the Internet that the house did not ask for;
#   - hands the house addresses by DHCP (from .100, the router as gateway
#     and DNS) and answers DNS by asking the Internet's DNS server (.53 on
#     the Internet's segment, role inet-sites).
#
# The house has no route to the office: the only thing a laptop here can
# reach of the company is what the company publishes on the Internet (its
# VPN edge). The lab never reaches the real internet; this Internet is the
# lab's own segment. It plays somebody else's equipment (the ISP's box), so
# the lab brings it up by itself at start; nobody in the lab configures it.

role=home-router
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

for b in iptables dnsmasq; do
    command -v "$b" >/dev/null 2>&1 || { echo "$b missing from the Alpine packages (prepare the router again in Setup)" >&2; exit 1; }
done
[ -n "$WINLAB_NIC0_IP" ] && [ -n "$WINLAB_NIC1_IP" ] || { echo 'the home router needs two cables: the house (NIC 1) and the Internet (NIC 2)' >&2; exit 1; }

ip link set eth0 up && ip link set eth1 up || exit 1
ip addr replace "$WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX" dev eth0 || exit 1
ip addr replace "$WINLAB_NIC1_IP/$WINLAB_NIC1_PREFIX" dev eth1 || exit 1
log "house eth0 $WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX, Internet eth1 $WINLAB_NIC1_IP/$WINLAB_NIC1_PREFIX"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# NAT and a home router's firewall: out freely, back only what was asked for.
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
iptables -F FORWARD
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
log "NAT: the house goes out as $WINLAB_NIC1_IP; nothing comes in unasked"

# DHCP and DNS for the house; names are asked of the Internet's DNS.
net=$(echo "$WINLAB_NIC0_IP" | awk -F. '{print $1"."$2"."$3}')
inet_dns=$(echo "$WINLAB_NIC1_IP" | awk -F. '{print $1"."$2"."$3".53"}')
mkdir -p /etc/winlab-home "$done_dir"
cat > /etc/winlab-home/dnsmasq.conf <<EOF
# The home router's DHCP and DNS for the house.
interface=eth0
bind-interfaces
no-resolv
no-hosts
server=$inet_dns
domain=home.arpa
dhcp-range=$net.100,$net.199,255.255.255.0,12h
dhcp-option=option:router,$WINLAB_NIC0_IP
dhcp-option=option:dns-server,$WINLAB_NIC0_IP
dhcp-authoritative
log-dhcp
log-facility=/var/log/home-router.log
pid-file=/run/winlab-home-dnsmasq.pid
EOF
[ -f /run/winlab-home-dnsmasq.pid ] && kill "$(cat /run/winlab-home-dnsmasq.pid)" 2>/dev/null
sleep 1
dnsmasq --conf-file=/etc/winlab-home/dnsmasq.conf || exit 1
log "DHCP $net.100-$net.199 on eth0, DNS forwarded to $inet_dns"

date -Iseconds > "$done_dir/$role"
