#!/bin/sh
# The Internet of a web-filtering lab, on one Alpine host on the outside
# segment: a handful of web sites under made-up .example names (RFC 2606,
# never real brands) and the Internet's DNS server that knows them. The lab
# has no real internet and never gets one; this host is all the "outside" a
# proxy lesson needs.
#
#   203.0.113.80  the sites, HTTP on 80 and HTTPS on 443, chosen by name
#                 (Host header, SNI): news, wiki, games (and play.games),
#                 shop, social, video, and pki.example, where the sites'
#                 certificate authority publishes its root (/root.crt)
#   203.0.113.53  the Internet's DNS: every *.example name -> 203.0.113.80,
#                 except the public names a lab gives other hosts on the
#                 Internet (node vars inet_names = ["vpn.corp.example=
#                 203.0.113.10"]: a company's VPN edge in the remote-access lab)
#
# The HTTPS certificate comes from "Example Trust Services Root", a CA that
# plays the public CAs a real PC already trusts. Its key is derived from a
# fixed seed, so the root is the same on every boot and in every copy of the
# lab: a PC that trusts it once keeps trusting it. It is a lab CA for made-up
# names, published on purpose, and worth nothing outside the lab.
#
# Every site also answers /uid/index.html with the plain text
# "uid=0(root) gid=0(root) groups=0(root)": the well-known, harmless test page
# for a network IDS (the same body the public "test my NIDS" pages serve).
# It attacks nothing; a sensor's stock rule (ET Open sid 2100498) reports it,
# so the intrusion-detection lab gets a real alert from a plain curl.
#
# Every visit is logged to /var/log/inet-sites.log (time, source address,
# scheme, site, path, status), so a lesson can see who reached the Internet
# directly and who came through the proxy. Each page shows the address the
# visit came from.
#
# It plays somebody else's equipment (the Internet), so the lab brings it up
# by itself at start; nobody in the lab configures it.

role=inet-sites
done_dir=/var/lib/winlab/done
etc=/etc/winlab-sites
www=/srv/winlab-sites
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

for b in nginx openssl dnsmasq; do
    command -v "$b" >/dev/null 2>&1 || { echo "$b missing from the Alpine packages (prepare the router again in Setup)" >&2; exit 1; }
done

ifc=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1)
[ -n "$ifc" ] || { echo 'no network interface found' >&2; exit 1; }
ip link set "$ifc" up
SITES_IP=${WINLAB_NIC0_IP:-203.0.113.80}
PREFIX=${WINLAB_NIC0_PREFIX:-24}
DNS_IP=$(echo "$SITES_IP" | awk -F. '{print $1"."$2"."$3".53"}')
log "sites $SITES_IP/$PREFIX, DNS $DNS_IP"
ip addr replace "$SITES_IP/$PREFIX" dev "$ifc" || exit 1
ip addr replace "$DNS_IP/$PREFIX" dev "$ifc" || exit 1
# Back to the office only through its router (rt01), as on the real Internet.
[ -n "$WINLAB_NIC0_GW" ] && ip route replace default via "$WINLAB_NIC0_GW"

mkdir -p "$done_dir" "$etc" "$www"
touch /var/log/inet-sites.log /var/log/inet-dns.log

# ---------------------------------------------------------------- the CA
# The root's key from a fixed seed (an EC P-256 private key is any number
# below the curve's order): the same root on every boot.
seed=$(printf '%s' 'winlab: the Example Trust Services root of the lab Internet' | sha256sum | cut -c1-64)
cat > "$etc/rootkey.asn1" <<EOF
asn1=SEQUENCE:ec
[ec]
version=INTEGER:1
key=FORMAT:HEX,OCTETSTRING:$seed
params=EXPLICIT:0,OID:prime256v1
EOF
openssl asn1parse -genconf "$etc/rootkey.asn1" -out "$etc/root.der" -noout >/dev/null || exit 1
openssl ec -inform DER -in "$etc/root.der" -out "$etc/root.key" 2>/dev/null || exit 1
rm -f "$etc/root.der" "$etc/rootkey.asn1"
chmod 600 "$etc/root.key"
openssl req -x509 -new -key "$etc/root.key" -sha256 -days 3650 -set_serial 1 \
    -subj '/C=ZZ/O=Example Trust Services/CN=Example Trust Services Root' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' -out "$etc/root.crt" || exit 1

SITES="news wiki games shop social video pki"
san=""
for s in $SITES; do san="$san,DNS:$s.example,DNS:*.$s.example"; done
san=${san#,}
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj '/O=Example Hosting/CN=news.example' -keyout "$etc/sites.key" -out "$etc/sites.csr" 2>/dev/null || exit 1
cat > "$etc/sites.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=$san
EOF
openssl x509 -req -in "$etc/sites.csr" -CA "$etc/root.crt" -CAkey "$etc/root.key" -sha256 -days 397 \
    -set_serial "0x$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')" -extfile "$etc/sites.ext" \
    -out "$etc/sites.crt" 2>/dev/null || exit 1
chmod 600 "$etc/sites.key"

# ---------------------------------------------------------------- the sites
page() {  # page <site> <title> <colour> <text>
    mkdir -p "$www/$1"
    cat > "$www/$1/index.html" <<EOF
<!doctype html>
<html><head><meta charset="utf-8"><meta name="winlab-site" content="$1.example">
<title>$2</title>
<style>body{font:15px 'Segoe UI',sans-serif;margin:0;background:#f4f5f7;color:#222}
header{background:$3;color:#fff;padding:18px 28px;font-size:22px}main{padding:18px 28px}
small{color:#666}</style></head>
<body><header>$2</header><main><p>$4</p>
<p><small>$1.example on the lab Internet: you reached it from <!--# echo var="remote_addr" -->
over <!--# echo var="scheme" -->.</small></p></main></body></html>
EOF
}
page news   "News Example: today's headlines" "#1f5fa8" "Markets steady, weather mild, the office network works. A site the company allows."
page wiki   "Wiki Example: the free reference" "#4a5560" "Articles on everything, written by everyone. A site the company allows."
page games  "Games Example: play now" "#b23a48" "Thousands of browser games. The company blocks this one."
mkdir -p "$www/play.games"; cp "$www/games/index.html" "$www/play.games/index.html"
page shop   "Shop Example: deals of the day" "#c27c0e" "Everything half price until noon. Allowed only at lunch time."
page social "Social Example: what friends are saying" "#6b3fb0" "Posts, likes and photos. Allowed only for the marketing team."
page video  "Video Example: watch anything" "#20805a" "Hours of video. On no list at all: what does the proxy do with it?"
page pki    "Example Trust Services" "#2b2f36" "The certificate authority behind every HTTPS site on the lab Internet. Its root: <a href=\"/root.crt\">root.crt</a>."
cp "$etc/root.crt" "$www/pki/root.crt"

cat > "$etc/nginx.conf" <<EOF
user nginx;
worker_processes 1;
pid /run/winlab-sites-nginx.pid;
error_log /var/log/inet-sites-error.log warn;
events { worker_connections 256; }
http {
    include /etc/nginx/mime.types;
    log_format inet '\$time_iso8601 \$remote_addr \$scheme \$host \$request_uri \$status';
    access_log /var/log/inet-sites.log inet;
    ssl_certificate $etc/sites.crt;
    ssl_certificate_key $etc/sites.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssi on;
    server {
        listen 80 default_server;
        listen 443 ssl default_server;
        server_name _;
        default_type text/plain;
        location / { return 404 "no site by that name on the lab Internet\n"; }
    }
EOF
for s in $SITES play.games; do
    names="$s.example"
    [ "$s" = "play.games" ] || names="$s.example www.$s.example"
    crt=""
    [ "$s" = "pki" ] && crt='location ~ \.crt$ { types { } default_type application/x-x509-ca-cert; }'
    cat >> "$etc/nginx.conf" <<EOF
    server {
        listen 80;
        listen 443 ssl;
        server_name $names;
        root $www/$s;
        add_header X-Example-Site $s.example always;
        location = /uid/index.html { default_type text/plain; return 200 "uid=0(root) gid=0(root) groups=0(root)\n"; }
        $crt
    }
EOF
done
echo "}" >> "$etc/nginx.conf"

[ -f /run/winlab-sites-nginx.pid ] && kill "$(cat /run/winlab-sites-nginx.pid)" 2>/dev/null
sleep 1
nginx -t -c "$etc/nginx.conf" >/dev/null 2>&1 || { nginx -t -c "$etc/nginx.conf"; exit 1; }
nginx -c "$etc/nginx.conf" || exit 1
log "sites on $SITES_IP: $(echo $SITES | sed 's/\([a-z]*\)/\1.example/g'), HTTP and HTTPS"

# ---------------------------------------------------------------- the DNS
cat > "$etc/dnsmasq.conf" <<EOF
# The lab Internet's DNS server: authoritative for every *.example name.
listen-address=$DNS_IP
bind-interfaces
no-resolv
no-hosts
address=/example/$SITES_IP
address=/ns.example/$DNS_IP
log-queries
log-facility=/var/log/inet-dns.log
pid-file=/run/winlab-sites-dnsmasq.pid
EOF
# Other hosts' public names (WINLAB_INET_NAMES: name=address ...); the longer
# name wins over address=/example/ in dnsmasq.
for pair in $WINLAB_INET_NAMES; do
    n=${pair%%=*}; a=${pair#*=}
    case "$n" in *.example) ;; *) log "skipping $n: only .example names on the lab Internet"; continue ;; esac
    echo "address=/$n/$a" >> "$etc/dnsmasq.conf"
    log "DNS: $n -> $a"
done
[ -f /run/winlab-sites-dnsmasq.pid ] && kill "$(cat /run/winlab-sites-dnsmasq.pid)" 2>/dev/null
sleep 1
dnsmasq --conf-file="$etc/dnsmasq.conf" || exit 1
log "DNS on $DNS_IP: *.example -> $SITES_IP"

date -Iseconds > "$done_dir/$role"
