#!/bin/sh
# The web farm's front door on the Ubuntu appliance: nginx from the 'nginx'
# pack (winlab packs fetch nginx), plugged in as a USB stick before this
# runs, proxies intranet.<domain> and wiki.<domain> to an upstream of the
# IIS machines in vars.backends (WINLAB_BACKENDS), with passive health
# checks: a backend that fails twice is left out for 10 seconds, and a
# request that meets a 502/503 is retried on the other one. With a
# certificate at /etc/ssl/winlab/intranet.pem (its chain) and intranet.key,
# port 80 redirects to HTTPS; without one it serves plain HTTP. This is the
# model answer of the nginx lesson, for `winlab roles apply` and CI; in the
# lab the student writes the same files by hand.

role=web-proxy
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }
export DEBIAN_FRONTEND=noninteractive

[ -f "$done_dir/$role" ] && { log 'already configured'; exit 0; }
domain="${WINLAB_DOMAIN:-corp.lab}"
backends="${WINLAB_BACKENDS:-}"
[ -n "$backends" ] || { echo 'no backends: set vars.backends on this machine (the IIS servers)' >&2; exit 1; }

# ---- 1. nginx from the pack stick ----------------------------------------
if ! command -v nginx >/dev/null 2>&1; then
    mp="${WINLAB_PACK_MOUNT:-/mnt/winlab-pack}"
    mkdir -p "$mp"
    mountpoint -q "$mp" || mount -o ro "LABEL=${WINLAB_PACK_LABEL:-WLPACK}" "$mp" 2>/dev/null ||
        { echo "the nginx pack stick is not plugged in (winlab packs fetch nginx, then apply the role again)" >&2; exit 1; }
    [ -f "$mp/Packages" ] || { echo "no Packages index on the pack stick at $mp" >&2; exit 1; }
    log "installing nginx from the pack at $mp"
    echo "deb [trusted=yes] file:$mp ./" > /etc/apt/sources.list.d/winlab-pack.list
    apt-get -q -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/winlab-pack.list \
            -o Dir::Etc::sourceparts=- update >/dev/null || { echo 'apt could not read the pack' >&2; exit 1; }
    apt-get -q -y --no-install-recommends \
            -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/winlab-pack.list \
            -o Dir::Etc::sourceparts=- install nginx || { echo 'installing nginx from the pack failed' >&2; exit 1; }
    rm -f /etc/apt/sources.list.d/winlab-pack.list
    umount "$mp" 2>/dev/null || true
fi

# ---- 2. the upstream and the virtual hosts -------------------------------
servers=""
first=""
for b in $backends; do
    case "$b" in *.*) h="$b" ;; *) h="$b.$domain" ;; esac
    [ -n "$first" ] || first="$h"
    servers="$servers    server $h:80 max_fails=2 fail_timeout=10s;
"
done
proxy='        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_next_upstream error timeout http_502 http_503;'
cert=/etc/ssl/winlab/intranet.pem
key=/etc/ssl/winlab/intranet.key
{
    echo "# winlab web-proxy: intranet.$domain over the farm, wiki.$domain on $first"
    echo "upstream intranet_farm {"
    printf '%s' "$servers"
    echo "}"
    if [ -s "$cert" ] && [ -s "$key" ]; then
        echo "server {"
        echo "    listen 80;"
        echo "    server_name intranet.$domain wiki.$domain;"
        echo '    return 301 https://$host$request_uri;'
        echo "}"
        listen="443 ssl"
        tls="    ssl_certificate $cert;
    ssl_certificate_key $key;"
    else
        listen="80"
        tls=""
    fi
    for site in intranet wiki; do
        [ "$site" = intranet ] && to="http://intranet_farm" || to="http://$first"
        echo "server {"
        echo "    listen $listen;"
        echo "    server_name $site.$domain;"
        [ -n "$tls" ] && echo "$tls"
        echo "    location / {"
        echo "        proxy_pass $to;"
        echo "$proxy"
        echo "    }"
        echo "}"
    done
} > /etc/nginx/sites-available/intranet
ln -sf /etc/nginx/sites-available/intranet /etc/nginx/sites-enabled/intranet
rm -f /etc/nginx/sites-enabled/default

nginx -t 2>/dev/null || { echo 'nginx refuses the configuration (nginx -t)' >&2; nginx -t >&2; exit 1; }
systemctl enable nginx >/dev/null 2>&1 || true
systemctl reload nginx 2>/dev/null || systemctl restart nginx || { echo 'nginx failed to start; see journalctl -u nginx' >&2; exit 1; }

# ---- 3. the firewall, when one is on -------------------------------------
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 80/tcp >/dev/null 2>&1; ufw allow 443/tcp >/dev/null 2>&1
fi

mkdir -p "$done_dir"
date -Iseconds > "$done_dir/$role"
log "done: intranet.$domain over $(echo $backends | wc -w) backends ($backends), wiki.$domain on $first$([ -n "$tls" ] && echo ', HTTP redirects to HTTPS')"
