#!/bin/sh
# The lab's monitoring appliance on Ubuntu: Prometheus scrapes every Windows
# machine that has the metrics role (and this machine's own node exporter),
# Grafana draws it. The packages come from the 'grafana' pack (winlab packs
# fetch grafana: Grafana from Grafana Labs' apt repository, Prometheus and the
# node exporter from the Ubuntu archive), plugged in as a USB stick before
# this runs; beside them on the stick winlab put prometheus.yml with the
# lab's targets, starter alert rules, Grafana's provisioning files and two
# dashboards (winlab/metrics.py). The runner prepends WINLAB_* variables
# (roles.sh_env): the lab's one password becomes Grafana's admin password.

role=grafana
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }
export DEBIAN_FRONTEND=noninteractive

[ -f "$done_dir/$role" ] && { log 'already configured'; exit 0; }

# ---- 1. the pack stick: packages and the generated files -------------------
mp="${WINLAB_PACK_MOUNT:-/mnt/winlab-pack}"
mkdir -p "$mp"
mountpoint -q "$mp" || mount -o ro "LABEL=${WINLAB_PACK_LABEL:-WLPACK}" "$mp" 2>/dev/null ||
    { echo "the grafana pack stick is not plugged in (winlab packs fetch grafana, then apply the role again)" >&2; exit 1; }
[ -f "$mp/Packages" ] || { echo "no Packages index on the pack stick at $mp" >&2; exit 1; }
[ -f "$mp/prometheus.yml" ] || { echo "the stick carries no prometheus.yml; it was plugged in by something other than the role runner" >&2; exit 1; }
stage=/var/lib/winlab/grafana
mkdir -p "$stage"
for f in prometheus.yml prometheus-rules.yml grafana-datasource.yaml grafana-dashboards.yaml; do
    cp "$mp/$f" "$stage/$f"
done
cp "$mp"/dash-*.json "$stage/" 2>/dev/null || true

have_grafana() { [ -x /usr/sbin/grafana-server ] || [ -x /usr/share/grafana/bin/grafana-server ] || command -v grafana-server >/dev/null 2>&1; }
if ! command -v prometheus >/dev/null 2>&1 || ! have_grafana; then
    log "installing grafana, prometheus and prometheus-node-exporter from the pack at $mp"
    echo "deb [trusted=yes] file:$mp ./" > /etc/apt/sources.list.d/winlab-pack.list
    apt-get -q -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/winlab-pack.list \
            -o Dir::Etc::sourceparts=- update >/dev/null || { echo 'apt could not read the pack' >&2; exit 1; }
    apt-get -q -y --no-install-recommends \
            -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/winlab-pack.list \
            -o Dir::Etc::sourceparts=- \
            install grafana prometheus prometheus-node-exporter ||
        { echo 'package installation from the pack failed' >&2; exit 1; }
    rm -f /etc/apt/sources.list.d/winlab-pack.list
fi
umount "$mp" 2>/dev/null || true

# ---- 2. Prometheus: the lab's targets and the starter rules ---------------
install -o root -g root -m 0644 "$stage/prometheus.yml" /etc/prometheus/prometheus.yml
mkdir -p /etc/prometheus/rules
install -o root -g root -m 0644 "$stage/prometheus-rules.yml" /etc/prometheus/rules/winlab.yml
if command -v promtool >/dev/null 2>&1; then
    promtool check config /etc/prometheus/prometheus.yml >/dev/null ||
        { echo 'promtool refuses the generated prometheus.yml' >&2; promtool check config /etc/prometheus/prometheus.yml >&2; exit 1; }
fi
systemctl enable prometheus prometheus-node-exporter >/dev/null 2>&1 || true
systemctl restart prometheus || { echo 'prometheus failed to start; see journalctl -u prometheus' >&2; exit 1; }
systemctl restart prometheus-node-exporter 2>/dev/null || true

# ---- 3. Grafana: data source, dashboards, anonymous viewing, admin password
mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards
install -o root -g grafana -m 0640 "$stage/grafana-datasource.yaml" /etc/grafana/provisioning/datasources/winlab.yaml
install -o root -g grafana -m 0640 "$stage/grafana-dashboards.yaml" /etc/grafana/provisioning/dashboards/winlab.yaml
for f in "$stage"/dash-*.json; do
    [ -f "$f" ] && install -o grafana -g grafana -m 0644 "$f" "/var/lib/grafana/dashboards/$(basename "$f")"
done
chown -R grafana:grafana /var/lib/grafana/dashboards
# The lab is isolated: anyone on it may look at the dashboards without a
# login (Viewer); changing anything needs the admin account.
if ! grep -q '^\[auth.anonymous\]' /etc/grafana/grafana.ini 2>/dev/null || ! grep -q '^enabled = true' /etc/grafana/grafana.ini; then
    cat >> /etc/grafana/grafana.ini <<'INI'

; ---- winlab: the lab has no internet and the dashboards are the lesson ----
[auth.anonymous]
enabled = true
org_role = Viewer

[analytics]
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false

[news]
news_feed_enabled = false
INI
fi
systemctl daemon-reload
systemctl enable grafana-server >/dev/null 2>&1 || true
systemctl restart grafana-server || { echo 'grafana-server failed to start; see journalctl -u grafana-server' >&2; exit 1; }

# Wait for Grafana's database, then set the admin password to the lab's.
i=0
until curl -fs http://127.0.0.1:3000/api/health >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -ge 60 ] && break; sleep 2
done
if [ -n "$WINLAB_ADMIN_PASSWORD" ]; then
    if grafana-cli admin reset-admin-password "$WINLAB_ADMIN_PASSWORD" >/dev/null 2>&1 ||
       grafana cli admin reset-admin-password "$WINLAB_ADMIN_PASSWORD" >/dev/null 2>&1; then
        log 'Grafana admin password set to the lab password'
    else
        echo 'warning: could not set the Grafana admin password; log in as admin / admin and change it' >&2
    fi
fi

# ---- 4. the firewall, when one is on: Grafana, Prometheus, node exporter --
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 3000/tcp >/dev/null 2>&1; ufw allow 9090/tcp >/dev/null 2>&1; ufw allow 9100/tcp >/dev/null 2>&1
fi

mkdir -p "$done_dir"
date -Iseconds > "$done_dir/$role"
targets=$(grep -c '^      - targets:' /etc/prometheus/prometheus.yml 2>/dev/null || echo 0)
log "done: Grafana on http://$(hostname):3000 (admin, the lab password; viewing needs no login), Prometheus on 9090, $targets scrape targets"
