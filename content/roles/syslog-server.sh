#!/bin/sh
# A central syslog server on the Ubuntu appliance: rsyslog (in the image)
# listens on UDP and TCP 514 and files what arrives per sending host under
# /var/log/remote/<host>/<program>.log. Windows machines send with the
# monitoring role's forwarder or any syslog agent; the lab router and other
# Linux machines with their own rsyslog or logger. Rotated daily, 14 days.

role=syslog-server
done_dir=/var/lib/winlab/done
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

[ -f "$done_dir/$role" ] && { log 'already configured'; exit 0; }
command -v rsyslogd >/dev/null 2>&1 || { echo 'rsyslog is missing from this image' >&2; exit 1; }

mkdir -p /var/log/remote
chown syslog:adm /var/log/remote 2>/dev/null || true
chmod 750 /var/log/remote

cat > /etc/rsyslog.d/10-winlab-remote.conf <<'CONF'
# winlab: receive syslog from the lab on UDP and TCP 514, one tree per host.
module(load="imudp")
input(type="imudp" port="514" ruleset="remote")
module(load="imtcp")
input(type="imtcp" port="514" ruleset="remote")

template(name="RemoteFile" type="string"
         string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME:::secpath-replace%.log")
template(name="RemoteLine" type="string"
         string="%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")

ruleset(name="remote") {
    action(type="omfile" dynaFile="RemoteFile" template="RemoteLine"
           dirCreateMode="0750" fileCreateMode="0640" dirOwner="syslog" dirGroup="adm")
}
CONF

cat > /etc/logrotate.d/winlab-remote <<'CONF'
/var/log/remote/*/*.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
CONF

rsyslogd -N1 >/dev/null 2>&1 || { echo 'rsyslog refuses the configuration (rsyslogd -N1)' >&2; rsyslogd -N1 >&2; exit 1; }
systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl restart rsyslog || { echo 'rsyslog failed to start; see journalctl -u rsyslog' >&2; exit 1; }

# The firewall, when one is on: let the lab in.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 514/udp >/dev/null 2>&1; ufw allow 514/tcp >/dev/null 2>&1
fi

# A first line from this host, so the tree exists before anything else arrives.
logger -n 127.0.0.1 -P 514 -d -t winlab "syslog server ready on $(hostname)" 2>/dev/null || true

mkdir -p "$done_dir"
date -Iseconds > "$done_dir/$role"
log 'done: listening on 514/udp and 514/tcp; logs under /var/log/remote/<host>/'
