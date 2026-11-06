#!/bin/sh
# A network printer on the Alpine appliance, the way an office laser printer
# sits on the LAN: it takes its address from DHCP (or the one the lab gives
# it), answers SNMP so Windows sees it online, prints whatever reaches port
# 9100 (raw, "JetDirect") and runs CUPS, the print server, with its web
# pages on port 631 for the lab's networks (https://<printer>:631/).
#
# Out of the box CUPS has no queue, as a print server fresh from the box:
# the student adds one in its web pages (Administration > Add Printer),
# picks the printer's own engine ("Output tray" under Local Printers),
# shares it, and Windows adds it over IPP
# (http://<printer>:631/printers/<queue>) or over TCP/IP to port 9100.
# Either way each page that comes out lands in /var/spool/tray as its own
# file: the paper tray the workbench's printer panel shows.
#
# Signing in to CUPS's administration pages: root, with the lab's password
# (Start > Lab password); CUPS checks it against the device's own accounts
# (Basic authentication), and this sets root's to the one the runner gives.
#
# The printer's own front panel (the workbench's printer window): the paper
# tray, the front door, the Online button, the toner. Each is a flag in
# /var/lib/printer-panel, the printer engine's sensors: nopaper, jam,
# door-open, offline, toner-low (and cancel, the Cancel button). While one
# stops the engine, a job waits in the engine the way it does on a real
# printer: CUPS shows it processing with the printer's reason
# (media-empty-error, media-jam-error, door-open-error, offline-report), a
# raw job on 9100 sits in the printer's buffer, and both come out when the
# paper is loaded, the jam cleared (open the door, close it) or the printer
# put online again. Toner low only warns (toner-low-report).
#
# What the student sets up in CUPS (its queues, sharing, job history, the
# server settings) lives on the printer's flash, its small data disk, and
# stays there between starts; the first start writes CUPS's factory
# settings there. The device runs this at every power-on: it is the
# printer's firmware.

role=netprinter
done_dir=/var/lib/winlab/done
tray=/var/spool/tray
flash=/var/lib/printer
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

for tool in tcpsvd snmpd udhcpc cupsd mkfs.ext4; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool missing from the appliance (prepare the router again in Setup)" >&2; exit 1; }
done

ifc=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1)
[ -n "$ifc" ] || { echo 'no network interface found' >&2; exit 1; }
ip link set "$ifc" up
if [ -n "$WINLAB_NIC0_IP" ]; then
    log "address $WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX"
    ip addr replace "$WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX" dev "$ifc" || exit 1
    [ -n "$WINLAB_NIC0_GW" ] && ip route replace default via "$WINLAB_NIC0_GW"
else
    log "asking for an address (DHCP) as $WINLAB_HOSTNAME"
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" -q -t 10 -T 2 >/dev/null 2>&1 ||
        log 'no DHCP answer yet; it keeps asking in the background'
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" >/dev/null 2>&1 &
fi

panel=/var/lib/printer-panel
mkdir -p "$tray" "$done_dir" /etc/snmp "$panel"
rm -f "$panel/cancel" "$panel/busy"
# The engine's state, from the panel's flags (the first that stops it).
cat > /usr/local/bin/winlab-printer-state <<'STATE'
#!/bin/sh
p=/var/lib/printer-panel
if [ -e $p/door-open ]; then echo door-open
elif [ -e $p/jam ]; then echo jam
elif [ -e $p/nopaper ]; then echo paper-out
elif [ -e $p/offline ]; then echo offline
else echo ready
fi
STATE
chmod 755 /usr/local/bin/winlab-printer-state
# One job per connection, named by its arrival; the panel lists them. A job
# that arrives while the engine is stopped waits in the buffer.
cat > /usr/local/bin/winlab-print-job <<'JOB'
#!/bin/sh
f="/var/spool/tray/$(date +%Y%m%d-%H%M%S)-$$.prn"
cat > "$f.part" || exit 0
while [ "$(winlab-printer-state)" != ready ]; do
    [ -e /var/lib/printer-panel/cancel ] && { rm -f /var/lib/printer-panel/cancel "$f.part"; exit 0; }
    touch /var/lib/printer-panel/busy
    sleep 2
done
rm -f /var/lib/printer-panel/busy
mv "$f.part" "$f"
JOB
chmod 755 /usr/local/bin/winlab-print-job
pkill -f '[t]cpsvd .* 9100' 2>/dev/null  # [t]: not this script's own text (it runs as sh -c)
tcpsvd -E 0.0.0.0 9100 /usr/local/bin/winlab-print-job >/dev/null 2>&1 &

# SNMP: the printer MIB's status (idle, 3) and a description, read-only on
# the community Windows asks with ("public").
cat > /etc/snmp/snmpd.conf <<CONF
agentAddress udp:161
rocommunity public
sysName ${WINLAB_HOSTNAME:-printer}
sysDescr winlab network printer (CUPS, IPP on 631, raw 9100, PCL and text)
sysLocation ${WINLAB_PRINTER_LOCATION:-office}
sysContact the lab's administrator
CONF
pkill snmpd 2>/dev/null
snmpd -c /etc/snmp/snmpd.conf -Lsd udp:161 || log 'SNMP did not start: Windows may show the printer offline'

# ---- the flash: the last unlabelled whole disk (the system disk comes
# first, winlab's own volumes are labelled WL*), formatted on first start.
disks=""
for d in $(ls /dev/sd? /dev/vd? 2>/dev/null | sort); do
    blkid "$d" 2>/dev/null | grep -q 'LABEL="WL' && continue   # winlab's own volumes
    disks="$disks $d"
done
set -- $disks
if [ $# -ge 2 ]; then
    eval "disk=\${$#}"
    if ! blkid "$disk" 2>/dev/null | grep -q 'LABEL="prnflash"'; then
        log "formatting its flash $disk (first start)"
        mkfs.ext4 -q -L prnflash "$disk" || exit 1
    fi
    mkdir -p "$flash"
    grep -qs " $flash " /proc/mounts || mount -L prnflash "$flash" || exit 1
else
    log 'no flash disk: CUPS settings last until power-off'
    mkdir -p "$flash"
fi

# ---- the printer's engine, as a CUPS backend: "Output tray" under Local
# Printers on Add Printer. Mode 0700, so CUPS runs it as root.
mkdir -p /usr/lib/cups/backend
cat > /usr/lib/cups/backend/tray <<'BACKEND'
#!/bin/sh
# CUPS backend: job-id user title copies options [file]
if [ $# -eq 0 ]; then
    echo 'direct tray:/ "Unknown" "Output tray (this printer'"'"'s own print engine)"'
    exit 0
fi
p=/var/lib/printer-panel
if [ -e $p/toner-low ]; then echo 'STATE: +toner-low-report' >&2; echo 'ATTR: marker-levels=8' >&2
else echo 'STATE: -toner-low-report' >&2; echo 'ATTR: marker-levels=80' >&2
fi
# The engine stopped (no paper, a jam, the door open, offline): the job
# waits here, processing, with the printer's reason, until it can print.
while :; do
    s=$(/usr/local/bin/winlab-printer-state)
    [ "$s" = ready ] && break
    [ -e $p/cancel ] && { rm -f $p/cancel $p/busy; echo 'INFO: cancelled at the printer' >&2; exit 0; }
    touch $p/busy
    case "$s" in
        paper-out) echo 'STATE: +media-empty-error' >&2; echo 'INFO: Load paper in tray 1' >&2 ;;
        jam) echo 'STATE: +media-jam-error' >&2; echo 'INFO: Paper jam' >&2 ;;
        door-open) echo 'STATE: +door-open-error' >&2; echo 'INFO: Close the front door' >&2 ;;
        offline) echo 'STATE: +offline-report' >&2; echo 'INFO: The printer is offline' >&2 ;;
    esac
    sleep 3
done
rm -f $p/busy
echo 'STATE: -media-empty-error,media-jam-error,door-open-error,offline-report' >&2
f="/var/spool/tray/$(date +%Y%m%d-%H%M%S)-$$.prn"
n=${4:-1}
[ "$n" -ge 1 ] 2>/dev/null || n=1
: > "$f.part"
while [ "$n" -gt 0 ]; do
    if [ -n "$6" ]; then cat "$6"; else cat; fi >> "$f.part" || exit 1
    [ -n "$6" ] || break   # standard input reads once
    n=$((n - 1))
done
mv "$f.part" "$f"
echo "INFO: printed to the output tray" >&2
exit 0
BACKEND
chmod 700 /usr/lib/cups/backend/tray

# ---- CUPS: factory settings on the flash the first time, then the
# student's from there. /etc/cups (cupsd.conf, printers.conf, the PPDs) and
# /var/spool/cups (job history) live on the flash.
if [ ! -f "$flash/cups/cupsd.conf" ]; then
    log 'writing CUPS factory settings'
    mkdir -p "$flash/cups" "$flash/spool"
    cp -a /etc/cups/. "$flash/cups/" 2>/dev/null
    cat > "$flash/cups/cupsd.conf" <<'CONF'
# CUPS as this printer ships: web interface on, administration from the
# lab's networks, sign-in with the device's own accounts (Basic), and
# encryption required as CUPS itself prefers: port 631 answers https with
# the self-signed certificate CUPS makes for itself on first use.
LogLevel warn
MaxLogSize 1m
PageLogFormat
Listen 0.0.0.0:631
Listen /run/cups/cups.sock
ServerAlias *
Browsing No
WebInterface Yes
DefaultAuthType Basic
DefaultEncryption Required
PreserveJobHistory Yes
PreserveJobFiles No
IdleExitTimeout 0
<Location />
  Order allow,deny
  Allow @LOCAL
  Allow 10.0.0.0/8
  Allow 172.16.0.0/12
  Allow 192.168.0.0/16
</Location>
<Location /admin>
  Order allow,deny
  Allow @LOCAL
  Allow 10.0.0.0/8
  Allow 172.16.0.0/12
  Allow 192.168.0.0/16
</Location>
<Location /admin/conf>
  AuthType Default
  Require user @SYSTEM
  Order allow,deny
  Allow @LOCAL
  Allow 10.0.0.0/8
  Allow 172.16.0.0/12
  Allow 192.168.0.0/16
</Location>
<Location /admin/log>
  AuthType Default
  Require user @SYSTEM
  Order allow,deny
  Allow @LOCAL
  Allow 10.0.0.0/8
  Allow 172.16.0.0/12
  Allow 192.168.0.0/16
</Location>
<Policy default>
  JobPrivateAccess default
  JobPrivateValues default
  SubscriptionPrivateAccess default
  SubscriptionPrivateValues default
  <Limit Create-Job Print-Job Print-URI Validate-Job>
    Order deny,allow
  </Limit>
  <Limit Send-Document Send-URI Hold-Job Release-Job Restart-Job Purge-Jobs Set-Job-Attributes Create-Job-Subscription Renew-Subscription Cancel-Subscription Get-Notifications Reprocess-Job Cancel-Current-Job Suspend-Current-Job Resume-Job Cancel-My-Jobs Close-Job CUPS-Move-Job CUPS-Get-Document>
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>
  <Limit CUPS-Add-Modify-Printer CUPS-Delete-Printer CUPS-Add-Modify-Class CUPS-Delete-Class CUPS-Set-Default CUPS-Get-Devices>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>
  <Limit Pause-Printer Resume-Printer Enable-Printer Disable-Printer Pause-Printer-After-Current-Job Hold-New-Jobs Release-Held-New-Jobs Deactivate-Printer Activate-Printer Restart-Printer Shutdown-Printer Startup-Printer Promote-Job Schedule-Job-After Cancel-Jobs CUPS-Accept-Jobs CUPS-Reject-Jobs>
    AuthType Default
    Require user @SYSTEM
    Order deny,allow
  </Limit>
  <Limit Cancel-Job CUPS-Authenticate-Job>
    Require user @OWNER @SYSTEM
    Order deny,allow
  </Limit>
  <Limit All>
    Order deny,allow
  </Limit>
</Policy>
CONF
    # root and the lpadmin group administer CUPS
    touch "$flash/cups/cups-files.conf"
    sed -i '/^SystemGroup/d' "$flash/cups/cups-files.conf"
    echo 'SystemGroup lpadmin root' >> "$flash/cups/cups-files.conf"
    # its own self-signed certificate for https on 631, made on first use
    sed -i '/^CreateSelfSignedCerts/d' "$flash/cups/cups-files.conf"
    echo 'CreateSelfSignedCerts yes' >> "$flash/cups/cups-files.conf"
fi
grep -qs ' /etc/cups ' /proc/mounts || mount --bind "$flash/cups" /etc/cups || exit 1
mkdir -p /var/spool/cups "$flash/spool"
grep -qs ' /var/spool/cups ' /proc/mounts || mount --bind "$flash/spool" /var/spool/cups || exit 1
chgrp -R lp /etc/cups /var/spool/cups 2>/dev/null
chmod 710 /var/spool/cups 2>/dev/null

# The device's own administrator: root, with the lab's password.
[ -n "$WINLAB_ADMIN_PASSWORD" ] || { echo 'WINLAB_ADMIN_PASSWORD is empty' >&2; exit 1; }
printf 'root:%s\n' "$WINLAB_ADMIN_PASSWORD" | chpasswd >/dev/null || exit 1
grep -q '^lpadmin:' /etc/group || addgroup -S lpadmin
addgroup root lpadmin 2>/dev/null

mkdir -p /run/cups /var/log/cups
rc-service cupsd restart >/dev/null 2>&1 || { pkill cupsd 2>/dev/null; cupsd; } ||
    { echo 'CUPS did not start' >&2; exit 1; }

date -Iseconds > "$done_dir/$role"
log "ready: CUPS on https://${WINLAB_HOSTNAME:-printer}:631/ (root, the lab password), raw 9100; pages go to $tray"
