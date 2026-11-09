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
# door-open, offline, toner-low, toner-empty (and cancel, the Cancel button). While one
# stops the engine, a job waits in the engine the way it does on a real
# printer: CUPS shows it processing with the printer's reason
# (media-empty-error, media-jam-error, door-open-error, offline-report), a
# raw job on 9100 sits in the printer's buffer, and both come out when the
# paper is loaded, the jam cleared (open the door, close it) or the printer
# put online again. Toner low only warns (toner-low-report); toner empty
# (toner-empty) stops the engine like a jam until a new cartridge is fitted.
#
# The printer reports its state the two ways a network printer does, from
# the same sensors, whether or not a job is printing:
# - SNMP: the HOST-RESOURCES-MIB rows a print monitor reads (hrDeviceStatus,
#   hrPrinterStatus, hrPrinterDetectedErrorState: Windows' Standard TCP/IP
#   port with SNMP status on shows "Paper jam", "Out of paper", "Toner low"
#   from them) and the Printer MIB (RFC 3805): the input tray's level, the
#   toner's prtMarkerSuppliesLevel, the alert table and the front panel's
#   two lines, served by net-snmp's own pass extension from
#   /usr/local/bin/winlab-printer-mib. net-snmp's built-in host-resources
#   device modules are left out (snmpd -I), so device 1 is the printer.
# - IPP: each CUPS queue on the printer whose device is its own engine
#   (tray:/) carries the printer-state-reasons (media-jam-error,
#   media-empty-error, door-open-error, toner-empty-error, toner-low-report,
#   offline-report) that IPP clients, Windows' IPP class driver among them,
#   read with Get-Printer-Attributes; winlab-printer-reasons keeps them in
#   step with the sensors on the queues the student made.
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
elif [ -e $p/toner-empty ]; then echo toner-empty
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

# SNMP: the printer's status from its sensors (HOST-RESOURCES-MIB device 1
# and the Printer MIB, see above), read-only on the community Windows asks
# with ("public").
cat > /usr/local/bin/winlab-printer-mib <<'MIB'
#!/bin/sh
# winlab-printer-mib: the printer's status for net-snmp's pass directive
# (HOST-RESOURCES-MIB's printer rows and the Printer MIB, RFC 3805), read
# from the engine's sensors. snmpd runs it as: winlab-printer-mib -g|-n OID
p=/var/lib/printer-panel
f() { [ -e "$p/$1" ]; }
state=ready
if f door-open; then state=door-open
elif f jam; then state=jam
elif f nopaper; then state=paper-out
elif f toner-empty; then state=toner-empty
elif f offline; then state=offline
fi
# hrPrinterDetectedErrorState: lowPaper noPaper lowToner noToner doorOpen
# jammed offline serviceRequested (first byte, high bit first), then
# inputTrayMissing ... inputTrayEmpty (0x04 in the second byte).
b1=0; b2=0
f nopaper && { b1=$((b1 | 64)); b2=$((b2 | 4)); }
f toner-low && b1=$((b1 | 32))
f toner-empty && b1=$((b1 | 16))
f door-open && b1=$((b1 | 8))
f jam && b1=$((b1 | 4))
f offline && b1=$((b1 | 2))
# hrDeviceStatus running(2) warning(3) down(5); hrPrinterStatus other(1) idle(3) printing(4)
if [ $state != ready ]; then dev=5; prt=1
elif f toner-low; then dev=3; prt=3
else dev=2; prt=3
fi
[ $state = ready ] && f busy && prt=4
level=80; f toner-low && level=8; f toner-empty && level=0
tray=180; f nopaper && tray=0
tst=0; f nopaper && tst=16
case $state in
    ready) l1=Ready; l2=; f toner-low && l2='Toner low' ;;
    door-open) l1='Front door open'; l2='Close the door' ;;
    jam) l1='Paper jam'; l2='Open front door' ;;
    paper-out) l1='Load Tray 1'; l2='PLAIN A4' ;;
    toner-empty) l1='Toner empty'; l2='Replace toner' ;;
    offline) l1=Offline; l2='Press Online' ;;
esac
now=$(date +%s); up=$(cut -d. -f1 /proc/uptime)
when() { m=$(stat -c %Y "$p/$1" 2>/dev/null || echo "$now"); t=$(( (up - (now - m)) * 100 )); [ $t -gt 0 ] || t=0; echo $t; }
H=.1.3.6.1.2.1.25.3; P=.1.3.6.1.2.1.43
{
echo "$H.2.1.1.1 integer 1"
echo "$H.2.1.2.1 objectid .1.3.6.1.2.1.25.3.1.5"
echo "$H.2.1.3.1 string winlab network printer (PCL, text)"
echo "$H.2.1.4.1 objectid .0.0"
echo "$H.2.1.5.1 integer $dev"
echo "$H.2.1.6.1 counter 0"
echo "$H.5.1.1.1 integer $prt"
printf '%s octet %02X %02X\n' "$H.5.1.2.1" $b1 $b2
echo "$P.5.1.1.16.1 string $(hostname)"
echo "$P.8.2.1.2.1.1 integer 4"
echo "$P.8.2.1.8.1.1 integer 8"
echo "$P.8.2.1.9.1.1 integer 250"
echo "$P.8.2.1.10.1.1 integer $tray"
echo "$P.8.2.1.11.1.1 integer $tst"
echo "$P.8.2.1.12.1.1 string PLAIN A4"
echo "$P.8.2.1.13.1.1 string Tray 1"
echo "$P.11.1.1.2.1.1 integer 1"
echo "$P.11.1.1.3.1.1 integer 1"
echo "$P.11.1.1.4.1.1 integer 3"
echo "$P.11.1.1.5.1.1 integer 3"
echo "$P.11.1.1.6.1.1 string Black Toner Cartridge"
echo "$P.11.1.1.7.1.1 integer 19"
echo "$P.11.1.1.8.1.1 integer 100"
echo "$P.11.1.1.9.1.1 integer $level"
echo "$P.16.5.1.2.1.1 string $l1"
echo "$P.16.5.1.2.1.2 string $l2"
n=0
alert() {  # severity training group group-index code description flag
    n=$((n + 1))
    echo "$P.18.1.1.2.1.$n integer $1"
    echo "$P.18.1.1.3.1.$n integer $2"
    echo "$P.18.1.1.4.1.$n integer $3"
    echo "$P.18.1.1.5.1.$n integer $4"
    echo "$P.18.1.1.6.1.$n integer -2"
    echo "$P.18.1.1.7.1.$n integer $5"
    echo "$P.18.1.1.8.1.$n string $6"
    echo "$P.18.1.1.9.1.$n timeticks $(when "$7")"
}
f door-open && alert 3 3 6 1 501 'Front door open' door-open
f jam && alert 3 4 13 1 8 'Paper jam: open the front door and take the sheet out' jam
f nopaper && alert 3 3 8 1 808 'Tray 1 empty: load PLAIN A4' nopaper
f toner-empty && alert 3 4 11 1 1101 'Toner empty: replace the black toner cartridge' toner-empty
f toner-low && ! f toner-empty && alert 4 4 11 1 1104 'Toner low: order a black toner cartridge' toner-low
} | awk -v op="$1" -v req="$2" '
function cmp(a, b,   x, y, i, n, m) {
    n = split(a, x, "."); m = split(b, y, ".")
    for (i = 2; i <= n && i <= m; i++) { if (x[i] + 0 < y[i] + 0) return -1; if (x[i] + 0 > y[i] + 0) return 1 }
    return (n < m) ? -1 : (n > m) ? 1 : 0
}
{ oid = $1; type = $2; val = substr($0, length($1) + length($2) + 3)
  if (op == "-g") { if (oid == req) { best = oid; bt = type; bv = val } }
  else if (cmp(oid, req) > 0 && (best == "" || cmp(oid, best) < 0)) { best = oid; bt = type; bv = val } }
END { if (best != "") { print best; print bt; print bv } }'
MIB
chmod 755 /usr/local/bin/winlab-printer-mib
cat > /etc/snmp/snmpd.conf <<CONF
agentAddress udp:161
rocommunity public
sysName ${WINLAB_HOSTNAME:-printer}
sysDescr winlab network printer (CUPS, IPP on 631, raw 9100, PCL and text)
sysLocation ${WINLAB_PRINTER_LOCATION:-office}
sysContact the lab's administrator
pass .1.3.6.1.2.1.25.3.2 /bin/sh /usr/local/bin/winlab-printer-mib
pass .1.3.6.1.2.1.25.3.5 /bin/sh /usr/local/bin/winlab-printer-mib
pass .1.3.6.1.2.1.43 /bin/sh /usr/local/bin/winlab-printer-mib
CONF
pkill snmpd 2>/dev/null
snmpd -c /etc/snmp/snmpd.conf -Lsd -I -hr_device,hr_other,hr_proc,hr_network,hr_print,hr_disk,hr_partition udp:161 ||
    log 'SNMP did not start: Windows may show the printer offline'

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
if [ -e $p/toner-empty ]; then echo 'STATE: +toner-empty-error' >&2; echo 'ATTR: marker-levels=0' >&2
elif [ -e $p/toner-low ]; then echo 'STATE: +toner-low-report' >&2; echo 'ATTR: marker-levels=8' >&2
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
        toner-empty) echo 'STATE: +toner-empty-error' >&2; echo 'INFO: Toner empty: replace the cartridge' >&2 ;;
        offline) echo 'STATE: +offline-report' >&2; echo 'INFO: The printer is offline' >&2 ;;
    esac
    sleep 3
done
rm -f $p/busy
echo 'STATE: -media-empty-error,media-jam-error,door-open-error,toner-empty-error,offline-report' >&2
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

# The IPP side of the sensors: every queue on this printer that prints to
# its own engine (tray:/) carries the printer-state-reasons the panel shows,
# idle or printing, set the way CUPS takes them (the queue's
# printer-state-reasons option), whenever a sensor changes. It never makes a
# queue: one the student added to the engine is the only kind it touches.
cat > /usr/local/bin/winlab-printer-reasons <<'REASONS'
#!/bin/sh
p=/var/lib/printer-panel
last=
while :; do
    r=
    [ -e $p/door-open ] && r="$r,door-open-error"
    [ -e $p/jam ] && r="$r,media-jam-error"
    [ -e $p/nopaper ] && r="$r,media-empty-error"
    if [ -e $p/toner-empty ]; then r="$r,toner-empty-error"
    elif [ -e $p/toner-low ]; then r="$r,toner-low-report"
    fi
    [ -e $p/offline ] && r="$r,offline-report"
    r=${r#,}; r=${r:-none}
    qs=$(LC_ALL=C lpstat -v 2>/dev/null | sed -n 's/^device for \([^:]*\): tray:.*/\1/p')
    if [ "$r|$qs" != "$last" ] && [ -n "$qs" ]; then
        ok=1
        for q in $qs; do lpadmin -p "$q" -o "printer-state-reasons=$r" 2>/dev/null || ok=; done
        [ -n "$ok" ] && last="$r|$qs"
    fi
    sleep 2
done
REASONS
chmod 755 /usr/local/bin/winlab-printer-reasons
pkill -f '[w]inlab-printer-reasons' 2>/dev/null
nohup /usr/local/bin/winlab-printer-reasons >/dev/null 2>&1 &

date -Iseconds > "$done_dir/$role"
log "ready: CUPS on https://${WINLAB_HOSTNAME:-printer}:631/ (root, the lab password), raw 9100; pages go to $tray"
