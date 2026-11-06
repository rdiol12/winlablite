#!/bin/sh
# An IP camera on the Alpine appliance: what a small fixed camera's firmware
# does, with BusyBox alone. It asks for its address by DHCP (as a camera out
# of the box does), and serves its own web pages on port 80:
#   /                   the live view (a snapshot every two seconds)
#   /cgi-bin/snap       the picture: the scene and the overlay (name, date, time)
#   /cgi-bin/setup      first visit only: create the admin password (there is
#                       no default one, as current cameras ship)
#   /cgi-bin/admin      signed in as admin: camera name, overlay text, NTP
#                       server, the recorder allowed to pull the stream
# Settings live on its flash (/etc/ipcam) and survive a power cycle of the
# appliance's run, the clock is set from the NTP server named in its pages.
# QEMU has no camera sensor, so the picture is drawn: a scene and its overlay.
#
# The device runs this at every power-on: it is the camera's firmware.

role=ipcam
done_dir=/var/lib/winlab/done
etc=/etc/ipcam
www=/var/www/ipcam
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

command -v httpd >/dev/null 2>&1 || busybox httpd --help >/dev/null 2>&1 ||
    { echo 'httpd missing from the appliance (prepare the router again in Setup)' >&2; exit 1; }

ifc=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1)
[ -n "$ifc" ] || { echo 'no network interface found' >&2; exit 1; }
ip link set "$ifc" up
if [ -n "$WINLAB_NIC0_IP" ]; then
    ip addr replace "$WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX" dev "$ifc" || exit 1
    [ -n "$WINLAB_NIC0_GW" ] && ip route replace default via "$WINLAB_NIC0_GW"
elif ! ip -4 addr show dev "$ifc" | grep -q 'inet '; then
    log "asking for an address (DHCP) as $WINLAB_HOSTNAME"
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" -q -t 10 -T 2 >/dev/null 2>&1 ||
        log 'no DHCP answer yet; it keeps asking in the background'
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" >/dev/null 2>&1 &
fi

mkdir -p "$etc" "$www/cgi-bin" "$done_dir"
[ -f "$etc/name" ] || echo "$WINLAB_HOSTNAME" > "$etc/name"
[ -f "$etc/overlay" ] || echo "" > "$etc/overlay"
[ -f "$etc/ntp" ] || : > "$etc/ntp"
[ -f "$etc/recorder" ] || : > "$etc/recorder"
mac=$(cat /sys/class/net/"$ifc"/address 2>/dev/null)

# ---- the pages ---------------------------------------------------------------
cat > "$www/index.html" <<'HTML'
<!doctype html><meta charset="utf-8"><title>IP camera</title>
<style>body{font:14px sans-serif;background:#1d2229;color:#e8ecf1;margin:0}header{background:#0f1318;padding:10px 16px;font-weight:600}
main{padding:16px}img{width:640px;max-width:100%;border:1px solid #3a424d;background:#000}a{color:#7cc4ff}</style>
<header>IP camera · live view</header><main><img id="v" src="/cgi-bin/snap" alt="live view">
<p><a href="/cgi-bin/admin">Settings</a> · <a href="/cgi-bin/setup">First-time setup</a></p></main>
<script>setInterval(()=>{document.getElementById('v').src='/cgi-bin/snap?'+Date.now()},2000)</script>
HTML

cat > "$www/cgi-bin/snap" <<'CGI'
#!/bin/sh
etc=/etc/ipcam
name=$(cat $etc/name 2>/dev/null | tr -d '<>&"')
ovl=$(cat $etc/overlay 2>/dev/null | tr -d '<>&"')
now=$(date '+%Y-%m-%d %H:%M:%S')
echo "Content-Type: image/svg+xml"; echo "Cache-Control: no-store"; echo
cat <<SVG
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 360"><rect width="640" height="360" fill="#3d4652"/>
<rect y="210" width="640" height="150" fill="#58616b"/><path d="M0 300L640 250" stroke="#d8d24a" stroke-width="4" stroke-dasharray="30 20"/>
<rect x="60" y="90" width="180" height="120" fill="#6b7480"/><rect x="95" y="140" width="40" height="70" fill="#2b3138"/>
<rect x="380" y="120" width="210" height="90" fill="#737c87"/><rect x="400" y="140" width="40" height="30" fill="#a9c7e3"/>
<rect x="0" y="0" width="640" height="26" fill="#000" fill-opacity=".45"/>
<text x="8" y="18" fill="#fff" font-family="monospace" font-size="14">$name  $ovl</text>
<text x="632" y="18" fill="#fff" font-family="monospace" font-size="14" text-anchor="end">$now</text></svg>
SVG
CGI

cat > "$www/cgi-bin/setup" <<'CGI'
#!/bin/sh
etc=/etc/ipcam
echo "Content-Type: text/html"; echo
if [ -s $etc/admin ]; then echo "<p>The admin password is set. <a href=/cgi-bin/admin>Sign in</a></p>"; exit 0; fi
if [ "$REQUEST_METHOD" = POST ]; then
  read -r body
  pw=$(echo "$body" | sed -n 's/.*pw=\([^&]*\).*/\1/p' | sed 's/+/ /g;s/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g' | xargs -0 printf '%b' 2>/dev/null)
  if [ ${#pw} -lt 8 ]; then echo "<p>At least 8 characters. <a href=/cgi-bin/setup>Back</a></p>"; exit 0; fi
  hash=$(httpd -m "$pw" 2>/dev/null || busybox httpd -m "$pw")
  echo "/cgi-bin/admin:admin:$hash" > $etc/admin
  cp $etc/admin /etc/httpd-ipcam.conf
  pkill -HUP -f 'httpd -p 80' 2>/dev/null  # httpd reads its password file again
  echo "<p>Saved. <a href=/cgi-bin/admin>Sign in as admin</a></p>"; exit 0
fi
echo "<h3>Create the camera's admin password</h3><form method=post><input type=password name=pw minlength=8> <button>Save</button></form>"
CGI

cat > "$www/cgi-bin/admin" <<'CGI'
#!/bin/sh
etc=/etc/ipcam
echo "Content-Type: text/html"; echo
if [ ! -s $etc/admin ]; then echo "<p>Set the admin password first: <a href=/cgi-bin/setup>first-time setup</a></p>"; exit 0; fi
field() { echo "$1" | tr '&' '\n' | sed -n "s/^$2=//p" | sed 's/+/ /g;s/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g' | xargs -0 printf '%b' 2>/dev/null | tr -d '<>&"\n' | cut -c1-63; }
if [ "$REQUEST_METHOD" = POST ]; then
  read -r body
  field "$body" name > $etc/name; field "$body" overlay > $etc/overlay
  field "$body" ntp > $etc/ntp; field "$body" recorder > $etc/recorder
  ntp=$(cat $etc/ntp)
  [ -n "$ntp" ] && { pkill -x ntpd 2>/dev/null; ntpd -p "$ntp" 2>/dev/null & }
  echo "<p>Saved.</p>"
fi
cat <<HTML
<h3>Camera settings</h3><form method=post>
<p>Camera name <input name=name value="$(cat $etc/name)"></p>
<p>Overlay text <input name=overlay value="$(cat $etc/overlay)"></p>
<p>NTP server <input name=ntp value="$(cat $etc/ntp)"></p>
<p>Recorder allowed to pull the stream <input name=recorder value="$(cat $etc/recorder)"></p>
<button>Save</button></form><p><a href=/>Live view</a></p>
HTML
CGI
chmod 755 "$www/cgi-bin/"*
cat "$etc/admin" > /etc/httpd-ipcam.conf 2>/dev/null || : > /etc/httpd-ipcam.conf

pkill -f 'httpd -p 80' 2>/dev/null
(cd "$www" && httpd -p 80 -h "$www" -c /etc/httpd-ipcam.conf) || { echo 'httpd did not start' >&2; exit 1; }
ntp=$(cat "$etc/ntp")
[ -n "$ntp" ] && { ntpd -p "$ntp" 2>/dev/null & }

date -Iseconds > "$done_dir/$role"
log "ready: web pages on port 80 (MAC $mac)"
