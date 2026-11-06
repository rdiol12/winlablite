#!/bin/sh
# The Admin workstation: a small Linux desktop on the Alpine appliance, so
# a lab without a Windows PC still has a browser to open the devices' own
# pages (CUPS on the printer, the NAS's, the phone system's...). Its screen
# boots straight into a light desktop (Xorg, Openbox and a tint2 panel) with
# Firefox ESR open; the panel has Firefox and a terminal.
#
# It signs in to its own desktop by itself, as the unprivileged user
# "admin" (no password, no admin rights): that is this machine's own login, not a
# device's. Firefox starts on an empty page with no bookmarks: the student
# types each device's address and signs in to it there.
#
# It takes its address from DHCP (or the one the lab gives it). The device
# runs this at every power-on: it is the workstation's start-up.

role=admin-desktop
done_dir=/var/lib/winlab/done
user=admin
home=/home/$user
xdir=/run/winlab-x
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

for tool in Xorg xauth openbox firefox-esr udevd udhcpc; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool missing from the appliance (prepare the router again in Setup)" >&2; exit 1; }
done

ifc=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1)
[ -n "$ifc" ] || { echo 'no network interface found' >&2; exit 1; }
ip link set "$ifc" up
if [ -n "$WINLAB_NIC0_IP" ]; then
    log "address $WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX"
    ip addr replace "$WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX" dev "$ifc" || exit 1
    [ -n "$WINLAB_NIC0_GW" ] && ip route replace default via "$WINLAB_NIC0_GW"
    for d in $WINLAB_DNS; do echo "nameserver $d"; done > /etc/resolv.conf.winlab
    [ -s /etc/resolv.conf.winlab ] && mv /etc/resolv.conf.winlab /etc/resolv.conf
    rm -f /etc/resolv.conf.winlab
elif ! ip -4 addr show dev "$ifc" | grep -q 'inet '; then
    log "asking for an address (DHCP) as $WINLAB_HOSTNAME"
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" -q -t 10 -T 2 >/dev/null 2>&1 ||
        log 'no DHCP answer yet; it keeps asking in the background'
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" >/dev/null 2>&1 &
fi
mkdir -p "$done_dir"

if pgrep -x Xorg >/dev/null 2>&1; then
    date -Iseconds > "$done_dir/$role"
    log 'the desktop is already up'
    exit 0
fi

# ---- the user: unprivileged, its password locked (it never types one).
id "$user" >/dev/null 2>&1 || adduser -D -s /bin/sh -g 'Lab administrator' "$user"
for g in video input audio; do addgroup "$user" "$g" 2>/dev/null; done

# ---- devices: udev finds the screen, keyboard and tablet for Xorg.
for m in bochs drm_kms_helper evdev usbhid hid_generic; do modprobe "$m" 2>/dev/null; done
udevd --daemon 2>/dev/null
udevadm trigger --type=subsystems --action=add 2>/dev/null
udevadm trigger --type=devices --action=add 2>/dev/null
udevadm settle --timeout=20 2>/dev/null

# ---- the desktop's own settings, in the user's home.
mkdir -p "$home/.config/openbox" "$home/.config/tint2"
cat > "$home/.config/openbox/autostart" <<'AUTO'
xsetroot -solid '#2b3a4a' 2>/dev/null
tint2 &
firefox-esr about:blank &
AUTO
cat > "$home/.config/openbox/menu.xml" <<'MENU'
<?xml version="1.0" encoding="UTF-8"?>
<openbox_menu xmlns="http://openbox.org/3.4/menu">
  <menu id="root-menu" label="Admin workstation">
    <item label="Firefox"><action name="Execute"><command>firefox-esr</command></action></item>
    <item label="Terminal"><action name="Execute"><command>xterm</command></action></item>
    <separator/>
    <item label="Restart the desktop"><action name="Restart"/></item>
  </menu>
</openbox_menu>
MENU
cat > "$home/.config/tint2/tint2rc" <<'PANEL'
panel_items = LTSC
panel_position = bottom center horizontal
panel_size = 100% 34
panel_background_id = 1
panel_padding = 4 2 4
rounded = 0
border_width = 0
background_color = #1d2733 100
border_color = #1d2733 100
rounded = 4
border_width = 0
background_color = #3b4b5d 100
border_color = #3b4b5d 100
launcher_padding = 2 2 4
launcher_icon_size = 26
launcher_item_app = /usr/share/applications/firefox-esr.desktop
launcher_item_app = /usr/share/applications/xterm.desktop
taskbar_mode = single_desktop
task_text = 1
task_icon = 1
task_maximum_size = 220 30
task_active_background_id = 2
task_font_color = #ffffff 100
time1_format = %H:%M
clock_font_color = #ffffff 100
clock_padding = 8 0
systray_padding = 4 2 4
PANEL
chown -R "$user:$user" "$home"

# Firefox: no first-run tour or internet start pages (the lab has no
# internet) and none of its own bookmarks; nothing else is set.
for d in /usr/lib/firefox-esr /usr/lib/firefox; do
    [ -d "$d" ] || continue
    mkdir -p "$d/distribution"
    cat > "$d/distribution/policies.json" <<'POL'
{"policies": {"DisableTelemetry": true, "DisableFirefoxStudies": true, "DisableAppUpdate": true,
  "DontCheckDefaultBrowser": true, "NoDefaultBookmarks": true, "OverrideFirstRunPage": "",
  "OverridePostUpdatePage": "", "UserMessaging": {"WhatsNew": false, "ExtensionRecommendations": false,
  "FeatureRecommendations": false, "SkipOnboarding": true},
  "Homepage": {"URL": "about:blank", "StartPage": "homepage"}}}
POL
done

# ---- Xorg on its own console (vt7), its cookie for the user only.
mkdir -p "$xdir"
chmod 711 "$xdir"
cookie=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
rm -f "$xdir/auth" "$home/.Xauthority"
xauth -q -f "$xdir/auth" add :0 . "$cookie"
xauth -q -f "$home/.Xauthority" add :0 . "$cookie"
chown "$user:$user" "$home/.Xauthority"
chmod 600 "$xdir/auth" "$home/.Xauthority"
log 'starting the desktop'
Xorg :0 vt7 -nolisten tcp -auth "$xdir/auth" -noreset >/var/log/Xorg.winlab.log 2>&1 &
i=0
while [ ! -S /tmp/.X11-unix/X0 ] && [ $i -lt 30 ]; do sleep 1; i=$((i + 1)); done
[ -S /tmp/.X11-unix/X0 ] || { echo 'Xorg did not start (see /var/log/Xorg.winlab.log)' >&2; exit 1; }
chvt 7 2>/dev/null

# The user's session; Openbox's autostart opens the panel and Firefox.
launch='exec openbox-session'
command -v dbus-launch >/dev/null 2>&1 && launch='exec dbus-launch --exit-with-session openbox-session'
su -s /bin/sh "$user" -c "cd; export DISPLAY=:0 XAUTHORITY=$home/.Xauthority; $launch" >/dev/null 2>&1 &

date -Iseconds > "$done_dir/$role"
log "ready: the desktop as $user, Firefox ESR on its screen"
