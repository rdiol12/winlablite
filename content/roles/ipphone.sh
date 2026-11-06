#!/bin/sh
# A desk IP phone on the Alpine appliance: its screen is GNOME Calls, a real
# SIP softphone, full screen in a one-application Wayland session (cage), the
# way a phone's display shows nothing but the phone. It takes its address
# from DHCP (or the one the lab gives it) and, out of the box, has no
# account: the student opens Calls' menu, VoIP Accounts, and enters the
# server (the phone system's address), the extension (User ID) and its
# secret, as set in FreePBX. Nothing here knows an extension or a server.
#
# The phone keeps its settings on its own small flash disk (the last
# unlabelled disk, formatted the first time), so an account survives a
# power cycle. The handset is silent: the machine has no sound card, so the
# call's audio goes to a null sink and the microphone is a test tone; SIP
# and RTP cross the network like a real phone's.
#
# The device runs this at every power-on: it is the phone's firmware.

role=ipphone
done_dir=/var/lib/winlab/done
user=phone
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

for tool in gnome-calls cage seatd gnome-keyring-daemon dbus-run-session mkfs.ext4 udhcpc; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool missing from the appliance (prepare the router again in Setup)" >&2; exit 1; }
done

ifc=$(ip -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' | cut -d@ -f1)
[ -n "$ifc" ] || { echo 'no network interface found' >&2; exit 1; }
ip link set "$ifc" up
if [ -n "$WINLAB_NIC0_IP" ]; then
    log "address $WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX"
    ip addr replace "$WINLAB_NIC0_IP/$WINLAB_NIC0_PREFIX" dev "$ifc" || exit 1
    [ -n "$WINLAB_NIC0_GW" ] && ip route replace default via "$WINLAB_NIC0_GW"
elif ! ip -4 addr show dev "$ifc" | grep -q inet; then
    log "asking for an address (DHCP) as $WINLAB_HOSTNAME"
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" -q -t 10 -T 2 >/dev/null 2>&1 ||
        log 'no DHCP answer yet; it keeps asking in the background'
    udhcpc -b -i "$ifc" -x "hostname:$WINLAB_HOSTNAME" >/dev/null 2>&1 &
fi

# ---- the phone's flash: its settings and the softphone's keyring ----------
disks=""
for d in $(ls /dev/sd? /dev/vd? 2>/dev/null | sort); do
    blkid "$d" 2>/dev/null | grep -q 'LABEL="WL' && continue   # winlab's own volumes
    disks="$disks $d"
done
set -- $disks
home=/home/$user
id "$user" >/dev/null 2>&1 || adduser -D -h "$home" -s /bin/sh "$user"
for g in video input seat audio; do
    addgroup "$user" "$g" 2>/dev/null
done
if [ $# -ge 2 ]; then
    eval "disk=\${$#}"
    if ! blkid "$disk" 2>/dev/null | grep -q 'LABEL="phonedata"'; then
        log "formatting the phone's flash $disk (first start)"
        mkfs.ext4 -q -L phonedata "$disk" || exit 1
    fi
    mkdir -p "$home"
    grep -qs " $home " /proc/mounts || mount -L phonedata "$home" || exit 1
else
    log 'no flash disk: the account lasts until the phone is powered off'
    mkdir -p "$home"
fi
chown "$user:$user" "$home"

# ---- the screen: devices, a seat, one full-screen application --------------
for m in bochs bochs-drm usbhid hid-generic evdev; do modprobe "$m" 2>/dev/null; done
rc-service udev start >/dev/null 2>&1 && { udevadm trigger >/dev/null 2>&1; udevadm settle -t 10 >/dev/null 2>&1; }
rc-service seatd start >/dev/null 2>&1 || { seatd -g seat >/dev/null 2>&1 & }
rc-service dbus start >/dev/null 2>&1

uid=$(id -u "$user")
run="/run/user/$uid"
mkdir -p "$run"; chown "$user:$user" "$run"; chmod 700 "$run"
pkill -f '[w]inlab-phone-ui' 2>/dev/null   # [w]: not this script's own text (it runs as sh -c)
pkill -x cage 2>/dev/null
cat > /usr/local/bin/winlab-phone-ui <<'UI'
#!/bin/sh
# The phone's screen: GNOME Calls with its SIP provider, full screen in cage.
# Restarted if it is closed, as a phone's display comes back.
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export LIBSEAT_BACKEND=seatd WLR_RENDERER=pixman WLR_NO_HARDWARE_CURSORS=1 GSK_RENDERER=cairo
export CALLS_AUDIOSRC=audiotestsrc CALLS_AUDIOSINK=fakesink
while :; do
    dbus-run-session -- sh -c '
        printf "" | gnome-keyring-daemon --unlock --components=secrets >/dev/null 2>&1
        exec cage -s -- gnome-calls -p sip' >>"$HOME/.phone-ui.log" 2>&1
    sleep 3
done
UI
chmod 755 /usr/local/bin/winlab-phone-ui
setsid su - "$user" -c 'exec /usr/local/bin/winlab-phone-ui' </dev/null >/dev/null 2>&1 &

mkdir -p "$done_dir"
date -Iseconds > "$done_dir/$role"
log 'the softphone is on the screen; sign it in to the phone system in Calls: menu > VoIP Accounts'
