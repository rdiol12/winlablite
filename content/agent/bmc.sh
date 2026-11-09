#!/bin/sh
# winlab BMC: the management processor of one server, answering on that
# server's management port (winlab/power.py). The router starts one per
# server, each in its own network namespace with the port's own MAC and
# address, as an access port of the switch the management cable is in:
#   tcpsvd 0.0.0.0 80 /usr/local/bin/winlab-bmc /var/lib/winlab-bmc/<server>
# One connection per run: the request on stdin, the reply on stdout.
#
# The web pages are OpenBMC's own web UI (webui-vue, Apache-2.0), when it
# was fetched at preparation and unpacked next to the servers' folders
# (/var/lib/winlab-bmc/webui, winlab/openbmcui.py): this script serves its
# files as they are and answers the Redfish API the pages call, the way
# OpenBMC's bmcweb does: a session from SessionService/Sessions (its
# cookies and X-Auth-Token), the system, its power actions, the event log,
# the BMC and its network port, the account. Without it, a browser gets
# winlab's own pages (overview, power, virtual console, event log).
# Invoke-RestMethod or curl may also sign in with HTTP Basic. Every page and
# resource but the service root asks for the user and password on the
# server's toe tag, or of a local user an administrator added (AccountService:
# Administrator, Operator or ReadOnly, kept in accounts and by winlab across
# the BMC's starts). What a page asks that this BMC does not do answers with
# a Redfish error, so the page says it could not, as on a real BMC.
#
# Beyond power it does what a server's BMC does, each queued for winlab the
# same way: virtual media (a disc of the lab's media shelf, listed in
# media.list, into the server's DVD drive, or out), the boot override (the
# next or every boot from the DVD, the disk or into the firmware's setup),
# keystrokes from the virtual console, a static address on its own port.
# The chassis sensors (sensors) are modelled by winlab from the server's
# load and say so.
#
# What it knows of the server is what winlab writes into the folder: power
# (On/Off), health (OK/Critical), seen (when winlab last looked), screen.png,
# and its fixed facts (name, ip, mac, mask, gateway, cpus, memory). What it
# asks of the server it appends to queue; winlab carries it out on the
# machine (QMP: reset, power off, the power button, a start) and writes the
# outcome to events, the event log these pages show.

D=${1:?usage: winlab-bmc <server folder>}
W=${D%/*}/webui
cr=$(printf '\r')
peer=${TCPREMOTEIP:-unknown}

read -r method target proto || exit 0
method=${method%"$cr"}
target=${target%"$cr"}
len=0
auth=''
xtoken=''
xsrf=''
cookie=''
xhr=''
while IFS= read -r h; do
    h=${h%"$cr"}
    [ -z "$h" ] && break
    v=${h#*:}
    v=${v# }
    case "$h" in  # header names in any case
        [Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh]:*) len=$(printf '%s' "$v" | tr -dc 0-9) ;;
        [Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]:*) auth=$v ;;
        [Xx]-[Aa][Uu][Tt][Hh]-[Tt][Oo][Kk][Ee][Nn]:*) xtoken=$(printf '%s' "$v" | tr -dc 0-9a-f) ;;
        [Xx]-[Xx][Ss][Rr][Ff]-[Tt][Oo][Kk][Ee][Nn]:*) xsrf=$(printf '%s' "$v" | tr -dc 0-9a-f) ;;
        [Cc][Oo][Oo][Kk][Ii][Ee]:*) cookie=$v ;;
        [Xx]-[Rr][Ee][Qq][Uu][Ee][Ss][Tt][Ee][Dd]-[Ww][Ii][Tt][Hh]:*) xhr=1 ;;
    esac
done
body=''
# A firmware package for UpdateService's HttpPushUri is the request body
# itself (application/octet-stream, as bmcweb takes it): it goes to a file,
# up to UPMAX bytes; every other body is a few lines of JSON or a form.
UPMAX=4194304
upload=''
toobig=''
case "$method ${target%%\?*}" in
    "POST /redfish/v1/UpdateService" | "POST /redfish/v1/UpdateService/" | "POST /redfish/v1/UpdateService/update" | "POST /redfish/v1/UpdateService/update/")
        upload=1
        rm -f "$D/upload.tar"
        if [ "${len:-0}" -gt "$UPMAX" ] 2>/dev/null; then toobig=1
        elif [ "${len:-0}" -gt 0 ] 2>/dev/null; then head -c "$len" > "$D/upload.tar"
        fi ;;
esac
if [ -z "$upload" ] && [ "${len:-0}" -gt 0 ] 2>/dev/null && [ "$len" -le 8192 ]; then
    body=$(head -c "$len")
fi
path=${target%%\?*}
# OpenBMC's names for its resources, and the short ones of the first
# winlab BMC (scripts and lessons written for /redfish/v1/Systems/1 work on)
case "$path" in
    /redfish/v1/Systems/1 | /redfish/v1/Systems/1/*) path=/redfish/v1/Systems/system${path#/redfish/v1/Systems/1} ;;
    /redfish/v1/Managers/1/LogServices/IEL/Entries*) path=/redfish/v1/Systems/system/LogServices/EventLog/Entries${path#/redfish/v1/Managers/1/LogServices/IEL/Entries} ;;
    /redfish/v1/Managers/1 | /redfish/v1/Managers/1/*) path=/redfish/v1/Managers/bmc${path#/redfish/v1/Managers/1} ;;
esac
[ "$path" != / ] && path=${path%/}

now() { date '+%Y-%m-%d %H:%M:%S'; }
event() { printf '%s|%s|%s\n' "$(now)" "$1" "$(printf '%s' "$2" | tr -d '"\\|<>')" >> "$D/events"; }
get() { cat "$D/$1" 2>/dev/null | head -n 1; }
js() { printf '%s' "$1" | tr -d '"\\\000-\037'; }  # a value safe inside a JSON string

extra=''
refresh=''
reply() {  # status, content type, body
    n=$(printf '%s' "$3" | wc -c | tr -d ' ')
    printf 'HTTP/1.0 %s\r\nServer: winlab-bmc\r\nContent-Type: %s\r\nContent-Length: %s\r\nCache-Control: no-store\r\nConnection: close\r\n%s\r\n' \
        "$1" "$2" "$n" "$extra"
    printf '%s' "$3"
    exit 0
}
header() { extra="$extra$1$cr
"; }
json() { reply "${2:-200 OK}" 'application/json' "$1"; }
fail() {  # status, Redfish message id, message
    json "{\"error\":{\"code\":\"Base.1.16.0.$2\",\"message\":\"$3\",\"@Message.ExtendedInfo\":[{\"@odata.type\":\"#Message.v1_1_1.Message\",\"MessageId\":\"Base.1.16.0.$2\",\"Message\":\"$3\",\"Severity\":\"Warning\",\"Resolution\":\"None.\"}]}}" "$1"
}
missing() { fail '404 Not Found' ResourceNotFound "The resource at $(js "$path") was not found on this BMC."; }
refuse() { fail '405 Method Not Allowed' OperationNotAllowed "${1:-This BMC does not do that.}"; }
ok() { json '{"@Message.ExtendedInfo":[{"@odata.type":"#Message.v1_1_1.Message","MessageId":"Base.1.16.0.Success","Message":"The request completed successfully.","Severity":"OK","Resolution":"None."}]}'; }

name=$(get name)
user=$(get user)
# The firmware this BMC keeps an inventory of (winlab/bmcfw.py writes the
# files; these defaults are bmcfw.DEFAULTS): its own image and the backup,
# the server's BIOS with its release date, and a BIOS image staged for the
# next power-on from off.
fw_bmc=$(get fw_bmc); fw_bmc=${fw_bmc:-2.14.0}
fw_bak=$(get fw_bmc_backup); fw_bak=${fw_bak:-2.13.1}
set -- $(get fw_bios)
fw_bios=${1:-1.2.0} fw_bdate=${2:-03/14/2025}
set -- $(get fw_bios_pending)
fw_pend=${1:-} fw_pdate=${2:-}
machine=$(get machine); machine=${machine:-WL-R200}
want=$(get auth)
webui=''
[ -f "$W/index.html" ] && webui=1

# ------------------------------------------------------------------ static files
# The web UI's own files, as built: hashed names under js/ and css/, gzipped
# (served as they are, with Content-Encoding, as bmcweb does).
static() {
    f=${1#/}
    case "$f" in *..* | */.* | .*) reply '404 Not Found' 'text/plain' 'not found' ;; esac
    enc=''
    if [ -f "$W/$f" ]; then file=$W/$f
    elif [ -f "$W/$f.gz" ]; then file=$W/$f.gz; enc=gzip
    else reply '404 Not Found' 'text/plain' 'not found'
    fi
    case "$f" in
        *.html) t='text/html; charset=utf-8' ;; *.js) t='text/javascript' ;; *.css) t='text/css' ;;
        *.svg) t='image/svg+xml' ;; *.png) t='image/png' ;; *.ico) t='image/x-icon' ;;
        *.woff2) t='font/woff2' ;; *.woff) t='font/woff' ;; *.json) t='application/json' ;;
        *) t='application/octet-stream' ;;
    esac
    cache='max-age=31536000, immutable'
    [ "$f" = index.html ] && cache='no-store'
    n=$(wc -c < "$file" | tr -d ' ')
    printf 'HTTP/1.0 200 OK\r\nServer: winlab-bmc\r\nContent-Type: %s\r\nContent-Length: %s\r\nCache-Control: %s\r\n%sX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n' \
        "$t" "$n" "$cache" "${enc:+Content-Encoding: $enc$cr
}"
    [ "$method" = HEAD ] || cat "$file"
    exit 0
}
if [ -n "$webui" ] && { [ "$method" = GET ] || [ "$method" = HEAD ]; }; then
    case "$path" in
        / | /index.html) static /index.html ;;
        /favicon.ico | /js/* | /css/* | /assets/* | /fonts/* | /img/*) static "$path" ;;
    esac
fi

# ------------------------------------------------------------------ who asks
# HTTP Basic with the toe tag or a local user's; or a session: its
# X-Auth-Token, or its SESSION cookie, which a change must back with the
# X-XSRF-TOKEN the session gave. Each local user is a line of accounts:
# name, role, the base64 of name:secret as Basic sends it, enabled.
S=$D/sessions
mkdir -p "$S" 2>/dev/null
find "$S" -type f -mmin +60 -exec rm -f {} \; >/dev/null 2>&1  # SessionTimeout: an hour unused
rand() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
session_of() {  # token -> session id
    [ -n "$1" ] || return 1
    for s in "$S"/*; do
        [ -f "$s" ] || continue
        read -r t x u p < "$s"
        [ "$t" = "$1" ] && { sid=${s##*/}; sx=$x; su=$u; return 0; }
    done
    return 1
}
acct() {  # the enabled local user whose Basic sign-in this is
    [ -n "$1" ] && [ -f "$D/accounts" ] || return 1
    awk -v a="$1" '$3 == a && $4 == "true" { print; f = 1; exit } END { exit !f }' "$D/accounts"
}
role_of() {  # the toe tag's account is the administrator; a local user has its own role
    [ "$1" = "$user" ] && { echo Administrator; return; }
    awk -v u="$1" '$1 == u { print $2; exit }' "$D/accounts" 2>/dev/null
}
who=''
sid=''
sx=''
su=''
how=''
ctoken=$(printf '%s' "$cookie" | tr ';' '\n' | sed -n 's/^ *SESSION=\([0-9a-f]*\).*/\1/p' | head -n 1)
if [ -n "$auth" ]; then
    if [ -n "$want" ] && [ "$auth" = "Basic $want" ]; then who=$user; how=basic
    elif l=$(acct "${auth#Basic }"); then who=${l%% *}; how=basic
    elif [ -n "$want" ]; then event Warning "Login failure from $peer"
    fi
elif session_of "$xtoken"; then who=$su; how=token
elif session_of "$ctoken"; then
    case "$method" in
        GET | HEAD) who=$su; how=cookie ;;
        *) [ -n "$xsrf" ] && [ "$xsrf" = "$sx" ] && { who=$su; how=cookie; } ;;
    esac
fi
[ -z "$want" ] && who=$user
role=''
[ -n "$who" ] && role=$(role_of "$who")
[ -n "$who" ] && [ -z "$role" ] && who=''  # a session of a user deleted since
may() {  # operate: power, media, boot, the LED; configure: users and the port
    case "$role:$1" in
        Administrator:* | Operator:operate) return 0 ;;
    esac
    fail '403 Forbidden' InsufficientPrivilege "The account $who ($role) may not do that on this BMC."
}
[ -n "$sid" ] && [ -n "$who" ] && touch "$S/$sid"
need() {  # a resource behind the sign-in
    [ -n "$who" ] && return 0
    [ -n "$upload" ] && rm -f "$D/upload.tar"
    [ -z "$xhr" ] && extra='WWW-Authenticate: Basic realm="Management processor of '"$name"'"'"$cr"'
'
    fail '401 Unauthorized' NoValidSession "Sign in with the user and password on the server's toe tag."
}

power=$(get power)
[ -n "$power" ] || power=Off
health=$(get health)
[ -n "$health" ] || health=OK
seen=$(get seen)
age=$(( $(date +%s) - ${seen:-0} ))
lost=''
[ "$age" -gt 30 ] && lost=1
TYPES='On ForceOff GracefulShutdown GracefulRestart ForceRestart PushPowerButton PowerCycle'

ask() {  # a power action from this request; false when it is not one
    case " $TYPES " in *" $1 "*) ;; *) return 1 ;; esac
    [ -n "$1" ] || return 1
    printf '%s %s\n' "$1" "$peer" >> "$D/queue"
    event Info "Power: $1 requested by $who from $peer"
    date -u '+%Y-%m-%dT%H:%M:%S+00:00' > "$D/lastreset"
}

boot_set() {  # target, enabled: the boot override, queued; false when not one this BMC takes
    case "$1" in None | Cd | Hdd | BiosSetup) ;; *) return 1 ;; esac
    case "${2:-Once}" in Disabled | Once | Continuous) ;; *) return 1 ;; esac
    e=${2:-Once}
    [ "$1" = None ] && e=Disabled
    [ "$e" = Disabled ] && set -- None Disabled
    printf '%s %s\n' "$1" "$e" > "$D/boot"
    printf 'Boot=%s:%s %s\n' "$1" "$e" "$peer" >> "$D/queue"
    event Info "Boot override $1 ($e) set by $who from $peer"
}

# ------------------------------------------------------------------ winlab's own pages
page() {  # title, body html
    reply '200 OK' 'text/html; charset=utf-8' "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'>$refresh<title>$1 - $name</title>
<style>body{margin:0;font:14px Segoe UI,Arial,sans-serif;background:#eef1f5;color:#1d2530}
header{background:#1d2a38;color:#fff;padding:10px 18px;display:flex;align-items:center;gap:12px}
header b{font-size:16px}header span{opacity:.75}nav{background:#2b3b4d;padding:0 12px}
nav a{color:#dbe6f2;display:inline-block;padding:9px 12px;text-decoration:none}nav a:hover{background:#3a4f66}
main{padding:18px;max-width:900px}.card{background:#fff;border:1px solid #d3dae3;border-radius:6px;padding:14px 16px;margin-bottom:14px}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:5px 8px;border-bottom:1px solid #e3e8ee}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}.On{background:#2fa84f}.Off{background:#8a96a3}
.bad{color:#b3261e;font-weight:600}.warn{background:#fff4d6;border-color:#e9c46a}
button{font:inherit;padding:6px 12px;margin:4px 6px 4px 0;border:1px solid #9aa7b5;border-radius:4px;background:#f7f9fb;cursor:pointer}
button:hover{background:#e6edf5}.sev-Critical{color:#b3261e}.sev-Warning{color:#9a6700}code{background:#eef1f5;padding:1px 4px}</style></head>
<body><header><svg width=28 height=28 viewBox='0 0 28 28'><rect x=2 y=5 width=24 height=18 rx=3 fill='#3d7bd9'/><path d='M7 14h4l2-4 3 8 2-4h3' fill=none stroke='#fff' stroke-width=2/></svg>
<div><b>Management processor</b> <span>of $name</span></div></header>
<nav><a href='/'>Overview</a><a href='/console'>Virtual console</a><a href='/media'>Virtual media and boot</a><a href='/log'>Event log</a><a href='/firmware'>Firmware</a><a href='/redfish/v1/Systems/1'>Redfish</a></nav><main>$2</main></body></html>"
}

overview() {
    pend=''
    [ -s "$D/queue" ] && pend="<p>Waiting to carry out: <b>$(cut -d' ' -f1 "$D/queue" | tr '\n' ' ')</b></p>"
    state="<span class='dot $power'></span>$power"
    [ "$health" = Critical ] && state="$state <span class=bad>&middot; not responding</span>"
    warn=''
    [ -n "$lost" ] && warn="<div class='card warn'>The management processor has no word from the server's power controller (winlab's desktop is not running on the lab's PC): requests wait until it is back.</div>"
    page Overview "$warn<div class=card><table>
<tr><th>Server</th><td>$name</td></tr><tr><th>Power</th><td>$state</td></tr>
<tr><th>Health</th><td>$( [ "$health" = Critical ] && echo "<span class=bad>Critical: the operating system stopped responding</span>" || echo OK)</td></tr>
<tr><th>Management address</th><td>$(get ip)</td></tr></table>$pend</div>
<div class=card><b>Power</b><form method=post action=/power>
<button name=action value=PushPowerButton title='As pressing the power button once'>Momentary press</button>
<button name=action value=ForceOff title='As holding the power button: off at once, unsaved work is lost'>Press and hold</button>
<button name=action value=ForceRestart title='Reset: the server restarts at once'>Reset</button>
<button name=action value=PowerCycle title='Off, then on again'>Cold boot</button>
<button name=action value=On>Power on</button></form>
<p style='margin:6px 0 0;color:#5b6773'>Scripts use Redfish: <code>POST /redfish/v1/Systems/1/Actions/ComputerSystem.Reset</code> with <code>{&quot;ResetType&quot;:&quot;ForceRestart&quot;}</code>.</p></div>"
}

console_page() {
    at=$(get screen.at)
    if [ "$power" = On ] && [ $(( $(date +%s) - ${at:-0} )) -gt 4 ] && ! grep -q '^Screenshot' "$D/queue" 2>/dev/null; then
        printf 'Screenshot %s\n' "$peer" >> "$D/queue"
    fi
    refresh="<meta http-equiv=refresh content=5>"
    if [ "$power" != On ]; then
        img="<p>The server is off: there is no picture.</p>"
    elif [ -s "$D/screen.png" ]; then
        img="<img src='/screen.png?${at:-0}' style='max-width:100%;border:1px solid #333;background:#000' alt='the server screen'><p style='color:#5b6773'>Taken $(date -d "@${at:-0}" '+%H:%M:%S' 2>/dev/null); it refreshes every few seconds.</p>"
    else
        img="<p>Taking a picture of the screen…</p>"
    fi
    keys=''
    [ "$power" = On ] && keys="<div class=card><form method=post action=/keys style='display:flex;gap:6px;flex-wrap:wrap;align-items:center'>
<input name=text autocomplete=off placeholder='Type here, then Send keys' style='flex:1;min-width:200px;font:inherit;padding:5px'>
<button>Send keys</button><button name=key value=enter>Enter</button><button name=key value=tab>Tab</button><button name=key value=esc>Esc</button>
<button name=key value=ctrl-alt-del>Ctrl+Alt+Del</button><button name=key value=f2>F2</button><button name=key value=f12>F12</button></form></div>"
    page 'Virtual console' "<div class=card>$img</div>$keys"
}

media_page() {
    in=$(get vmedia)
    opts=$(awk -F'|' 'NF >= 2 { printf "<option value=\"%s\">%s</option>", $1, $2 }' "$D/media.list" 2>/dev/null)
    # the default set here, not inside the page's quotes: bash (Git's sh on
    # Windows) reads a quote inside ${x:-...} within double quotes as a quote
    [ -n "$opts" ] || opts="<option value=''>no disc on the lab's media shelf</option>"
    b=$(get boot)
    page 'Virtual media and boot' "<div class=card><b>Virtual DVD</b><p>${in:+In the drive: <b>$in</b>}${in:-The drive is empty.}</p>
<form method=post action=/media><select name=image style='font:inherit;padding:5px'>$opts</select>
<button name=op value=insert>Insert</button><button name=op value=eject>Eject</button></form>
<p style='color:#5b6773;margin:6px 0 0'>The discs on the lab's media shelf. Nothing from outside the lab.</p></div>
<div class=card><b>Boot override</b><p>Now: <b>${b:-None Disabled}</b></p><form method=post action=/boot>
<select name=target style='font:inherit;padding:5px'><option>None</option><option value=Cd>DVD drive</option><option value=Hdd>Disk</option><option value=BiosSetup>Firmware setup</option></select>
<select name=enabled style='font:inherit;padding:5px'><option>Once</option><option>Continuous</option></select> <button>Save</button></form></div>"
}
form() {  # one field of an urlencoded form, in the characters it may hold
    printf '%s' "$body" | tr '&' '\n' | sed -n "s/^$1=//p" | head -n 1 | tr -cd "$2"
}

firmware_page() {
    st=''
    [ -n "$fw_pend" ] && st="<tr><th>BIOS staged</th><td>$fw_pend ($fw_pdate): written at the server's next power-on from off</td></tr>"
    page Firmware "<div class=card><table><tr><th>Model</th><td>$machine</td></tr>
<tr><th>BMC, active image</th><td>$fw_bmc</td></tr><tr><th>BMC, backup image</th><td>$fw_bak</td></tr>
<tr><th>BIOS</th><td>$fw_bios ($fw_bdate)</td></tr>$st</table></div>
<div class=card><b>Update firmware</b><p>A package from the vendor (.tar with a MANIFEST). Check its SHA-256 against the vendor's list first.</p>
<input type=file id=fwfile accept='.tar'> <button onclick='up()'>Start update</button><p id=fwout></p>
<script>function up(){var f=document.getElementById('fwfile').files[0],o=document.getElementById('fwout');if(!f){o.textContent='Choose a package first.';return}
o.textContent='Uploading and verifying...';fetch('/redfish/v1/UpdateService/update',{method:'POST',body:f,credentials:'same-origin',headers:{'Content-Type':'application/octet-stream'}})
.then(function(r){return r.json().then(function(j){o.textContent=(r.ok?'':'Refused: ')+((j.error&&j.error.message)||(j.Messages&&j.Messages[0]&&j.Messages[0].Message)||r.status)})})}</script>
<p style='color:#5b6773;margin:6px 0 0'>Scripts: <code>POST /redfish/v1/UpdateService/update</code> with the package as the body.</p></div>"
}

log_page() {
    rows=$(tail -n 200 "$D/events" 2>/dev/null | awk -F'|' '{r = "<tr><td>" $1 "</td><td class=sev-" $2 ">" $2 "</td><td>" $3 "</td></tr>" r} END {print r}')
    page 'Event log' "<div class=card><table><tr><th>When</th><th>Severity</th><th>Event</th></tr>${rows:-<tr><td colspan=3>empty</td></tr>}</table></div>"
}

own_pages() {
    if [ "$how" != basic ] && [ -n "$want" ]; then
        extra='WWW-Authenticate: Basic realm="Management processor of '"$name"'"'"$cr"'
'
        reply '401 Unauthorized' 'text/plain' "Log in with the user and password on the server's toe tag."
    fi
    back() {
        extra="Location: /$1$cr
"
        reply '303 See Other' 'text/plain' 'done'
    }
    case "$method $path" in
        "GET /" | "GET /index.html") overview ;;
        "POST /power")
            may operate
            act=$(printf '%s' "$body" | sed -n 's/.*action=\([A-Za-z]*\).*/\1/p')
            ask "$act"
            back ;;
        "GET /console") console_page ;;
        "POST /keys")
            may operate
            k=$(form key 'a-z0-9-')
            tx=$(form text 'A-Za-z0-9%+._~*-' | cut -c1-600)
            if [ -n "$k" ]; then printf 'Keys=k:%s %s\n' "$k" "$peer" >> "$D/queue"
            elif [ -n "$tx" ]; then printf 'Keys=u:%s %s\n' "$tx" "$peer" >> "$D/queue"
            fi
            back console ;;
        "GET /media") media_page ;;
        "POST /media")
            may operate
            op=$(form op 'a-z')
            im=$(form image 'a-z0-9-')
            if [ "$op" = eject ]; then printf 'EjectMedia %s\n' "$peer" >> "$D/queue"; event Info "Virtual media: eject requested by $who from $peer"
            elif [ -n "$im" ] && grep -q "^$im|" "$D/media.list" 2>/dev/null; then
                printf 'InsertMedia=%s %s\n' "$im" "$peer" >> "$D/queue"; event Info "Virtual media: $im requested by $who from $peer"
            fi
            back media ;;
        "POST /boot")
            may operate
            boot_set "$(form target 'A-Za-z')" "$(form enabled 'A-Za-z')" >/dev/null
            back media ;;
        "GET /screen.png")
            [ -s "$D/screen.png" ] || reply '404 Not Found' 'text/plain' 'no picture yet'
            n=$(wc -c < "$D/screen.png" | tr -d ' ')
            printf 'HTTP/1.0 200 OK\r\nContent-Type: image/png\r\nContent-Length: %s\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n' "$n"
            cat "$D/screen.png"
            exit 0 ;;
        "GET /log") log_page ;;
        "GET /firmware") firmware_page ;;
    esac
    reply '404 Not Found' 'text/plain' 'not found'
}
case "$path" in /redfish | /redfish/*) ;; *)
    # Beside OpenBMC's web UI (no KVM on this BMC) the console's keys and the
    # virtual media keep winlab's own pages.
    case "$path" in /console | /keys | /screen.png | /media | /boot) ;; *)
        [ -n "$webui" ] && reply '404 Not Found' 'text/plain' 'not found' ;;
    esac
    own_pages ;;
esac

# ------------------------------------------------------------------ Redfish
R=/redfish/v1
SYS=$R/Systems/system
MGR=$R/Managers/bmc
CH=$R/Chassis/chassis
member() { printf '{"@odata.id":"%s"}' "$1"; }
collection() {  # odata id, type, name, member ids...
    id=$1 t=$2 n=$3
    shift 3
    m=''
    for x in "$@"; do m="$m${m:+,}$(member "$x")"; done
    json "{\"@odata.id\":\"$id\",\"@odata.type\":\"#$t\",\"Name\":\"$n\",\"Members@odata.count\":$#,\"Members\":[$m]}"
}
only() {  # the methods a resource takes
    for m in "$@"; do [ "$method" = "$m" ] && return 0; done
    header "Allow: $(echo "$@" | tr ' ' ',')"
    refuse "$method is not allowed on $path."
}
field() {  # a string property of the request body
    printf '%s' "$body" | tr -d '\n' | sed -n 's/.*"'"$1"'"[ ]*:[ ]*"\([^"]*\)".*/\1/p'
}
flag() {  # a boolean property of the request body
    printf '%s' "$body" | tr -d '\n' | sed -nE 's/.*"'"$1"'"[ ]*:[ ]*(true|false).*/\1/p'
}
mac=$(get mac)
ip=$(get ip)
serial=$(printf '%s' "$mac" | tr -d ':' | tr a-f A-F | cut -c7-)
uuid=$(printf '%s' "$mac" | tr -d ':')
uuid="00000000-0000-4000-8000-${uuid:-000000000000}"
st=Enabled
[ "$power" = Off ] && st=StandbyOffline
h=OK
[ "$health" = Critical ] && h=Critical
led=$(get led)
[ "$led" = true ] || led=false
iso() { date -u '+%Y-%m-%dT%H:%M:%S+00:00'; }

system() {
    cpus=$(get cpus) mem=$(get memory)
    tag=$(js "$(get assettag)")
    last=$(get lastreset)
    set -- $(get boot)
    bt=${1:-None} be=${2:-Disabled}
    printf '{"@odata.id":"%s","@odata.type":"#ComputerSystem.v1_22_0.ComputerSystem","Id":"system","Name":"system","Description":"The server this BMC manages","HostName":"%s","SystemType":"Physical","Manufacturer":"QEMU","Model":"Standard PC (Q35 + ICH9, 2009)","SerialNumber":"%s","AssetTag":"%s","UUID":"%s","BiosVersion":"%s","PowerState":"%s",%s"LocationIndicatorActive":%s,"Status":{"State":"%s","Health":"%s","HealthRollup":"%s"},"ProcessorSummary":{"Count":%s,"CoreCount":%s,"Status":{"State":"Enabled","Health":"OK"}},"MemorySummary":{"TotalSystemMemoryGiB":%s,"Status":{"State":"Enabled","Health":"OK"}},"Boot":{"BootSourceOverrideEnabled":"%s","BootSourceOverrideEnabled@Redfish.AllowableValues":["Disabled","Once","Continuous"],"BootSourceOverrideMode":"UEFI","BootSourceOverrideTarget":"%s","BootSourceOverrideTarget@Redfish.AllowableValues":["None","Cd","Hdd","BiosSetup"]},"VirtualMedia":{"@odata.id":"%s"},"LogServices":{"@odata.id":"%s/LogServices"},"Actions":{"#ComputerSystem.Reset":{"target":"%s/Actions/ComputerSystem.Reset","@Redfish.ActionInfo":"%s/ResetActionInfo","ResetType@Redfish.AllowableValues":["On","ForceOff","GracefulShutdown","GracefulRestart","ForceRestart","PushPowerButton","PowerCycle"]}},"Bios":{"@odata.id":"%s/Bios"},"Links":{"ManagedBy":[{"@odata.id":"%s"}],"Chassis":[{"@odata.id":"%s"}]}}' \
        "$SYS" "$(js "$name")" "WL$serial" "$tag" "$uuid" "$fw_bios" "$power" "${last:+\"LastResetTime\":\"$last\",}" "$led" "$st" "$h" "$h" \
        "${cpus:-1}" "${cpus:-1}" "$(awk -v m="${mem:-0}" 'BEGIN { printf "%g", m / 1024 }')" "$be" "$bt" "$MGR/VirtualMedia" "$SYS" "$SYS" "$SYS" "$SYS" "$MGR" "$CH"
}

entries() {  # every line of the log an entry; its line number its Id
    awk -F'|' -v base="$SYS/LogServices/EventLog/Entries" -v resolved="$D/resolved" -v one="$1" '
        BEGIN { while ((getline r < resolved) > 0) done[r] = 1 }
        { if (one != "" && NR != one) next
          sev = ($2 == "Info") ? "OK" : $2; t = $1; sub(" ", "T", t)
          e = sprintf("{\"@odata.id\":\"%s/%d\",\"@odata.type\":\"#LogEntry.v1_9_0.LogEntry\",\"Id\":\"%d\",\"Name\":\"System Event Log Entry\",\"EntryType\":\"Event\",\"Created\":\"%s+00:00\",\"Modified\":\"%s+00:00\",\"Severity\":\"%s\",\"Message\":\"%s\",\"Resolved\":%s}", base, NR, NR, t, t, sev, $3, (NR in done) ? "true" : "false")
          out[++n] = e }
        END { if (one != "") { if (n) print out[1]; exit }
              s = (n > 200) ? n - 199 : 1; m = ""
              for (i = s; i <= n; i++) m = m (i > s ? "," : "") out[i]
              printf "{\"@odata.id\":\"%s\",\"@odata.type\":\"#LogEntryCollection.LogEntryCollection\",\"Name\":\"System Event Log Entries\",\"Members@odata.count\":%d,\"Members\":[%s]}", base, (n ? n - s + 1 : 0), m }' \
        "$D/events" 2>/dev/null
}

sessions_ids() { for s in "$S"/*; do [ -f "$s" ] && printf '%s\n' "$R/SessionService/Sessions/${s##*/}"; done; }
session_json() {  # id
    read -r t x u p < "$S/$1"
    printf '{"@odata.id":"%s/SessionService/Sessions/%s","@odata.type":"#Session.v1_7_0.Session","Id":"%s","Name":"User Session","UserName":"%s","ClientOriginIPAddress":"%s","SessionType":"Redfish","Roles":["%s"]}' \
        "$R" "$1" "$1" "$u" "$p" "$(role_of "$u")"
}

account_json() {  # user
    if [ "$1" = "$user" ]; then ar=Administrator ae=true
    else
        ar=$(role_of "$1")
        ae=$(awk -v u="$1" '$1 == u { print $4; exit }' "$D/accounts" 2>/dev/null)
    fi
    printf '{"@odata.id":"%s/AccountService/Accounts/%s","@odata.type":"#ManagerAccount.v1_7_0.ManagerAccount","Id":"%s","Name":"User Account","UserName":"%s","RoleId":"%s","Enabled":%s,"Locked":false,"Locked@Redfish.AllowableValues":["false"],"PasswordChangeRequired":false,"AccountTypes":["Redfish","WebUI"],"Links":{"Role":{"@odata.id":"%s/AccountService/Roles/%s"}}}' \
        "$R" "$1" "$1" "$1" "$ar" "${ae:-true}" "$R" "$ar"
}

inventory() {  # id, version, related item, description, state, extra properties
    json "{\"@odata.id\":\"$R/UpdateService/FirmwareInventory/$1\",\"@odata.type\":\"#SoftwareInventory.v1_4_0.SoftwareInventory\",\"Id\":\"$1\",\"Name\":\"Software Inventory\",\"Description\":\"$4\",\"Version\":\"$2\",$6\"Manufacturer\":\"winlab\",\"Updateable\":true,\"RelatedItem\":[{\"@odata.id\":\"$3\"}],\"RelatedItem@odata.count\":1,\"Status\":{\"State\":\"$5\",\"Health\":\"OK\",\"HealthRollup\":\"OK\"}}"
}

fw_refuse() {  # why: the package is not taken
    rm -rf "$D/upload.tar" "$D/upload.d"
    event Warning "Firmware update from $peer refused: $1"
    fail '400 Bad Request' ActionParameterValueError "Firmware update refused: $1"
}

fw_update() {  # the package in upload.tar, checked as a BMC checks it, then taken
    [ "$role" = Administrator ] || { rm -f "$D/upload.tar"; may configure; }
    [ -n "$toobig" ] && fw_refuse "the package is larger than this BMC takes ($UPMAX bytes)"
    [ -s "$D/upload.tar" ] || fail '400 Bad Request' ActionParameterMissing "Send the firmware package as the body of the POST (Content-Type: application/octet-stream)."
    u=$D/upload.d
    rm -rf "$u"
    mkdir -p "$u"
    tar -xf "$D/upload.tar" -C "$u" 2>/dev/null && [ -f "$u/MANIFEST" ] ||
        fw_refuse "not a firmware package (a tar with a MANIFEST)"
    mf() { sed -n "s/^$1=//p" "$u/MANIFEST" | tr -d '\r' | head -n 1; }
    fp=$(mf purpose)
    fver=$(mf version | tr -cd 'A-Za-z0-9._-' | cut -c1-32)
    fmach=$(mf MachineName | tr -cd 'A-Za-z0-9._-' | cut -c1-32)
    fdate=$(mf ReleaseDate | tr -cd '0-9/' | cut -c1-10)
    fimg=$(mf ImageFile | tr -cd 'A-Za-z0-9._-')
    fsum=$(mf ImageSHA256 | tr -cd '0-9a-f')
    case "$fp" in
        *.VersionPurpose.BMC) fk=bmc ;;
        *.VersionPurpose.Host) fk=bios ;;
        *) fw_refuse "the MANIFEST's purpose is neither BMC nor Host" ;;
    esac
    [ -n "$fver" ] || fw_refuse "the MANIFEST names no version"
    [ "$fmach" = "$machine" ] || fw_refuse "the image is for model ${fmach:-unknown}; this server is $machine"
    [ -n "$fimg" ] && [ -f "$u/$fimg" ] || fw_refuse "the package holds no image file"
    got=$(sha256sum "$u/$fimg" | cut -d' ' -f1)
    [ -n "$fsum" ] && [ "$got" = "$fsum" ] || fw_refuse "the image's SHA-256 does not match its MANIFEST: the package is damaged or was altered"
    rm -rf "$u" "$D/upload.tar"
    if [ "$fk" = bmc ]; then
        [ "$fver" = "$fw_bmc" ] && fw_refuse "BMC firmware $fver is already the active image"
        printf '%s\n' "$fw_bmc" > "$D/fw_bmc_backup"
        printf '%s\n' "$fver" > "$D/fw_bmc"
        printf 'Firmware=bmc:%s %s\n' "$fver" "$peer" >> "$D/queue"
        event Info "BMC firmware $fver verified (model $fmach, SHA-256 matches) and activated by $who from $peer; the BMC restarted on it. Backup image: $fw_bmc"
        tm="BMC firmware $fver is active; the BMC restarted on it."
    else
        printf '%s' "$fdate" | grep -Eq '^[0-9]{2}/[0-9]{2}/[0-9]{4}$' || fw_refuse "the MANIFEST's ReleaseDate is not MM/DD/YYYY"
        [ "$fver" = "$fw_bios" ] && fw_refuse "BIOS firmware $fver is already on the server"
        printf '%s %s\n' "$fver" "$fdate" > "$D/fw_bios_pending"
        printf 'Firmware=bios:%s:%s %s\n' "$fver" "$fdate" "$peer" >> "$D/queue"
        event Info "BIOS firmware $fver verified (model $fmach, SHA-256 matches) and staged by $who from $peer: it is written at the server's next power-on from off. Running now: $fw_bios"
        tm="BIOS firmware $fver is staged: power the server off and on (a power cycle) to write it."
    fi
    json "{\"@odata.id\":\"$R/TaskService/Tasks/0\",\"@odata.type\":\"#Task.v1_4_3.Task\",\"Id\":\"0\",\"Name\":\"Firmware update\",\"TaskState\":\"Completed\",\"TaskStatus\":\"OK\",\"PercentComplete\":100,\"Messages\":[{\"@odata.type\":\"#Message.v1_1_1.Message\",\"MessageId\":\"Update.1.0.UpdateSuccessful\",\"Message\":\"$tm\",\"Severity\":\"OK\",\"Resolution\":\"None.\"}]}" '202 Accepted'
}

login() {
    u=$(field UserName)
    b=$(printf '%s:%s' "$u" "$(field Password)" | base64 | tr -d '\n')
    if [ -n "$want" ] && [ "$b" = "$want" ] && [ "$u" = "$user" ]; then :
    elif l=$(acct "$b") && [ "${l%% *}" = "$u" ]; then :
    else
        event Warning "Login failure from $peer"
        fail '401 Unauthorized' ResourceAtUriUnauthorized "The user name or password is not the one on the server's toe tag, nor a user of this BMC."
    fi
    t=$(rand 16)
    x=$(rand 16)
    i=$(rand 5)
    printf '%s %s %s %s\n' "$t" "$x" "$u" "$peer" > "$S/$i"
    event Info "Login: $u signed in from $peer"
    header "Location: $R/SessionService/Sessions/$i"
    header "X-Auth-Token: $t"
    header "Set-Cookie: SESSION=$t; Path=/; SameSite=Strict; HttpOnly"
    header "Set-Cookie: XSRF-TOKEN=$x; Path=/; SameSite=Strict"
    header "Set-Cookie: IsAuthenticated=true; Path=/; SameSite=Strict"
    json "$(session_json "$i")" '201 Created'
}

case "$path" in
    /redfish) only GET HEAD; json '{"v1":"/redfish/v1/"}' ;;
    $R) only GET HEAD
        json "{\"@odata.id\":\"$R\",\"@odata.type\":\"#ServiceRoot.v1_15_0.ServiceRoot\",\"Id\":\"RootService\",\"Name\":\"Root Service\",\"RedfishVersion\":\"1.17.0\",\"UUID\":\"$uuid\",\"Product\":\"winlab BMC\",\"Vendor\":\"winlab\",\"Systems\":{\"@odata.id\":\"$R/Systems\"},\"Managers\":{\"@odata.id\":\"$R/Managers\"},\"Chassis\":{\"@odata.id\":\"$R/Chassis\"},\"SessionService\":{\"@odata.id\":\"$R/SessionService\"},\"AccountService\":{\"@odata.id\":\"$R/AccountService\"},\"UpdateService\":{\"@odata.id\":\"$R/UpdateService\"},\"ManagerProvidingService\":{\"@odata.id\":\"$MGR\"},\"Links\":{\"Sessions\":{\"@odata.id\":\"$R/SessionService/Sessions\"}}}" ;;
    $R/SessionService/Sessions)
        [ "$method" = POST ] && login
        need; only GET
        # shellcheck disable=SC2046
        collection "$path" SessionCollection.SessionCollection 'Session Collection' $(sessions_ids) ;;
    $R/SessionService/Sessions/*)
        need
        i=${path##*/}
        case "$i" in *[!0-9a-f]* | '') missing ;; esac
        [ -f "$S/$i" ] || missing
        only GET DELETE
        if [ "$method" = DELETE ]; then
            rm -f "$S/$i"
            [ "$i" = "$sid" ] && header "Set-Cookie: SESSION=; Path=/; Max-Age=0" && header "Set-Cookie: XSRF-TOKEN=; Path=/; Max-Age=0"
            ok
        fi
        json "$(session_json "$i")" ;;
esac

need
case "$path" in
    $R/SessionService) only GET
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#SessionService.v1_1_8.SessionService\",\"Id\":\"SessionService\",\"Name\":\"Session Service\",\"ServiceEnabled\":true,\"SessionTimeout\":3600,\"Sessions\":{\"@odata.id\":\"$path/Sessions\"}}" ;;
    $R/AccountService) only GET
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#AccountService.v1_10_0.AccountService\",\"Id\":\"AccountService\",\"Name\":\"Account Service\",\"Description\":\"The toe tag's account and the BMC's local users\",\"ServiceEnabled\":true,\"MinPasswordLength\":8,\"MaxPasswordLength\":20,\"AccountLockoutThreshold\":0,\"AccountLockoutDuration\":0,\"Accounts\":{\"@odata.id\":\"$path/Accounts\"},\"Roles\":{\"@odata.id\":\"$path/Roles\"}}" ;;
    $R/AccountService/Accounts)
        if [ "$method" = POST ]; then
            may configure
            nu=$(field UserName) nr=$(field RoleId) ns=$(field Password) ne=$(flag Enabled)
            nr=${nr:-ReadOnly}
            printf '%s' "$nu" | grep -Eq '^[A-Za-z][A-Za-z0-9._-]{0,15}$' ||
                fail '400 Bad Request' PropertyValueFormatError "UserName: a letter, then up to 15 letters, digits, dot, dash or underscore."
            case "$nr" in Administrator | Operator | ReadOnly) ;; *)
                fail '400 Bad Request' PropertyValueNotInList "RoleId must be Administrator, Operator or ReadOnly." ;; esac
            [ ${#ns} -ge 8 ] && [ ${#ns} -le 20 ] ||
                fail '400 Bad Request' PropertyValueFormatError "The password must be 8 to 20 characters."
            { [ "$nu" = "$user" ] || awk -v u="$nu" '$1 == u { f = 1 } END { exit !f }' "$D/accounts" 2>/dev/null; } &&
                fail '409 Conflict' ResourceAlreadyExists "The user $nu exists already."
            [ "$(wc -l < "$D/accounts" 2>/dev/null || echo 0)" -lt 15 ] ||
                fail '400 Bad Request' CreateLimitReachedForResource "This BMC holds 15 local users."
            printf '%s %s %s %s\n' "$nu" "$nr" "$(printf '%s:%s' "$nu" "$ns" | base64 | tr -d '\n')" "${ne:-true}" >> "$D/accounts"
            event Info "Account $nu ($nr) created by $who from $peer"
            header "Location: $path/$nu"
            json "$(account_json "$nu")" '201 Created'
        fi
        only GET
        # shellcheck disable=SC2046
        collection "$path" ManagerAccountCollection.ManagerAccountCollection 'Accounts Collection' "$path/$user" \
            $(awk -v p="$path" '{ print p "/" $1 }' "$D/accounts" 2>/dev/null) ;;
    $R/AccountService/Accounts/*)
        au=${path##*/}
        [ "$au" = "$user" ] || awk -v u="$au" '$1 == u { f = 1 } END { exit !f }' "$D/accounts" 2>/dev/null || missing
        only GET PATCH DELETE
        if [ "$method" != GET ]; then
            [ "$au" = "$user" ] && refuse "The toe tag's account is the BMC's factory account: it stays as printed on the tag."
            np=$(field Password) nr=$(field RoleId) ne=$(flag Enabled)
            # a user may change only its own password; the rest is an administrator's
            { [ "$method" = PATCH ] && [ "$au" = "$who" ] && [ -n "$np" ] && [ -z "$nr" ] && [ -z "$ne" ]; } || may configure
            if [ "$method" = DELETE ]; then
                awk -v u="$au" '$1 != u' "$D/accounts" > "$D/accounts.new" && mv "$D/accounts.new" "$D/accounts"
                event Info "Account $au deleted by $who from $peer"
                ok
            fi
            if [ -n "$np" ]; then
                [ ${#np} -ge 8 ] && [ ${#np} -le 20 ] ||
                    fail '400 Bad Request' PropertyValueFormatError "The password must be 8 to 20 characters."
                nb=$(printf '%s:%s' "$au" "$np" | base64 | tr -d '\n')
            fi
            case "$nr" in '' | Administrator | Operator | ReadOnly) ;; *)
                fail '400 Bad Request' PropertyValueNotInList "RoleId must be Administrator, Operator or ReadOnly." ;; esac
            awk -v u="$au" -v r="$nr" -v b="$nb" -v e="$ne" '$1 == u { if (r != "") $2 = r; if (b != "") $3 = b; if (e != "") $4 = e } { print }' \
                "$D/accounts" > "$D/accounts.new" && mv "$D/accounts.new" "$D/accounts"
            event Info "Account $au changed by $who from $peer"
            ok
        fi
        json "$(account_json "$au")" ;;
    $R/AccountService/Roles) only GET; collection "$path" RoleCollection.RoleCollection 'Roles Collection' "$path/Administrator" "$path/Operator" "$path/ReadOnly" ;;
    $R/AccountService/Roles/Administrator | $R/AccountService/Roles/Operator | $R/AccountService/Roles/ReadOnly) only GET
        ri=${path##*/}
        case "$ri" in
            Administrator) pv='"Login","ConfigureManager","ConfigureUsers","ConfigureSelf","ConfigureComponents"' ;;
            Operator) pv='"Login","ConfigureSelf","ConfigureComponents"' ;;
            *) pv='"Login","ConfigureSelf"' ;;
        esac
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#Role.v1_2_2.Role\",\"Id\":\"$ri\",\"Name\":\"User Role\",\"RoleId\":\"$ri\",\"IsPredefined\":true,\"AssignedPrivileges\":[$pv],\"OemPrivileges\":[]}" ;;
    $R/Systems) only GET; collection "$path" ComputerSystemCollection.ComputerSystemCollection 'Computer System Collection' "$SYS" ;;
    $SYS)
        only GET PATCH
        if [ "$method" = PATCH ]; then
            may operate
            a=$(printf '%s' "$body" | grep -c '"AssetTag"')
            l=$(flag LocationIndicatorActive)
            bt=$(field BootSourceOverrideTarget) be=$(field BootSourceOverrideEnabled)
            [ "$a" -gt 0 ] || [ -n "$l" ] || [ -n "$bt$be" ] || fail '400 Bad Request' PropertyNotWritable "This BMC changes the AssetTag, LocationIndicatorActive and Boot of the system."
            if [ -n "$bt$be" ]; then
                set -- $(get boot)
                boot_set "${bt:-${1:-None}}" "${be:-Once}" ||
                    fail '400 Bad Request' PropertyValueNotInList "BootSourceOverrideTarget must be None, Cd, Hdd or BiosSetup; BootSourceOverrideEnabled Disabled, Once or Continuous."
            fi
            if [ "$a" -gt 0 ]; then
                v=$(field AssetTag | tr -cd 'A-Za-z0-9 ._-' | cut -c1-32)
                printf '%s\n' "$v" > "$D/assettag"
                event Info "Asset tag set to '$v' by $user from $peer"
            fi
            if [ -n "$l" ]; then
                printf '%s\n' "$l" > "$D/led"
                event Info "Identify LED $( [ "$l" = true ] && echo on || echo off) by $user from $peer"
            fi
            ok
        fi
        json "$(system)" ;;
    $SYS/ResetActionInfo) only GET
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#ActionInfo.v1_1_2.ActionInfo\",\"Id\":\"ResetActionInfo\",\"Name\":\"Reset Action Info\",\"Parameters\":[{\"Name\":\"ResetType\",\"Required\":true,\"DataType\":\"String\",\"AllowableValues\":[\"$(echo $TYPES | sed 's/ /","/g')\"]}]}" ;;
    $SYS/Actions/ComputerSystem.Reset)
        only POST
        may operate
        rt=$(field ResetType)
        ask "$rt" && ok
        fail '400 Bad Request' ActionParameterValueNotInList "ResetType must be one of: $TYPES" ;;
    $SYS/LogServices) only GET; collection "$path" LogServiceCollection.LogServiceCollection 'System Log Services Collection' "$path/EventLog" ;;
    $SYS/LogServices/EventLog) only GET
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#LogService.v1_2_0.LogService\",\"Id\":\"EventLog\",\"Name\":\"Event Log Service\",\"Description\":\"System Event Log Service\",\"OverWritePolicy\":\"WrapsWhenFull\",\"DateTime\":\"$(iso)\",\"DateTimeLocalOffset\":\"+00:00\",\"Entries\":{\"@odata.id\":\"$path/Entries\"}}" ;;
    $SYS/LogServices/EventLog/Actions/LogService.ClearLog)
        refuse "This BMC keeps its event log: it is the record of what happened to the server." ;;
    $SYS/LogServices/EventLog/Entries) only GET; json "$(entries)" ;;
    $SYS/LogServices/EventLog/Entries/*)
        i=${path##*/}
        case "$i" in *[!0-9]* | '') missing ;; esac
        e=$(entries "$i")
        [ -n "$e" ] || missing
        [ "$method" = DELETE ] && refuse "This BMC keeps its event log: it is the record of what happened to the server."
        only GET PATCH
        if [ "$method" = PATCH ]; then
            r=$(flag Resolved)
            [ -n "$r" ] || fail '400 Bad Request' PropertyNotWritable "Only Resolved changes on an event log entry."
            { grep -vx "$i" "$D/resolved" 2>/dev/null; [ "$r" = true ] && echo "$i"; } > "$D/resolved.new"
            mv "$D/resolved.new" "$D/resolved"
            ok
        fi
        json "$e" ;;
    $R/Managers) only GET; collection "$path" ManagerCollection.ManagerCollection 'Manager Collection' "$MGR" ;;
    $MGR)
        only GET PATCH
        if [ "$method" = PATCH ]; then
            may configure
            ai=$(printf '%s' "$body" | tr -d '\n' | sed -n 's/.*"ActiveSoftwareImage"[ ]*:[ ]*{[^}]*"@odata.id"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
            [ -n "$ai" ] || fail '400 Bad Request' PropertyNotWritable "This BMC changes only Links.ActiveSoftwareImage of the manager."
            case "${ai##*/}" in
                bmc_active) ok ;;
                bmc_backup)
                    printf '%s\n' "$fw_bmc" > "$D/fw_bmc_backup"; printf '%s\n' "$fw_bak" > "$D/fw_bmc"
                    printf 'Firmware=bmc-switch %s\n' "$peer" >> "$D/queue"
                    event Info "BMC firmware: switched to the backup image $fw_bak by $who from $peer; the BMC restarted on it (backup now $fw_bmc)"
                    ok ;;
                *) fail '400 Bad Request' PropertyValueNotInList "ActiveSoftwareImage must be $R/UpdateService/FirmwareInventory/bmc_active or bmc_backup." ;;
            esac
        fi
        json "{\"@odata.id\":\"$MGR\",\"@odata.type\":\"#Manager.v1_14_0.Manager\",\"Id\":\"bmc\",\"Name\":\"Management processor of $(js "$name")\",\"Description\":\"Baseboard Management Controller\",\"ManagerType\":\"BMC\",\"Model\":\"winlab BMC\",\"FirmwareVersion\":\"$fw_bmc\",\"UUID\":\"$uuid\",\"PowerState\":\"On\",\"DateTime\":\"$(iso)\",\"DateTimeLocalOffset\":\"+00:00\",\"Status\":{\"State\":\"Enabled\",\"Health\":\"OK\",\"HealthRollup\":\"OK\"},\"EthernetInterfaces\":{\"@odata.id\":\"$MGR/EthernetInterfaces\"},\"VirtualMedia\":{\"@odata.id\":\"$MGR/VirtualMedia\"},\"LogServices\":{\"@odata.id\":\"$MGR/LogServices\"},\"Links\":{\"ManagerForServers\":[{\"@odata.id\":\"$SYS\"}],\"ManagerForChassis\":[{\"@odata.id\":\"$CH\"}],\"ActiveSoftwareImage\":{\"@odata.id\":\"$R/UpdateService/FirmwareInventory/bmc_active\"}}}" ;;
    $MGR/EthernetInterfaces) only GET; collection "$path" EthernetInterfaceCollection.EthernetInterfaceCollection 'Ethernet Network Interface Collection' "$path/eth0" ;;
    $MGR/EthernetInterfaces/eth0)
        only GET PATCH
        if [ "$method" = PATCH ]; then
            may configure
            flat=$(printf '%s' "$body" | tr -d '\n')
            dh=$(printf '%s' "$flat" | sed -nE 's/.*"DHCPEnabled"[ ]*:[ ]*(true|false).*/\1/p')
            [ "$dh" = true ] && fail '400 Bad Request' ActionNotSupported "This management port keeps a static address: DHCP is not offered on it."
            na=$(printf '%s' "$flat" | sed -n 's/.*"IPv4StaticAddresses"[ ]*:[ ]*\[[ ]*{[^}]*"Address"[ ]*:[ ]*"\([0-9.]*\)".*/\1/p')
            [ -n "$na" ] || fail '400 Bad Request' PropertyNotWritable "This BMC changes only IPv4StaticAddresses[0].Address; the mask and gateway are the network's."
            printf '%s' "$na" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' ||
                fail '400 Bad Request' PropertyValueFormatError "$na is not an IPv4 address."
            printf 'Address=%s %s\n' "$na" "$peer" >> "$D/queue"
            event Info "Management address $na requested by $who from $peer: the BMC moves to it"
            ok
        fi
        gw=$(get gateway) mask=$(get mask)
        a="{\"Address\":\"$ip\",\"SubnetMask\":\"${mask:-255.255.255.0}\",\"Gateway\":\"${gw:-0.0.0.0}\",\"AddressOrigin\":\"Static\"}"
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#EthernetInterface.v1_9_0.EthernetInterface\",\"Id\":\"eth0\",\"Name\":\"Manager Ethernet Interface\",\"Description\":\"Management Network Interface\",\"InterfaceEnabled\":true,\"LinkStatus\":\"LinkUp\",\"SpeedMbps\":1000,\"FullDuplex\":true,\"MACAddress\":\"$mac\",\"PermanentMACAddress\":\"$mac\",\"HostName\":\"$(js "$name")-bmc\",\"FQDN\":\"$(js "$name")-bmc\",\"MTUSize\":1500,\"DHCPv4\":{\"DHCPEnabled\":false,\"UseDNSServers\":false,\"UseDomainName\":false,\"UseNTPServers\":false},\"DHCPv6\":{\"OperatingMode\":\"Disabled\"},\"IPv4Addresses\":[$a],\"IPv4StaticAddresses\":[$a],\"IPv6Addresses\":[],\"IPv6StaticAddresses\":[],\"IPv6DefaultGateway\":\"::\",\"NameServers\":[],\"StaticNameServers\":[],\"VLANs\":{\"@odata.id\":\"$path/VLANs\"},\"Status\":{\"State\":\"Enabled\",\"Health\":\"OK\"}}" ;;
    $MGR/LogServices) only GET; collection "$path" LogServiceCollection.LogServiceCollection 'Open BMC Log Services Collection' ;;
    $MGR/VirtualMedia) only GET; collection "$path" VirtualMediaCollection.VirtualMediaCollection 'Virtual Media Services' "$path/CD1" ;;
    $MGR/VirtualMedia/CD1)
        only GET
        in=$(js "$(get vmedia)")
        imgs=$(awk -F'|' 'NF >= 2 { printf "%s\"%s\"", (n++ ? "," : ""), $1 }' "$D/media.list" 2>/dev/null)
        ins=false
        [ -n "$in" ] && ins=true
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#VirtualMedia.v1_6_0.VirtualMedia\",\"Id\":\"CD1\",\"Name\":\"Virtual CD\",\"Description\":\"The server's DVD drive; images are the discs on the lab's media shelf\",\"MediaTypes\":[\"CD\",\"DVD\"],\"ConnectedVia\":\"$( [ "$ins" = true ] && echo URI || echo NotConnected)\",\"Image\":$( [ "$ins" = true ] && echo "\"$in\"" || echo null),\"ImageName\":\"$in\",\"Image@Redfish.AllowableValues\":[$imgs],\"Inserted\":$ins,\"WriteProtected\":true,\"Status\":{\"State\":\"Enabled\",\"Health\":\"OK\"},\"Actions\":{\"#VirtualMedia.InsertMedia\":{\"target\":\"$path/Actions/VirtualMedia.InsertMedia\"},\"#VirtualMedia.EjectMedia\":{\"target\":\"$path/Actions/VirtualMedia.EjectMedia\"}}}" ;;
    $MGR/VirtualMedia/CD1/Actions/VirtualMedia.InsertMedia)
        only POST
        may operate
        im=$(field Image)
        im=${im%/}
        im=${im##*/}
        im=${im%.iso}
        im=$(printf '%s' "$im" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9-')
        [ -n "$im" ] && grep -q "^$im|" "$D/media.list" 2>/dev/null ||
            fail '400 Bad Request' ActionParameterValueNotInList "Image must be a disc on the lab's media shelf: $(cut -d'|' -f1 "$D/media.list" 2>/dev/null | tr '\n' ' ')"
        printf 'InsertMedia=%s %s\n' "$im" "$peer" >> "$D/queue"
        event Info "Virtual media: $im requested by $who from $peer"
        ok ;;
    $MGR/VirtualMedia/CD1/Actions/VirtualMedia.EjectMedia)
        only POST
        may operate
        printf 'EjectMedia %s\n' "$peer" >> "$D/queue"
        event Info "Virtual media: eject requested by $who from $peer"
        ok ;;
    $R/Chassis) only GET; collection "$path" ChassisCollection.ChassisCollection 'Chassis Collection' "$CH" ;;
    $CH) only GET
        json "{\"@odata.id\":\"$CH\",\"@odata.type\":\"#Chassis.v1_22_0.Chassis\",\"Id\":\"chassis\",\"Name\":\"chassis\",\"ChassisType\":\"RackMount\",\"Manufacturer\":\"QEMU\",\"Model\":\"Standard PC (Q35 + ICH9, 2009)\",\"SerialNumber\":\"WL$serial\",\"PowerState\":\"$power\",\"LocationIndicatorActive\":$led,\"Status\":{\"State\":\"$st\",\"Health\":\"$h\",\"HealthRollup\":\"$h\"},\"Sensors\":{\"@odata.id\":\"$CH/Sensors\"},\"Links\":{\"ComputerSystems\":[{\"@odata.id\":\"$SYS\"}],\"ManagedBy\":[{\"@odata.id\":\"$MGR\"}]}}" ;;
    $CH/Sensors) only GET
        # shellcheck disable=SC2046
        collection "$path" SensorCollection.SensorCollection 'Sensors' $(awk -F'|' -v p="$path" 'NF >= 5 { print p "/" $1 }' "$D/sensors" 2>/dev/null) ;;
    $CH/Sensors/*)
        only GET
        si=${path##*/}
        line=$(awk -F'|' -v i="$si" '$1 == i { print; exit }' "$D/sensors" 2>/dev/null)
        [ -n "$line" ] || missing
        IFS='|' read -r sid2 sn sr su2 sty <<EOF_SENSOR
$line
EOF_SENSOR
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#Sensor.v1_2_0.Sensor\",\"Id\":\"$sid2\",\"Name\":\"$sn\",\"Description\":\"Modelled by winlab from the server's load, not measured\",\"Reading\":$sr,\"ReadingUnits\":\"$su2\",\"ReadingType\":\"$sty\",\"Status\":{\"State\":\"Enabled\",\"Health\":\"OK\"}}" ;;
    $R/UpdateService)
        [ "$method" = POST ] && fw_update
        only GET
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#UpdateService.v1_11_1.UpdateService\",\"Id\":\"UpdateService\",\"Name\":\"Update Service\",\"Description\":\"Takes a firmware package as the body of a POST to HttpPushUri; checks its MANIFEST, machine name and SHA-256\",\"ServiceEnabled\":true,\"HttpPushUri\":\"$path/update\",\"HttpPushUriOptions\":{\"HttpPushUriApplyTime\":{\"ApplyTime\":\"Immediate\"}},\"MaxImageSizeBytes\":$UPMAX,\"FirmwareInventory\":{\"@odata.id\":\"$path/FirmwareInventory\"}}" ;;
    $R/UpdateService/update) only POST; fw_update ;;
    $R/UpdateService/FirmwareInventory)
        only GET
        if [ -n "$fw_pend" ]; then
            collection "$path" SoftwareInventoryCollection.SoftwareInventoryCollection 'Software Inventory Collection' "$path/bmc_active" "$path/bmc_backup" "$path/bios_active" "$path/bios_staged"
        fi
        collection "$path" SoftwareInventoryCollection.SoftwareInventoryCollection 'Software Inventory Collection' "$path/bmc_active" "$path/bmc_backup" "$path/bios_active" ;;
    $R/UpdateService/FirmwareInventory/*)
        only GET
        fi_id=${path##*/}
        case "$fi_id" in
            bmc_active) inventory "$fi_id" "$fw_bmc" "$MGR" 'BMC image, active' Enabled ;;
            bmc_backup) inventory "$fi_id" "$fw_bak" "$MGR" 'BMC image, backup' StandbySpare ;;
            bios_active) inventory "$fi_id" "$fw_bios" "$SYS/Bios" "BIOS image, released $fw_bdate" Enabled "\"ReleaseDate\":\"$(printf '%s' "$fw_bdate" | awk -F/ '{print $3 "-" $1 "-" $2}')T00:00:00+00:00\"," ;;
            bios_staged) [ -n "$fw_pend" ] || missing
                inventory "$fi_id" "$fw_pend" "$SYS/Bios" 'BIOS image, staged: written at the next power-on from off' StandbyOffline ;;
            *) missing ;;
        esac ;;
    $SYS/Bios) only GET
        json "{\"@odata.id\":\"$path\",\"@odata.type\":\"#Bios.v1_2_0.Bios\",\"Id\":\"BIOS\",\"Name\":\"BIOS Configuration\",\"Description\":\"The server's UEFI firmware\",\"Links\":{\"ActiveSoftwareImage\":{\"@odata.id\":\"$R/UpdateService/FirmwareInventory/bios_active\"},\"SoftwareImages\":[{\"@odata.id\":\"$R/UpdateService/FirmwareInventory/bios_active\"}]}}" ;;
esac
missing
