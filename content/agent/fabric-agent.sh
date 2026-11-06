#!/bin/sh
# winlab fabric agent. Same serial JSON protocol as the Windows agent, but runs
# sh commands -- this is how 'winlab net fault' drives the switch/router live.
#
# Request   {"id":N,"shell":"sh","b64":"<base64 cmd>"}
# Response  {"id":N,"rc":N,"out":"<b64>","err":"<b64>","host":"fabric"}
#
# The fabric's control serial is the SECOND serial port (ttyS1): ttyS0 is the
# boot console. QEMU attaches winlab's control chardev there.

PORT=/dev/ttyS1
LOG=/var/log/winlab-fabric.log
HOST=fabric

log() { echo "$(date '+%H:%M:%S') $*" >> "$LOG"; }

b64enc() { printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 | tr -d '\n'; }
b64dec() { printf '%s' "$1" | base64 -d 2>/dev/null; }

# Minimal JSON field extractor (values are base64 or integers, no nesting).
field() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\\([^\"]*\\)\".*/\\1/p"; }
field_int() { printf '%s' "$1" | sed -n "s/.*\"$2\":\\([0-9]*\\).*/\\1/p"; }

log "fabric agent starting on $PORT"
stty -F "$PORT" 115200 raw -echo 2>/dev/null

# Announce readiness so the host knows the fabric is up.
printf '{"event":"ready","host":"%s","agent":1}\n' "$HOST" > "$PORT"

while IFS= read -r line < "$PORT"; do
  [ -z "$line" ] && continue
  case "$line" in
    *'"b64"'*) ;;
    *) continue ;;
  esac
  id=$(field_int "$line" id)
  cmd=$(b64dec "$(field "$line" b64)")
  log "exec #$id: $cmd"
  out=$(sh -c "$cmd" 2>/tmp/winlab.err)
  rc=$?
  err=$(cat /tmp/winlab.err 2>/dev/null)
  printf '{"id":%s,"rc":%s,"out":"%s","err":"%s","host":"%s"}\n' \
    "${id:-0}" "$rc" "$(b64enc "$out")" "$(b64enc "$err")" "$HOST" > "$PORT"
done
