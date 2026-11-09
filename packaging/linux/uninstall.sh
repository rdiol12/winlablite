#!/usr/bin/env bash
# Removes winlab for this user. Your machines and progress (the data folder)
# are kept unless you answer yes, or pass --purge.
set -euo pipefail

prog="$HOME/.local/lib/winlab"
purge=0
[ "${1:-}" = "--purge" ] && purge=1
data=""
[ -f "$prog/winlab-home.txt" ] && data="$(head -n1 "$prog/winlab-home.txt")"

if [ -x "$prog/winlab" ]; then
  "$prog/winlab" lab down --all >/dev/null 2>&1 || true
  pkill -f "$prog/winlab" >/dev/null 2>&1 || true
fi
rm -f "$HOME/.local/bin/winlab"
rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/applications/winlab.desktop"
rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/256x256/apps/winlab.png"
rm -rf "$prog"
echo "winlab removed."

if [ -n "$data" ] && [ -d "$data" ]; then
  if [ "$purge" = 0 ] && [ -t 0 ]; then
    read -r -p "Also delete the machines, images and progress in $data? [y/N] " a
    case "$a" in y|Y|yes|YES) purge=1 ;; esac
  fi
  if [ "$purge" = 1 ]; then
    # Only what winlab made there, as the Windows uninstaller does.
    rm -rf "$data/images" "$data/runtime" "$data/var" "$data/content"
    rmdir "$data" 2>/dev/null || true
    echo "data deleted."
  else
    echo "data kept in $data"
  fi
fi
