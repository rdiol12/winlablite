#!/usr/bin/env bash
# Installs winlab for this user: no root, nothing system-wide. Run it from the
# unpacked tarball:
#
#   ./install.sh                     program in ~/.local/lib/winlab, data in ~/.local/share/winlab
#   ./install.sh --data /big/disk/winlab   keep the machines (tens of GB) on another drive
#
# Running it again upgrades the program and keeps the data. ./uninstall.sh
# (also copied into the program folder) removes it.
#
# QEMU, the UEFI firmware and swtpm come from your distribution. winlab's
# Setup screen installs them with your package manager (it asks for your
# password), or install them yourself first, e.g. on Ubuntu:
#   sudo apt install qemu-system-x86 qemu-utils ovmf swtpm
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
data="${XDG_DATA_HOME:-$HOME/.local/share}/winlab"
while [ $# -gt 0 ]; do
  case "$1" in
    --data) data="$2"; shift 2 ;;
    --data=*) data="${1#--data=}"; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

if [ "$(uname -m)" != "x86_64" ]; then
  echo "winlab runs on 64-bit Intel or AMD PCs (x86_64); this one is $(uname -m)." >&2
  exit 1
fi
[ -x "$here/winlab" ] || { echo "run install.sh from the unpacked winlab folder" >&2; exit 1; }

prog="$HOME/.local/lib/winlab"
bin="$HOME/.local/bin"
apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
icons="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/256x256/apps"
mkdir -p "$prog" "$bin" "$apps" "$icons" "$data"
data="$(cd "$data" && pwd)"

# A running winlab keeps its labs; stop them so the program can be replaced.
if [ -x "$prog/winlab" ] && pgrep -f "$prog/winlab" >/dev/null 2>&1; then
  echo "stopping the running labs (their disks keep their state)..."
  "$prog/winlab" lab down --all >/dev/null 2>&1 || true
  pkill -f "$prog/winlab" >/dev/null 2>&1 || true
fi

install -m 755 "$here/winlab" "$prog/winlab.new" && mv -f "$prog/winlab.new" "$prog/winlab"
install -m 755 "$here/uninstall.sh" "$prog/uninstall.sh"
for f in README.md LICENSING.md CURRICULUM.md EULA.txt EULA.es.txt EULA.he.txt EULA.ar.txt; do
  [ -f "$here/$f" ] && install -m 644 "$here/$f" "$prog/$f"
done
# The data folder the program uses (winlab/paths.py reads it beside the binary).
printf '%s\n' "$data" > "$prog/winlab-home.txt"
ln -sfn "$prog/winlab" "$bin/winlab"

install -m 644 "$here/winlab.png" "$icons/winlab.png"
sed "s|@EXEC@|$prog/winlab|g" "$here/winlab.desktop" > "$apps/winlab.desktop"
chmod 644 "$apps/winlab.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$apps" >/dev/null 2>&1 || true
command -v gtk-update-icon-cache >/dev/null 2>&1 \
  && gtk-update-icon-cache -q -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" >/dev/null 2>&1 || true

echo "winlab installed."
echo "  program : $prog/winlab  (also 'winlab' on your PATH via $bin)"
echo "  data    : $data"
echo
"$prog/winlab" setup --check 2>/dev/null | sed -n '1,/^$/p' || true
echo "Open winlab from your applications menu, or run: winlab"
case ":$PATH:" in *":$bin:"*) ;; *) echo "(add $bin to your PATH to type 'winlab' in a terminal)";; esac
