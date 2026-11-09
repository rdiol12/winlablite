#!/usr/bin/env bash
# Builds winlab for Linux: CPython + the winlab package + the content pack in
# one file (PyInstaller), packed with its installer into a tarball a customer
# unpacks and runs. Run on a Linux x86-64 build machine (the oldest glibc you
# want to support: the binary runs on that glibc and newer):
#
#   bash packaging/build-linux.sh            # release build
#   bash packaging/build-linux.sh --no-protect   # test build, licensing as bytecode
#
# Output
#   dist/linux/winlab                           the program
#   dist/winlab-<version>-linux-x86_64.tar.gz   winlab + install.sh + uninstall.sh
#                                               + winlab.desktop + icon + documents
#
# What is and is not inside (see LICENSING.md): the same rule as the Windows
# build. In: CPython, winlab, the content pack, PyInstaller's bootloader. Out:
# QEMU, the UEFI firmware, swtpm (the customer's distribution packages them;
# Setup installs them with the package manager), the DSC modules and the
# viewers (fetched by `winlab bootstrap`), Microsoft media.
set -euo pipefail

PY="${PYTHON:-python3}"
PROTECT=1
for a in "$@"; do
  case "$a" in
    --no-protect) PROTECT=0 ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
version="$("$PY" -c 'import winlab; print(winlab.__version__)')"
echo "winlab Linux build  version $version"

"$PY" -m PyInstaller --version >/dev/null 2>&1 || "$PY" -m pip install --upgrade pyinstaller

mkdir -p build dist/linux
"$PY" -m winlab icon build/winlab.png --size 256

# The trial's own content, staged and encrypted (packaging/trialpack.py: a
# fresh key, written as winlab/licensing/trialkey.py and compiled below).
content_dir="$root/build/content-core"
"$PY" -c "import sys; from pathlib import Path; from winlab import edition; print('  content: core', edition.stage(Path(sys.argv[1]), Path(sys.argv[2])))" "$root/content" "$content_dir"
"$PY" packaging/trialpack.py "$content_dir" | sed 's/^/  /'
printf 'core' > "$root/build/edition.txt"
trap 'rm -f "$root/winlab/licensing/trialkey.py"' EXIT

pkg="$root"
hidden=()
if [ "$PROTECT" = 1 ]; then
  "$PY" -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('Cython') else 1)" \
    || "$PY" -m pip install 'cython==3.1.2' setuptools
  pkg="$root/build/protected"
  while IFS= read -r line; do
    case "$line" in
      "hidden-import: "*) hidden+=(--hidden-import "${line#hidden-import: }") ;;
      *) echo "  $line" ;;
    esac
  done < <("$PY" packaging/protect.py "$pkg")
else
  echo "  protect: skipped (--no-protect); the code ships as bytecode"
fi

"$PY" -m PyInstaller \
  --name winlab --onefile --console --clean --noconfirm \
  --paths "$pkg" \
  --distpath "$root/dist/linux" \
  --workpath "$root/build/pyinstaller-linux" \
  --specpath "$root/build/pyinstaller-linux" \
  --add-data "$content_dir:content" \
  --add-data "$root/build/edition.txt:." \
  --add-data "$root/winlab/webui_page.html:winlab" \
  --collect-submodules winlab \
  --exclude-module winlab.licensing.server \
  "${hidden[@]}" \
  packaging/winlab_entry.py

if [ "$PROTECT" = 1 ]; then
  # Proof that PyInstaller packed the compiled copy (see build-exe.ps1).
  if grep -rqsF -e 'licensing/client.py' -e 'winlab/content.py' -e 'winlab/packs.py' \
       -e 'licensing/trialkey.py' -e 'winlab/webui.py' build/pyinstaller-linux --include='*.toc'; then
    echo "a protected module was packed as bytecode" >&2; exit 1
  fi
  echo "  protect: the whole winlab package is native code in the binary"
fi

bin="$root/dist/linux/winlab"
[ -x "$bin" ] || { echo "expected $bin" >&2; exit 1; }
echo "  built: $bin ($(du -h "$bin" | cut -f1))"

name="winlab-core-$version-linux-x86_64"
stage="$root/build/$name"
rm -rf "$stage"; mkdir -p "$stage"
cp "$bin" "$stage/winlab"
cp packaging/linux/install.sh packaging/linux/uninstall.sh packaging/linux/winlab.desktop "$stage/"
cp build/winlab.png "$stage/winlab.png"
cp README.md LICENSING.md CURRICULUM.md "$stage/"
for f in EULA.txt EULA.es.txt EULA.he.txt EULA.ar.txt; do if [ -f "$f" ]; then cp "$f" "$stage/"; fi; done
chmod 755 "$stage/winlab" "$stage/install.sh" "$stage/uninstall.sh"
tar -C "$root/build" -czf "$root/dist/$name.tar.gz" "$name"
echo "  tarball: dist/$name.tar.gz"
echo
echo "  test : ./dist/linux/winlab doctor"
echo "  ship : the tarball; the customer runs ./install.sh (no root needed)"
