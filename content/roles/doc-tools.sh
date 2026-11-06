#!/bin/sh
# The Admin tools server (winlab/doctools.py): a plain Debian 12 server on
# which the student installs the IT department's own tools by hand, GLPI,
# DokuWiki and Vaultwarden, from the glpi, dokuwiki and vaultwarden package
# sticks its Settings plug in.
#
# This is its whole factory state: nothing is installed or configured here.
# It only leaves a message of the day that says what the box is for and
# where the sticks mount, so a student who logs in knows where to begin.
# It runs at every power-on and changes nothing the student made.

role=doc-tools
log() { echo "$(date '+%H:%M:%S')  [$role] $*"; }

[ -f /etc/debian_version ] || { echo 'the Admin tools server runs on Debian (image debian12)' >&2; exit 1; }

cat > /etc/motd <<'EOF'

  Admin tools server: the IT department's inventory, wiki and password vault.
  Nothing is installed yet. Plug in a package stick (the machine's Settings),
  then: sudo mkdir -p /mnt/winlab-pack; sudo mount LABEL=WLPACK /mnt/winlab-pack
  and read README.txt and INSTALL.txt on it.

EOF
log "ready: a plain Debian 12 server; GLPI, DokuWiki and Vaultwarden are yours to install"
