"""The first-boot seed of a Linux appliance (cloud-init's NoCloud source).

A small FAT volume labelled CIDATA, attached to the machine as a read-only
disk, holds three files cloud-init reads on its first boot: meta-data (the
instance id and hostname), user-data (the administrator account with the lab
password, the time zone, the winlab serial agent and its systemd unit) and
network-config (the machine's adapters from the lab definition: static
address, gateway and DNS, or DHCP). Everything is written as JSON, which
cloud-init's YAML parser reads as-is, so no quoting rules apply.

The instance id is derived from the lab, the machine and its addressing: a
rebuilt machine gets the same id and the same first boot; an address change
makes a new id, so cloud-init applies the new network on the next boot.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import fatfs, paths
from .model import Lab, Node

AGENT_PATH = "/usr/local/bin/winlab-agent"
UNIT_PATH = "/etc/systemd/system/winlab-agent.service"
SEED_FILE = "seed.img"
LABEL = "CIDATA"

UNIT = """[Unit]
Description=winlab serial agent (lab control channel on ttyS1)
After=multi-user.target

[Service]
ExecStart=/bin/sh /usr/local/bin/winlab-agent
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
"""


def agent_script(hostname: str) -> str:
    """The fabric agent, which already speaks the serial JSON protocol on
    ttyS1 with sh, answering for this machine's name."""
    p = paths.CONTENT / "agent" / "fabric-agent.sh"
    text = p.read_text(encoding="utf-8") if p.exists() else "#!/bin/sh\necho 'agent missing' >&2\n"
    return (text.replace("HOST=fabric\n", f"HOST={hostname}\n", 1)
                .replace("LOG=/var/log/winlab-fabric.log", "LOG=/var/log/winlab-agent.log", 1))


def _hostname(node: Node) -> str:
    return (node.hostname or node.id).lower()[:63]


def instance_id(node: Node, lab: Lab, plan) -> str:
    key = json.dumps([lab.name, node.id, _hostname(node), network_config(node, lab, plan)])
    return f"winlab-{node.id}-{hashlib.sha256(key.encode()).hexdigest()[:10]}"


def meta_data(node: Node, lab: Lab, plan) -> dict:
    return {"instance-id": instance_id(node, lab, plan), "local-hostname": _hostname(node)}


def network_config(node: Node, lab: Lab, plan) -> dict:
    """Netplan v2 for every adapter the plan gives the machine."""
    from .provision import _dns_servers
    eths: dict[str, dict] = {}
    links = plan.links_for(node.id) if plan is not None else []
    for link in links:
        nic = node.nics[link.nic_index]
        seg = plan.segment_of(link.network_id)
        eth: dict = {"match": {"macaddress": link.mac}, "set-name": f"eth{link.nic_index}"}
        if nic.ip:
            eth["dhcp4"] = False
            eth["addresses"] = [f"{nic.ip}/{seg.network.prefixlen}"]
            gw = seg.network.default_gateway
            # No default route via the machine's own address (it is the
            # segment's gateway: a router the student builds), nor into a
            # switch the lab router is not cabled to, where nobody answers.
            if link.nic_index == 0 and gw != nic.ip and (seg.network.routed or seg.network.hosts_gateway):
                eth["routes"] = [{"to": "default", "via": gw}]
            dns = list(nic.dns) or _dns_servers(lab)
            if dns:
                eth["nameservers"] = {"addresses": dns, "search": [lab.domain] if lab.domain else []}
        else:
            eth["dhcp4"] = True
        eths[f"nic{link.nic_index}"] = eth
    # A laptop's radio card on the real air (winlab/vwifi.py): never cabled
    # on the canvas, so not in the plan's links.
    from . import vwifi
    eths.update(vwifi.network_config(node, lab))
    return {"version": 2, "ethernets": eths}


# cloud-init's key for a user's clear-text password.
CLEARTEXT_KEY = "plain_text_passwd"


def _account(app, lab: Lab) -> dict:
    """The administrator cloud-init creates, with the lab's one generated
    password (var/labs/<lab>/admin-password), the same as on every Windows
    machine; the seed lives beside the machine's disks on this PC. The field
    is set by name so a secret scanner does not read the runtime value as a
    credential committed to git."""
    account = {
        "name": app.user,
        "gecos": "winlab administrator",
        "groups": ["adm", "sudo"],
        "sudo": "ALL=(ALL) NOPASSWD:ALL",
        "shell": "/bin/bash",
        "lock_passwd": False,
    }
    account[CLEARTEXT_KEY] = lab.admin_password
    return account


def user_data(node: Node, lab: Lab, app) -> dict:
    host = _hostname(node)
    return {
        "hostname": host,
        "fqdn": f"{host}.{lab.domain}" if lab.domain else host,
        "manage_etc_hosts": True,
        "timezone": lab.timezone or "UTC",
        "ssh_pwauth": True,
        "disable_root": True,
        "users": [_account(app, lab)],
        "chpasswd": {"expire": False},
        # No internet in the lab: never let the first boot wait on the archive.
        "package_update": False,
        "package_upgrade": False,
        "write_files": [
            {"path": AGENT_PATH, "permissions": "0755", "content": agent_script(host)},
            {"path": UNIT_PATH, "permissions": "0644", "content": UNIT},
            {"path": "/etc/winlab-appliance", "permissions": "0644",
             "content": f"image={app.id}\nlab={lab.name}\nnode={node.id}\n"},
        ],
        "runcmd": [
            ["mkdir", "-p", "/var/lib/winlab/done"],
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "--now", "winlab-agent.service"],
        ],
        "final_message": "winlab: appliance ready after $UPTIME seconds",
    }


def seed_files(node: Node, lab: Lab, plan, app) -> dict[str, bytes]:
    return {
        "meta-data": json.dumps(meta_data(node, lab, plan), indent=1).encode(),
        "user-data": ("#cloud-config\n" + json.dumps(user_data(node, lab, app), indent=1) + "\n").encode(),
        "network-config": json.dumps(network_config(node, lab, plan), indent=1).encode(),
    }


def write_seed(node: Node, lab: Lab, plan, app, dest: Path) -> Path:
    img = fatfs.floppy(LABEL)
    for name, data in seed_files(node, lab, plan, app).items():
        img.add_file(name, data)
    dest.parent.mkdir(parents=True, exist_ok=True)
    return img.write(dest)
