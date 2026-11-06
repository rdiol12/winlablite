"""Per-node provisioning media.

Two volumes per Windows node:
  * a FAT12 floppy holding autounattend.xml, which is the medium Windows Setup
    detects most reliably
  * a FAT16 disk holding the agent, role scripts and node facts, because the
    floppy's 1.44 MB cannot hold the payload
"""

from __future__ import annotations

import json
from pathlib import Path

from . import fatfs, paths, unattend
from .model import Lab, Node
from .netplan import TopologyPlan

AGENT_DIR = paths.CONTENT / "agent"
PROV_LABEL = "WLPROV"
DATA_LABEL = "WLDATA"
DATA_MB = 96


def lab_addressed(node: Node) -> bool:
    """Whether the lab gives this machine its addresses at start. Only the
    equipment that is not the student's does: another company's VPN gateway,
    the Internet's hosts, a device's own firmware (winlab/roles.py
    SELF_STARTING). Every other machine comes up the way a fresh install
    does, with nothing set, and gets an address only from the student: typed
    in by hand or leased from a DHCP server they built."""
    from .roles import SELF_STARTING
    return bool(set(node.roles) & set(SELF_STARTING))


def node_facts(node: Node, lab: Lab, plan: TopologyPlan, addresses: bool = True) -> dict:
    """What the machine's agent and roles read (facts.json). With
    addresses=False (a machine the student sets up, see lab_addressed) the
    adapters carry only what the hardware knows, their MAC and cable, and
    nothing about the plan's addresses, gateways or DNS servers:
    apply-network.ps1 then leaves the adapters alone."""
    if not addresses:
        return _student_facts(node, lab, plan)
    nics = []
    for link in plan.links_for(node.id):
        nic = node.nics[link.nic_index]
        seg = plan.segment_of(link.network_id)
        nics.append(
            {
                "index": link.nic_index,
                "mac": nic.mac,
                "network": link.network_id,
                "vlan": seg.vid,
                "ip": nic.ip or "",
                "prefix": seg.network.prefixlen,
                "gateway": seg.network.default_gateway,
                "dhcp": nic.dhcp,
                "dns": nic.dns,
                "wan": bool(seg.network.wan),
            }
        )
    devices = [
        {"kind": d.kind, "name": d.name, "shared": d.shared,
         "driver": d.driver, "location": d.location, "vars": d.vars}
        for d in node.devices
    ]
    return {
        "node": node.id,
        "hostname": node.hostname or node.id.upper()[:15],
        "kind": node.kind,
        "roles": node.roles,
        "vars": node.vars,
        "nics": nics,
        "devices": devices,
        "lab_devices": _lab_devices(lab),
        "lab": {
            "name": lab.name,
            "domain": lab.domain,
            "netbios": lab.netbios,
            "admin_password": lab.admin_password,
            "timezone": lab.timezone,
        },
        "dns_servers": _dns_servers(lab, node),
        "dhcp_relayed": _dhcp_relayed(node, plan),
        "file_servers": [
            n.hostname or n.id.upper()[:15] for n in lab.node_list() if "file" in n.roles
        ],
    }


def _student_facts(node: Node, lab: Lab, plan: TopologyPlan) -> dict:
    """What the machine is, not what it should become: C:\\winlab\\facts.json is
    readable from inside it, so it carries none of the plan (roles, role
    options, addresses, DNS servers, the domain) for a student to copy."""
    full = node_facts(node, lab, plan)
    return {
        "node": full["node"],
        "hostname": full["hostname"],
        "kind": full["kind"],
        "addressing": "student",
        "nics": [{k: n[k] for k in ("index", "mac", "network", "vlan", "wan")} for n in full["nics"]],
        "lab": {"name": lab.name, "timezone": lab.timezone},
    }


def _dhcp_relayed(node: Node, plan: TopologyPlan) -> list[dict]:
    """Segments whose DHCP traffic the fabric relays to this node. A DHCP
    server only sees relayed requests; it still needs a scope for each of
    those subnets, or the client on the far side never gets a lease."""
    mine = {nic.ip for nic in node.nics if nic.ip}
    out = []
    for seg in plan.segments.values():
        if not mine.intersection(seg.relay_to):
            continue
        net = seg.network
        out.append(
            {
                "network": net.id,
                "subnet": str(net.net.network_address),
                "prefix": net.prefixlen,
                "gateway": net.default_gateway,
            }
        )
    return sorted(out, key=lambda s: s["subnet"])


def _lab_devices(lab: Lab) -> list[dict]:
    """Every shared device in the lab, so a client can auto-connect to all of
    them without naming each one."""
    out = []
    for n in lab.node_list():
        for d in n.devices:
            if d.shared:
                out.append({"kind": d.kind, "host": n.hostname or n.id.upper()[:15],
                            "name": d.name})
    return out


def _dns_servers(lab: Lab, node: Node | None = None) -> list[str]:
    """Every DNS server of the lab, the ones at the machine's own site first:
    a cloud member resolves against the cloud's replica DC, not across the
    VPN, exactly as its DNS client settings would say in Azure."""
    from . import sites
    here = sites.site_of_node(lab, node.id) if node else ""
    near, far = [], []
    for n in lab.node_list():
        if "ad-ds" in n.roles or "dns" in n.roles:
            for nic in n.nics:
                if nic.ip:
                    (near if sites.site_of_node(lab, n.id) == here else far).append(nic.ip)
    return near + far


def _agent_files() -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    if not AGENT_DIR.exists():
        return out
    for f in sorted(AGENT_DIR.glob("*")):
        if f.is_file():
            out[f.name] = f.read_bytes()
    return out


def _role_files() -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    if not paths.ROLES.exists():
        return out
    for f in sorted(paths.ROLES.glob("*.ps1")):
        out[f.name] = f.read_bytes()
    return out


def _dsc_files(node: Node, lab: Lab, plan: TopologyPlan) -> dict[str, bytes]:
    """The node's generated DSC configuration and the resource-module bundle
    (fetched at bootstrap; absent until then, in which case the role runner
    sends it over serial on first apply)."""
    from . import dsc, psmodules, roles

    out: dict[str, bytes] = {}
    try:
        manifest = roles.load_manifest()
        names = [rd.name for rd in roles.order_roles(roles.effective_roles(node), manifest)
                 if rd.engine == "dsc"]
    except roles.RoleError:
        return out
    if not names:
        return out
    out["node.dsc.ps1"] = dsc.render(dsc.compile_node(node, lab, plan, names)).encode("utf-8")
    z = psmodules.zip_path()
    if z.exists():
        out[psmodules.ZIP_NAME] = z.read_bytes()
    return out


def _module_bundle() -> dict[str, bytes]:
    from . import psmodules
    z = psmodules.zip_path()
    return {psmodules.ZIP_NAME: z.read_bytes()} if z.exists() else {}


def _download_files(node: Node) -> dict[str, bytes]:
    """Installers a role fetched onto this PC (the Windows exporter, Windows Admin
    Center), when the node has the role and the fetch is done; absent until then, in which case
    the role runner sends them over the agent channel."""
    from . import roles
    out: dict[str, bytes] = {}
    try:
        manifest = roles.load_manifest()
        plan = roles.order_roles(roles.effective_roles(node), manifest)
    except roles.RoleError:
        return out
    for download_id in roles.downloads_for(plan):
        if download_id in roles.DOWNLOADS:
            out.update(roles.download_module(download_id).files())
    return out


def build_answer_floppy(node: Node, lab: Lab, dest: Path, firmware: str) -> Path:
    img = fatfs.floppy(PROV_LABEL)
    img.add_file("autounattend.xml", unattend.render(node, lab, firmware=firmware))
    return img.write(dest)


def data_disk_mb(payload: dict[str, bytes]) -> int:
    """DATA_MB, or more when a big installer (Windows Admin Center) rides
    along: room for every file plus a tenth, in 32 MB steps."""
    need = sum(len(b) for b in payload.values()) * 11 // 10 + (16 << 20)
    return max(DATA_MB, -(-need // (32 << 20)) * 32)


def build_data_disk(
    node: Node, lab: Lab, plan: TopologyPlan, dest: Path,
    extra: dict[str, bytes] | None = None,
) -> Path:
    # Everything sits at the volume root: fatfs writes no subdirectories, and
    # winlab-stage0.cmd copies *.ps1 / *.json / *.cmd to C:\winlab.
    payload: dict[str, bytes] = dict(_agent_files())
    payload.update(_role_files())
    mine = lab_addressed(node)
    payload["facts.json"] = json.dumps(
        node_facts(node, lab, plan, addresses=mine), indent=2
    ).encode("utf-8")
    if mine:
        # A machine the student sets up gets no generated configuration on
        # its disk to read the answers from: `winlab roles apply` (the CLI,
        # CI, the career game) sends it over the agent channel when it runs.
        payload.update(_dsc_files(node, lab, plan))
    else:
        z = _module_bundle()
        if z:
            payload.update(z)
    payload.update(_download_files(node))
    payload.update(extra or {})

    img = fatfs.disk(data_disk_mb(payload), DATA_LABEL)
    for name, data in payload.items():
        img.add_file(name, data)

    return img.write(dest)


def build_fabric_config(plan: TopologyPlan, dest: Path) -> Path:
    from .netplan import render_fabric_setup

    img = fatfs.disk(16, "WLFAB")
    img.add_file("fabric.sh", render_fabric_setup(plan))
    img.add_file(
        "facts.json",
        json.dumps(
            {
                "lab": plan.lab.name,
                "links": [
                    {
                        "iface": l.fabric_iface,
                        "node": l.node_id,
                        "nic": l.nic_index,
                        "network": l.network_id,
                        "port": l.port,
                        "mode": l.mode,
                    }
                    for l in plan.links
                ],
                "segments": {
                    s.network.id: {
                        "vid": s.vid,
                        "cidr": s.network.cidr,
                        "gateway": s.network.router_ip,
                        "svi": s.svi,
                        "dhcp": s.serves_dhcp,
                        "relay_to": s.relay_to,
                    }
                    for s in plan.segments.values()
                },
            },
            indent=2,
        ),
    )
    return img.write(dest)
