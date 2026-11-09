"""Command surface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, edition, hostprobe, netplan, paths, schema, state
from .schema import LabError



def _nic_arg(value: str, flag: str) -> tuple[int, str, str]:
    """N:NET[:IP] for --cable, --tag and --untag."""
    from . import editor
    parts = value.split(":")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1]:
        raise editor.EditError(f"{flag} takes N:NET (a nic number and a network), got '{value}'")
    return int(parts[0]), parts[1], (parts[2] if len(parts) > 2 else "")


def _resolve_lab(explicit: str) -> str:
    if explicit:
        return explicit
    labs = state.known_labs()
    if len(labs) == 1:
        return labs[0]
    if not labs:
        raise LabError("no running lab; start one with 'winlab lab up <lab>'")
    raise LabError(f"multiple labs running ({', '.join(labs)}); pass --lab")


def _not_yet(name: str) -> int:
    """A command the parser knows and main() does not dispatch: a bug."""
    print(f"winlab: '{name}' has no handler; run 'winlab -h' for the commands", file=sys.stderr)
    return 70


class _Parser(argparse.ArgumentParser):
    """`winlab exec <node> [options] -- <command...>`: everything after `--`
    is the command. Python before 3.12.7 hands `--` and what follows to no
    one once the optional positional is filled (empty), so it is split off
    here, on every version alike."""

    def parse_known_args(self, args=None, namespace=None):
        args = list(sys.argv[1:] if args is None else args)
        tail = None
        if args[:1] == ["exec"] and "--" in args:
            i = args.index("--")
            args, tail = args[:i], args[i + 1:]
        ns, extra = super().parse_known_args(args, namespace)
        if tail is not None:
            ns.command = list(getattr(ns, "command", None) or []) + tail
        return ns, extra


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="winlab",
        description="Portable, isolated Windows Server lab orchestrator.",
    )
    p.add_argument("--version", action="version", version=f"winlab {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="<command>")

    dr_ = sub.add_parser("doctor", help="report whether this host can run a lab, and how fast")
    dr_.add_argument("--bundle", nargs="?", const="", default=None, metavar="OUT.zip",
                     help="also write a support file (logs and settings, secrets removed) "
                          "to OUT.zip, by default var/support/winlab-support-<time>.zip")

    su = sub.add_parser(
        "setup", help="first run in one command: check this PC, then download and prepare "
                      "everything a lab needs except the Windows ISO you get from Microsoft")
    su.add_argument("lab", nargs="?", default="",
                    help="lab to get ready (default: the last lab opened, else ad-ds-basics)")
    su.add_argument("--check", action="store_true", help="only check this PC and list what is left")

    g = sub.add_parser("gui", help="open the desktop for a lab (what double-clicking winlab.exe does)")
    g.add_argument("lab", nargs="?", default="",
                   help="lab name or path to a .toml definition (default: the last lab opened, else ad-ds-basics)")
    g.add_argument("--port", type=int, default=8780)
    g.add_argument("--no-browser", action="store_true", help="do not open a browser")

    bs = sub.add_parser(
        "bootstrap", help="fetch the portable qemu runtime and DSC modules into ./runtime (installs nothing)"
    )
    bs.add_argument(
        "--plan",
        action="store_true",
        help="resolve and list the packages that would be fetched, then stop",
    )
    bs.add_argument("--refresh", action="store_true", help="re-fetch the package database")
    bs.add_argument(
        "--keep-downloads", action="store_true", help="keep archives for offline re-bootstrap"
    )

    lab = sub.add_parser("lab", help="work with lab definitions")
    labsub = lab.add_subparsers(dest="labcmd", metavar="<subcommand>")
    labsub.add_parser("list", help="list available lab definitions")
    ln = labsub.add_parser("new", help="an empty network of your own to build from nothing (the Workbench's New)")
    ln.add_argument("name", help="2-31 lower-case letters, digits and dashes, starting with a letter")
    ln.add_argument("--description", default="")
    lrm = labsub.add_parser("rm", help="delete a lab you made, with its machines' disks, save points and notes")
    lrm.add_argument("lab")
    lrm.add_argument("--yes", action="store_true", help="do not ask first")
    lrn = labsub.add_parser("rename", help="give a lab you made a new name (its machines move with it)")
    lrn.add_argument("lab")
    lrn.add_argument("new_name")
    v = labsub.add_parser("validate", help="check a lab definition for errors")
    v.add_argument("lab", help="lab name or path to a .toml definition")
    vsw = labsub.add_parser("vswitch", help="virtual switches (Hyper-V's Virtual Switch Manager): show them, "
                            "or make a network's switch private, internal (reaches this PC) or external (reaches the internet)")
    vsw.add_argument("lab", help="lab name")
    vsw.add_argument("network", nargs="?", help="the network (switch) to change")
    vsw.add_argument("kind", nargs="?", choices=["private", "internal", "external"])
    vsw.add_argument("--port", action="append", default=None, metavar="NODE:PORT[@HOSTPORT]",
                     help="a machine's port this PC may open on 127.0.0.1 (internal or external switch); repeat it")
    pl = labsub.add_parser("plan", help="compile a lab and show the resulting topology")
    pl.add_argument("lab", help="lab name or path to a .toml definition")
    pl.add_argument(
        "--fabric-script",
        action="store_true",
        help="also print the switch/router configuration the fabric will run",
    )
    pl.add_argument(
        "--no-port-check",
        action="store_true",
        help="skip binding loopback ports (useful when a lab is already running)",
    )
    dg = labsub.add_parser("diagram", help="write the topology as a diagrams.net (.drawio) diagram")
    dg.add_argument("lab", help="lab name or path to a .toml definition")
    dg.add_argument("--out", default="", help="output .drawio path (default: var/<lab>.drawio)")

    pw = labsub.add_parser("password", help="show the lab's Administrator password")
    pw.add_argument("lab", help="lab name or path to a .toml definition")

    up = labsub.add_parser("up", help="boot a lab")
    up.add_argument("lab", help="lab name or path to a .toml definition")
    up.add_argument(
        "--dry-run",
        action="store_true",
        help="print the qemu command line for every machine without booting",
    )
    up.add_argument(
        "--accel", default="", help="override the accelerator (whpx, kvm, tcg)"
    )
    up.add_argument(
        "--display",
        choices=("window", "none"),
        default="window",
        help="open a screen per machine, or run headless",
    )
    up.add_argument(
        "--only", default="",
        help="comma-separated machines to boot; their domain controller comes along",
    )
    up.add_argument(
        "--force", action="store_true",
        help="boot even if the host does not have the memory free",
    )

    ns = labsub.add_parser("save", help="save the network as a file (.wlnet: the design, no disks) to share or keep")
    ns.add_argument("lab", help="lab name")
    ns.add_argument("dest", nargs="?", default=".", help="a file or folder (default: here)")
    no = labsub.add_parser("open", help="open a network file as a new lab (its machines are built fresh here)")
    no.add_argument("file", help="the .wlnet file")
    no.add_argument("--as", dest="as_name", default="", help="the lab's name here (default: the file's, or the next free one)")
    nv = labsub.add_parser("versions", help="a lab's saved versions, or save one now with --save")
    nv.add_argument("lab", help="lab name")
    nv.add_argument("--save", metavar="NOTE", nargs="?", const="", default=None, help="save this version now")
    nr = labsub.add_parser("restore", help="put a lab's design back to a saved version (the lab off)")
    nr.add_argument("lab", help="lab name")
    nr.add_argument("version", help="the version's id from `lab versions`")

    lh = labsub.add_parser("history", help="what was changed on a lab's workbench, when and by whom")
    lh.add_argument("lab", help="lab name")
    lh.add_argument("--device", default="", help="only the changes to this device")
    lh.add_argument("-n", "--limit", type=int, default=40, help="how many (newest first, default 40)")
    for name, what in (("undo", "take back the last layout or cabling change"),
                       ("redo", "put back the change undo took back")):
        lu = labsub.add_parser(name, help=what)
        lu.add_argument("lab", help="lab name")

    for name, what in (("down", "stop a lab"), ("status", "show running lab state")):
        s = labsub.add_parser(name, help=what)
        s.add_argument("lab", nargs="?", help="lab name")
        if name == "down":
            s.add_argument("--all", action="store_true",
                           help="stop every running lab (what the uninstaller does first)")

    ev = labsub.add_parser(
        "eval", help="days left on each Windows machine's evaluation licence")
    ev.add_argument("lab", help="lab name")
    ev.add_argument("--rearm", default="", metavar="NODE",
                    help="restart that machine's evaluation clock (slmgr /rearm)")

    sp = labsub.add_parser(
        "suspend", help="hibernate the Windows machines and shut the rest down; "
                        "`lab up` (or `lab resume`) brings them back where they were")
    sp.add_argument("lab", help="lab name or path to a .toml definition")
    sp.add_argument("--only", default="", help="comma-separated machines (default: the whole lab)")
    rl = labsub.add_parser(
        "reload", help="restart only the lab's router and switches; the machines keep running "
                       "and their network cables come back by themselves")
    rl.add_argument("lab", help="lab name or path to a .toml definition")
    rsm = labsub.add_parser("resume", help="start a suspended lab (the same as `lab up`)")
    rsm.add_argument("lab", help="lab name or path to a .toml definition")
    rsm.add_argument("--only", default="", help="comma-separated machines")
    rsm.add_argument("--accel", default="", help="override the accelerator (whpx, kvm, tcg)")
    rsm.add_argument("--display", choices=("window", "none"), default="window")
    rsm.add_argument("--force", action="store_true",
                     help="start even if the host does not have the memory free")

    rs = labsub.add_parser(
        "reset", help="rebuild stopped machines from their image on the next boot")
    rs.add_argument("lab", help="lab name or path to a .toml definition")
    rs.add_argument("--only", default="",
                    help="comma-separated machines (default: every machine)")
    rs.add_argument("--yes", action="store_true",
                    help="confirm: their disks and checkpoints are deleted")

    ex = labsub.add_parser(
        "export", help="write a stopped lab (definition, disks, password) into a folder")
    ex.add_argument("lab", help="lab name")
    ex.add_argument("folder", help="a new folder to create, e.g. D:\\labs\\corp-2026-10")
    ex.add_argument("--thin", action="store_true",
                    help="copy the machines' own disks only (fast, keeps checkpoints; "
                         "needs the same base images on the other PC)")
    ex.add_argument("--compress", action="store_true",
                    help="compress the standalone disks (smaller, slower)")
    lset = labsub.add_parser("set", help="change a lab-wide setting")
    lset.add_argument("lab")
    lset.add_argument("--lean", choices=("on", "off"), default=None,
                      help="the Low-memory profile on every Windows machine (off: stock Windows, "
                           "the default; on: idle services, telemetry and auto-update off, "
                           "Defender off on servers, for a small PC)")
    lset.add_argument("--domain", default=None, metavar="NAME",
                      help="the AD domain's DNS name (winlab's default: corp.lab); "
                           "before the first domain controller is built")
    lset.add_argument("--netbios", default=None, metavar="NAME",
                      help="the domain's NetBIOS name (default: the domain's first part, upper case)")
    lset.add_argument("--share", default=None, metavar="NAME",
                      help="the file server's main share, the DFS root and the mapped drive "
                           "(winlab's default: Company)")
    lset.add_argument("--site", action="append", default=[], metavar="KEY=NAME",
                      help="name an AD site (KEY is the site machines carry, e.g. HQ=London); repeatable")
    lset.add_argument("--scope", action="append", default=[], metavar="NETWORK=NAME",
                      help="name the DHCP scope for a network; repeatable")
    im_ = labsub.add_parser("import", help="bring an exported folder in as a lab")
    im_.add_argument("folder", help="the folder 'lab export' wrote")
    im_.add_argument("--as", dest="as_name", default="", metavar="NAME",
                     help="import under another name (machines keep their MAC addresses)")
    im_.add_argument("--show", action="store_true", help="only describe what is in the folder")

    img = sub.add_parser("images", help="image catalog, acquisition and bases")
    imgsub = img.add_subparsers(dest="imgcmd", metavar="<subcommand>")
    imgsub.add_parser("list", help="show catalog state and what each image needs")
    f = imgsub.add_parser("fetch", help="download a freely redistributable image")
    f.add_argument("image", help="alpine, an appliance, or a Linux installer DVD "
                                 "(ubuntu24, rocky9, rhel9, rhel10, debian13, alpine-std, proxmox-ve9, proxmox-bs4, "
                                 "ubuntu24-desktop) or opnsense-dvd")
    im = imgsub.add_parser("import", help="import media you downloaded yourself")
    im.add_argument("image", help="a catalog id, or linux: a Linux installer DVD, "
                                  "recognised from the disc; firewall: OPNsense or pfSense CE")
    im.add_argument("path")
    pr = imgsub.add_parser("prepare", help="prepare a reusable base image")
    pr.add_argument("image", help="ws2025 | ws2025-core | ws2022 | ws2022-core | ws2019 | "
                                  "ws2019-core | win11 | win10 | fabric")
    pr.add_argument("--size", type=int, default=64, help="base disk GB (Windows)")
    pr.add_argument("--windowed", action="store_true", help="show the installer window")
    pr.add_argument("--keep-iso", action="store_true",
                    help="keep the ISO copy after the base is prepared (default: remove it)")
    pr.add_argument("--no-compress", action="store_true",
                    help="store the base uncompressed (default: zstd-compressed qcow2)")
    pr.add_argument("--no-virtio", action="store_true",
                    help="leave the virtio-win drivers out (emulated NIC and disk only)")
    ia = imgsub.add_parser("add", help="add your own ISO for machines you install by hand")
    ia.add_argument("image", help="a short name, e.g. ubuntu-24 or opnsense")
    ia.add_argument("path", help="the .iso file")
    ia.add_argument("--title", default="", help="what to call it in the app")
    ia.add_argument("--firmware", choices=("bios", "uefi"), default="bios")
    ia.add_argument("--disk-gb", type=int, default=32, help="system disk size")
    irm = imgsub.add_parser("rm", help="remove an ISO you added")
    irm.add_argument("image")

    tp = sub.add_parser("template", help="machines turned into images: make, list, remove")
    tpsub = tp.add_subparsers(dest="tplcmd", metavar="<subcommand>")
    tpsub.add_parser("list", help="list your templates")
    tc = tpsub.add_parser("create", help="turn a stopped machine into a template")
    tc.add_argument("lab")
    tc.add_argument("node", help="the machine to copy (it is left as it is)")
    tc.add_argument("name", help="a short name, e.g. fileserver-gold")
    tc.add_argument("--title", default="", help="what to call it in the app")
    tc.add_argument("--no-generalize", action="store_true",
                    help="Windows: skip sysprep, so clones are identical inside")
    tc.add_argument("--full", action="store_true",
                    help="a standalone image instead of one that shares the base")
    tc.add_argument("--accel", default="", help="whpx | kvm | tcg (default: detect)")
    trm = tpsub.add_parser("rm", help="delete a template (machines made from it keep running)")
    trm.add_argument("name")

    node = sub.add_parser("node", help="add, remove or reconfigure machines")
    node.add_argument("lab")
    nodesub = node.add_subparsers(dest="nodecmd", metavar="<op>")
    na = nodesub.add_parser("add", help="add one or more machines")
    na.add_argument("id")
    na.add_argument("--kind", default="windows-server",
                    choices=("windows-server", "windows-client", "linux", "custom"))
    na.add_argument("--net", default="", help="network to attach to")
    na.add_argument("--ip", default="", help="static ip (omit for DHCP)")
    na.add_argument("--roles", default="", help="comma-separated roles")
    na.add_argument("--cpus", type=int, default=0)
    na.add_argument("--memory", type=int, default=0, help="MB")
    na.add_argument("--count", type=int, default=1, help="create N numbered machines")
    na.add_argument("--image", default="",
                    help="image id: a catalog image, one of your templates (the kind "
                         "and hardware come with it), or for --kind custom an ISO "
                         "from 'images add'")
    nr = nodesub.add_parser("rm", help="remove a machine")
    nr.add_argument("id")
    nc = nodesub.add_parser("clone", help="a second machine copied from a stopped one")
    nc.add_argument("src", help="the machine to copy")
    nc.add_argument("id", help="the new machine's name")
    nc.add_argument("--ip", default="", help="static ip for the copy (default: next free)")
    nc.add_argument("--exact", action="store_true",
                    help="skip sysprep on a Windows copy: identical inside, same name and SID")
    nrn = nodesub.add_parser("rename", help="give a machine a new computer name")
    nrn.add_argument("id", help="the machine, by its id or its current name")
    nrn.add_argument("name", help="the new computer name (1-15 letters, digits, hyphens)")
    ns = nodesub.add_parser("set", help="reconfigure a machine")
    ns.add_argument("id")
    ns.add_argument("--name", default="", metavar="NAME",
                    help="a new computer name (Windows takes it at install, or renames itself)")
    ns.add_argument("--cpus", type=int, default=0)
    ns.add_argument("--memory", type=int, default=0)
    ns.add_argument("--add-role", default="")
    ns.add_argument("--rm-role", default="")
    ns.add_argument("--move-to", default="", help="move to another network")
    ns.add_argument("--ip", default="")
    ns.add_argument("--boot-order", type=int, default=0, help="lower boots first")
    ns.add_argument("--start-delay", type=int, default=None, metavar="SECONDS",
                    help="pause this long after this machine starts before the next one")
    ns.add_argument("--wait-ready", choices=("on", "off"), default=None,
                    help="the next machines wait until this one's agent answers (Windows)")
    ns.add_argument("--add-disk", type=int, default=0, metavar="GB", help="add a data disk")
    ns.add_argument("--rm-disk", action="store_true", help="remove the last data disk")
    ns.add_argument("--add-nic", default="", metavar="NET[:IP]", help="add a nic on a network")
    ns.add_argument("--rm-nic", type=int, default=0, metavar="N", help="remove nicN (not 0)")
    ns.add_argument("--cable", default="", metavar="N:NET[:IP]",
                    help="plug nicN into another network (what dragging a machine onto a "
                         "switch in the Network map does)")
    ns.add_argument("--tag", default="", metavar="N:NET",
                    help="carry NET tagged on nicN's cable (a trunk port)")
    ns.add_argument("--untag", default="", metavar="N:NET", help="take a tagged network off nicN")
    ns.add_argument("--iso", default=None, metavar="IMAGE",
                    help="keep an ISO in the drive (an image id, or 'none' to eject)")
    ns.add_argument("--usb", type=int, default=None, metavar="GB",
                    help="virtual usb stick size (0 removes it)")
    ns.add_argument("--gpu", choices=("on", "off"), default=None,
                    help="emulated 3D-capable display adapter")
    ns.add_argument("--hardware", choices=("pc", "virtio"), default=None,
                    help="pc: a regular PC (Intel devices Windows drives itself, the default); "
                         "virtio: Red Hat's paravirtual devices, less CPU, drivers from the base")
    ns.add_argument("--lean", choices=("on", "off"), default=None,
                    help="the Low-memory profile on this Windows machine (off: stock Windows)")
    ns.add_argument("--description", default=None)
    nodesub.add_parser("list", help="list machines")

    rp = sub.add_parser("roles", help="inspect or apply the role plan for a node")
    rp.add_argument("lab")
    rolesub = rp.add_subparsers(dest="rolecmd", metavar="<op>")
    rpl = rolesub.add_parser("plan", help="show the ordered role plan for a node")
    rpl.add_argument("node")
    rap = rolesub.add_parser("apply", help="apply roles to a running node over serial")
    rap.add_argument("node")
    rts = rolesub.add_parser("test", help="report DSC drift: what differs from the node's desired state")
    rts.add_argument("node")

    dp = sub.add_parser("dsc", help="the desired-state role engine: modules and generated configurations")
    dsub = dp.add_subparsers(dest="dsccmd", metavar="<op>")
    dsub.add_parser("modules", help="show the DSC resource modules and whether they are fetched")
    df = dsub.add_parser("fetch", help="fetch the DSC resource modules from the PowerShell Gallery")
    df.add_argument("--refresh", action="store_true", help="re-download even if present")
    dr = dsub.add_parser("render", help="print the DSC configuration winlab generates for a node")
    dr.add_argument("lab")
    dr.add_argument("node")
    dra = dsub.add_parser("render-all", help="write every lab's generated configurations into a directory")
    dra.add_argument("out_dir")

    net = sub.add_parser("net", help="add, remove or reconfigure networks")
    net.add_argument("lab")
    netsub = net.add_subparsers(dest="netcmd", metavar="<op>")
    ea = netsub.add_parser("add", help="add a network segment")
    ea.add_argument("id")
    ea.add_argument("--cidr", default="", help="CIDR (auto-allocated if omitted)")
    ea.add_argument("--vlan", type=int, default=None)
    ea.add_argument("--dhcp", action="store_true", help="the router serves a DHCP pool here (an ISP's handoff)")
    ea.add_argument("--wan", action="store_true")
    ea.add_argument("--desc", default="")
    er = netsub.add_parser("rm", help="remove a network segment")
    er.add_argument("id")
    netsub.add_parser("list", help="list networks")
    nc = netsub.add_parser("check", help="test the network from inside a running machine, as an admin would: "
                                         "link, address, gateway, DNS, then every other machine (read-only)")
    nc.add_argument("node")
    nc.add_argument("--to", action="append", default=[], help="only this machine (repeatable)")
    ef = netsub.add_parser("fault", help="inject or clear a network fault/attack scenario")
    ef.add_argument("scenario", nargs="?", default="", help="scenario id (omit to list)")
    ef.add_argument("--on", default="", help="segment id the scenario targets")
    ef.add_argument("--clear", action="store_true", help="remove the scenario")
    ef.add_argument("--param", action="append", default=[], help="k=v scenario parameter")
    ef.add_argument("--dry-run", action="store_true", help="print the fabric commands only")

    fwp = sub.add_parser("fw", help="zone firewall on the lab router (Azure NSG model)")
    fwp.add_argument("lab")
    fwsub = fwp.add_subparsers(dest="fwcmd", metavar="<op>")
    fwsub.add_parser("list", help="every segment's rule tables, defaults included")
    fwsub.add_parser("on", help="turn the zone firewall on")
    fwsub.add_parser("off", help="turn it off: the router forwards everything between segments")
    fa = fwsub.add_parser("add", help="add a rule to a segment's table")
    fa.add_argument("name")
    fa.add_argument("--on", required=True, metavar="SEGMENT",
                    help="the segment whose table the rule joins")
    fa.add_argument("--priority", type=int, required=True, help="100 to 4096; lowest first")
    fa.add_argument("--direction", choices=("inbound", "outbound"), default="inbound")
    fa.add_argument("--from", dest="src", default="Any", metavar="SRC",
                    help="address, CIDR, segment, machine, Any, VirtualNetwork or Internet")
    fa.add_argument("--to", dest="dst", default="Any", metavar="DST", help="same forms as --from")
    fa.add_argument("--ports", default="*", help="'*', 3389, '80,443' or 1000-2000")
    fa.add_argument("--proto", default="Any", help="Any, Tcp, Udp or Icmp")
    fa.add_argument("--action", default="Allow", help="Allow or Deny")
    fa.add_argument("--desc", default="")
    fr = fwsub.add_parser("rm", help="remove a rule from the lab and from the running router")
    fr.add_argument("name")
    fr.add_argument("--on", default="", metavar="SEGMENT")
    fv = fwsub.add_parser("verify", help="would a flow pass, and by which rule (IP flow verify)")
    fv.add_argument("source", help="machine id or address")
    fv.add_argument("destination", help="machine id or address")
    fv.add_argument("--port", type=int, default=0)
    fv.add_argument("--proto", default="Tcp", help="Tcp, Udp or Icmp")
    fwsub.add_parser("live", help="effective rules and hit counts from the running router")
    fwsub.add_parser("apply", help="push the lab's tables to the running router now")

    ex = sub.add_parser("exercise", help="list, brief and grade exercises")
    exsub = ex.add_subparsers(dest="excmd", metavar="<op>")
    exsub.add_parser("list", help="list available exercises")
    eb = exsub.add_parser("show", help="show an exercise brief")
    eb.add_argument("id")
    es = exsub.add_parser("start", help="boot only the machines an exercise uses")
    es.add_argument("id")
    es.add_argument("--accel", default="", help="override the accelerator (whpx, kvm, tcg)")
    es.add_argument("--display", choices=("window", "none"), default="window")
    es.add_argument("--force", action="store_true",
                    help="boot even if the host does not have the memory free")
    eg = exsub.add_parser("grade", help="grade an exercise against the running lab")
    eg.add_argument("id")
    eg.add_argument("--lab", default="", help="lab name (defaults to the exercise's)")

    acp = sub.add_parser("activity", help="activities: a network to build, scored as the student builds it")
    acsub = acp.add_subparsers(dest="actcmd", metavar="<op>")
    am = acsub.add_parser("make", help="make an activity (.wlact) whose target is this workbench network")
    am.add_argument("lab", help="the finished network (a workbench lab)")
    am.add_argument("dest", nargs="?", default=".", help="a file or folder (default: here)")
    am.add_argument("--title", required=True)
    am.add_argument("--instructions", default="", help="the text, or @file to read it from a file")
    am.add_argument("--start", default="empty", help="empty, partial (the --keep devices) or version:<id>")
    am.add_argument("--keep", default="", help="partial start: devices to keep, e.g. srv01,net:sw1,ap:ap01")
    am.add_argument("--cables", action="store_true", help="partial start: keep their cables too")
    am.add_argument("--time", type=int, default=0, help="time limit in minutes (default: none)")
    am.add_argument("--score-only", action="store_true", help="the student sees the score, not which items are wrong")
    am.add_argument("--points", default="", help="points per item by category, e.g. devices=2,roles=1,ip=0")
    am.add_argument("--skip", default="", help="item ids not to grade (see `activity items`)")
    am.add_argument("--guest", action="append", default=[], metavar="CHECK:MACHINE[:ARG][:POINTS]",
                    help="an in-guest check, e.g. t:dc:dc01:3 or t:joined:pc01:corp.lab (repeatable)")
    ai = acsub.add_parser("items", help="what a network would be graded on, and the in-guest checks")
    ai.add_argument("lab")
    ao = acsub.add_parser("open", help="open an activity: its starting network becomes a new lab")
    ao.add_argument("file")
    ao.add_argument("--as", dest="as_name", default="", help="the lab's name here")
    ac = acsub.add_parser("check", help="the score of a lab opened from an activity")
    ac.add_argument("lab")
    ac.add_argument("--guest", action="store_true", help="run the in-guest checks first (machines on)")
    ah = acsub.add_parser("hand-in", help="hand the activity in: its score stands")
    ah.add_argument("lab")

    sp = sub.add_parser("snap", help="snapshot a lab's disks")
    sp.add_argument("lab")
    spsub = sp.add_subparsers(dest="snapcmd", metavar="<op>")
    ss = spsub.add_parser(
        "save", help="save a named checkpoint (running machines pause for a moment)")
    ss.add_argument("tag")
    ss.add_argument("--only", default="", help="comma-separated machines")
    sr = spsub.add_parser(
        "restore", help="revert to a checkpoint (running machines restart)")
    sr.add_argument("tag")
    sr.add_argument("--only", default="", help="comma-separated machines")
    sd = spsub.add_parser("rm", help="delete a snapshot")
    sd.add_argument("tag")
    spsub.add_parser("list", help="list snapshots")

    co = sub.add_parser("console", help="show how to reach a machine's screen/serial")
    co.add_argument("node")
    co.add_argument("--lab", default="")

    ec = sub.add_parser("exec", help="run a command inside a machine")
    ec.add_argument("node")
    ec.add_argument("--lab", default="")
    ec.add_argument("--cmd", dest="shell", default="", help="shell: cmd (default powershell)")
    ec.add_argument("command", nargs="*",
                    help="command to run (after --)")

    ky = sub.add_parser("keys", help="type on a machine's own keyboard, as at its screen")
    ky.add_argument("lab")
    ky.add_argument("node")
    ky.add_argument("typed", nargs="+", help="text to type; <ctrl-alt-del>, <enter>, <tab>, <esc>, <win-r> and "
                                            "the other keys in angle brackets press that key")

    ca = sub.add_parser("console-agent", help="serve an appliance's serial console as a winlab agent (started by `lab up`)")
    from .consoleagent import add_arguments as _console_agent_arguments
    _console_agent_arguments(ca)

    sh = sub.add_parser("shell", help="interactive shell inside a machine")
    sh.add_argument("node")
    sh.add_argument("--lab", default="")
    sh.add_argument("--cmd", dest="use_cmd", action="store_true", help="use cmd instead of powershell")

    cp = sub.add_parser("cp", help="copy a file in or out (use node:path for the guest)")
    cp.add_argument("src")
    cp.add_argument("dst")
    cp.add_argument("--lab", default="")

    bk = sub.add_parser("break", help="inject, hint, verify or clear an OS-level problem inside a machine")
    bk.add_argument("node", nargs="?", default="", help="machine to break (omit to list)")
    bk.add_argument("scenario", nargs="?", default="", help="scenario id")
    bk.add_argument("--lab", default="")
    bk.add_argument("--clear", action="store_true", help="fix the problem for me")
    bk.add_argument("--hint", type=int, default=0, metavar="N", help="show hint N (1-3) instead of breaking")
    bk.add_argument("--verify", action="store_true", help="check whether my fix holds")
    bk.add_argument("--param", action="append", default=[], help="k=v parameter")
    from . import physfaults
    physfaults.add_cli(sub)  # winlab fault <lab> ...: cables, cards and disks of a running network
    from . import disks
    disks.add_cli(sub)  # winlab disk <lab> <node> ...: drive bays, buses, failing disks
    from . import sysdisk
    sysdisk.add_cli(sub)  # winlab sysdisk <lab> <node> die|mend|replace: the system disk dies
    from . import pcbuild
    pcbuild.add_cli(sub)  # the thermal trip's watcher, started at power-on (hidden)
    from . import drsite
    drsite.add_cli(sub)  # winlab dr <lab> lose|rebuild|status: the head office site is lost
    from . import bareos
    bareos.add_cli(sub)  # winlab bareos status|stick <lab>: the Bareos client for Windows on a stick
    from . import updates
    updates.add_cli(sub)  # winlab updates list|stick|disc|label|fetch: Microsoft's packages, carried in
    from . import edge
    edge.add_cli(sub)  # winlab edge status|stick: the Edge MSI and policy templates the user downloaded
    from . import bitlocker
    bitlocker.add_cli(sub)  # winlab bitlocker <lab> <node> ...: the TPM, key sticks, moving a disk, drills
    from . import power
    power.add_cli(sub)  # winlab power <lab> ...: servers' management ports, a hang, Wake-on-LAN
    from . import ups
    ups.add_cli(sub)  # winlab ups <lab> ...: the UPS, power cut, power back, the drill
    from . import alerts
    alerts.add_cli(sub)  # winlab alerts list|ack|note|tick|rota|source|test|drill: on-call alerting
    from . import rack, toolkit
    from . import building as _building
    _building.add_cli(sub)  # winlab building <lab> show|place|remove: where each machine stands
    rack.add_cli(sub)  # winlab rack <lab> show|move|label|tag|labels|export|audit: the rack and its documentation
    from . import campus
    campus.add_cli(sub)  # winlab job list|spec <job>|handover <lab>: client jobs and their specifications
    from . import inherited, serverroom
    inherited.add_cli(sub)   # winlab inherited <lab> status|handover|notes: the inherited company scenario
    from . import aidc
    aidc.add_cli(sub)        # winlab aidc <lab> status|handover|notes: the AI data center scenario
    serverroom.add_cli(sub)  # winlab room <lab> status|walk|back|on|off: the locked server room
    toolkit.add_cli(sub)  # winlab toolkit fetch|status|stick: PuTTY, WinSCP, Notepad++, Sysinternals on a stick
    from . import classes
    classes.add_cli(sub)  # winlab class new|add-student|assign|export|open|handin|import|grades|csv
    from . import itops
    itops.add_cli(sub)  # winlab itops add|show: the IT ops server (osTicket, Prometheus, Alertmanager)
    from . import lifecycle
    lifecycle.add_cli(sub)  # winlab lifecycle send|show: HR's joiner and leaver requests into osTicket
    from . import helpdesk
    helpdesk.add_cli(sub)  # winlab helpdesk list|show|take|note|wait|resolve|start|stop|tick|report|settings
    from . import workday
    workday.add_cli(sub)  # winlab workday start|stop|status|tick|level|shifts, winlab staff list|password
    from . import company, shift, wear
    wear.add_cli(sub)  # winlab wear <lab> status|level|tick|seed|clear: servers wear out on the lab clock
    shift.add_cli(sub)  # winlab shift start|check|show|tick <lab>: the start-of-shift report and checklist
    company.add_cli(sub)  # winlab company start|status|next|plan|save|resume|stop <lab>: a company run
    from . import traffic
    traffic.add_cli(sub)  # winlab load status|profile|period|busy|background|links: the load engine
    from . import secops
    secops.add_cli(sub)  # winlab secops status|fetch|stick|sct-fetch: Greenbone, software, Wazuh agent, the SCT
    from . import selftest
    selftest.add_cli(sub)  # winlab selftest <lab>|--lesson|--exercise|--all: prove the lessons on this PC

    ln = sub.add_parser("learn", help="the lessons: the study path over the labs")
    lnsub = ln.add_subparsers(dest="learncmd", metavar="<op>")
    lnsub.add_parser("list", help="list lessons by module, with progress")
    lsh = lnsub.add_parser("show", help="show a lesson: why, steps, verify commands, check")
    lsh.add_argument("id")
    lan = lnsub.add_parser("answer", help="print the configuration winlab generates for a lesson's role")
    lan.add_argument("id")
    lqz = lnsub.add_parser("quiz", help="answer a lesson's recall questions from memory")
    lqz.add_argument("id")
    lqz.add_argument("--answers", default="",
                     help="letters in order, e.g. b,a,c (otherwise asked one by one)")
    lrv = lnsub.add_parser("review", help="today's spaced review: recall questions from finished lessons come back")
    lrv.add_argument("--answers", default="",
                     help="letters in order, e.g. b,a,c (otherwise asked one by one)")
    lrv.add_argument("--status", action="store_true", help="only say how many are due and how they stand")
    lnsub.add_parser("check", help="validate every lesson's references (content authors)")
    lsc = lnsub.add_parser("scripts", help="write every check, verify and problem script as .ps1 (CI parses them)")
    lsc.add_argument("out")
    lst = lnsub.add_parser("start", help="boot only the machines a lesson uses")
    lst.add_argument("id")
    lst.add_argument("--accel", default="", help="override the accelerator (whpx, kvm, tcg)")
    lst.add_argument("--display", choices=("window", "none"), default="window")
    lst.add_argument("--force", action="store_true",
                     help="boot even if the host does not have the memory free")

    mc = sub.add_parser("mecm", help="Configuration Manager: build the media disc the mecm role installs from")
    mcsub = mc.add_subparsers(dest="mecmcmd", metavar="<op>")
    mcsub.add_parser("status", help="what is prepared, what was found in Downloads, what is missing")
    mcp = mcsub.add_parser("prepare", help="build mecm.iso from the Microsoft downloads")
    mcp.add_argument("folder", nargs="*", help="where the downloads are (default: Downloads, Desktop, Documents)")
    mcp.add_argument("--media", default="", help="the extracted Configuration Manager folder")
    mcp.add_argument("--adk", default="", help="adksetup.exe, or its offline layout folder")
    mcp.add_argument("--winpe", default="", help="adkwinpesetup.exe, or its offline layout folder")
    mcp.add_argument("--odbc", default="", help="msodbcsql.msi (ODBC Driver 18 for SQL Server, x64)")
    mcp.add_argument("--prereqs", default="", help="a folder setupdl.exe already filled")

    sbp = sub.add_parser("secureboot", help="Secure Boot: Microsoft's certificates for machines set to UEFI with Secure Boot")
    sbsub = sbp.add_subparsers(dest="sbcmd", metavar="<op>")
    sbsub.add_parser("status", help="which certificates are on this PC, and this PC's platform key")
    sbsub.add_parser("fetch", help="download Microsoft's KEK and db certificates (and dbx) from Microsoft")
    sbi = sbsub.add_parser("import", help="pick them out of a folder you downloaded them into")
    sbi.add_argument("folder", nargs="*", help="where they are (default: Downloads, Desktop, Documents)")

    of = sub.add_parser("office", help="Microsoft 365 Apps: build the disc a lab installs Office from")
    ofsub = of.add_subparsers(dest="officecmd", metavar="<op>")
    ofst = ofsub.add_parser("status", help="what is prepared, what was found in Downloads, what is missing")
    ofx = ofsub.add_parser("xml", help="print the download configuration for setup.exe /download")
    ofp = ofsub.add_parser("prepare", help="build office.iso on the lab's media shelf from the Microsoft downloads")
    for a in (ofst, ofp):
        a.add_argument("--lab", default="windows11-desktops", help="whose shelf the disc goes on")
    for a in (ofx, ofp):
        a.add_argument("--channel", default="MonthlyEnterprise",
                       choices=("MonthlyEnterprise", "SemiAnnual", "Current", "SemiAnnualPreview"))
        a.add_argument("--edition", default="64", choices=("64", "32"))
        a.add_argument("--language", default="en-us")
    ofx.add_argument("--source", default=r"C:\Office", help="the SourcePath the download fills")
    ofp.add_argument("folder", nargs="*", help="where the downloads are (default: Downloads, Desktop, Documents)")
    ofp.add_argument("--odt", default="", help="officedeploymenttool_*.exe, or the folder it extracted to")
    ofp.add_argument("--source", default="", help="a folder setup.exe /download already filled (holds Office\\Data)")
    ofp.add_argument("--admx", default="", help="admintemplates_x64_*.exe, or the folder it extracted to")
    ofp.add_argument("--no-admx", action="store_true", help="leave the administrative templates off the disc")

    us = sub.add_parser("usmt", help="User State Migration Tool: build the disc a lab migrates users with")
    ussub = us.add_subparsers(dest="usmtcmd", metavar="<op>")
    usst = ussub.add_parser("status", help="what is prepared, what was found, what is missing")
    usp = ussub.add_parser("prepare", help="build usmt.iso on the lab's media shelf from USMT or the ADK")
    for a in (usst, usp):
        a.add_argument("--lab", default="windows11-desktops", help="whose shelf the disc goes on")
    usp.add_argument("folder", nargs="*", help="where to look (default: Downloads, Desktop, Documents, "
                                               "and an ADK installed on this PC)")
    usp.add_argument("--usmt", default="", help="a USMT amd64 folder (scanstate.exe, loadstate.exe, MigDocs.xml)")
    usp.add_argument("--adk", default="", help="adksetup.exe, or its offline layout folder")

    cm = sub.add_parser("commands", help="the command reference: every command the lessons use, searchable")
    cm.add_argument("query", nargs="*", help="words to look for (name, what it does, lessons)")
    cm.add_argument("--kind", choices=("powershell", "windows", "linux", "firewall", "sql", "cloud", "switch"), default="")
    cm.add_argument("--examples", type=int, default=2, help="lesson lines to show per command")

    ex = sub.add_parser("exam", help="exam prep: readiness per skill area, and timed practice exams",
                        description="winlab exam [<track>]  readiness for a track (az-802 when none is named); "
                                    "winlab exam list | start <track> [--questions N --minutes M] | resume | "
                                    "abandon | history [<track>]")
    ex.add_argument("id", nargs="?", default="az-802",
                    help="a track for its readiness, or list, start, resume, abandon, history")
    ex.add_argument("track", nargs="?", default="", help="the track for start and history")
    ex.add_argument("--questions", type=int, default=0, help="how many questions (default: the track's)")
    ex.add_argument("--minutes", type=int, default=0, help="the clock (default: the track's)")

    oc = sub.add_parser("oncall", help="a helpdesk shift: blind tickets on the running lab, a clock and a score")
    oc.add_argument("--lab", default="")
    ocsub = oc.add_subparsers(dest="occmd", metavar="<op>")
    ocs = ocsub.add_parser("start", help="start a shift on the running machines")
    ocs.add_argument("--minutes", type=int, default=45)
    ocs.add_argument("--tickets", type=int, default=4)
    ocsub.add_parser("status", help="the open ticket, the queue, the clock")
    ocsub.add_parser("resolve", help="say the open ticket is fixed; winlab checks the machine")
    ocsub.add_parser("escalate", help="hand the open ticket on: no points, winlab undoes it")
    ocsub.add_parser("end", help="end the shift now")

    from . import breakfix
    breakfix.add_cli(sub)  # winlab breakfix start|status|note|hint|check|answer|giveup|close|history
    from . import interview
    interview.add_cli(sub)  # winlab interview start|status|begin|answer|submit|practical|skip|quit|close|history
    from . import incidents
    incidents.add_cli(sub)  # winlab incident start|status|check|hint|answer|giveup|close|history
    from . import subnetdrill
    subnetdrill.add_cli(sub)  # winlab drill subnet [--count N --kind K]|history

    sc = sub.add_parser("scenario", help="scenario days: a story on a lab you built, mail on a clock, "
                                         "problems injected, your work graded, a debrief")
    sc.add_argument("--lab", default="")
    scsub = sc.add_subparsers(dest="sccmd", metavar="<op>")
    scsub.add_parser("list", help="every scenario, its lab, length and the lessons to do first")
    scst = scsub.add_parser("start", help="start a scenario day on its lab's running machines")
    scst.add_argument("id")
    scsub.add_parser("status", help="the inbox, the open tasks, the clock")
    scsub.add_parser("check", help="grade the open tasks inside the machines (Check my work)")
    scsub.add_parser("stop", help="end the day now: open problems are undone, then the debrief")

    ck = sub.add_parser("clock", help="the lab's own clock: show, pause, resume, jump ahead or set it")
    ck.add_argument("--lab", default="")
    cksub = ck.add_subparsers(dest="ckcmd", metavar="<op>")
    cksub.add_parser("show", help="lab time, real time, and what each machine did with the last change")
    cksub.add_parser("pause", help="stop the lab clock (running machines pause with it)")
    cksub.add_parser("resume", help="run the lab clock again at normal speed")
    ckj = cksub.add_parser("jump", help="move lab time ahead: 1h, 30min, 2d, 1w, tonight, 09:00 or a date")
    ckj.add_argument("when", nargs="+")
    cks = cksub.add_parser("set", help="put lab time at a date (2026-12-24 09:00), or 'real' to follow real time")
    cks.add_argument("when", nargs="+")
    ckw = cksub.add_parser("skew", help="run one machine's clock off lab time (+10min, -6min, +1w; 0 puts it back); "
                                        "no machine: the lab's time sources")
    ckw.add_argument("node", nargs="?", default="")
    ckw.add_argument("amount", nargs="?", default="")

    pk = sub.add_parser("pki", help="the lab CA in use: what LDAPS, HTTPS and RDP present, whether the CRL answers (read-only)")
    pk.add_argument("pkicmd", nargs="?", default="check", choices=["check"])
    pk.add_argument("--lab", default="")

    pg = sub.add_parser("progress", help="what you have completed")
    pgsub = pg.add_subparsers(dest="progcmd", metavar="<op>")
    pgsub.add_parser("show", help="lessons done, started and next")
    pgr = pgsub.add_parser("reset", help="forget progress (one lesson, or everything)")
    pgr.add_argument("id", nargs="?", default="", help="lesson id; omit for everything")
    pge = pgsub.add_parser("export", help="write your progress, results, certificates and notes to one file "
                                         "(.wlprogress) to take to another PC")
    pge.add_argument("file", nargs="?", default="", help="where to write it (default: winlab-progress-<name>-<date>.wlprogress here)")
    pgi = pgsub.add_parser("import", help="merge a progress file from another PC into this one's (nothing here is lost)")
    pgi.add_argument("file")

    tk = sub.add_parser("tracks", help="tracks of lessons, each with its own certificate (and a link to share it)")
    tksub = tk.add_subparsers(dest="trackcmd", metavar="<op>")
    tksub.add_parser("list", help="every track: checked lessons done, next lesson, certificate")
    tkc = tksub.add_parser("certificate", help="write a finished track's certificate as a page to print or save as PDF")
    tkc.add_argument("track")
    tkc.add_argument("--name", default="", help="the name on it (default: the one last used)")
    tkc.add_argument("--html", default="", help="file to write (default: certificate-<track>.html)")
    tks = tksub.add_parser("share", help="publish a verification link for a finished track's certificate "
                                         "(sends its facts and this PC's licence key to winlab's website)")
    tks.add_argument("track")
    tks.add_argument("--name", default="")
    tkw = tksub.add_parser("withdraw", help="take a certificate's verification link down")
    tkw.add_argument("track")

    md = sub.add_parser("media", help="plug a USB stick into a machine or put a disc in its drive")
    md.add_argument("lab")
    md.add_argument("node")
    mdsub = md.add_subparsers(dest="mediacmd", metavar="<op>")
    mdsub.add_parser("drivers", help="plug in the driver stick: Red Hat's virtio-win drivers and "
                                     "installer for this Windows, plus your packages from images/drivers")
    mp = mdsub.add_parser("plug", help="plug a stick from the media shelf into a USB port, "
                                       "or a new one holding a folder's files")
    mp.add_argument("folder", help="a stick on the shelf (see list), or a folder")
    mp.add_argument("--port", type=int, default=0, help="the USB port, 1 to 4 (default: the first free one)")
    mpk = mdsub.add_parser("pack", help="plug in a package stick (a pack from 'packs list' for this machine's "
                                        "image): what the machine's Settings > Plug the package stick does")
    mpk.add_argument("pack")
    mu = mdsub.add_parser("unplug", help="pull the stick out: it goes back on the shelf with its files")
    mu.add_argument("--port", type=int, default=1, help="the USB port (default 1)")
    mi = mdsub.add_parser("insert", help="put a disc in the DVD drive (an image id from 'images list', "
                                         "or a disc on the shelf: see list)")
    mi.add_argument("image")
    mi.add_argument("--drive", type=int, default=0, help="the DVD drive, 1 or 2 (default: the first empty one)")
    me = mdsub.add_parser("eject", help="eject the disc: it goes back on the shelf")
    me.add_argument("--drive", type=int, default=1, help="the DVD drive (default 1)")
    mdsub.add_parser("list", help="the media shelf, and what is in this machine's drives and ports")
    mbo = mdsub.add_parser("boot", help="what the machine's firmware tries first at power-on")
    mbo.add_argument("first", choices=("dvd", "disk"))
    mbu = mdsub.add_parser("burn", help="burn a folder to a disc on the shelf and put it in the drive")
    mbu.add_argument("folder")
    mbu.add_argument("--label", default="", help="the disc's label (default: the folder's name)")
    mb = mdsub.add_parser("blank", help="plug in a new, empty stick (Windows asks to format it)")
    mb.add_argument("--gb", type=int, default=16, help="its size: 8, 16, 32 or 64 (default 16)")
    mdsub.add_parser("status", help="what is plugged in, and which drive bays are empty")
    for op, what in (("pull", "pull a data disk out of its bay (live: it stops answering at once)"),
                     ("back", "put a pulled disk back, with its data (machine off)"),
                     ("new-disk", "fit a new blank disk in a pulled disk's bay (machine off)")):
        bp = mdsub.add_parser(op, help=what)
        bp.add_argument("bay", type=int, help="the bay: 1 is the first data disk")

    wbp = sub.add_parser("workbench", help="do what a drag or a click on the Workbench does (wb-cable, wb-add, "
                                           "wb-stp-cable, con-plug ...): the hands' part of a lab, for "
                                           "scripts and the self-test")
    wbp.add_argument("lab")
    wbp.add_argument("action", help="the Workbench's action, such as wb-cable or con-plug")
    wbp.add_argument("params", nargs="*", default=[], help="key=value pairs (node=pc01 network=lan nic=0)")
    tmp = sub.add_parser("terminal", help="type one line into a machine's Terminal window (its serial console), "
                                          "as a person at that window does, and print what comes back: for "
                                          "the vendor routers and firewalls, which have no winlab agent")
    tmp.add_argument("lab")
    tmp.add_argument("node")
    tmp.add_argument("line", help="the line; Enter is pressed after it (an empty string is Enter alone)")
    tmp.add_argument("--wait", type=float, default=2.0, help="seconds to read the answer (default 2)")
    tmp.add_argument("--expect", default="", help="read until this regular expression shows (up to --timeout)")
    tmp.add_argument("--timeout", type=float, default=600.0)
    pk = sub.add_parser("packs", help="packages for Linux appliances, fetched from the distribution's "
                                      "archive onto this PC and plugged in as a stick")
    pksub = pk.add_subparsers(dest="packcmd", metavar="<op>")
    pksub.add_parser("list", help="every pack, what it installs and whether it is fetched")
    pkf = pksub.add_parser("fetch", help="resolve a pack against the appliance image and download it")
    pkf.add_argument("pack", help="a pack id from 'packs list' (sssd)")
    pkf.add_argument("--refresh", action="store_true", help="re-read the archive's package index")
    ml = sub.add_parser("mail", help="Thunderbird for the lab's PCs, fetched from Mozilla onto this PC "
                                     "(the media shelf writes it onto a mail client stick)")
    mlsub = ml.add_subparsers(dest="mailcmd", metavar="<op>")
    mlsub.add_parser("status", help="whether Thunderbird is fetched, which release")
    mlsub.add_parser("fetch", help="fetch the current ESR release for Windows and Linux")
    mls = mlsub.add_parser("stick", help="write the mail client stick onto a lab's media shelf")
    mls.add_argument("lab", help="the lab whose shelf gets the stick")
    ws = sub.add_parser("wireshark", help="Wireshark for the lab's Windows PCs, fetched from wireshark.org onto "
                                          "this PC (the media shelf writes it onto a Wireshark stick); never Npcap")
    wssub = ws.add_subparsers(dest="wscmd", metavar="<op>")
    wssub.add_parser("status", help="whether Wireshark is fetched, which release")
    wssub.add_parser("fetch", help="fetch the Windows x64 installer, checked against the release's SHA-256")
    wss = wssub.add_parser("stick", help="write the Wireshark stick onto a lab's media shelf")
    wss.add_argument("lab", help="the lab whose shelf gets the stick")
    wm = sub.add_parser("webmin", help="Webmin, the storage array's and the NTP server's management pages, "
                                       "fetched from its GitHub release onto this PC")
    wmsub = wm.add_subparsers(dest="wmcmd", metavar="<op>")
    wmsub.add_parser("status", help="whether the pinned release is fetched")
    wmsub.add_parser("fetch", help="fetch it (SHA-256 checked) and rebuild the Alpine repository volume with it")
    dt = sub.add_parser("docs", help="the admin's documentation tools: GLPI, DokuWiki and Vaultwarden packs for "
                                     "the Admin tools server, phpIPAM and NetBox for the network, the GLPI Agent "
                                     "and the staff directory sticks")
    dtsub = dt.add_subparsers(dest="docscmd", metavar="<op>")
    dtsub.add_parser("status", help="which of the packs and the GLPI Agent are fetched")
    dtf = dtsub.add_parser("fetch", help="fetch the GLPI Agent and the glpi, dokuwiki and vaultwarden packs, "
                                         "or the phpipam and netbox packs (net)")
    dtf.add_argument("what", nargs="?", default="all", choices=("agent", "packs", "net", "all"),
                     help="agent (the MSI), packs (glpi, dokuwiki, vaultwarden; they need the debian12 image), "
                          "net (phpipam, netbox) or all (the default)")
    dts = dtsub.add_parser("stick", help="write the GLPI Agent or the staff directory stick onto a lab's media shelf")
    dts.add_argument("lab", help="the lab whose shelf gets the stick")
    dts.add_argument("kind", choices=("agent", "staff"), help="agent (the GLPI Agent MSI) or staff (HR's directory)")
    no = sub.add_parser("netops", help="the network team's tools: LibreNMS, Oxidized and Uptime Kuma packs for "
                                       "the Network operations server")
    nosub = no.add_subparsers(dest="netopscmd", metavar="<op>")
    nosub.add_parser("status", help="which of the three packs are fetched")
    nof = nosub.add_parser("fetch", help="fetch the librenms, oxidized and uptime-kuma packs (each image by digest)")
    nof.add_argument("what", nargs="?", default="all", choices=("librenms", "oxidized", "uptime-kuma", "all"),
                     help="one pack or all (the default); they need the debian12 image")
    ct = sub.add_parser("containers", help="container images, k3s and Docker for Windows, fetched onto this PC "
                                           "(the media shelf writes them onto sticks for the containers lab)")
    ctsub = ct.add_subparsers(dest="ctrcmd", metavar="<op>")
    ctsub.add_parser("status", help="what is fetched: each image, k3s, Docker for Windows")
    ctf = ctsub.add_parser("fetch", help="pull the images from their registries, fetch k3s, Docker for Windows, "
                                         "Kubernetes for kubeadm and Helm")
    ctf.add_argument("what", nargs="?", default="all", choices=["all", "images", "k3s", "docker-win", "kubeadm", "helm"])
    cta = ctsub.add_parser("add", help="put another image on the fetch list (pulled on this PC, never in the lab)")
    cta.add_argument("image", help="an image name as docker pull takes it (postgres:16-alpine)")
    cta.add_argument("--windows", action="store_true", help="a Windows image (ltsc2025 for Windows Server 2025)")
    ctr = ctsub.add_parser("remove", help="take an image you added off the list")
    ctr.add_argument("image")
    cts = ctsub.add_parser("stick", help="write a stick onto a lab's media shelf")
    cts.add_argument("lab", help="the lab whose shelf gets the stick")
    cts.add_argument("kind", choices=["images", "k3s", "docker-win", "kubeadm", "kubeadm-upgrade", "helm"])
    cts.add_argument("--image", action="append", default=[], help="only this image (repeatable)")
    dbp = sub.add_parser("databases", help="pgAdmin 4, HeidiSQL and the PostgreSQL ODBC driver for the lab's "
                                           "Windows machines, fetched onto this PC (the media shelf writes "
                                           "them onto a database clients stick)")
    dbsub = dbp.add_subparsers(dest="dbcmd", metavar="<op>")
    dbsub.add_parser("status", help="which clients are fetched, which releases")
    dbf = dbsub.add_parser("fetch", help="fetch the Windows clients from their projects' own releases")
    dbf.add_argument("client", nargs="?", default="", help="only this one: pgadmin, heidisql or psqlodbc")
    dbs = dbsub.add_parser("stick", help="write the database clients stick onto a lab's media shelf")
    dbs.add_argument("lab", help="the lab whose shelf gets the stick")
    rt = sub.add_parser("routing", help="FRRouting for the routers you build (OSPF, BGP), fetched from the "
                                        "Ubuntu archive onto this PC as the frr pack")
    rtsub = rt.add_subparsers(dest="routecmd", metavar="<op>")
    rts = rtsub.add_parser("status", help="whether the frr pack is fetched; with a lab, its routers and links")
    rts.add_argument("lab", nargs="?", default="", help="a lab whose routing layout to show (dynamic-routing)")
    rtf = rtsub.add_parser("fetch", help="resolve the frr pack against the Ubuntu image and download it")
    rtf.add_argument("--refresh", action="store_true", help="re-read the archive's package index")
    v6 = sub.add_parser("ipv6", help="the ipv6-dual-stack lab: the ipv6-router and ipv6-tools packs fetched "
                                     "onto this PC from the Ubuntu archive, and the lab's IPv6 address plan")
    v6sub = v6.add_subparsers(dest="v6cmd", metavar="<op>")
    v6s = v6sub.add_parser("status", help="whether both packs are fetched; with a lab, its IPv6 address plan")
    v6s.add_argument("lab", nargs="?", default="", help="a lab whose IPv6 plan to show (ipv6-dual-stack)")
    v6f = v6sub.add_parser("fetch", help="fetch the ipv6-router and ipv6-tools packs from the Ubuntu archive")
    v6f.add_argument("--refresh", action="store_true", help="re-read the archive's package index")
    wpx = sub.add_parser("webproxy", help="the web-proxy lab: the squid and nftables packs fetched onto this "
                                          "PC, and the lab Internet it filters")
    wpxsub = wpx.add_subparsers(dest="wpxcmd", metavar="<op>")
    wpxsub.add_parser("status", help="whether both packs are fetched, and the lab Internet's sites")
    wpxf = wpxsub.add_parser("fetch", help="fetch the squid and nftables packs from the Ubuntu archive")
    wpxf.add_argument("--refresh", action="store_true", help="re-read the archive's package index")
    azp = sub.add_parser("azure", help="the lab's Azure (azure-hybrid, azure-admin): floci-az, restic, rest-server and the "
                                       "administrator's tools (Azure CLI, AzCopy, Bicep) fetched onto "
                                       "this PC, and what the lab made of the subscription")
    azsub = azp.add_subparsers(dest="azcmd", metavar="<op>")
    azsub.add_parser("status", help="whether the lab's Azure is fetched")
    azsub.add_parser("fetch", help="fetch floci-az from Docker Hub; restic, rest-server, the Azure CLI, AzCopy "
                                            "and Bicep from GitHub")
    azl = azsub.add_parser("log", help="what the lab built from the subscription, newest last")
    azl.add_argument("lab", help="the lab (azure-hybrid)")
    azl.add_argument("-n", type=int, default=40, help="lines to show (40)")
    awsp = sub.add_parser("aws", help="the aws-cloud lab's AWS: moto and the AWS CLI fetched onto this PC")
    awssub = awsp.add_subparsers(dest="awscmd", metavar="<op>")
    awssub.add_parser("status", help="whether the lab's AWS is fetched")
    awssub.add_parser("fetch", help="fetch moto's image from Docker Hub and the AWS CLI v2 from Amazon")
    idsp = sub.add_parser("ids", help="the intrusion-detection lab: the suricata, nftables and nginx packs and "
                                      "the ET Open rules fetched onto this PC")
    idssub = idsp.add_subparsers(dest="idscmd", metavar="<op>")
    idssub.add_parser("status", help="whether the packs and the rules are fetched")
    idsf = idssub.add_parser("fetch", help="fetch the packs from the Ubuntu archive and ET Open from "
                                           "rules.emergingthreats.net (--rules-only: just the rules)")
    idsf.add_argument("--refresh", action="store_true", help="re-read the archive's package index")
    idsf.add_argument("--rules-only", action="store_true", help="fetch only the ET Open rules")
    idss = idssub.add_parser("stick", help="write the Suricata rules stick onto a lab's media shelf")
    idss.add_argument("lab", help="the lab whose shelf gets the stick")
    sph = sub.add_parser("softphone", help="MicroSIP, the softphone for the lab's Windows PCs, fetched from "
                                           "microsip.org onto this PC")
    sphsub = sph.add_subparsers(dest="spcmd", metavar="<op>")
    sphsub.add_parser("status", help="whether MicroSIP is fetched, which release")
    sphsub.add_parser("fetch", help="fetch MicroSIP's installer (its SHA-256 recorded here)")
    sphs = sphsub.add_parser("stick", help="write the softphone stick onto a lab's media shelf")
    sphs.add_argument("lab", help="the lab whose shelf gets the stick")
    rax = sub.add_parser("remoteaccess", help="the remote-access lab: WireGuard for Windows and the wireguard "
                                              "and nftables packs, fetched onto this PC")
    raxsub = rax.add_subparsers(dest="racmd", metavar="<op>")
    raxsub.add_parser("status", help="whether the client and the packs are fetched, and the lab Internet's names")
    raxf = raxsub.add_parser("fetch", help="fetch WireGuard for Windows (signed list checked) and/or the packs")
    raxf.add_argument("what", nargs="?", default="all", choices=("all", "client", "packs"),
                      help="client (the MSI), packs (from the Ubuntu archive) or all (the default)")
    raxf.add_argument("--refresh", action="store_true", help="re-read the archive's package index")
    raxs = raxsub.add_parser("stick", help="write the VPN client stick onto a lab's media shelf")
    raxs.add_argument("lab", help="the lab whose shelf gets the stick")
    aut = sub.add_parser("automation", help="the automation lab: the ansible and baseline packs and the DSC "
                                            "modules fetched onto this PC, the DSC modules stick")
    autsub = aut.add_subparsers(dest="autcmd", metavar="<op>")
    autsub.add_parser("status", help="whether both packs and the DSC modules are fetched")
    autf = autsub.add_parser("fetch", help="fetch the ansible and baseline packs from the Ubuntu archive and the "
                                           "DSC modules from the PowerShell Gallery")
    autf.add_argument("--refresh", action="store_true", help="re-read the archive's package index")
    auts = autsub.add_parser("stick", help="write the DSC modules stick onto a lab's media shelf")
    auts.add_argument("lab", help="the lab whose shelf gets the stick")
    xp = sub.add_parser("exporter", help="the Prometheus Windows exporter (windows_exporter), fetched onto "
                                         "this PC for the metrics role")
    xpsub = xp.add_subparsers(dest="expcmd", metavar="<op>")
    xpsub.add_parser("status", help="whether it is fetched, which release")
    xpsub.add_parser("fetch", help="download the latest release's MSI from GitHub, checksum verified")
    tr = sub.add_parser("transcript", help="your skills transcript: lessons passed, problems fixed, shifts, exam readiness")
    tr.add_argument("--html", metavar="FILE", help="write the print-ready page to FILE instead of printing text")
    tr.add_argument("--name", default="", help="the name on the page (default: the one on your certificate)")
    wc = sub.add_parser("wac", help="Windows Admin Center (Microsoft), fetched onto this PC for the wac role")
    wcsub = wc.add_subparsers(dest="waccmd", metavar="<op>")
    wcsub.add_parser("status", help="whether it is fetched, which version, its SHA-256")
    wcsub.add_parser("fetch", help="download the installer from Microsoft (about 200 MB)")
    vt = sub.add_parser("virtio", help="the virtio-win guest drivers (Red Hat), fetched onto this PC")
    vtsub = vt.add_subparsers(dest="virtcmd", metavar="<op>")
    vtsub.add_parser("status", help="which drivers are fetched, from which release")
    vtf = vtsub.add_parser("fetch", help="download the stable virtio-win ISO and keep the drivers")
    vtf.add_argument("--refresh", action="store_true", help="fetch again even if present")
    vtf.add_argument("--keep-iso", action="store_true", help="keep the ISO after extracting")
    vti = vtsub.add_parser("import", help="take the drivers from a virtio-win ISO you downloaded")
    vti.add_argument("path")

    vw = sub.add_parser("viewer", help="the browser console viewer (noVNC), fetched at bootstrap")
    vwsub = vw.add_subparsers(dest="viewcmd", metavar="<op>")
    vwsub.add_parser("status", help="is the viewer fetched")
    vwf = vwsub.add_parser("fetch", help="fetch (or re-verify) the pinned viewer files")
    vwf.add_argument("--refresh", action="store_true", help="re-download every file")

    wn = sub.add_parser("window", help="open a URL in winlab's own program window (what gui starts)")
    wn.add_argument("url")
    wn.add_argument("--fetch", action="store_true", help="fetch the WebView2 loader first")
    wn.add_argument("--no-fallback", action="store_true",
                    help="fail (exit 3) instead of opening an Edge/Chrome window when the native one cannot start")

    up = sub.add_parser("update", help="check whether a newer winlab is published (sends only a version string)")
    up.add_argument("--install", action="store_true",
                    help="download the newer version (licensed copies), check it, and run its installer (Windows)")
    up.add_argument("--auto", choices=("on", "off"), default="",
                    help="check automatically once a day when the desktop starts (licensed copies)")

    pk = sub.add_parser("content-pack", help="the encrypted content packs: build one for a release, or see what this PC opens")
    pksub = pk.add_subparsers(dest="packcmd", metavar="<op>")
    pb = pksub.add_parser("build", help="encrypt the paid content of content/ into a pack")
    pb.add_argument("out", help="the pack file to write, e.g. content/packs/labs-full.wlpack")
    pb.add_argument("--key-hex", default="", help="the 32-byte pack key as 64 hex (else WINLAB_PACK_KEY_LABS_FULL)")
    pb.add_argument("--content", default="", help="the plain content folder (default: this install's content/)")
    pb.add_argument("--pack", default="labs-full", help="pack id (default labs-full)")
    pb.add_argument("--strip", action="store_true",
                    help="delete the plain files that went into the pack (release build only)")
    pksub.add_parser("plan", help="list what goes into labs-full and what stays free")
    pksub.add_parser("status", help="which packs are here and whether this PC opens them")

    ic = sub.add_parser("icon", help="write winlab's own application icon (.ico for the exe build, or a .png)")
    ic.add_argument("path", help="destination: *.ico (every size) or *.png")
    ic.add_argument("--size", type=int, default=256, help="pixels for a .png (default 256)")

    lic = sub.add_parser("license", help="activate and inspect the license")
    licsub = lic.add_subparsers(dest="liccmd", metavar="<op>")
    licsub.add_parser("status", help="show current license state")
    la = licsub.add_parser("activate", help="activate a key against the vendor server")
    la.add_argument("key")
    la.add_argument("--server", default="")
    lo = licsub.add_parser("activate-offline", help="activate from a pasted token (air-gapped)")
    lo.add_argument("token", help="token JSON, or @path to a file")
    licsub.add_parser("refresh", help="re-activate to extend the re-check window")
    ld = licsub.add_parser("deactivate", help="move to another PC: free this PC's seat on the site and remove the license here")
    ld.add_argument("--local", action="store_true", help="only remove the license here (offline; the seat stays taken)")
    licsub.add_parser("fingerprint", help="print this machine's id for offline activation")

    if edition.is_core():
        # winlab core has only its own commands (winlab/edition.py).
        sub._choices_actions[:] = [a for a in sub._choices_actions if edition.keeps_command(a.dest)]
        for name in [n for n in sub.choices if not edition.keeps_command(n)]:
            del sub.choices[name]
        p.description = "winlab core: a portable, isolated Windows Server lab (one lab, its lessons and drills)."
    return p


def cmd_doctor(bundle: str | None = None) -> int:
    paths.ensure_dirs()
    report = hostprobe.probe()
    text = hostprobe.render(report)
    print(text)
    if bundle is not None:
        from . import support
        try:
            b = support.make_bundle(bundle or None, doctor=text)
        except OSError as exc:
            print(f"support file not written: {exc}", file=sys.stderr)
            return 3
        print()
        print(support.render(b))
    return 1 if report.blockers else 0


def cmd_setup(lab_name: str, check_only: bool) -> int:
    """The desktop's Setup window in the console: the PC checklist, then
    Get everything ready, then what only the student can do."""
    from . import readiness, webui
    paths.ensure_dirs()
    report = hostprobe.probe()
    items = readiness.checks(report)
    print("This PC\n" + readiness.render(items) + "\n")
    try:
        dash = webui.Dashboard(schema.load(lab_name or webui.default_lab()), accel=report.accel)
    except LabError as exc:
        print(f"setup: {exc}", file=sys.stderr)
        return 2
    if not check_only:
        print(f"Getting lab '{dash.lab.name}' ready (downloads happen once; Ctrl+C stops, "
              f"running it again carries on)\n")
        try:
            dash.stream_get_ready(
                lambda line: None if line.startswith(webui.PCT_LINE) else print(f"  {line}", flush=True))
        except Exception as exc:  # noqa: BLE001 every step raises its own error type
            print(f"\nsetup stopped: {exc}", file=sys.stderr)
            return 3
        print()
    st = dash.setup_state(quick=True)
    need = [m for m in st["media"] if m["needed"]]
    for m in need:
        print(f"Windows from Microsoft: {m['title']} ({', '.join(m['who'])} boot from it)\n"
              f"  1. download the free evaluation ISO: {m['page']}\n"
              f"  2. winlab images import {m['image']} <the .iso you downloaded>\n"
              f"  3. winlab setup {dash.lab.name}   (prepares its base, about 45 minutes)\n")
    found = readiness.find_isos() if need else []
    for f in found:
        if any(m["image"] in f["fits"] for m in need):
            fit = next(m["image"] for m in need if m["image"] in f["fits"])
            print(f"  found on this PC: winlab images import {fit} \"{f['path']}\"")
    left = [s_ for s_ in st["steps"] if not s_["done"] and s_["id"] != "up"]
    if not left:
        print(f"Ready. Open winlab (or: winlab lab up {dash.lab.name}).")
    return 0 if not left else 1


def cmd_lab_down_all() -> int:
    labs = state.known_labs()
    for name in labs:
        cmd_lab_down(name)
    if not labs:
        print("no running lab")
    return 0


def cmd_bootstrap(plan_only: bool, refresh: bool, keep: bool) -> int:
    from . import bootstrap as bs

    try:
        if plan_only:
            db = bs.load_db(refresh=refresh)
            closure = bs.resolve(db, bs.ROOT_PACKAGES)
            total = sum(p.csize for p in closure)
            print(f"roots: {', '.join(bs.ROOT_PACKAGES)}")
            print(f"closure: {len(closure)} packages, {total / (1024 ** 2):.0f} MiB compressed\n")
            for p in closure:
                print(f"  {p.name:<46} {p.version:<22} {p.csize / 1024:>8.0f} KiB")
            return 0
        bs.bootstrap(refresh=refresh, keep_downloads=keep)
        return 0
    except bs.BootstrapError as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return 3


def _pairs(items: list[str], what: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        key, sep, val = item.partition("=")
        if not sep or not key.strip():
            raise ValueError(f"--{what} takes KEY=NAME, not {item!r}")
        out[key.strip()] = val.strip()
    return out


def _print_names(lab) -> None:
    from . import naming
    v = naming.as_lab_names(lab)
    if v["has_domain"]:
        print(f"  domain        {v['domain']}  (NetBIOS {v['netbios']})")
    print(f"  file share    {v['share']}")
    for s in v["sites"]:
        print(f"  site          {s['name']}" + (f"  (key {s['key']})" if s["name"] != s["key"] else ""))
    for s in v["scopes"]:
        print(f"  DHCP scope    {s['network']}: {s['name']}")
    for m in v["machines"]:
        print(f"  machine       {m['id']:<12} {m['name']}")


def cmd_lab_set(args) -> int:
    from . import editor
    try:
        lab = editor.load_for_edit(args.lab)
        naming_args = (args.domain, args.netbios, args.share)
        if args.lean is None and all(a is None for a in naming_args) \
                and not args.site and not args.scope:
            print(f"{lab.name}: Low-memory profile {'on' if lab.lean else 'off (stock Windows)'}")
            _print_names(lab)
            return 0
        if args.lean is not None:
            editor.set_lab_lean(lab, args.lean == "on")
        changed = editor.set_lab_names(
            lab, domain=args.domain, netbios=args.netbios, share=args.share,
            sites=_pairs(args.site, "site"), scopes=_pairs(args.scope, "scope"))
        editor.save(lab)
        if args.lean is not None:
            print(f"{lab.name}: Low-memory profile {args.lean}; every Windows machine picks it up at "
                  f"its next configuration (winlab lab up)")
        if changed:
            print(f"{lab.name}: {', '.join(changed)}. The lessons and their checks use the new "
                  f"names; running machines take them at their next Configure.")
        return 0
    except (editor.EditError, editor.LabError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_netfile(args) -> int:
    from . import netfile
    try:
        if args.labcmd == "open":
            lab = netfile.open_bytes(Path(args.file).expanduser().read_bytes(), args.as_name)
            print(f"opened as lab '{lab.name}' ({len(lab.nodes)} machines): winlab lab up {lab.name}")
            return 0
        lab = schema.load(args.lab)
        if args.labcmd == "save":
            print(f"saved {netfile.save(lab, args.dest)}")
        elif args.labcmd == "versions":
            if args.save is not None:
                pt = netfile.savepoint(lab, args.save)
                print(f"saved version {pt['id']}")
            for p in netfile.savepoints(lab.name):
                print(f"{p['id']}  {p['machines']} machines  {p['note']}")
        else:
            st = state.load(lab.name)
            netfile.restore(lab, args.version, bool(st and st.running()))
            print(f"{lab.name} is back at version {args.version}; what you had is a version too")
        return 0
    except (netfile.NetFileError, LabError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_lab_history(args) -> int:
    from . import history
    try:
        lab = schema.load(args.lab)
        if args.labcmd == "history":
            print(history.render(lab.name, args.device, args.limit))
            return 0
        r = history.step(history.Bench(lab), back=args.labcmd == "undo")
        print(r["message"])
        return 0
    except (history.HistoryError, LabError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_media(args) -> int:
    from . import editor, media
    from .hardware import HardwareError
    try:
        lab = editor.load_for_edit(args.lab)
        node = lab.nodes.get(args.node)
        if node is None:
            print(f"no such node '{args.node}' in {lab.name}", file=sys.stderr)
            return 2
        if args.mediacmd == "drivers":
            files = media.driver_files(node.image)
            if len(files) <= 1:
                print("no drivers on this PC yet: winlab virtio fetch (and put your own packages "
                      "under images/drivers)", file=sys.stderr)
                return 1
            r = media.plug(lab.name, node.id, files, media.STICK_LABEL_DRIVERS)
        elif args.mediacmd == "pack":
            from . import debpacks, roles
            pack = debpacks.PACKS.get(args.pack)
            if pack is None or pack.image != node.image:
                print(f"no package stick '{args.pack}' for {node.id} ({node.image}): see winlab packs list",
                      file=sys.stderr)
                return 2
            try:
                files = debpacks.pack_files(pack.id)
            except debpacks.PackError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            for role_name in pack.roles:
                files.update(roles.role_stick_files(lab, node, role_name))
            r = media.plug(lab.name, node.id, files, debpacks.STICK_LABEL)
            from . import openwisp, unifi
            ctl = {unifi.PACK: unifi, openwisp.PACK: openwisp}.get(pack.id)
            if ctl is not None and ctl.mark(node):   # the controller's page beside the machine
                editor.save(lab)
        elif args.mediacmd in ("plug", "unplug", "insert", "eject", "list", "boot", "burn"):
            return _media_shelf(args, lab, node)
        elif args.mediacmd == "blank":
            r = media.plug_blank(lab.name, node.id, args.gb)
            print(f"a blank {args.gb} GB stick plugged in"
                  + ("" if r["live"] else " (the machine is off: it is in the port at the next start)"))
            return 0
        elif args.mediacmd in ("pull", "back", "new-disk"):
            from . import hardware
            i = args.bay - 1
            if args.mediacmd == "pull":
                live = hardware.pull(lab.name, node, i)
                print(f"bay {args.bay} pulled" + (": the disk stops answering now" if live
                                                   else "; it is empty at the next start"))
            elif args.mediacmd == "back":
                hardware.put_back(lab.name, node, i)
                print(f"the disk is back in bay {args.bay}, with its data")
            else:
                from . import disks
                disks.replace(lab.name, node, i)  # a new drive: its own serial number
                print(f"a new blank {node.data_disks_gb[i]} GB disk in bay {args.bay}")
            return 0
        else:
            st = media.status(lab.name, node.id)
            print(f"stick: {'plugged in, ' + str(st['stick_mb']) + ' MB' if st['stick'] else 'none'}")
            print(f"disc:  {node.vars.get('iso') or 'none'}")
            from . import disks
            for b in disks.status(lab.name, node):
                print(f"bay {b['bay']}: {b['gb']} GB {b['bus_title']} data disk"
                      f"{', pulled out' if b['pulled'] else ', failing' if b['failing'] else ''}")
            print(f"your packages (images/drivers): {', '.join(st['packages']) or 'none'}")
            return 0
        print(f"stick plugged in: {r['files']} files, {r['size_mb']} MB"
              + ("" if r["live"] else " (the machine is off: it is in the port at the next start)"))
        return 0
    except (editor.EditError, media.MediaError, editor.LabError, HardwareError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_terminal(args) -> int:
    """winlab terminal <lab> <node> <line>: one line typed into the machine's
    serial console (the loopback socket behind its Terminal window), then
    what it answers. The Terminal window itself must be closed: the console
    takes one connection at a time."""
    import re as _re
    import socket
    import time as _time

    from . import state as _state
    st = _state.load(args.lab)
    ns = st.nodes.get(args.node) if st else None
    port = getattr(ns, "term_port", 0) if ns else 0
    if not ns or not port or not _state.pid_alive(ns.pid):
        print(f"error: {args.node} is not running or has no Terminal window", file=sys.stderr)
        return 1
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    except OSError as exc:
        print(f"error: {args.node}'s console does not answer ({exc}): close its Terminal window", file=sys.stderr)
        return 1
    out = b""
    with sock:
        sock.sendall(args.line.encode("utf-8") + b"\r")
        want = _re.compile(args.expect) if args.expect else None
        end = _time.monotonic() + (args.timeout if want else max(args.wait, 0.1))
        sock.settimeout(0.5)
        while _time.monotonic() < end:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                chunk = b""
            except OSError:
                break
            if chunk:
                out += chunk
                if want and want.search(out.decode("utf-8", "replace")):
                    break
    text = out.decode("utf-8", "replace")
    print(text)
    if want and not want.search(text):
        print(f"error: {args.expect!r} did not show within {args.timeout:g} s", file=sys.stderr)
        return 1
    return 0


def cmd_workbench(args) -> int:
    """winlab workbench <lab> <action> key=value...: one Workbench action, as
    the desktop runs it (workbench.act, consolecable.act)."""
    from . import consolecable, netplan, schema, workbench

    params: dict = {}
    for kv in args.params:
        if "=" not in kv:
            print(f"error: {kv!r} is not key=value", file=sys.stderr)
            return 2
        k, v = kv.split("=", 1)
        params[k] = v

    class _Bench:
        def __init__(self):
            self.wb_live = workbench.Live()
            self.reload()

        def reload(self):
            self.lab = schema.load(args.lab)
            self.plan = netplan.compile_topology(self.lab, check_ports=False)

    try:
        bench = _Bench()
    except schema.LabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.action.startswith("con-"):
        r = consolecable.act(bench, args.action, params)
    elif args.action.startswith("wb-"):
        r = workbench.act(bench, args.action, params)
    else:
        print("error: a Workbench action starts with wb- or con-", file=sys.stderr)
        return 2
    print(r.get("message", ""))
    return 0 if r.get("ok", True) else 1


def _media_shelf(args, lab, node) -> int:
    """winlab media insert|eject|plug|unplug|list|boot|burn: the media shelf."""
    from . import mediashelf as ms
    off = " (the machine is off: it is there at power-on)"
    try:
        if args.mediacmd == "list":
            for line in ms.describe(lab.name, node):
                print(line)
            print("\ndiscs on the shelf:")
            for d in ms.view(lab, set()).get("discs", []):
                where = f"  in {', '.join(d['in'])}" if d["in"] else ""
                print(f"  {d['ref'].split(':', 1)[1] if d['ref'].startswith('image:') else Path(d['ref'][5:]).stem:<20} "
                      f"{d['title']} ({d['kind']}{', ' + str(d['mb']) + ' MB' if d['mb'] else ''}){where}")
            print("sticks on the shelf:")
            for s in ms.sticks(lab.name) or [{"id": "", "title": "none", "mb": 0}]:
                print(f"  {s['id']:<20} {s['title']}" + (f" ({s['mb']} MB)" if s["mb"] else ""))
            return 0
        if args.mediacmd == "boot":
            ms.set_boot(lab.name, node, args.first)
            print(f"{node.id} boots from its {'DVD drive, then its disk' if args.first == 'dvd' else 'disk'}"
                  " from its next power-on")
            return 0
        if args.mediacmd in ("insert", "burn"):
            ref = (ms.burn(lab.name, args.folder, args.label)["ref"] if args.mediacmd == "burn"
                   else ms.find_disc(lab.name, args.image))
            r = ms.insert(lab, node.id, ref, (args.drive - 1) if getattr(args, "drive", 0) else None)
            print(f"{r['title']} is in DVD drive {r['drive'] + 1}" + ("" if r["live"] else off))
            return 0
        if args.mediacmd == "eject":
            r = ms.eject(lab, node.id, args.drive - 1)
            print(f"{r['title']} ejected, back on the shelf" if r else "the drive was empty")
            return 0
        if args.mediacmd == "unplug":
            r = ms.unplug(lab, node.id, args.port - 1)
            print(f"{r['title']} pulled out, back on the shelf as {r['id']}" if r else "no stick in that port")
            return 0
        stick = args.folder
        if stick not in {s["id"] for s in ms.sticks(lab.name)}:
            stick = ms.new_from_folder(lab.name, args.folder)["id"]
        r = ms.plug(lab, node.id, stick, (args.port - 1) if args.port else None)
        print(f"{r['title']} is in USB port {r['port'] + 1}" + ("" if r["live"] else off))
        return 0
    except ms.ShelfError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def cmd_containers(args) -> int:
    from . import containers

    try:
        if args.ctrcmd == "fetch":
            containers.fetch(args.what, progress=lambda m: print(f"  {m}"))
            print()
        elif args.ctrcmd == "add":
            r = containers.add_image(args.image, "windows" if args.windows else "linux")
            print(f"{r['ref']} ({r['os']}) is on the list: winlab containers fetch images pulls it onto this PC")
            return 0
        elif args.ctrcmd == "remove":
            print(f"{args.image}: {'removed' if containers.remove_image(args.image) else 'was not on your list'}")
            return 0
        elif args.ctrcmd == "stick":
            r = containers.to_stick(args.lab, args.kind, args.image or None)
            print(f"{r['title']} is on {args.lab}'s media shelf as {r['id']} ({r['files']} files, {r['mb']} MB)")
            return 0
        print(containers.render_status())
        return 0
    except containers.ContainerError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_mail(args) -> int:
    from . import mail

    try:
        if args.mailcmd == "fetch":
            mail.fetch(progress=lambda m: print(f"  {m}"))
            print()
        elif args.mailcmd == "stick":
            r = mail.to_stick(args.lab)
            print(f"{r['title']} is on {args.lab}'s media shelf as {r['id']} ({r['files']} files, {r['mb']} MB)")
            return 0
        print(mail.render_status())
        return 0
    except mail.MailError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_netops(args) -> int:
    from . import netops
    if getattr(args, "netopscmd", None) == "fetch":
        errors = netops.fetch(args.what, progress=lambda m: print(f"  {m}"))
        for e in errors:
            print(f"  failed: {e}", file=sys.stderr)
        print()
        print(netops.render_status())
        return 3 if errors else 0
    print(netops.render_status())
    return 0


def cmd_docs(args) -> int:
    from . import doctools, schema

    try:
        if args.docscmd == "fetch":
            errors = doctools.fetch(args.what, progress=lambda m: print(f"  {m}"))
            for e in errors:
                print(f"  failed: {e}", file=sys.stderr)
            print()
            print(doctools.render_status())
            return 3 if errors else 0
        if args.docscmd == "stick":
            r = doctools.to_stick(schema.load(args.lab), args.kind)
            print(f"{r['title']} is on {args.lab}'s media shelf as {r['id']} ({r['files']} files, {r['mb']} MB)")
            return 0
        print(doctools.render_status())
        return 0
    except (doctools.DocsError, schema.LabError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_wireshark(args) -> int:
    from . import wireshark

    try:
        if args.wscmd == "fetch":
            wireshark.fetch(progress=lambda m: print(f"  {m}"))
            print()
        elif args.wscmd == "stick":
            r = wireshark.to_stick(args.lab)
            print(f"{r['title']} is on {args.lab}'s media shelf as {r['id']} ({r['files']} files, {r['mb']} MB)")
            return 0
        print(wireshark.render_status())
        return 0
    except wireshark.WiresharkError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_databases(args) -> int:
    from . import databases

    try:
        if args.dbcmd == "fetch":
            databases.fetch(args.client, progress=lambda m: print(f"  {m}"))
            print()
        elif args.dbcmd == "stick":
            r = databases.to_stick(args.lab)
            print(f"{r['title']} is on {args.lab}'s media shelf as {r['id']} ({r['files']} files, {r['mb']} MB)")
            return 0
        print(databases.render_status())
        return 0
    except databases.DatabaseError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_webmin(args) -> int:
    from . import webmin

    try:
        if args.wmcmd == "fetch":
            webmin.fetch_onto_volume(progress=lambda m: print(f"  {m}"))
        s = webmin.summary()
        print(f"webmin {s['version']} ({s['license']}): " + (f"ready, fetched {s['fetched']}" if s["ready"]
              else f"not fetched ({webmin.SIZE_TEXT}); then: winlab webmin fetch"))
        print(f"  store: {webmin.store()}")
        return 0
    except webmin.WebminError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_routing(args) -> int:
    from . import routing, schema

    try:
        if args.routecmd == "fetch":
            routing.fetch(progress=lambda m: print(f"  {m}"), refresh=args.refresh)
            print()
            print(routing.render_status())
            return 0
        lab = schema.load(args.lab) if getattr(args, "lab", "") else None
        print(routing.render_status(lab))
        return 0
    except routing.RoutingError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3
    except schema.LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2


def cmd_aws(args) -> int:
    from . import aws

    try:
        if args.awscmd == "fetch":
            aws.fetch(progress=lambda m: print(f"  {m}"))
            print()
        print(aws.render_status())
        return 0
    except aws.AwsError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_azure(args) -> int:
    from . import azure

    try:
        if args.azcmd == "fetch":
            azure.fetch(progress=lambda m: print(f"  {m}"))
            print()
        elif args.azcmd == "log":
            p = azure.log_path(args.lab)
            lines = p.read_text(encoding="utf-8").splitlines() if p.is_file() else []
            print("\n".join(lines[-args.n:]) if lines else
                  f"nothing built in {args.lab} yet: what you create in the portal shows here once the lab runs")
            return 0
        print(azure.render_status())
        return 0
    except azure.AzureError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_ids(args) -> int:
    from . import ids

    try:
        if args.idscmd == "fetch":
            say = lambda m: print(f"  {m}")  # noqa: E731
            if args.rules_only:
                ids.fetch(progress=say)
            else:
                ids.fetch_all(progress=say, refresh=args.refresh)
            print()
        elif args.idscmd == "stick":
            r = ids.to_stick(args.lab)
            print(f"{r['title']} is on {args.lab}'s media shelf ({r['files']} files, {r['mb']} MB): "
                  f"plug it into the sensor")
            return 0
        print(ids.render_status())
        return 0
    except ids.IdsError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_webproxy(args) -> int:
    from . import webproxy

    try:
        if args.wpxcmd == "fetch":
            webproxy.fetch(progress=lambda m: print(f"  {m}"), refresh=args.refresh)
            print()
        print(webproxy.render_status())
        return 0
    except webproxy.WebProxyError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_ipv6(args) -> int:
    from . import ipv6, schema

    try:
        if args.v6cmd == "fetch":
            ipv6.fetch(progress=lambda m: print(f"  {m}"), refresh=args.refresh)
            print()
            print(ipv6.render_status())
            return 0
        lab = schema.load(args.lab) if getattr(args, "lab", "") else None
        print(ipv6.render_status(lab))
        return 0
    except ipv6.Ipv6Error as exc:
        print(f"{exc}", file=sys.stderr)
        return 3
    except schema.LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2


def cmd_softphone(args) -> int:
    from . import softphone

    try:
        if args.spcmd == "fetch":
            softphone.fetch(progress=lambda m: print(f"  {m}"))
            print()
        elif args.spcmd == "stick":
            r = softphone.to_stick(args.lab)
            print(f"{r['title']} is on {args.lab}'s media shelf as {r['id']} ({r['files']} files, {r['mb']} MB)")
            return 0
        print(softphone.render_status())
        return 0
    except softphone.SoftphoneError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_remoteaccess(args) -> int:
    from . import remoteaccess

    try:
        if args.racmd == "fetch":
            remoteaccess.fetch(args.what, progress=lambda m: print(f"  {m}"), refresh=args.refresh)
            print()
        elif args.racmd == "stick":
            r = remoteaccess.to_stick(args.lab)
            print(f"{r['title']} is on {args.lab}'s media shelf as {r['id']} ({r['files']} files, {r['mb']} MB)")
            return 0
        print(remoteaccess.render_status())
        return 0
    except remoteaccess.RemoteAccessError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_automation(args) -> int:
    from . import automation

    try:
        if args.autcmd == "fetch":
            automation.fetch(progress=lambda m: print(f"  {m}"), refresh=args.refresh)
            print()
        elif args.autcmd == "stick":
            r = automation.to_stick(args.lab)
            print(f"{r['title']} is on {args.lab}'s media shelf as {r['id']} ({r['files']} files, {r['mb']} MB)")
            return 0
        print(automation.render_status())
        return 0
    except automation.AutomationError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_packs(args) -> int:
    from . import debpacks

    try:
        if args.packcmd == "fetch":
            debpacks.fetch(args.pack, progress=lambda m: print(f"  {m}"), refresh=args.refresh)
            print()
        print(debpacks.render_status())
        return 0
    except debpacks.PackError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_exporter(args) -> int:
    from . import exporters

    try:
        if args.expcmd == "fetch":
            exporters.fetch(progress=lambda m: print(f"  {m}"))
            print()
        print(exporters.render_status())
        return 0
    except exporters.ExporterError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_wac(args) -> int:
    from . import wac

    try:
        if args.waccmd == "fetch":
            wac.fetch(progress=lambda m: print(f"  {m}"))
            print()
        print(wac.render_status())
        return 0
    except wac.WacError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_virtio(args) -> int:
    from . import virtio

    try:
        if args.virtcmd == "fetch":
            virtio.fetch(refresh=args.refresh, keep_iso=args.keep_iso)
        elif args.virtcmd == "import":
            virtio.import_iso(args.path)
        print(virtio.render_status())
        return 0
    except virtio.VirtioError as exc:
        print(f"{exc}", file=sys.stderr)
        return 3


def cmd_images(args) -> int:
    from . import images

    try:
        if args.imgcmd in (None, "list"):
            print(images.render_status())
            return 0
        if args.imgcmd == "fetch":
            dest = images.fetch(args.image)
            print(f"\n  {args.image}: {dest}")
            return 0
        if args.imgcmd == "import":
            dest = images.import_media(args.image, args.path)
            print(f"\n  {args.image}: {dest}")
            return 0
        if args.imgcmd == "add":
            entry = images.add_custom(args.image, args.path, title=args.title,
                                      firmware=args.firmware, disk_gb=args.disk_gb)
            print(f"\n  {entry.id}: {entry.iso}\n  use it with: winlab node <lab> add "
                  f"<name> --kind custom --image {entry.id}")
            return 0
        if args.imgcmd == "rm":
            images.remove_custom(args.image)
            print(f"removed {args.image}")
            return 0
        if args.imgcmd == "prepare":
            from . import prepare

            try:
                if args.image == "fabric":
                    prepare.prepare_fabric()
                elif images.CATALOG.get(args.image) and images.CATALOG[args.image].kind == "linux-installer":
                    print(f"{args.image} is a Linux installer DVD: a machine boots it and you install "
                          f"by hand, so there is no base to prepare. Get it with: winlab images fetch "
                          f"{args.image}", file=sys.stderr)
                    return 4
                elif images.is_media(args.image):
                    how = images.CATALOG[args.image].get or f"winlab images import {args.image} <file.iso>"
                    print(f"{args.image} is installation media a role installs from inside a "
                          f"machine; there is no base to prepare. Get it with: {how}", file=sys.stderr)
                    return 4
                else:
                    prepare.prepare_windows(
                        args.image, size_gb=args.size, headless=not args.windowed,
                        compress=not args.no_compress, keep_iso=args.keep_iso,
                        virtio=not args.no_virtio,
                    )
                return 0
            except prepare.PrepareError as exc:
                print(f"{exc}", file=sys.stderr)
                return 4
    except images.ImageError as exc:
        print(f"{exc}", file=sys.stderr)
        return 4
    print("usage: winlab images {list,fetch,import}", file=sys.stderr)
    return 2


def cmd_lab_export(args) -> int:
    from . import transfer

    try:
        lab = schema.load(args.lab)
        transfer.export_lab(lab, args.folder, thin=args.thin, compress=args.compress)
        return 0
    except (LabError, transfer.TransferError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 4


def cmd_lab_import(args) -> int:
    from . import transfer

    try:
        if args.show:
            print(transfer.describe_export(Path(args.folder).expanduser()))
            return 0
        lab = transfer.import_lab(args.folder, new_name=args.as_name)
        print(f"\nopen it: winlab gui {lab.name}")
        return 0
    except (LabError, transfer.TransferError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 4


def cmd_template(args) -> int:
    from . import images, templates

    try:
        if args.tplcmd in (None, "list"):
            tpls = images.templates()
            if not tpls:
                print("no templates yet. Make one from a stopped machine:\n"
                      "  winlab template create <lab> <machine> <name>")
                return 0
            for t in tpls.values():
                print(f"  {t.id:<14} {t.title}")
                print(f"  {'':<14} {templates.describe(t)}")
                print(f"  {'':<14} {t.cpus} vCPU, {t.memory_mb} MB, {t.disk_gb} GB disk"
                      + (f", data disks {t.data_disks_gb}" if t.data_disks_gb else ""))
            print("\nuse one with: winlab node <lab> add <name> --image <template>")
            return 0
        if args.tplcmd == "rm":
            images.remove_template(args.name)
            print(f"removed {args.name}")
            return 0
        if args.tplcmd == "create":
            lab = schema.load(args.lab)
            t = templates.create(lab, args.node, args.name, title=args.title,
                                 generalize_=False if args.no_generalize else None,
                                 full=args.full, accel=args.accel)
            print(f"\n  {t.id}: {t.disk}")
            return 0
    except (images.ImageError, templates.TemplateError, LabError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 4
    print("usage: winlab template {list,create,rm}", file=sys.stderr)
    return 2


def cmd_lab_diagram(target: str, out: str) -> int:
    from . import drawio

    try:
        lab = schema.load(target)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    plan = netplan.compile_topology(lab, check_ports=False)
    dest = Path(out) if out else paths.VAR / f"{lab.name}{drawio.EXT}"
    if dest.suffix.lower() != drawio.EXT:
        dest = dest.with_suffix(drawio.EXT)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(drawio.dumps(plan), encoding="utf-8")
    print(f"{dest}")
    return 0


def cmd_lab_up(target: str, dry_run: bool, accel: str, display: str,
               only: list[str] | None = None, force: bool = False) -> int:
    from . import hostprobe, membudget
    from .providers.qemu import QemuProvider, render_commands

    try:
        lab = schema.load(target)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    if not accel:
        accel = hostprobe.probe().accel

    if dry_run:
        plan = netplan.compile_topology(lab, check_ports=False)
        try:
            ids, _ = membudget.with_dependencies(lab, only or [n.id for n in lab.node_list()])
        except membudget.BudgetError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
        b = membudget.plan(lab, ids, plan.fabric_memory_mb, hostprobe.available_ram_mb())
        membudget.apply(lab, b)
        provider = QemuProvider(plan, accel=accel, display=display)
        runtimes = provider.build_all()
        print(netplan.describe(plan))
        print(f"\naccelerator {accel}, display {display}\n")
        print(render_commands({k: v for k, v in runtimes.items()
                               if k == "fabric" or k in ids}))
        print(f"memory: {', '.join(ids)} + fabric need {membudget.gib(b.need_mb)}"
              f"{'' if b.trimmed else ' as defined'}; "
              f"{membudget.gib(b.avail_mb)} free now")
        for line in membudget.explain(lab, b):
            print(line)
        print(
            "dry run: nothing was booted. `winlab lab up` without --dry-run needs "
            "prepared images (winlab images list)."
        )
        return 0

    from . import images
    from .orchestrator import Orchestrator, OrchestratorError

    try:
        orch = Orchestrator(lab, accel=accel, display=display)
        report, budget = orch.budgeted_up(only=only, force=force,
                                          emit=lambda line: print(f"  {line}"))
    except (OrchestratorError, membudget.BudgetError, images.ImageError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 5

    for line in membudget.explain(lab, budget):
        print(line)
    for nid in report.skipped:
        print(f"  already  {nid}")
    if report.resumed:
        print(f"  {', '.join(report.resumed)}: resuming from hibernation")
    print(f"\nlab '{lab.name}' up on {accel}. `winlab lab status {lab.name}` to watch, "
          f"`winlab console <node>` to open a screen.")
    print(f"log on as Administrator with: {lab.admin_password}"
          f"  (`winlab lab password {lab.name}` shows it again)")
    for nid, why in report.failed.items():
        print(f"  {nid} did not start: {why}", file=sys.stderr)
    return 6 if report.failed else 0


def cmd_lab_suspend(target: str, only: list[str] | None) -> int:
    from .orchestrator import OrchestratorError, open_lab

    st = state.load(target)
    try:
        orch = open_lab((st.source_path if st else "") or target,
                        accel=(st.accel if st else "tcg"))
        rep = orch.suspend(only=only or None, emit=lambda line: print(f"  {line}"))
    except (LabError, OrchestratorError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    if rep.saved:
        print(f"saved: {', '.join(rep.saved)} (memory kept; they carry on where they were)")
    if rep.hibernated:
        print(f"hibernated: {', '.join(rep.hibernated)} (they resume where they were)")
    if rep.shut_down:
        print(f"shut down cleanly: {', '.join(rep.shut_down)} (no agent, so no hibernation)")
    if rep.powered_off:
        print(f"powered off after the timeout: {', '.join(rep.powered_off)}")
    for node_id, why in rep.failed.items():
        print(f"{node_id} is still running: {why}", file=sys.stderr)
    if rep.skipped:
        print(f"not running: {', '.join(rep.skipped)}")
    print(f"`winlab lab resume {orch.lab.name}` brings the lab back.")
    return 1 if rep.failed else 0


def cmd_lab_reload(target: str) -> int:
    """Power-cycles the lab's router and switches under running machines."""
    from .orchestrator import OrchestratorError, open_lab

    st = state.load(target)
    try:
        orch = open_lab((st.source_path if st else "") or target, accel=(st.accel if st else "tcg"),
                        display=(st.display if st else "window"))
        rep = orch.restart_fabric(emit=lambda line: print(f"  {line}"))
    except (LabError, OrchestratorError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    print(f"{orch.lab.name}: router and switches restarted"
          + (f"; {len(rep['machines'])} machine(s) kept running" if rep["machines"] else ""))
    return 0 if rep["redial"] or not rep["machines"] else 1


def cmd_lab_password(target: str) -> int:
    try:
        lab = schema.load(target)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    print(lab.admin_password)
    return 0


def cmd_lab_down(target: str) -> int:
    from .orchestrator import open_lab

    name = target or (state.known_labs()[0] if state.known_labs() else "")
    if not name:
        print("no running lab found", file=sys.stderr)
        return 1
    st = state.load(name)
    source = st.source_path if st else name
    try:
        orch = open_lab(source, accel=(st.accel if st else "tcg"))
    except LabError:
        # Definition changed or gone; fall back to killing by recorded pid.
        if st:
            for ns in st.nodes.values():
                if ns.pid:
                    from .orchestrator import _kill

                    _kill(ns.pid)
            state.clear(name)
            print(f"stopped lab '{name}' (by recorded pids)")
            return 0
        print(f"no state for lab '{name}'", file=sys.stderr)
        return 1
    stopped = orch.down()
    print(f"stopped lab '{name}': {', '.join(stopped) if stopped else 'nothing running'}")
    return 0


def cmd_lab_status(target: str) -> int:
    names = [target] if target else state.known_labs()
    if not names:
        print("no labs have been started")
        return 0
    for name in names:
        st = state.load(name)
        if not st:
            print(f"{name}: no state")
            continue
        running = st.running()
        print(f"{name}  ({st.accel}, {len(running)}/{len(st.nodes)} running)")
        from .procstats import sample

        for nid, ns in st.nodes.items():
            up = bool(ns.pid and state.pid_alive(ns.pid))
            alive = "up  " if up else ("susp" if ns.phase == state.SUSPENDED else "down")
            use = sample(ns.pid) if up else None
            cost = f"  {use.rss_mb} MB, cpu {use.cpu_seconds:.0f}s" if use else ""
            print(f"  [{alive}] {nid:<10} pid {ns.pid or '-':<8} "
                  f"qmp/{ns.qmp_port} serial/{ns.serial_port}  {ns.phase}{cost}")
    return 0


def cmd_break(args) -> int:
    from . import guestfaults
    from . import roles as roles_mod

    if not args.node or not args.scenario:
        print(guestfaults.render_catalog())
        return 0
    if args.scenario not in guestfaults.SCENARIOS:
        print(f"unknown scenario '{args.scenario}'. Run 'winlab break' to list them.",
              file=sys.stderr)
        return 2

    try:
        lab = _resolve_lab(args.lab)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    try:
        lab_def = schema.load(lab)
    except Exception:  # noqa: BLE001 - the running state decides below
        lab_def = None
    # The lab's own values first (its domain, DC, scope), then the user's --param.
    params = guestfaults.lab_params(lab_def) if lab_def is not None else {}
    for kv in args.param:
        if "=" in kv:
            k, v = kv.split("=", 1)
            params[k] = v
    if args.hint:
        try:
            print(f"hint {args.hint}: {guestfaults.hint(args.scenario, args.hint, params)}")
        except IndexError:
            print(f"hints go from 1 to {len(guestfaults.SCENARIOS[args.scenario].hints)}", file=sys.stderr)
            return 2
        return 0
    f = guestfaults.SCENARIOS[args.scenario]
    w = guestfaults.words(args.scenario, params)
    node_def = lab_def.nodes.get(args.node) if lab_def is not None else None
    if node_def is not None and not guestfaults.applies_to(f, node_def.kind, node_def.image):
        where = ", ".join(f.images) if f.images else f.os
        print(f"'{w['title']}' is a problem for {where} machines; {args.node} is "
              f"{node_def.kind} ({node_def.image or 'no image'})", file=sys.stderr)
        return 2
    if node_def is not None and not guestfaults.applies_to(f, node_def.kind, node_def.image,
                                                           roles_mod.effective_roles(node_def)):
        print(f"'{w['title']}' needs a machine with the {' or '.join(f.roles)} role; "
              f"{args.node} has none of them", file=sys.stderr)
        return 2

    ns = state.load(lab)
    node_state = ns.nodes.get(args.node) if ns else None
    if not node_state or not state.pid_alive(node_state.pid):
        print(f"{args.node} is not running", file=sys.stderr)
        return 5

    from . import problemengine
    from . import progress
    verb = "verifying" if args.verify else "fixing" if args.clear else "breaking"
    print(f"{verb}: {w['title']} on {args.node}")
    if f.host and not args.verify:
        # Broken from outside the machine (a checkpoint reverted); the verify runs inside.
        ok, msg = guestfaults.host_break(args.scenario, lab, args.node, args.clear, say=lambda s: print(f"  {s}"))
        print(msg, file=sys.stdout if ok else sys.stderr)
        if ok and not args.clear:
            print(f"symptom: {w['symptom']}")
            print(f"stuck? winlab break {args.node} {args.scenario} --hint 1")
        return 0 if ok else 1
    run = problemengine.guest_runner(lab)
    if args.verify:
        res = problemengine.verify_fix(run, lab, args.scenario, args.node, params)
        if res.status not in (problemengine.FIXED, problemengine.NOT_FIXED):
            print(res.message, file=sys.stderr)   # the check never ran: nothing counted
            return 5
        fixed = res.status == problemengine.FIXED
        progress.record_problem(args.scenario, args.node, fixed)
        print("fixed: the problem no longer reproduces" if fixed
              else f"not fixed yet: {args.node} still shows the problem")
        return 0 if fixed else 1
    pe = progress.load()["problems"].get(args.scenario) or {}
    if args.clear:
        res = problemengine.restore(run, lab, args.scenario, args.node, params)
        if res.ok:
            progress.problem_broken(args.scenario, args.node, False)
    else:
        res = problemengine.apply_break(run, lab, args.scenario, args.node, params,
                                        known_broken=pe.get("broken_on") == args.node)
        if res.broken and res.status != problemengine.ALREADY_BROKEN:
            progress.problem_broken(args.scenario, args.node, True)
        elif not res.broken and pe.get("broken_on") == args.node:
            progress.problem_broken(args.scenario, args.node, False)
    print(res.message, file=sys.stdout if res.ok else sys.stderr)
    if res.ok and not args.clear:
        print(f"teaches: {w['teaches']}")
        print(f"stuck? winlab break {args.node} {args.scenario} --hint 1")
    if not res.ok:
        print(f"details: {paths.lab_dir(lab) / 'problems.log'}", file=sys.stderr)
        return 5 if res.status in (problemengine.UNREACHABLE, problemengine.BUSY) else 1
    return 0


def _render_shift(v: dict) -> str:
    if not v.get("tickets"):
        return "no shift running: winlab oncall start [--minutes 45] [--tickets 4]"
    clock = "over" if v["done"] else f"{v['left'] // 60} min left"
    lines = [f"shift on {v['lab']}: {clock}, score {v['summary']['score']}"]
    for t in v["tickets"]:
        head = f"  #{t['n']} {t['status']:<12} {t['caller']} ({t['node']})"
        if t["status"] == "queued":
            lines.append(head)
            continue
        lines.append(head + (f"  {t['points']} pts" if t["status"] != "open" else ""))
        lines.append(f"      \"{t['text']}\"")
        if t.get("was"):
            lines.append(f"      it was: {t['was']}")
    return "\n".join(lines)


def cmd_oncall(args) -> int:
    from . import oncall

    try:
        lab = schema.load(_resolve_lab(args.lab))
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    run = oncall.guest_runner(lab.name)
    shift = oncall.load()
    if args.occmd == "start":
        if shift and shift.get("done"):
            oncall.save(None)
        try:
            shift = oncall.start(lab, oncall.running_nodes(lab), args.minutes, args.tickets, run)
        except RuntimeError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
    elif args.occmd in ("resolve", "escalate", "end"):
        if not shift:
            print("no shift running", file=sys.stderr)
            return 2
        if args.occmd == "resolve":
            fixed, msg = oncall.resolve(shift, run)
            print(msg)
        elif args.occmd == "escalate":
            print(oncall.escalate(shift, run))
        else:
            r = oncall.end(shift, run)
            print(f"shift over: {r['fixed']} of {r['tickets']} fixed, {r['score']} of {r['max']} points")
    elif shift and not shift.get("done"):
        from . import helpdesk
        helpdesk.tick(lab, run)            # the call mailed into the lab's osTicket, what was done there read back
        oncall.check_desk(shift, run)
        oncall.expire(shift, run, oncall._now())
    print(_render_shift(oncall.view(oncall.load())))
    return 0


def cmd_scenario(args) -> int:
    from . import oncall, scenarios

    if args.sccmd in (None, "list"):
        try:
            here = schema.load(_resolve_lab(args.lab)).name
        except LabError:
            here = ""
        print(scenarios.render_list(scenarios.catalog(here)))
        return 0
    st = scenarios.load_state()
    if args.sccmd == "start":
        try:
            scn = scenarios.load(args.id)
            lab = schema.load(scn.lab)
        except (scenarios.ScenarioError, LabError) as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
        if st and st.get("done"):
            scenarios.save_state(None)
        try:
            st = scenarios.start(scn, lab, oncall.running_nodes(lab), oncall.guest_runner(lab.name))
        except scenarios.ScenarioError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
        print(scenarios.render(scenarios.view(st, scn)))
        return 0
    if not st:
        print(scenarios.render({}))
        return 0 if args.sccmd == "status" else 2
    try:
        scn = scenarios.load(st["id"])
        lab = schema.load(st["lab"])
    except (scenarios.ScenarioError, LabError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    run = oncall.guest_runner(lab.name)
    if args.sccmd == "check":
        for r in scenarios.check(st, scn, lab, run):
            print(f"  {'pass' if r['passed'] else 'not yet'}  {r['title']}")
        print()
    elif args.sccmd == "stop":
        if st.get("done"):
            scenarios.save_state(None)
            print("scenario closed")
            return 0
        scenarios.finish(st, scn, lab, run, reason="ended")
    elif scenarios.tick(st, scn, lab, run):
        scenarios.save_state(st)
    print(scenarios.render(scenarios.view(scenarios.load_state(), scn)))
    return 0


def cmd_pki(args) -> int:
    """Read-only probes of the lab CA's certificates in use (winlab/pki.py)."""
    from . import pki
    try:
        lab = schema.load(_resolve_lab(args.lab))
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    res = pki.run_checks(lab, print)
    return 0 if res["total"] and res["ok"] == res["total"] else 1


def cmd_clock(args) -> int:
    from . import labclock

    try:
        lab = schema.load(_resolve_lab(args.lab))
        if args.ckcmd == "skew":
            from . import timesync
            if not args.node:
                print(timesync.render(lab))
                return 0
            if not args.amount:
                print(f"{args.node}: its clock runs {timesync.describe_skew(timesync.skew_of(lab.name, args.node))}")
                return 0
            print(timesync.set_skew(lab, args.node, args.amount))
            return 0
        if args.ckcmd not in (None, "show"):
            print(labclock.change(lab, args.ckcmd, " ".join(getattr(args, "when", []) or []),
                                  emit=print))
    except (LabError, ValueError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    print(labclock.render(lab.name))
    return 0


def _learn_quiz(lesson, answers: str = "", ask=input) -> int:
    from . import lessons, progress

    if not lesson.quiz:
        print(f"{lesson.id} has no recall questions")
        return 0
    view = lessons.quiz_view(lesson)
    given = [a.strip().lower() for a in answers.split(",")] if answers else []
    picked = []
    print(f"{lesson.title}: {len(view)} questions, from memory\n")
    for i, q in enumerate(view):
        print(f"{i + 1}. {q['q']}")
        for j, c in enumerate(q["choices"]):
            print(f"   {chr(97 + j)}) {c}")
        if given:
            a = given[i] if i < len(given) else ""
        else:
            try:
                a = ask("   your answer (letter, Enter skips): ").strip().lower()
            except EOFError:
                a = ""
        k = ord(a[0]) - 97 if a else -1
        picked.append(q["choices"][k] if 0 <= k < len(q["choices"]) else "")
        print()
    r = lessons.grade_quiz(lesson, picked)
    for x in r["results"]:
        mark = "right" if x["ok"] else ("skipped" if not x["picked"] else "wrong")
        print(f"{x['n'] + 1}. {mark}" + ("" if x["ok"] else f": {x['answer']}"))
        if x["why"]:
            print(f"   {x['why']}")
    e = progress.record_quiz(lesson.id, r["right"], r["total"])
    print(f"\n{r['right']} of {r['total']} right (best {e['quiz_best']})")
    return 0


def _learn_review(answers: str = "", only_status: bool = False, ask=input) -> int:
    from . import review

    st = review.status()
    if only_status or not st["today"]:
        print(f"review: {st['questions']} questions from finished lessons, {st['due']} due, "
              f"{st['answered_today']} answered today ({st['right_today']} right)")
        print("boxes (0 = learning, then " + ", ".join(f"{d}d" for d in st["intervals"]) + "): "
              + " ".join(str(n) for n in st["boxes"]))
        if not st["questions"]:
            print("finish a lesson and its recall questions come back here the next day")
        elif not st["today"]:
            print("nothing more to review today" + (f"; next on {st['next']}" if st["next"] else ""))
        return 0
    s = review.todays_set()
    given = [a.strip().lower() for a in answers.split(",")] if answers else []
    picked = {}
    print(f"review: {len(s['items'])} questions today, from memory\n")
    for i, q in enumerate(s["items"]):
        print(f"{i + 1}. [{q['lesson_title']}]\n   {q['q']}")
        for j, c in enumerate(q["choices"]):
            print(f"   {chr(97 + j)}) {c}")
        if given:
            a = given[i] if i < len(given) else ""
        else:
            try:
                a = ask("   your answer (letter, Enter skips): ").strip().lower()
            except EOFError:
                a = ""
        k = ord(a[0]) - 97 if a else -1
        picked[q["key"]] = q["choices"][k] if 0 <= k < len(q["choices"]) else ""
        print()
    r = review.answer(picked)
    for i, x in enumerate(r["results"]):
        if x.get("error"):
            continue
        if x.get("skipped"):
            print(f"{i + 1}. skipped: still due")
            continue
        print(f"{i + 1}. " + (f"right: back on {x['due']}" if x["ok"] else f"wrong, back tomorrow. The answer: {x['answer']}"))
        if x["why"]:
            print(f"   {x['why']}")
    st = r["status"]
    print(f"\n{r['right']} of {r['total']} right; {st['due']} still due, {st['answered_today']} answered today")
    return 0


def cmd_mecm(args) -> int:
    from . import mecm, readiness

    if args.mecmcmd in (None, "status"):
        print(mecm.render_status(mecm.status()))
        return 0
    folders = [Path(f).expanduser() for f in args.folder] or readiness.search_dirs()
    parts = mecm.find_parts(folders)
    for key in ("media", "adk", "winpe", "odbc", "prereqs"):
        val = getattr(args, key)
        if val:
            setattr(parts, "cm" if key == "media" else key, Path(val).expanduser())
    try:
        mecm.prepare(parts, progress=lambda m: print(f"  {m}", flush=True))
    except mecm.MecmError as exc:
        print(exc, file=sys.stderr)
        return 4
    return 0


def cmd_secureboot(args) -> int:
    from . import readiness, secureboot
    op = args.sbcmd or "status"
    if op == "import":
        return secureboot.cli(["import"] + [str(Path(f).expanduser()) for f in args.folder]
                              + ([] if args.folder else [str(d) for d in readiness.search_dirs()]))
    return secureboot.cli([op])


def cmd_office(args) -> int:
    from . import officemedia, readiness

    if args.officecmd in (None, "status"):
        print(officemedia.render_status(officemedia.status(getattr(args, "lab", officemedia.DEFAULT_LAB))))
        return 0
    try:
        if args.officecmd == "xml":
            print(officemedia.download_xml(args.source, args.channel, args.edition, args.language), end="")
            return 0
        folders = [Path(f).expanduser() for f in args.folder] or readiness.search_dirs()
        parts = officemedia.find_parts(folders)
        for key in ("odt", "source", "admx"):
            val = getattr(args, key)
            if val:
                setattr(parts, key, Path(val).expanduser())
        if args.no_admx:
            parts.admx = None
        officemedia.prepare(parts, lab_name=args.lab, channel=args.channel, edition=args.edition,
                            language=args.language, progress=lambda m: print(f"  {m}", flush=True))
    except officemedia.OfficeMediaError as exc:
        print(exc, file=sys.stderr)
        return 4
    print(f"On the {args.lab} shelf: winlab media {args.lab} dep01 insert office")
    return 0


def cmd_usmt(args) -> int:
    from . import readiness, usmtmedia

    if args.usmtcmd in (None, "status"):
        print(usmtmedia.render_status(usmtmedia.status(getattr(args, "lab", usmtmedia.DEFAULT_LAB))))
        return 0
    folders = [Path(f).expanduser() for f in args.folder] or (readiness.search_dirs() + usmtmedia.installed_dirs())
    parts = usmtmedia.find_parts(folders)
    if args.usmt:
        parts.usmt = Path(args.usmt).expanduser()
    if args.adk:
        parts.adk, parts.usmt = Path(args.adk).expanduser(), (parts.usmt if args.usmt else None)
    try:
        usmtmedia.prepare(parts, lab_name=args.lab, progress=lambda m: print(f"  {m}", flush=True))
    except usmtmedia.UsmtMediaError as exc:
        print(exc, file=sys.stderr)
        return 4
    print(f"On the {args.lab} shelf: winlab media {args.lab} dep01 insert usmt")
    return 0


def cmd_learn(args) -> int:
    from . import lessons, progress

    try:
        if args.learncmd in (None, "list"):
            allx = lessons.list_available()
            if not allx:
                print(f"no lessons in {lessons.LESSONS}")
                return 0
            print(progress.render(allx))
            return 0
        if args.learncmd == "show":
            print(lessons.render_brief(lessons.load(args.id)))
            return 0
        if args.learncmd == "answer":
            # Like the Learn window: open after a pass or failed gradings, and kept on the record.
            lesson = lessons.load(args.id)
            e = progress.load()["lessons"].get(lesson.id) or {}
            if e.get("status") != progress.STATUS_DONE and int(e.get("failed") or 0) < 3:
                print("the worked answer opens once the lesson is passed, or after 3 failed gradings",
                      file=sys.stderr)
                return 1
            progress.answer_viewed(lesson.id)
            print(lessons.model_answer(lesson))
            return 0
        if args.learncmd == "start":
            lesson = lessons.load(args.id)
            if not lesson.lab:
                print("the lesson names no lab", file=sys.stderr)
                return 2
            rc = cmd_lab_up(lesson.lab, False, args.accel, args.display,
                            only=lesson.needed_nodes() or None, force=args.force)
            if rc == 0:
                print(f"\n{lessons.render_brief(lesson)}")
            return rc
        if args.learncmd == "quiz":
            return _learn_quiz(lessons.load(args.id), args.answers)
        if args.learncmd == "review":
            return _learn_review(args.answers, args.status)
        if args.learncmd == "check":
            from . import helptopics, practice_exam, scenarios
            problems = lessons.validate_all()
            allx = lessons.list_available()
            print(f"{len(allx)} lessons, {len(problems)} problem(s)")
            for p in problems:
                print(f"  {p}")
            n_tracks, n_q, exam_problems = practice_exam.validate_all()
            print(f"{n_tracks} exam tracks, {n_q} practice questions, {len(exam_problems)} problem(s)")
            for p in exam_problems:
                print(f"  {p}")
            # Scenario days and Help topics are content too: same check.
            more = scenarios.validate_all() + helptopics.validate()
            print(f"{len(scenarios.list_available())} scenarios, {len(helptopics.load_all())} help topics, "
                  f"{len(more)} problem(s)")
            for p in more:
                print(f"  {p}")
            return 1 if problems or exam_problems or more else 0
        if args.learncmd == "scripts":
            written = lessons.write_scripts(Path(args.out))
            print(f"{len(written)} PowerShell snippets written to {args.out}")
            return 0
    except lessons.LessonError as exc:
        print(f"{exc}", file=sys.stderr)
        return 4
    print("usage: winlab learn {list,show,answer,start,quiz,review,check,scripts}", file=sys.stderr)
    return 2


def cmd_exam(args, ask=input, say=print) -> int:
    """Exam prep in the terminal. Practice exams here ask the multiple-choice
    questions; tasks on the lab are asked in the desktop's Exam prep, where
    the running machines are."""
    from . import exams
    from . import practice_exam as pe

    op = args.id
    try:
        if op == "list":
            titles = pe._lesson_titles()
            for e in exams.list_available():
                r = exams.readiness(e, titles=titles)
                n = len(pe.load_bank(e.id).questions) if pe.bank_path(e.id).exists() else 0
                say(f"  {e.id:<22} {e.title}")
                say(f"  {'':<22} readiness {r['overall']}%, {n} practice questions, "
                    f"{e.questions} per exam in {e.minutes} minutes"
                    + (f"; not covered in winlab: {', '.join(r['not_covered'])}" if r["not_covered"] else ""))
            say("\nwinlab exam <track> for readiness, winlab exam start <track> for a practice exam")
            return 0
        if op == "history":
            say(pe.render_history(pe.history(args.track)))
            return 0
        if op == "abandon":
            say("the open practice exam was abandoned" if pe.abandon() else "no practice exam is open")
            return 0
        if op in ("start", "resume"):
            if op == "start":
                if not args.track:
                    say("which track? winlab exam list")
                    return 2
                s = pe.start(args.track, args.questions or None, args.minutes or None)
                say(f"{s['title']}: {len(s['items'])} questions, {s['minutes']} minutes. The clock is running.")
                say("Lab tasks are asked in the desktop's Exam prep, where the machines run; this one is multiple choice.")
            else:
                s = pe.load_session()
                if not s or s.get("done"):
                    say("no practice exam is open: winlab exam start <track>")
                    return 2
            grader = pe.default_grader(s["lab"]) if s.get("lab") else None
            pe.run_terminal(s, ask, say, grader)
            return 0
        say(exams.render(exams.readiness(exams.load(op))))
        return 0
    except (exams.ExamError, pe.PracticeError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 2


def cmd_progress(args) -> int:
    from . import lessons, progress

    if args.progcmd in (None, "show"):
        print(progress.render(lessons.list_available()))
        return 0
    if args.progcmd == "reset":
        progress.reset(args.id)
        print(f"reset {args.id or 'all progress'}")
        return 0
    if args.progcmd in ("export", "import"):
        from . import progressfile
        try:
            if args.progcmd == "export":
                f = progressfile.export(args.file)
                c = progressfile.counts(progressfile.read(f.read_bytes()))
                print(f"wrote {f}: {c['lessons_done']} lessons done, {c['lessons_started']} started, "
                      f"{c['exams']} exam results, {c['certificates']} certificates, notes of {c['notes']} labs")
                print("open it on the other PC: winlab progress import <file>, or Progress > Import in the desktop")
            else:
                print(progressfile.import_file(args.file)["message"])
        except progressfile.ProgressFileError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0
    return 2


def cmd_tracks(args) -> int:
    from . import certificate, certshare, progress, tracks

    if args.trackcmd in (None, "list"):
        print(tracks.render())
        return 0
    name = getattr(args, "name", "") or progress.student()
    try:
        if args.trackcmd == "certificate":
            page, f = certificate.issue(name, args.track)
            out = Path(args.html or f"certificate-{args.track}.html")
            out.write_text(page, encoding="utf-8")
            print(f"wrote {out}: {f['title']}, credential ID {f['code']}")
            return 0
        if args.trackcmd == "share":
            c = certshare.share(args.track, name)
            print(f"shared: {c['url']}")
            return 0
        if args.trackcmd == "withdraw":
            certshare.withdraw(args.track)
            print("the verification link is withdrawn")
            return 0
    except certificate.NotYet as exc:
        print(f"not yet: {exc}", file=sys.stderr)
        return 1
    except (certshare.ShareError, tracks.TrackError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 2


def cmd_viewer(args) -> int:
    from . import castplayer, chartview, drawio, elkview, mapview, pixiview, termview, viewer

    if args.viewcmd in (None, "status"):
        from . import nativewin

        print(viewer.render_status())
        print(termview.render_status())
        print(mapview.render_status())
        print(chartview.render_status())
        print(castplayer.render_status())
        print(elkview.render_status())
        print(drawio.render_status())
        print(pixiview.render_status())
        print(nativewin.render_status())
        return 0 if viewer.ready() and termview.ready() else 1
    if args.viewcmd == "fetch":
        try:
            viewer.fetch(refresh=args.refresh)
            termview.fetch(refresh=args.refresh)
            try:
                mapview.fetch(refresh=args.refresh)
            except mapview.MapViewError as exc:
                print(f"Cytoscape.js not fetched ({exc}); the Network map keeps its VLAN view", file=sys.stderr)
            for part, what in ((chartview, "uPlot"), (castplayer, "asciinema-player"), (elkview, "ELK"),
                               (drawio, "the diagrams.net viewer"), (pixiview, "PixiJS")):
                try:
                    part.fetch(refresh=args.refresh)
                except part.TermError as exc:
                    print(f"{what} not fetched ({exc}); that window keeps its own drawing", file=sys.stderr)
            if sys.platform == "win32":
                from . import nativewin

                try:
                    nativewin.fetch(refresh=args.refresh)
                except (nativewin.NativeWindowError, OSError, ValueError) as exc:
                    print(f"WebView2 loader not fetched ({exc}); Edge window used", file=sys.stderr)
        except (viewer.ViewerError, termview.TermError) as exc:
            print(f"viewer fetch failed: {exc}", file=sys.stderr)
            return 3
        return 0
    return 2


def cmd_window(args) -> int:
    """winlab's own window on a URL, as a process the desktop follows: exit 0
    when the user closed it. When it cannot start, the reason is noted for the
    desktop to show and the Edge/Chrome app window opens in its place (and is
    followed the same way); a plain browser tab exits UNTRACKED."""
    from . import appwindow, nativewin

    profile = paths.VAR / "appwindow"
    try:
        if args.fetch:
            nativewin.fetch()
        return nativewin.run(args.url, profile)
    except (nativewin.NativeWindowError, OSError, ValueError) as exc:
        nativewin.note_fallback(getattr(exc, "code", "failed"), str(exc))
        print(f"winlab window: {exc}", file=sys.stderr)
        if args.no_fallback:
            return 3
    how, proc = appwindow.open_browser_window(args.url, profile)
    if proc is None:
        return appwindow.UNTRACKED
    return 0 if appwindow.wait_browser(proc) else appwindow.UNTRACKED


def cmd_icon(args) -> int:
    from . import appicon

    dest = appicon.write(args.path, size=args.size)
    print(f"wrote {dest} ({dest.stat().st_size} bytes)")
    return 0


def cmd_update(args=None) -> int:
    from . import update

    if args is not None and getattr(args, "auto", ""):
        update.set_auto(args.auto == "on")
        print(f"automatic update checks: {'on' if update.auto_enabled() else 'off'}"
              + ("" if update.auto_enabled() or args.auto == "off" else " (they need an activated license)"))
        return 0
    result = update.check()
    update.remember(result)
    print(update.render(result))
    if result["error"]:
        return 1
    if args is not None and getattr(args, "install", False):
        if not result["newer"]:
            return 0
        if not result["installable"]:
            print("this release cannot be installed from here: its manifest is not signed", file=sys.stderr)
            return 1
        try:
            exe = update.download(result["manifest"], progress=None)
            print(f"downloaded and checked {exe}")
            update.install(exe)
        except update.UpdateError as exc:
            print(f"{exc}", file=sys.stderr)
            return 1
        print("the installer is running; winlab starts again when it is done")
    return 0


def cmd_content_pack(args) -> int:
    from . import content, packs

    try:
        if args.packcmd == "build":
            key = packs.key_from(args.key_hex, args.pack)
            src = Path(args.content) if args.content else paths.CONTENT
            r = packs.build(src, Path(args.out), key, args.pack, strip=args.strip)
            print(f"pack {r['pack']}: {r['entries']} files encrypted into {r['out']} ({r['bytes']} bytes); "
                  f"{r['free']} stay free" + (f"; {r['stripped']} plain files removed" if r["stripped"] else ""))
            return 0
        if args.packcmd == "plan":
            packed, free = packs.plan(paths.CONTENT)
            print(f"labs-full ({len(packed)}):")
            for r in packed:
                print(f"  {r}")
            print(f"free ({len(free)}):")
            for r in free:
                print(f"  {r}")
            return 0
        if args.packcmd in (None, "status"):
            print(f"content mode: {content.mode()}")
            for f in sorted(content.packs_dir().glob(f"*{packs.EXT}")):
                pk = packs.Pack.read(f)
                key = content.pack_key(pk.id)
                ok = key is not None and pk.verify_key(key)
                print(f"  {f.name}: pack {pk.id}, {len(pk.names())} files, {'open' if ok else 'locked'}")
            return 0
    except packs.PackError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    print("usage: winlab content-pack {build,plan,status}", file=sys.stderr)
    return 2


def cmd_license(args) -> int:
    from . import licensing
    from .licensing import client as lic

    try:
        if args.liccmd in (None, "status"):
            print(lic.render(licensing.status()))
            return 0 if licensing.status().ok else 1
        if args.liccmd == "fingerprint":
            print(licensing.fingerprint())
            return 0
        if args.liccmd == "activate":
            st = licensing.activate(args.key, server=args.server)
            print(lic.render(st))
            return 0 if st.ok else 1
        if args.liccmd == "refresh":
            cur = licensing.status()
            if not cur.key:
                print("no license to refresh", file=sys.stderr)
                return 1
            st = licensing.activate(cur.key)
            print(lic.render(st))
            return 0 if st.ok else 1
        if args.liccmd == "activate-offline":
            token = args.token
            if token.startswith("@"):
                token = Path(token[1:]).read_text(encoding="utf-8")
            st = lic.activate_offline(token)
            print(lic.render(st))
            return 0 if st.ok else 1
        if args.liccmd == "deactivate":
            print(licensing.deactivate(online=not args.local))
            return 0
    except licensing.LicenseError as exc:
        print(f"{exc}", file=sys.stderr)
        return 4
    print("usage: winlab license {status,activate,activate-offline,refresh,deactivate,fingerprint}",
          file=sys.stderr)
    return 2


def cmd_access(args) -> int:
    from . import access

    try:
        lab = _resolve_lab(args.lab)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    try:
        if args.cmd == "console":
            print(access.console(lab, args.node))
            return 0
        if args.cmd == "exec":
            command = " ".join(a for a in args.command if a != "--").strip()
            if not command:
                print("nothing to run; usage: winlab exec <node> -- <command>",
                      file=sys.stderr)
                return 2
            shell = "cmd" if args.shell == "cmd" else "powershell"
            return access.run_exec(lab, args.node, command, shell=shell)
        if args.cmd == "shell":
            return access.interactive_shell(
                lab, args.node, shell="cmd" if args.use_cmd else "powershell"
            )
        if args.cmd == "cp":
            if ":" in args.src and not args.src[1:2] == ":":
                node, path = args.src.split(":", 1)
                access.copy_out(lab, node, path, args.dst)
                print(f"copied {node}:{path} -> {args.dst}")
            elif ":" in args.dst and not args.dst[1:2] == ":":
                node, path = args.dst.split(":", 1)
                access.copy_in(lab, node, args.src, path)
                print(f"copied {args.src} -> {node}:{path}")
            else:
                print("one of src/dst must be node:path", file=sys.stderr)
                return 2
            return 0
    except access.AccessError as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    return 2


def _reset_for_exercise(ex) -> int:
    """An exercise starts its reset_nodes from their image. Machines already
    running are left alone (stop them first for a clean attempt)."""
    if not ex.reset_nodes:
        return 0
    from .orchestrator import Orchestrator, OrchestratorError

    try:
        orch = Orchestrator(schema.load(ex.lab), accel="tcg", display="none")
        running = orch.running()
        idle = [n for n in ex.reset_nodes if n not in running]
        for nid in orch.reset(idle):
            print(f"  fresh    {nid}")
        for nid in ex.reset_nodes:
            if nid in running:
                print(f"  running  {nid} (kept as it is; stop it for a fresh start)")
    except (LabError, OrchestratorError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    return 0


def cmd_keys(args) -> int:
    """winlab keys <lab> <node> text <enter> ...: the machine's keyboard (QMP send-key)."""
    from . import naming, power
    extra = {"win-r": ["meta_l", "r"], "win": ["meta_l"], "win-x": ["meta_l", "x"], "alt-f4": ["alt", "f4"],
             "end": ["end"], "home": ["home"], "f10": ["f10"], "ctrl-x": ["ctrl", "x"]}
    presses: list[list[str]] = []
    for item in args.typed:
        if item.startswith("<") and item.endswith(">") and len(item) > 2:
            k = item[1:-1].lower()
            keys = power.SPECIAL_KEYS.get(k) or extra.get(k)
            if not keys:
                print(f"no key {item}: use {', '.join('<' + x + '>' for x in [*power.SPECIAL_KEYS, *extra])}",
                      file=sys.stderr)
                return 2
            presses.append(keys)
        else:
            presses += power.qcodes(item)
    try:
        lab = schema.load(args.lab)
        n = power.send_keys(lab.name, naming.resolve(lab, args.node), presses)
    except (LabError, power.PowerError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    print(f"{n} key press(es) on {args.node}")
    return 0


def cmd_exercise(args) -> int:
    from . import exercises

    try:
        if args.excmd in (None, "list"):
            avail = exercises.list_available()
            if not avail:
                print(f"no exercises in {paths.EXERCISES}")
                return 0
            for ex in avail:
                print(f"  {ex.id:<30} {ex.title}  ({len(ex.checks)} checks, lab {ex.lab})")
                need = exercises.footprint(ex)
                if need:
                    print(f"  {'':<30} boots {', '.join(need[0])}: {need[1] / 1024:.1f} GiB, "
                          f"{need[2] / 1024:.1f} GiB at the least")
            return 0
        if args.excmd == "start":
            ex = exercises.load(args.id)
            if not ex.lab:
                print("the exercise names no lab", file=sys.stderr)
                return 2
            rc = _reset_for_exercise(ex)
            if rc:
                return rc
            rc = cmd_lab_up(ex.lab, False, args.accel, args.display,
                            only=ex.needed_nodes(), force=args.force)
            if rc == 0:
                print(f"\n{exercises.render_brief(ex)}")
            return rc
        if args.excmd == "show":
            print(exercises.render_brief(exercises.load(args.id)))
            return 0
        if args.excmd == "grade":
            ex = exercises.load(args.id)
            lab = args.lab or ex.lab
            if not lab:
                print("no lab specified and the exercise names none", file=sys.stderr)
                return 2
            grade = exercises.grade(ex, lab)
            print(exercises.render_grade(grade, ex))
            return 0 if grade.passed else 1
    except exercises.ExerciseError as exc:
        print(f"{exc}", file=sys.stderr)
        return 4
    print("usage: winlab exercise {list,show,start,grade}", file=sys.stderr)
    return 2


def cmd_activity(args) -> int:
    from . import activity
    try:
        if args.actcmd == "open":
            lab = activity.open_bytes(Path(args.file).expanduser().read_bytes(), args.as_name)
            st = activity.status(lab)
            print(f"opened as lab '{lab.name}'; open it on the workbench: winlab gui {lab.name}\n")
            print(st["instructions"] or st["title"])
            return 0
        lab = schema.load(args.lab)
        if args.actcmd == "make":
            text = args.instructions
            if text.startswith("@"):
                text = Path(text[1:]).expanduser().read_text(encoding="utf-8")
            start, version = args.start, ""
            if start.startswith("version:"):
                start, version = "version", start[8:]
            guest = []
            for g in args.guest:
                bits = g.split(":")
                n = 3 if bits[0] == "x" else 2  # x:<exercise>:<check>, t:<common>, f:<problem>
                ref, rest = ":".join(bits[:n]), bits[n:]
                pts = int(rest.pop()) if len(rest) > 1 and rest[-1].isdigit() else 2
                guest.append(activity.guest_check(lab, ref, rest[0] if rest else "", rest[1] if len(rest) > 1 else "", pts))
            points = {k: int(v) for k, v in (p.split("=") for p in _csv(args.points) or [])}
            data = activity.make(lab, args.title, text, start, _csv(args.keep) or [], args.cables, version,
                                 args.time, "score" if args.score_only else "items", points, _csv(args.skip) or [], guest)
            dest = Path(args.dest).expanduser()
            if dest.is_dir() or not dest.suffix:
                dest = dest / f"{lab.name}{activity.EXT}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            _, rules, _ = activity.read(data)
            print(f"saved {dest}: {rules['items']} items and {rules['guest']} in-guest checks, "
                  f"{rules['points']} points")
        elif args.actcmd == "items":
            v = activity.items_view(lab)
            for c in v["categories"]:
                print(f"{c['id']:<9} {c['title']} ({c['count']} items, {c['points']} point each by default)")
                for it in v["items"]:
                    if it["cat"] == c["id"]:
                        print(f"    {it['id']:<28} {it['label']}")
            print("\nin-guest checks (--guest CHECK:MACHINE[:ARG][:POINTS]):")
            for g in v["catalog"]:
                print(f"    {g['id']:<40} {g['title']}" + (f"  [{g['arg']}]" if g["arg"] else ""))
        elif args.actcmd == "hand-in":
            print(activity.render(activity.hand_in(lab)))
        else:
            if args.guest:
                activity.check_guests(lab)
            st = activity.status(lab)
            print(activity.render(st))
            return 0 if st.get("activity") and st["percent"] == 100 else 1
        return 0
    except (activity.ActivityError, LabError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _csv(text: str) -> list[str] | None:
    return [x.strip() for x in text.split(",") if x.strip()] or None


def cmd_lab_eval(target: str, rearm: str) -> int:
    from . import evaluation as ev

    try:
        lab = schema.load(target)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    if rearm:
        try:
            print(ev.rearm(lab.name, rearm))
        except ev.EvaluationError as exc:
            print(f"{exc}", file=sys.stderr)
            return 4
        return 0
    st = state.load(lab.name)
    running = st.running() if st else {}
    rc = 0
    for node in lab.node_list():
        if not node.is_windows:
            continue
        if node.id not in running:
            old = ev.cached(lab.name).get(node.id)
            note = f"last seen: {ev.describe(old)}" if old else "not running"
            print(f"  {node.id:<12} {note}")
            continue
        try:
            clock = ev.check(lab.name, node.id)
        except ev.EvaluationError as exc:
            print(f"  {node.id:<12} {exc}")
            rc = 4
            continue
        flag = (f"  <- renew soon: winlab lab eval {lab.name} --rearm {node.id}"
                if clock.warn else "")
        print(f"  {node.id:<12} {ev.describe(clock)}{flag}")
    return rc


def cmd_lab_reset(target: str, only: list[str] | None, yes: bool) -> int:
    from .orchestrator import Orchestrator, OrchestratorError

    try:
        lab = schema.load(target)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    ids = only or [n.id for n in lab.node_list()]
    if not yes:
        print(f"this deletes the disks and checkpoints of: {', '.join(ids)}\n"
              f"they are rebuilt from their image on the next boot. "
              f"Run again with --yes to do it.", file=sys.stderr)
        return 2
    try:
        done = Orchestrator(lab, accel="tcg", display="none").reset(ids)
    except OrchestratorError as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    print(f"reset: {', '.join(done) if done else 'nothing had been built yet'}")
    return 0


def cmd_snap(args) -> int:
    from . import snapshots
    from .images import ImageError

    try:
        if args.snapcmd == "save":
            done = snapshots.save(args.lab, args.tag, only=_csv(args.only))
            print(f"saved checkpoint '{args.tag}' for: {', '.join(done)}")
            return 0
        if args.snapcmd == "restore":
            done = snapshots.restore(args.lab, args.tag, only=_csv(args.only))
            print(f"restored '{args.tag}' on: {', '.join(done)}")
            return 0
        if args.snapcmd == "rm":
            done = snapshots.delete(args.lab, args.tag)
            print(f"deleted '{args.tag}' from: {', '.join(done)}")
            return 0
        if args.snapcmd in (None, "list"):
            print(snapshots.render_listing(args.lab))
            return 0
    except ImageError as exc:
        print(f"{exc}", file=sys.stderr)
        return 4
    print("usage: winlab snap <lab> {save,restore,rm,list}", file=sys.stderr)
    return 2


def cmd_roles(args) -> int:
    from . import roles

    try:
        lab = schema.load(args.lab)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    node = lab.nodes.get(args.node)
    if not node:
        print(f"no such node '{args.node}'", file=sys.stderr)
        return 2

    try:
        topology = netplan.compile_topology(lab, check_ports=False)
        if args.rolecmd in (None, "plan"):
            print(roles.describe_plan(node, lab, topology))
            return 0
        if args.rolecmd in ("apply", "test"):
            st = state.load(lab.name)
            ns = st.nodes.get(args.node) if st else None
            if not ns or not ns.serial_port or not state.pid_alive(ns.pid):
                print(f"{args.node} is not running; start it with 'winlab lab up'",
                      file=sys.stderr)
                return 5
            from .guestctl import GuestChannel

            ch = GuestChannel(ns.serial_port).connect(retries=30, delay=2)
            try:
                if args.rolecmd == "test":
                    status = roles.test_roles(node, ch, topology=topology, lab=lab)
                    print(roles.render_status(node, status))
                    return 0 if status.get("in_desired_state") else 1
                print(f"applying roles to {args.node} over serial tcp/{ns.serial_port} …")
                result = roles.apply_roles(node, ch, topology=topology, lab=lab)
            finally:
                ch.close()
            for line in result.log:
                print(f"  {line}")
            print(f"applied: {', '.join(result.applied) or 'none'}; "
                  f"skipped: {', '.join(result.skipped) or 'none'}")
            return 0
    except roles.RoleError as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    print("usage: winlab roles <lab> {plan,apply,test} <node>", file=sys.stderr)
    return 2


def cmd_dsc(args) -> int:
    from . import psmodules

    if args.dsccmd in (None, "modules"):
        print(psmodules.render_status())
        return 0
    if args.dsccmd == "fetch":
        from .bootstrap import BootstrapError
        try:
            psmodules.fetch(refresh=args.refresh)
            return 0
        except (BootstrapError, psmodules.ModuleError) as exc:
            print(f"fetch failed: {exc}", file=sys.stderr)
            return 3
    if args.dsccmd == "render-all":
        from . import dsc, roles
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        n = 0
        try:
            manifest = roles.load_manifest()
            from . import content
            for f in content.glob(paths.LABS, "*.toml"):
                lab = schema.load(f.stem)
                topology = netplan.compile_topology(lab, check_ports=False)
                for node in lab.node_list():
                    plan = roles.order_roles(roles.effective_roles(node), manifest)
                    names = [rd.name for rd in plan if rd.engine == "dsc"]
                    if not names:
                        continue
                    cfg = dsc.compile_node(node, lab, topology, names)
                    text = dsc.render(cfg)
                    (out / f"{lab.name}-{node.id}.dsc.ps1").write_text(text, encoding="utf-8")
                    # The PowerShell inside Script resources is only a string
                    # to the MOF compiler; written out so CI parses it too.
                    for sname, body in dsc.script_blocks(cfg).items():
                        (out / "scripts" / sname).parent.mkdir(parents=True, exist_ok=True)
                        (out / "scripts" / sname).write_text(body, encoding="utf-8")
                    n += 1
        except (LabError, roles.RoleError, dsc.DscError) as exc:
            print(f"{exc}", file=sys.stderr)
            return 5
        print(f"rendered {n} configurations into {out}")
        return 0
    if args.dsccmd == "render":
        from . import dsc, roles
        try:
            lab = schema.load(args.lab)
        except LabError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
        node = lab.nodes.get(args.node)
        if not node:
            print(f"no such node '{args.node}'", file=sys.stderr)
            return 2
        try:
            manifest = roles.load_manifest()
            plan = roles.order_roles(roles.effective_roles(node), manifest)
            names = [rd.name for rd in plan if rd.engine == "dsc"]
            if not names:
                print(f"{args.node} has no DSC-backed roles", file=sys.stderr)
                return 1
            topology = netplan.compile_topology(lab, check_ports=False)
            print(dsc.render(dsc.compile_node(node, lab, topology, names)), end="")
            return 0
        except (roles.RoleError, dsc.DscError) as exc:
            print(f"{exc}", file=sys.stderr)
            return 5
    return 2


def cmd_node(args) -> int:
    from . import editor

    try:
        lab = editor.load_for_edit(args.lab)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    from . import naming

    if args.nodecmd in ("rm", "set", "rename"):
        args.id = naming.resolve(lab, args.id)
    if args.nodecmd == "clone":
        args.src = naming.resolve(lab, args.src)
    try:
        if args.nodecmd == "rename" or (args.nodecmd == "set" and args.name):
            new = args.name
            before = naming.display(lab, args.id)
            editor.set_node(lab, args.id, hostname=new)
            editor.save(lab)
            print(f"{args.id}: {before} is now {new}")
            if naming.installed(lab.name, args.id) and lab.nodes[args.id].is_windows:
                ok, note = naming.rename_live(lab, args.id)
                print(f"  {note}" if ok else
                      f"  Windows still calls itself {before} ({note}); it takes the new name "
                      f"at its next Configure (winlab roles {lab.name} apply {args.id})")
            if args.nodecmd == "rename":
                return 0
        if args.nodecmd == "add":
            roles = [r.strip() for r in args.roles.split(",") if r.strip()]
            created = editor.add_node(
                lab, args.id, kind=args.kind, network=args.net, ip=args.ip,
                roles=roles or None, cpus=args.cpus, memory_mb=args.memory,
                image=args.image, count=args.count,
            )
            editor.save(lab)
            for n in created:
                nic = n.primary_nic
                print(f"added {n.id}  {n.kind}  {nic.network if nic else '-'} "
                      f"{nic.ip if nic and nic.ip else 'dhcp'}  roles: "
                      f"{','.join(n.roles) or '-'}")
            print("\nrun 'winlab lab up' to boot the new machines.")
            return 0
        if args.nodecmd == "rm":
            if state.is_running(lab.name, args.id):
                print(f"{args.id} is running; shut it down first", file=sys.stderr)
                return 2
            editor.remove_node(lab, args.id)
            editor.save(lab)
            from . import mylabs
            parked = mylabs.park_machine(lab.name, args.id)
            print(f"removed {args.id}" + (" (its disks are put aside; a new machine with the same name "
                                          "starts afresh)" if parked else ""))
            return 0
        if args.nodecmd == "clone":
            from . import templates

            try:
                templates.clone_machine(lab, args.src, args.id, ip=args.ip,
                                        generalize_=False if args.exact else None)
            except templates.TemplateError as exc:
                print(f"{exc}", file=sys.stderr)
                return 5
            print(f"\nrun 'winlab lab up {lab.name} --only {args.id}' to boot it.")
            return 0
        if args.nodecmd == "set":
            changes = dict(
                cpus=args.cpus, memory_mb=args.memory,
                add_role=[r.strip() for r in args.add_role.split(",") if r.strip()],
                rm_role=[r.strip() for r in args.rm_role.split(",") if r.strip()],
                move_to=args.move_to, ip=args.ip,
                boot_order=args.boot_order, add_disk_gb=args.add_disk, rm_disk=args.rm_disk,
                add_nic=args.add_nic, rm_nic=args.rm_nic, iso=args.iso,
                usb_storage_gb=args.usb, gpu=(args.gpu == "on") if args.gpu else None,
                hardware=args.hardware, lean=(args.lean == "on") if args.lean else None,
                start_delay=args.start_delay,
                wait_ready=(args.wait_ready == "on") if args.wait_ready else None,
                description=args.description,
            )
            hw = editor.hardware_changes(changes)
            if hw and args.id in state.suspended(lab.name):
                print(f"{args.id} is suspended (hibernated): resume it before changing "
                      f"{', '.join(hw)}, or Windows cannot wake it", file=sys.stderr)
                return 5
            editor.set_node(lab, args.id, **changes)
            if args.cable:
                n, net, ip = _nic_arg(args.cable, "--cable")
                nic = editor.cable(lab, args.id, n, net, ip=ip)
                print(f"{args.id} nic{n} cabled to {net} ({nic.ip or 'DHCP'})")
            if args.tag:
                n, net, _ = _nic_arg(args.tag, "--tag")
                editor.tag(lab, args.id, n, net)
                print(f"{args.id} nic{n} carries {net} tagged")
            if args.untag:
                n, net, _ = _nic_arg(args.untag, "--untag")
                editor.untag(lab, args.id, n, net)
                print(f"{args.id} nic{n} no longer carries {net}")
            editor.save(lab)
            st = state.load(lab.name)
            live = bool(st and args.id in st.running())
            print(f"updated {args.id}" + (" (takes effect at its next start)" if live else ""))
            return 0
        if args.nodecmd in (None, "list"):
            for n in lab.node_list():
                nic = n.primary_nic
                print(f"  {n.id:<12} {naming.hostname_of(n):<16} {n.kind:<15} "
                      f"{nic.network if nic else '-':<12} "
                      f"{(nic.ip if nic and nic.ip else 'dhcp'):<15} "
                      f"roles: {','.join(n.roles) or '-'}")
            return 0
    except editor.EditError as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    print("usage: winlab node <lab> {add,rm,set,list}", file=sys.stderr)
    return 2


def cmd_net(args) -> int:
    from . import editor

    try:
        lab = editor.load_for_edit(args.lab)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    if args.netcmd == "check":
        from . import naming, netcheck
        try:
            res = netcheck.check(lab, naming.resolve(lab, args.node), netcheck.guest_runner(lab.name),
                                 to=[naming.resolve(lab, t) for t in args.to] or None, emit=print)
        except ValueError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
        print(f"\n{res['summary']}")
        return 0 if res["ok"] else 1

    try:
        if args.netcmd == "add":
            if args.cidr:
                editor.check_new_switch(lab, args.id, args.cidr)
            net = editor.add_network(
                lab, args.id, cidr=args.cidr, vlan=args.vlan, dhcp=args.dhcp,
                wan=args.wan, description=args.desc,
            )
            editor.save(lab)
            print(f"added network {net.id}  {net.cidr}  gw {net.router_ip}"
                  + (f"  vlan {net.vlan}" if net.vlan else ""))
            return 0
        if args.netcmd == "rm":
            editor.remove_network(lab, args.id)
            editor.save(lab)
            print(f"removed network {args.id}")
            return 0
        if args.netcmd == "fault":
            return cmd_net_fault(args, lab)
        if args.netcmd in (None, "list"):
            for net in sorted(lab.networks.values(), key=lambda n: n.id):
                tags = []
                if net.vlan:
                    tags.append(f"vlan {net.vlan}")
                if net.dhcp:
                    tags.append("dhcp")
                if net.wan:
                    tags.append("wan")
                suffix = f"  [{', '.join(tags)}]" if tags else ""
                print(f"  {net.id:<12} {net.cidr:<18} gw {net.router_ip}{suffix}")
            return 0
    except editor.EditError as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    print("usage: winlab net <lab> {add,rm,list}", file=sys.stderr)
    return 2


def _fabric_runner(lab_name: str):
    """A run(cmd) -> output callable on the lab's running router, or None
    with a reason when it is not up."""
    st = state.load(lab_name)
    fab = st.nodes.get("fabric") if st else None
    if not fab or not fab.serial_port or not state.pid_alive(fab.pid):
        return None, "the lab router is not running"
    from .guestctl import GuestChannel, GuestError
    try:
        ch = GuestChannel(fab.serial_port).connect(retries=10, delay=2)
    except GuestError as exc:
        return None, str(exc)

    from .routers import SHELL_GUARD  # the lab router's own processes only, never another router's

    def run(cmd: str, timeout: float = 60) -> str:
        res = ch.run(SHELL_GUARD + "\n" + cmd, shell="sh", timeout=timeout)
        return res.out if res.ok else (res.out or res.err)
    run.close = ch.close  # type: ignore[attr-defined]
    return run, ""


def fw_push(lab) -> tuple[bool, str]:
    """Replaces the running router's firewall table with the lab's. False
    with a note when the router is not up (the next start renders it)."""
    from . import firewall as fw, netplan
    plan = netplan.compile_topology(lab, check_ports=False)
    script = fw.live_script(lab, netplan.svi_of(plan), netplan._render_firewall_off(plan))
    run, why = _fabric_runner(lab.name)
    if not run:
        return False, f"{why}; the change takes effect at the next lab start"
    try:
        out = run(script, timeout=120)
    finally:
        run.close()
    tail = out.strip().splitlines()[-1] if out.strip() else ""
    return True, "applied to the running router" + (f" ({tail})" if tail else "")


def cmd_fw(args) -> int:
    from . import editor, firewall as fw
    from .schema import LabError

    try:
        lab = editor.load_for_edit(args.lab)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    op = args.fwcmd or "list"

    if op == "list":
        print(fw.describe(lab))
        return 0
    if op == "verify":
        try:
            v = fw.evaluate(lab, args.source, args.destination, args.port, args.proto)
        except fw.FirewallError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
        print(fw.describe_verdict(v))
        return 0 if v.allowed else 1
    if op == "live":
        run, why = _fabric_runner(lab.name)
        if not run:
            print(why, file=sys.stderr)
            return 5
        try:
            live = fw.read_live(run, lab)
        finally:
            run.close()
        if not live["present"]:
            print("the router has no zone firewall tables: it booted with the firewall off "
                  f"('winlab fw {lab.name} on', then 'winlab fw {lab.name} apply')")
            return 1
        for t in live["tables"]:
            print(f"{t['segment']} {t['direction']}  (chain {t['chain']})")
            for r in t["rules"]:
                flag = "   " if r["defined"] else " ! "
                pk = f"{r['packets']:>7}" if r["packets"] is not None else "      ?"
                prio = r["priority"] if r["priority"] is not None else "-"
                print(f"{flag}{pk} pkts  {prio:<6} {r['name']:<26} {r['verdict']:<7} {r['match']}")
            print()
        print("! = on the router but not in the lab definition (a fault, or a hand edit)")
        return 0
    if op == "apply":
        ok, msg = fw_push(lab)
        print(msg)
        return 0 if ok else 5

    # mutations: saved into the lab, then pushed to a running router
    try:
        if op in ("on", "off"):
            lab.firewall.enabled = op == "on"
            msg = ("zone firewall on: every segment now has NSG-style tables"
                   if op == "on" else "zone firewall off: the router forwards everything")
        elif op == "add":
            r = fw.add_rule(lab, name=args.name, priority=args.priority, direction=args.direction,
                            segment=args.on, source=args.src, destination=args.dst,
                            ports=args.ports, protocol=args.proto, action=args.action,
                            description=args.desc)
            msg = f"added {r.priority} {r.name} ({r.action}) to the {r.direction} table of {r.segment}"
        elif op == "rm":
            try:
                r = fw.remove_rule(lab, args.name, args.on)
                msg = f"removed {r.priority} {r.name} from the {r.direction} table of {r.segment}"
            except fw.FirewallError as exc:
                # Not in the definition: maybe only on the running router.
                run, why = _fabric_runner(lab.name)
                if not run:
                    print(f"{exc}", file=sys.stderr)
                    return 2
                try:
                    n = fw.remove_live(run, lab, args.name)
                finally:
                    run.close()
                if not n:
                    print(f"{exc}; nothing of that name on the running router either",
                          file=sys.stderr)
                    return 2
                print(f"removed {n} rule{'s' if n != 1 else ''} named {args.name} from the running "
                      f"router (it was never in the lab definition)")
                return 0
        else:
            print(f"unknown op {op}", file=sys.stderr)
            return 2
        editor.save(lab)
    except (fw.FirewallError, editor.EditError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    print(msg)
    ok, note = fw_push(lab)
    print(note)
    return 0


def fault_firewall_params(lab, segment: str) -> dict[str, str]:
    """The zone-firewall scenario parameters for a target segment: its
    inbound chain and another lab segment (the first that is not it and not
    the edge) to play the far side."""
    from . import firewall as fw
    others = [n.id for n in sorted(lab.networks.values(), key=lambda x: x.id)
              if n.id != segment and not n.wan] or [segment]
    other = others[0]
    return {"nsg_in": fw.chain_name(segment, fw.INBOUND),
            "nsg_out": fw.chain_name(segment, fw.OUTBOUND),
            "other": other, "other_cidr": lab.networks[other].cidr}


def cmd_net_fault(args, lab) -> int:
    from . import faults, netplan

    if not args.scenario:
        print(faults.render_catalog())
        return 0
    if args.scenario not in faults.SCENARIOS:
        print(f"unknown scenario '{args.scenario}'. Run 'winlab net {lab.name} fault' "
              f"to list them.", file=sys.stderr)
        return 2

    plan = netplan.compile_topology(lab, check_ports=False)
    params: dict[str, str] = {}

    # Resolve the target segment's SVI, gateway and prefix from the topology.
    seg = None
    if args.on and args.on in plan.segments:
        seg = plan.segments[args.on]
    elif args.on:
        print(f"no such segment '{args.on}'", file=sys.stderr)
        return 2
    else:
        seg = next(iter(plan.segments.values()))
    params["dev"] = seg.svi
    params["gw"] = seg.network.router_ip
    params["prefix"] = str(seg.network.prefixlen)
    hosts = list(seg.network.net.hosts())
    params.setdefault("victim", str(hosts[20]))
    params.setdefault("rogue_lo", str(hosts[180]))
    params.setdefault("rogue_hi", str(hosts[189]))
    params.setdefault("spoof_name", f"intranet.{lab.domain}")
    params.setdefault("target_cidr", seg.network.cidr)
    params.setdefault("target_host", seg.network.router_ip)
    params.setdefault("port", "445")
    # A member link on this segment, for link-flap.
    members = seg.members
    params.setdefault("fabric_iface", members[0].fabric_iface if members else "eth1")
    params.update(fault_firewall_params(lab, seg.network.id))
    if faults.SCENARIOS[args.scenario].needs_firewall and not lab.firewall.enabled:
        print(f"'{args.scenario}' needs the zone firewall on: winlab fw {lab.name} on",
              file=sys.stderr)
        return 2

    for kv in args.param:
        if "=" in kv:
            k, v = kv.split("=", 1)
            params[k] = v

    try:
        cmds = faults.build_commands(args.scenario, params, args.clear)
    except KeyError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    sc = faults.SCENARIOS[args.scenario]
    verb = "clearing" if args.clear else "applying"
    print(f"{verb} '{sc.id}' on segment {seg.network.id} ({seg.svi})")

    if args.dry_run:
        print("\nfabric commands:")
        for c in cmds:
            print(f"  {c}")
        if not args.clear and sc.observe:
            print(f"\nobserve: {sc.observe.format(**params)}")
        return 0

    st = state.load(lab.name)
    fab = st.nodes.get("fabric") if st else None
    if not fab or not fab.serial_port or not state.pid_alive(fab.pid):
        print("the fabric is not running; start the lab first "
              "(or use --dry-run to preview the commands)", file=sys.stderr)
        return 5

    from .guestctl import GuestChannel, GuestError

    try:
        ch = GuestChannel(fab.serial_port).connect(retries=10, delay=2)
    except GuestError as exc:
        print(f"{exc}", file=sys.stderr)
        return 5
    try:
        for c in cmds:
            res = ch.run(c, shell="sh", timeout=60)
            tag = "ok" if res.ok else f"rc={res.rc}"
            print(f"  [{tag}] {c}")
    finally:
        ch.close()
    if not args.clear and sc.observe:
        print(f"\nobserve on a node: {sc.observe.format(**params)}")
    return 0


def cmd_my_lab(args) -> int:
    """lab new / rm / rename: the user's own labs (winlab/mylabs.py)."""
    from . import editor, mylabs
    paths.ensure_dirs()
    try:
        if args.labcmd == "new":
            dest = editor.new_workbench(args.name, args.description)
            print(f"new network {dest.stem}: add machines with `winlab node {dest.stem} add ...`, "
                  f"or open it on the Workbench (winlab gui {dest.stem})")
            return 0
        if args.labcmd == "rm":
            if not args.yes:
                if not sys.stdin.isatty():
                    print(f"add --yes to delete {args.lab} and its machines' disks", file=sys.stderr)
                    return 2
                if input(f"delete {args.lab} and its machines' disks? [y/N] ").strip().lower() not in ("y", "yes"):
                    print("nothing deleted")
                    return 1
            gone = mylabs.delete(args.lab)
            print(f"deleted {args.lab}: {', '.join(gone) or 'nothing else was kept for it'}")
            return 0
        dest = mylabs.rename(args.lab, args.new_name)
        print(f"{args.lab} is now called {dest.stem}")
        return 0
    except (editor.EditError, mylabs.MyLabError, LabError, OSError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 2


def cmd_lab_list() -> int:
    from . import content
    paths.ensure_dirs()
    found = content.glob(paths.LABS, "*.toml")
    locked = content.locked_in(paths.LABS, "*.toml")
    if not found and not locked:
        print(f"no lab definitions in {paths.LABS}")
        return 0
    print(f"lab definitions in {paths.LABS}\n")
    for f in found:
        try:
            lab = schema.load(f)
        except LabError as exc:
            print(f"  {f.stem:<20} INVALID: {str(exc).splitlines()[0]}")
            continue
        tag = "free play: " if lab.sandbox else ""
        print(f"  {f.stem:<20} {len(lab.nodes)} nodes, {len(lab.networks)} networks"
              f"   {tag}{lab.description}")
    for f in locked:
        print(f"  {f.stem:<20} locked: {content.meta(f).get('description', '')}")
    if locked:
        print(f"\n{len(locked)} lab(s) are part of the full version. {content.UNLOCK_HINT}")
    return 0


def cmd_lab_validate(target: str) -> int:
    try:
        lab = schema.load(target)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    plan = netplan.compile_topology(lab, check_ports=False)
    print(f"{Path(lab.source_path).name}: ok -- {len(lab.nodes)} nodes, "
          f"{len(lab.networks)} networks, {plan.fabric_link_count} fabric links")
    return 0


def cmd_lab_vswitch(target: str, network: str | None, kind: str | None, ports: list[str] | None) -> int:
    from . import vswitch
    try:
        lab = schema.load(target)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    if network and kind:
        try:
            vswitch.set_kind(lab, network, kind, ports)
        except vswitch.VSwitchError as exc:
            print(f"{exc}", file=sys.stderr)
            return 1
        print(f"{network}: {vswitch.TITLES[kind]}. {vswitch.TEXT[kind]} Takes effect at the lab router's next start.")
    elif network or kind:
        print("give both the network and private, internal or external", file=sys.stderr)
        return 2
    for v in vswitch.view(lab):
        print(f"{v['id']:<14} {v['cidr']:<18} {vswitch.TITLES[v['kind']]:<17} {', '.join(v['machines'])}"
              + (f"   ports: {', '.join(v['host_ports'])}" if v["host_ports"] else ""))
    return 0


def cmd_lab_plan(target: str, show_fabric: bool, no_port_check: bool) -> int:
    try:
        lab = schema.load(target)
    except LabError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    plan = netplan.compile_topology(lab, check_ports=not no_port_check)
    print(netplan.describe(plan))
    # The real check, on the command lines QEMU would get: no user-mode or
    # bridged NIC, no shared folder, every host-side socket on 127.0.0.1.
    from .providers.qemu import QemuProvider, check_isolation
    runtimes = QemuProvider(plan, accel="tcg", display="none").build_all()
    from . import vswitch
    up = vswitch.active(lab)
    bad = {k: check_isolation(rt.argv, uplink=up and k == "fabric") for k, rt in runtimes.items()}
    bad = {k: v for k, v in bad.items() if v}
    if bad:
        for k, v in bad.items():
            print(f"isolation  {k}: " + "; ".join(v))
        return 1
    print(f"isolation  checked {len(runtimes)} QEMU command lines: no user-mode or bridged nic, "
          f"no shared folder, every control socket on 127.0.0.1"
          + (" (the router's card for the internal and external switches aside)" if up else ""))
    print("vswitch    " + vswitch.describe(lab))
    from .providers.qemu import hardware_of
    win = [n for n in lab.node_list() if n.kind != "linux"]
    if win:
        vio = [n.id for n in win if hardware_of(n) == "virtio"]
        asked = [n.id for n in win if n.hardware == "virtio" and hardware_of(n) == "pc"]
        print("hardware   pc: Intel 82574L nic, Intel ICH9 SATA, Intel HD Audio, USB 3, DVD drive; "
              "Windows drives them with its own drivers"
              + (f"  (virtio nic and disk: {', '.join(vio)})" if vio else "")
              + (f"  (virtio asked, no drivers in the base yet, runs as pc: {', '.join(asked)})" if asked else ""))
    from . import metrics
    mon = metrics.describe(lab)
    if mon:
        print(mon)
    if show_fabric:
        print("\n--- fabric configuration ---")
        print(netplan.render_fabric_setup(plan))
    return 0


def first_run() -> None:
    """Frozen exe only: refuse a read-only install folder with a clear message
    and lay the bundled content pack out next to the exe (see paths.seed_content)."""
    if not paths.FROZEN:
        return
    if not paths.writable(paths.ROOT):
        exe_dir = Path(sys.executable).resolve().parent
        if (exe_dir / paths.HOME_POINTER).exists():
            print(f"winlab: the data folder chosen at installation, {paths.ROOT}, is not writable. "
                  "Run the winlab installer again and pick a folder you own.", file=sys.stderr)
        else:
            print(f"winlab: {paths.ROOT} is not writable. Put winlab.exe in a folder you own "
                  "(for example D:\\winlab), or point WINLAB_HOME at one.", file=sys.stderr)
        raise SystemExit(2)
    rep = paths.seed_content()
    if rep.changed:
        kept = f", {len(rep.kept)} edited file(s) kept" if rep.kept else ""
        print(f"winlab: content pack in {paths.CONTENT}: {len(rep.added)} file(s) added, "
              f"{len(rep.updated)} upgraded{kept}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    first_run()

    if args.cmd is None:
        # A bare `winlab`, which is what double-clicking winlab.exe runs:
        # open the desktop on the last lab used. `winlab -h` still lists
        # the commands.
        args.cmd, args.lab, args.port, args.no_browser = "gui", "", 8780, False
        from . import quietstart

        if quietstart.relaunch_hidden():
            # Double-clicked: the copy that runs the desktop has no console
            # window; this one (and its console) goes away.
            return 0

    if args.cmd == "doctor":
        return cmd_doctor(getattr(args, "bundle", None))

    if args.cmd == "setup":
        return cmd_setup(args.lab, args.check)

    if args.cmd == "bootstrap":
        return cmd_bootstrap(args.plan, args.refresh, args.keep_downloads)

    if args.cmd == "images":
        return cmd_images(args)
    if args.cmd == "media":
        return cmd_media(args)
    if args.cmd == "workbench":
        return cmd_workbench(args)
    if args.cmd == "terminal":
        return cmd_terminal(args)
    if args.cmd == "virtio":
        return cmd_virtio(args)
    if args.cmd == "exporter":
        return cmd_exporter(args)
    if args.cmd == "wac":
        return cmd_wac(args)
    if args.cmd == "transcript":
        from . import transcript
        if args.html:
            Path(args.html).write_text(transcript.render(args.name), encoding="utf-8")
            print(f"wrote {args.html}: open it in a browser and print or save it as PDF")
        else:
            print(transcript.render_text())
        return 0
    if args.cmd == "packs":
        return cmd_packs(args)
    if args.cmd == "mail":
        return cmd_mail(args)
    if args.cmd == "wireshark":
        return cmd_wireshark(args)
    if args.cmd == "docs":
        return cmd_docs(args)
    if args.cmd == "netops":
        return cmd_netops(args)
    if args.cmd == "webmin":
        return cmd_webmin(args)
    if args.cmd == "containers":
        return cmd_containers(args)
    if args.cmd == "databases":
        return cmd_databases(args)
    if args.cmd == "routing":
        return cmd_routing(args)
    if args.cmd == "webproxy":
        return cmd_webproxy(args)
    if args.cmd == "ipv6":
        return cmd_ipv6(args)
    if args.cmd == "ids":
        return cmd_ids(args)
    if args.cmd == "azure":
        return cmd_azure(args)
    if args.cmd == "aws":
        return cmd_aws(args)
    if args.cmd == "softphone":
        return cmd_softphone(args)
    if args.cmd == "remoteaccess":
        return cmd_remoteaccess(args)
    if args.cmd == "automation":
        return cmd_automation(args)

    if args.cmd == "template":
        return cmd_template(args)

    if args.cmd == "node":
        return cmd_node(args)

    if args.cmd == "net":
        return cmd_net(args)
    if args.cmd == "fw":
        return cmd_fw(args)

    if args.cmd == "roles":
        return cmd_roles(args)

    if args.cmd == "dsc":
        return cmd_dsc(args)

    if args.cmd == "exercise":
        return cmd_exercise(args)
    if args.cmd == "keys":
        return cmd_keys(args)
    if args.cmd == "selftest":
        from . import selftest
        return selftest.run_cli(args)

    if args.cmd == "activity":
        return cmd_activity(args)
    if args.cmd == "class":
        from . import classes
        return classes.run_cli(args)
    if args.cmd in ("workday", "staff"):
        from . import workday
        return workday.run_cli(args)
    if args.cmd == "load":
        from . import traffic
        return traffic.run_cli(args)

    if args.cmd == "snap":
        return cmd_snap(args)

    if args.cmd in ("console", "exec", "shell", "cp"):
        return cmd_access(args)

    if args.cmd == "break":
        return cmd_break(args)
    if args.cmd == "fault":
        from . import physfaults
        return physfaults.run_cli(args)
    if args.cmd == "disk":
        from . import disks
        return disks.run_cli(args)
    if args.cmd == "sysdisk":
        from . import sysdisk
        return sysdisk.run_cli(args)
    if args.cmd == "hw-thermal":
        from . import pcbuild
        return pcbuild.run_thermal_cli(args)
    if args.cmd == "dr":
        from . import drsite
        return drsite.run_cli(args)
    if args.cmd == "bareos":
        from . import bareos
        return bareos.run_cli(args)
    if args.cmd == "updates":
        from . import updates
        return updates.run_cli(args)
    if args.cmd == "edge":
        from . import edge
        return edge.run_cli(args)
    if args.cmd == "secops":
        from . import secops
        return secops.run_cli(args)
    if args.cmd == "bitlocker":
        from . import bitlocker
        return bitlocker.run_cli(args)
    if args.cmd == "power":
        from . import power
        return power.run_cli(args)
    if args.cmd == "ups":
        from . import ups
        return ups.run_cli(args)
    if args.cmd == "alerts":
        from . import alerts
        return alerts.run_cli(args)
    if args.cmd == "building":
        from . import building
        return building.run_cli(args)
    if args.cmd == "rack":
        from . import rack
        return rack.run_cli(args)
    if args.cmd == "job":
        from . import campus
        return campus.run_cli(args)
    if args.cmd == "aidc":
        from . import aidc
        return aidc.run_cli(args)
    if args.cmd in ("inherited", "room"):
        from . import inherited, serverroom
        return (inherited if args.cmd == "inherited" else serverroom).run_cli(args)
    if args.cmd == "toolkit":
        from . import toolkit
        return toolkit.run_cli(args)

    if args.cmd == "learn":
        return cmd_learn(args)

    if args.cmd == "mecm":
        return cmd_mecm(args)
    if args.cmd == "secureboot":
        return cmd_secureboot(args)
    if args.cmd == "office":
        return cmd_office(args)
    if args.cmd == "usmt":
        return cmd_usmt(args)
    if args.cmd == "commands":
        from . import commands
        try:
            print(commands.render(commands.search(" ".join(args.query), args.kind), args.examples))
        except commands.CommandError as exc:
            print(exc, file=sys.stderr)
            return 4
        return 0
    if args.cmd == "exam":
        return cmd_exam(args)

    if args.cmd == "oncall":
        return cmd_oncall(args)
    if args.cmd == "breakfix":
        from . import breakfix
        return breakfix.run_cli(args)
    if args.cmd == "drill":
        from . import subnetdrill
        return subnetdrill.run_cli(args)
    if args.cmd == "interview":
        from . import interview
        return interview.run_cli(args)
    if args.cmd == "incident":
        from . import incidents
        return incidents.run_cli(args)
    if args.cmd == "helpdesk":
        from . import helpdesk
        return helpdesk.run_cli(args)
    if args.cmd == "itops":
        from . import itops
        return itops.run_cli(args)
    if args.cmd == "lifecycle":
        from . import lifecycle
        return lifecycle.run_cli(args)
    if args.cmd in ("wear", "shift", "company"):
        import importlib
        return importlib.import_module(f"winlab.{args.cmd}").run_cli(args)
    if args.cmd == "scenario":
        return cmd_scenario(args)

    if args.cmd == "clock":
        return cmd_clock(args)

    if args.cmd == "pki":
        return cmd_pki(args)

    if args.cmd == "progress":
        return cmd_progress(args)
    if args.cmd == "tracks":
        return cmd_tracks(args)

    if args.cmd == "viewer":
        return cmd_viewer(args)

    if args.cmd == "update":
        return cmd_update(args)
    if args.cmd == "content-pack":
        return cmd_content_pack(args)

    if args.cmd == "window":
        return cmd_window(args)
    if args.cmd == "icon":
        return cmd_icon(args)

    if args.cmd == "license":
        return cmd_license(args)

    if args.cmd == "console-agent":
        from . import consoleagent
        return consoleagent.run(args)

    if args.cmd == "gui":
        from . import webui

        try:
            webui.serve(args.lab, port=args.port, open_browser=not args.no_browser)
        except LabError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
        return 0

    if args.cmd == "lab":
        if args.labcmd is None:
            sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
            sub.choices["lab"].print_help(sys.stderr)
            return 2
        if args.labcmd == "list":
            return cmd_lab_list()
        if args.labcmd in ("new", "rm", "rename"):
            return cmd_my_lab(args)
        if args.labcmd in ("save", "open", "versions", "restore"):
            return cmd_netfile(args)
        if args.labcmd in ("history", "undo", "redo"):
            return cmd_lab_history(args)
        if args.labcmd == "password":
            return cmd_lab_password(args.lab)
        if args.labcmd == "validate":
            return cmd_lab_validate(args.lab)
        if args.labcmd == "vswitch":
            return cmd_lab_vswitch(args.lab, args.network, args.kind, args.port)
        if args.labcmd == "plan":
            return cmd_lab_plan(args.lab, args.fabric_script, args.no_port_check)
        if args.labcmd == "diagram":
            return cmd_lab_diagram(args.lab, args.out)
        if args.labcmd == "up":
            return cmd_lab_up(args.lab, args.dry_run, args.accel, args.display,
                              only=[n for n in args.only.split(",") if n], force=args.force)
        if args.labcmd == "down":
            if args.all:
                return cmd_lab_down_all()
            return cmd_lab_down(args.lab)
        if args.labcmd == "suspend":
            return cmd_lab_suspend(args.lab, _csv(args.only))
        if args.labcmd == "reload":
            return cmd_lab_reload(args.lab)
        if args.labcmd == "resume":
            return cmd_lab_up(args.lab, False, args.accel, args.display,
                              only=_csv(args.only), force=args.force)
        if args.labcmd == "status":
            return cmd_lab_status(args.lab)
        if args.labcmd == "eval":
            return cmd_lab_eval(args.lab, args.rearm)
        if args.labcmd == "reset":
            return cmd_lab_reset(args.lab, _csv(args.only), args.yes)
        if args.labcmd == "export":
            return cmd_lab_export(args)
        if args.labcmd == "import":
            return cmd_lab_import(args)
        if args.labcmd == "set":
            return cmd_lab_set(args)
        return _not_yet(args.labcmd)

    return _not_yet(args.cmd)
