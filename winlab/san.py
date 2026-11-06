"""A storage array (a SAN) on the workbench: drive bays, two iSCSI ports, and
its management pages, where the student builds RAID groups, volumes and
iSCSI targets.

The array is a small Alpine machine (the ``san`` role, content/roles/san.sh)
whose bays are its data disks: each drive reports its bay as its serial
number, blank drives come from the parts drawer (winlab/disks.py), and a
drive pulled while it runs is a hot-swap pull (winlab/hardware.py). Linux md
makes RAID groups of the drives, LVM carves volumes out of a group, and tgt
serves them over iSCSI on both of the array's ports, so a Windows server's
own iSCSI Initiator logs on to it, over two paths when both ports are cabled
(MPIO).

Out of the box it holds nothing. It is managed the way a Linux storage box
is: in Webmin (winlab/webmin.py), on https port 10000 of either port, from a
browser on a PC of the lab on the storage network. Its Linux RAID, Logical
Volume Management and iSCSI TGTd modules write what the student builds onto
the array itself (the drives' md superblocks and LVM metadata, mdadm.conf
and /etc/tgt/targets.conf on its internal disk); winlab keeps none of it.
What the front panel shows is read from the running array (``sanctl
status``): md's state of each group, LVM's volumes, tgt's targets and the
initiators logged on to them.
"""

from __future__ import annotations

import re

from . import hardware, naming, state
from .guestctl import GuestChannel, GuestError

ROLE = "san"
SANCTL = "/usr/local/sbin/sanctl"
TARGETS_CONF = "/etc/tgt/targets.conf"
PORTS = 2


class SanError(Exception):
    pass


def is_san(node) -> bool:
    return node.image == "alpine" and ROLE in node.roles


def host(node) -> str:
    return naming.hostname_of(node).lower()


def capacity_gb(level: str, sizes: list[int]) -> int:
    """What a RAID group of these drives holds."""
    if not sizes:
        return 0
    n, small = len(sizes), min(sizes)
    return {"raid0": sum(sizes), "raid1": small, "raid5": (n - 1) * small,
            "raid6": (n - 2) * small, "raid10": n // 2 * small}.get(level, 0)


# --------------------------------------------------------- the running array
running = state.is_running


def run(lab_name: str, node_id: str, line: str, factory=GuestChannel, timeout: int = 120,
        wait: bool = True) -> str:
    """One command on the array; its error as a SanError. A look at it
    (``wait`` False) does not wait for an array that is still booting."""
    from .appliance import ApplianceError, _channel
    try:
        ch = _channel(lab_name, node_id, factory, wait)
    except ApplianceError as exc:
        raise SanError(str(exc)) from None
    try:
        r = ch.run(line, shell="sh", timeout=timeout)
    except GuestError as exc:
        raise SanError(f"{node_id}: {exc}") from None
    finally:
        ch.close()
    if r.rc != 0:
        why = (r.err or r.out or "").strip().splitlines()
        raise SanError(why[-1] if why else f"the array said no (rc={r.rc})")
    return r.out


def parse_status(text: str) -> dict:
    """``sanctl status``: the bays' drives, each md group's state and its
    members, LVM's volumes, the ports, and tgt's targets."""
    out = {"bays": {}, "pools": {}, "lvs": {}, "ports": {}, "targets": []}
    sec, tgt_lines = "", []
    for line in text.splitlines():
        if line.startswith("#"):
            sec = line[1:].strip()
            continue
        w = line.split()
        if sec == "tgt":
            tgt_lines.append(line)
        elif sec == "bays" and len(w) == 4 and w[0] == "bay" and w[1].isdigit():
            out["bays"][int(w[1])] = {"dev": w[2], "mb": int(w[3]) if w[3].isdigit() else 0}
        elif sec == "pools" and w[:1] == ["pool"] and len(w) >= 9:
            out["pools"][w[1]] = {"md": w[2], "level": w[3], "state": w[4],
                                  "degraded": int(w[5]) if w[5].isdigit() else 0,
                                  "disks": int(w[6]) if w[6].isdigit() else 0,
                                  "sync": w[7], "progress": _progress(w[8]), "members": {}}
        elif sec == "pools" and w[:1] == ["member"] and len(w) >= 5 and w[1] in out["pools"]:
            bay = int(w[2]) if w[2].isdigit() else 0
            out["pools"][w[1]]["members"][bay or w[3]] = {"dev": w[3], "state": w[4],
                                                          "slot": w[5] if len(w) > 5 else ""}
        elif sec == "lvs" and len(w) >= 3:
            out["lvs"][f"{w[0]}/{w[1]}"] = {"vg": w[0], "lv": w[1], "gb": int(w[2]) if w[2].isdigit() else 0,
                                           "on": w[3] if len(w) > 3 else ""}
        elif sec == "ports" and len(w) >= 4 and w[1].isdigit():
            out["ports"][int(w[1])] = {"if": w[2], "link": w[3] == "1", "address": w[4] if len(w) > 4 else ""}
    out["targets"] = parse_targets("\n".join(tgt_lines))
    return out


def _progress(text: str) -> int:
    m = re.match(r"(\d+)/(\d+)", text)
    return int(int(m[1]) * 100 / int(m[2])) if m and int(m[2]) else -1


def parse_targets(text: str) -> list[dict]:
    """tgtadm --op show --mode target: per target its IQN, its LUNs, the
    accounts (CHAP) and the access list (addresses and initiator names in
    one list: tgt lets an initiator in when either matches), its sessions."""
    out: list[dict] = []
    cur, sec, lun = None, "", None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^Target (\d+): (\S+)", raw)
        if m:
            cur = {"tid": int(m[1]), "iqn": m[2], "luns": [], "accounts": [], "acl": [], "sessions": []}
            out.append(cur)
            sec = ""
            continue
        if cur is None or not line:
            continue
        if line.endswith("information:"):
            sec = line.split()[0]
            continue
        if sec == "I_T":
            m = re.match(r"I_T nexus: (\d+)", line)
            if m:
                cur["sessions"].append({"sid": int(m[1]), "initiator": "", "ips": []})
            elif line.startswith("Initiator:") and cur["sessions"]:
                cur["sessions"][-1]["initiator"] = line.split()[1]
            elif line.startswith("IP Address:") and cur["sessions"]:
                cur["sessions"][-1]["ips"].append(line.split(":", 1)[1].strip())
        elif sec == "LUN":
            m = re.match(r"LUN: (\d+)", line)
            if m:
                lun = {"lun": int(m[1]), "path": "", "mb": 0}
                cur["luns"].append(lun)
            elif lun is not None and line.startswith("Backing store path:"):
                lun["path"] = line.split(":", 1)[1].strip()
            elif lun is not None and line.startswith("Size:"):
                m = re.match(r"Size: (\d+) MB", line)
                lun["mb"] = int(m[1]) if m else 0
        elif sec == "Account":
            cur["accounts"].append(line)
        elif sec == "ACL":
            cur["acl"].append(line)
    for t in out:
        t["luns"] = [l for l in t["luns"] if l["lun"] and l["path"] not in ("", "None")]
    return out


def status(lab_name: str, node_id: str, factory=GuestChannel) -> dict:
    return parse_status(run(lab_name, node_id, f"{SANCTL} status", factory, timeout=60, wait=False))


def bay_states(lab, node, live: dict | None) -> list[dict]:
    """Each bay as the front panel draws it: its drive, the RAID group the
    array says it is in and how that drive is doing there (md's word)."""
    pulled = hardware.pulled(lab.name, node.id, len(node.data_disks_gb))
    member: dict[int, tuple[str, dict]] = {}
    for name, p in ((live or {}).get("pools") or {}).items():
        for bay, m in p["members"].items():
            if isinstance(bay, int):
                member[bay] = (name, m)
    rows = []
    for i, gb in enumerate(node.data_disks_gb):
        bay = i + 1
        pool, m = member.get(bay, ("", None))
        dev = ((live or {}).get("bays") or {}).get(bay, {}).get("dev", "")
        if i in pulled:
            st = "pulled"
        elif live is None:
            st = "off"
        elif m is not None:
            lp = live["pools"][pool]
            st = ("failed" if "faulty" in m["state"] else "online" if "in_sync" in m["state"]
                  else "rebuilding" if lp.get("sync") in ("recover", "resync") else "spare")
        elif bay not in live["bays"]:
            st = "missing"
        else:
            st = "spare"
        rows.append({"bay": bay, "gb": gb, "pool": pool, "dev": dev, "state": st})
    return rows


def pool_health(p: dict | None) -> str:
    if not p:
        return "offline"
    if p["sync"] in ("recover", "resync") and p["progress"] >= 0:
        return f"rebuilding {p['progress']}%"
    if p["degraded"]:
        return "degraded"
    return "healthy" if p["state"] in ("clean", "active", "active-idle", "write-pending") else p["state"]


def view(lab, node, live: dict | None, why: str = "") -> dict:
    """The front panel: the bays, the ports and, while the array runs, what
    it says itself about its groups, volumes and targets."""
    pools = []
    for name, p in ((live or {}).get("pools") or {}).items():
        bays = sorted(b for b in p["members"] if isinstance(b, int))
        pools.append({"name": name, "level": p["level"], "bays": bays, "health": pool_health(p),
                      "gb": capacity_gb(p["level"], [node.data_disks_gb[b - 1] for b in bays
                                                      if 0 < b <= len(node.data_disks_gb)])})
    targets = [{"iqn": t["iqn"], "luns": [{"lun": l["lun"], "path": l["path"], "mb": l["mb"]} for l in t["luns"]],
                "acl": t["acl"], "chap": t["accounts"], "sessions": t["sessions"]}
               for t in (live or {}).get("targets", [])]
    ports = []
    for i in range(PORTS):
        nic = node.nics[i] if i < len(node.nics) else None
        lp = (live or {}).get("ports", {}).get(i + 1, {})
        ports.append({"port": i + 1, "network": nic.network if nic else "", "address": (nic.ip or "") if nic else "",
                      "live": lp.get("address", ""), "link": lp.get("link", False)})
    return {"node": node.id, "host": host(node), "running": live is not None, "why": why,
            "bays": bay_states(lab, node, live), "pools": pools, "targets": targets, "ports": ports,
            "volumes": list(((live or {}).get("lvs") or {}).values())}


# --------------------------------------------------------- the desktop
def cable_ip(lab, node, nic: int, network: str) -> str | None:
    """A port cabled to a switch nobody hands addresses on gets the first
    free one, as a new array's ports come set from the factory."""
    if not is_san(node) or network not in lab.networks or lab.networks[network].dhcp:
        return None
    from . import editor
    return editor.next_free_ip(lab, network)


def act(dash, action: str, params: dict) -> dict:
    """san-state: the front panel's view of the array."""
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node") or ""))
    node = lab.nodes.get(node_id)
    if node is None or not is_san(node):
        return {"ok": False, "message": "no such storage array"}
    if action == "san-state":
        live, why = None, ""
        if running(lab.name, node_id):
            try:
                live = status(lab.name, node_id)
            except SanError as exc:
                why = f"starting: {exc}"
        return {"ok": True, **view(lab, node, live, why), "on": running(lab.name, node_id)}
    return {"ok": False, "message": f"unknown storage array action {action!r}"}


# --------------------------------------------------------- drills
# What the drills change is what Webmin's iSCSI TGTd module writes: the
# targets' lines in targets.conf (and conf.d), applied with tgt-admin the way
# the module's Restart does on this array, then every session closed so the initiators log
# on again and meet the change. A copy of each file is kept beside it.
_CONFS = "/etc/tgt/targets.conf /etc/tgt/conf.d/*.conf"
_APPLY = (f"tgt-admin --update ALL -f -c {TARGETS_CONF} >/dev/null 2>&1; "
          "tgtadm --lld iscsi --op update --mode sys --name State -v ready >/dev/null 2>&1; "
          f"{SANCTL} drop-all")
_SHOW = "out=$(tgtadm --lld iscsi --op show --mode target 2>/dev/null); "
_ACL_FILE = "/etc/winlab-san/fault-acl"
_CHAP_FILE = "/etc/winlab-san/fault-chap"

_ACL_APPLY = (
    f"files=$(ls {_CONFS} 2>/dev/null); "
    "grep -qsE '^[[:space:]]*initiator-(address|name)[[:space:]]' $files || "
    "{ echo 'nothing to break: the targets let everyone in. Lock the target to srv01 first: its address and its IQN "
    "(Webmin, iSCSI TGTd, the target: Allow connections from addresses, and from initiators)'; exit 1; }; "
    f"[ -f {_ACL_FILE} ] && {{ echo broken; exit 0; }}; mkdir -p /etc/winlab-san; : > {_ACL_FILE}.new; "
    "for f in $files; do grep -qE '^[[:space:]]*initiator-(address|name)[[:space:]]' \"$f\" || continue; "
    "cp \"$f\" \"$f.winlab\"; "
    f"awk -v keep={_ACL_FILE}.new '"
    "function other(v,  n, o, a, b) { if (v ~ /^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$/) { split(v, o, \".\"); "
    "return o[1] \".\" o[2] \".\" o[3] \".\" (o[4] % 254 + 1) } "
    "n = length(v); a = substr(v, n - 1, 1); b = substr(v, n, 1); return (a == b) ? v \"2\" : substr(v, 1, n - 2) b a } "
    "$1 ~ /^initiator-(address|name)$/ { w = other($2); print $2, w >> keep; sub(/[^ \\t]+[ \\t]*$/, w) } { print }' "
    "\"$f.winlab\" > \"$f\"; done; "
    f"mv {_ACL_FILE}.new {_ACL_FILE}; {_APPLY}; echo broken")
_ACL_CLEAR = (
    f"for f in {_CONFS}; do [ -f \"$f.winlab\" ] && mv \"$f.winlab\" \"$f\"; done; rm -f {_ACL_FILE}; "
    f"{_APPLY}; echo ok")
_ACL_VERIFY = (
    _SHOW + "acl=$(echo \"$out\" | awk '/ACL information:/ { a = 1; next } /^Target |information:/ { a = 0 } "
    "a && NF { print $1 }'); ok=True; [ -n \"$acl\" ] || ok=False; echo \"$acl\" | grep -qx ALL && ok=False; "
    "echo \"$out\" | grep -q 'I_T nexus:' || ok=False; "
    f"[ -f {_ACL_FILE} ] && while read -r good bad; do echo \"$acl\" | grep -qxF \"$good\" || ok=False; "
    f"echo \"$acl\" | grep -qxF \"$bad\" && ok=False; done < {_ACL_FILE}; echo $ok")

_CHAP_APPLY = (
    f"files=$(ls {_CONFS} 2>/dev/null); "
    "grep -qsE '^[[:space:]]*incominguser[[:space:]]' $files || "
    "{ echo 'nothing to break: set CHAP on the target first (Webmin, iSCSI TGTd, the target: Authentication by clients)'; "
    "exit 1; }; "
    f"[ -f {_CHAP_FILE} ] && {{ echo broken; exit 0; }}; mkdir -p /etc/winlab-san; "
    "new=$(head -c 12 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 14); "
    "for f in $files; do grep -qE '^[[:space:]]*incominguser[[:space:]]' \"$f\" || continue; "
    "cp \"$f\" \"$f.winlab-chap\"; "
    "awk -v s=\"$new\" '$1 == \"incominguser\" { sub(/[^ \\t]+[ \\t]*$/, s) } { print }' \"$f.winlab-chap\" > \"$f\"; done; "
    f"( umask 077; echo \"$new\" > {_CHAP_FILE} ); {_APPLY}; echo broken")
_CHAP_CLEAR = (
    f"for f in {_CONFS}; do [ -f \"$f.winlab-chap\" ] && mv \"$f.winlab-chap\" \"$f\"; done; rm -f {_CHAP_FILE}; "
    f"{_APPLY}; echo ok")
_CHAP_VERIFY = (
    _SHOW + "acc=$(echo \"$out\" | awk '/Account information:/ { a = 1; next } /ACL information:|^Target / { a = 0 } "
    "a && NF'); ok=True; [ -n \"$acc\" ] || ok=False; echo \"$out\" | grep -q 'I_T nexus:' || ok=False; "
    f"if [ -f {_CHAP_FILE} ]; then s=$(cat {_CHAP_FILE}); "
    f"grep -qsE \"^[[:space:]]*incominguser[[:space:]].*[[:space:]]$s[[:space:]]*\\$\" {_CONFS} && ok=False; fi; "
    "echo $ok")


def _faults():
    from .guestfaults import LINUX, GuestFault
    return [
        GuestFault(
            id="san-wrong-iqn",
            roles=(ROLE,),
            images=("alpine",),
            title="The server's iSCSI disk is gone: the array no longer lets it in",
            os=LINUX,
            teaches="iSCSI access control on a Linux target (tgt): initiator addresses and initiator names (IQNs) "
                    "in one list, either one letting an initiator in; reading the initiator's login error; "
                    "comparing both sides letter by letter",
            symptom="the server's iSCSI disk vanished from Disk Management; the iSCSI Initiator shows the target "
                    "Reconnecting, then Inactive, and Connect fails with 'Authorization Failure'",
            apply=_ACL_APPLY,
            clear=_ACL_CLEAR,
            shell="sh",
            hints=(
                "Start at the server: Get-IscsiTarget shows the target not connected, and Connect-IscsiTarget "
                "answers 'Authorization Failure'. The array is there (Test-NetConnection <array port> -Port 3260 "
                "succeeds), so it heard the login and refused this initiator.",
                "A tgt target lets in an initiator whose address or IQN is on its list. In the array's Webmin, "
                "Hardware > iSCSI TGTd, open the target: Allow connections from addresses, and from initiators. "
                "On the server: (Get-InitiatorPort).NodeAddress is the name it logs on with, Get-NetIPAddress its "
                "storage address. Compare them letter by letter.",
                "Both lines name a machine one typo away from the server. Correct them in Webmin, Save, then "
                "Restart iSCSI TGTd on the module's page (or tgt-admin --update ALL -c /etc/tgt/targets.conf on "
                "the array's screen). On the server: Get-IscsiTarget | Connect-IscsiTarget -IsPersistent $true "
                "(or Refresh in the initiator) and the disk is back.",
            ),
            verify=_ACL_VERIFY,
        ),
        GuestFault(
            id="san-chap-mismatch",
            roles=(ROLE,),
            images=("alpine",),
            title="The server cannot log on to the array: CHAP fails",
            os=LINUX,
            teaches="CHAP between an iSCSI initiator and a target: the shared secret, where each side keeps it, "
                    "and that a login error is not a network error",
            symptom="the server's iSCSI disk is gone; the initiator retries and logs 'Target failed to "
                    "authenticate' / 'Authentication Failure' (iScsiPrt events in the System log)",
            apply=_CHAP_APPLY,
            clear=_CHAP_CLEAR,
            shell="sh",
            hints=(
                "The server sees the target (Get-IscsiTarget lists it) but cannot log on: Connect-IscsiTarget "
                "with your CHAP user and secret fails with an authentication error, and the System log has iScsiPrt "
                "errors. The network is fine: the target answered, and said no.",
                "CHAP is a secret both sides keep: the target asks, the initiator proves it knows it. Someone set "
                "another secret on the array; the server still sends the old one. In the array's Webmin, iSCSI "
                "TGTd, open the target: Authentication by clients lists the user and the secret it now expects.",
                "Set the secret again on the array, the one the server uses (12 to 16 characters), Save and "
                "Restart iSCSI TGTd on the module's page. Then on the server Get-IscsiTarget | Connect-IscsiTarget -AuthenticationType "
                "ONEWAYCHAP -ChapUsername <user> -ChapSecret <secret> -IsPersistent $true, once for each path.",
            ),
            verify=_CHAP_VERIFY,
        ),
    ]


FAULT_IDS = ("san-wrong-iqn", "san-chap-mismatch")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
