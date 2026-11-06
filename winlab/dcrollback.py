"""USN rollback, caused the way it happens in real companies: a domain
controller is reverted to an old checkpoint of its disk.

A domain controller numbers every change it makes (its update sequence
number, USN) and its partners remember the highest number they have seen
from it, keyed by its invocation ID. Put the DC's disk back to an earlier
point and it starts numbering again from the old value under the same
invocation ID; its partners believe they already have those changes and
silently ignore them. Since Windows Server 2003 SP1 the reverted DC notices
when a partner is ahead of it (Directory Service event 2095), stops
replicating, pauses Netlogon and sets "Dsa Not Writable". Hypervisors that
present a VM-Generation ID let Server 2012 and later reset the invocation ID
themselves after a revert; winlab's checkpoints present none, like an old
hypervisor, a disk image copied back, or a SAN snapshot, so the rollback is
the real one.

The drill (`winlab break <dc> usn-rollback`, or Break in the lesson):

  1. ask the DC for its invocation ID and a partner DC that is running;
  2. checkpoint the DC alone (winlab/snapshots.py, while it runs);
  3. write on the DC after the checkpoint: OU=USN drill with five users,
     the OU's description naming the invocation ID, then push them to the
     partners (repadmin /syncall /APed);
  4. wait until the partner holds the five users;
  5. revert the DC to the checkpoint: it restarts with a disk that never
     made those changes, under the same invocation ID.

The student repairs it the supported way (force-demote and promote again
after a metadata cleanup, or restore a real system state backup); the
fault's verify (winlab/identityops.py) runs on the DC and wants the drill
users back, a new invocation ID, nothing quarantined and clean replication.

Everything that touches a machine goes through callables, so the suite
drives the sequence without a VM.
"""

from __future__ import annotations

import time

from . import state
from .dayops import SECRET  # a random password made inside the guest

TAG = "usn-rollback"
DRILL_OU = "USN drill"
DRILL_USERS = 5


class RollbackError(Exception):
    pass


# ------------------------------------------------------------ the scripts
ASK = (
    "$me = Get-ADDomainController -Identity $env:COMPUTERNAME -Server $env:COMPUTERNAME; "
    "$p = @(Get-ADDomainController -Filter * -Server $env:COMPUTERNAME | Where-Object { $_.Name -ne $env:COMPUTERNAME }); "
    "'INV ' + $me.InvocationId; "
    "foreach ($x in $p) { 'PARTNER ' + $x.Name }"
)

DRILL = (
    "$dom = Get-ADDomain -Server $env:COMPUTERNAME; "
    f"$ou = 'OU={DRILL_OU},' + $dom.DistinguishedName; "
    "$inv = [string](Get-ADDomainController -Identity $env:COMPUTERNAME -Server $env:COMPUTERNAME).InvocationId; "
    "if (-not (Get-ADOrganizationalUnit -Filter \"DistinguishedName -eq '$ou'\" -Server $env:COMPUTERNAME)) { "
    f"New-ADOrganizationalUnit -Name '{DRILL_OU}' -Path $dom.DistinguishedName -ProtectedFromAccidentalDeletion $false "
    "-Server $env:COMPUTERNAME }; "
    "Set-ADOrganizationalUnit -Identity $ou -Server $env:COMPUTERNAME "
    "-Description ('written on ' + $env:COMPUTERNAME + ' after the checkpoint; invocation ' + $inv); "
    f"foreach ($i in 1..{DRILL_USERS}) {{ $n = 'usn-drill-0' + $i; "
    "if (-not (Get-ADUser -Filter \"SamAccountName -eq '$n'\" -Server $env:COMPUTERNAME)) { "
    "New-ADUser -Name $n -SamAccountName $n -Path $ou -Description 'Created after the checkpoint' "
    f"-AccountPassword {SECRET} -Enabled $false -Server $env:COMPUTERNAME }} }}; "
    "repadmin /syncall $env:COMPUTERNAME /APed | Out-Null; "
    "'DRILL ' + $inv"
)

COUNT = (
    f"$ou = 'OU={DRILL_OU},' + (Get-ADDomain -Server $env:COMPUTERNAME).DistinguishedName; "
    "@(Get-ADUser -SearchBase $ou -Filter \"SamAccountName -like 'usn-drill-*'\" -Server $env:COMPUTERNAME "
    "-ErrorAction SilentlyContinue).Count"
)


def parse_ask(out: str) -> tuple[str, list[str]]:
    """(invocation ID, partner names) from what ASK printed."""
    inv, partners = "", []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("INV "):
            inv = line[4:].strip()
        elif line.startswith("PARTNER "):
            partners.append(line[8:].strip())
    return inv, partners


def node_for(lab, hostname: str) -> str:
    """The lab's machine id for a DC's host name ('' when none matches)."""
    from . import naming
    for n in lab.node_list():
        if naming.hostname_of(n).upper() == hostname.upper() or n.id.upper() == hostname.upper():
            return n.id
    return ""


# -------------------------------------------------------------- the drill
def rollback(lab, dc: str, *, run, save, restore, running, sleep=time.sleep,
             say=lambda line: None, wait_s: int = 300) -> str:
    """Roll `dc` back over its own changes. run(node, script, timeout) ->
    (ok, out); save(nodes) and restore(nodes) checkpoint and revert;
    running() -> the running machine ids. Raises RollbackError, with what
    to do, when the lab cannot have one."""
    if dc not in lab.nodes:
        raise RollbackError(f"{dc} is not a machine of lab {lab.name}")
    up = set(running())
    if dc not in up:
        raise RollbackError(f"{dc} is not running")
    say(f"asking {dc} for its invocation ID and its partners")
    ok, out = run(dc, ASK, 120)
    inv, names = parse_ask(out if ok else "")
    if not ok or not inv:
        raise RollbackError(f"{dc} did not answer as a domain controller: {(out or '').strip()[:200]}")
    partner = next((node_for(lab, n) for n in names if node_for(lab, n) in up), "")
    if not partner:
        raise RollbackError(f"{dc} has no running partner DC: a rollback needs another domain controller "
                            "that has seen its changes (promote a second DC first, and start it)")
    say(f"checkpoint '{TAG}' of {dc} (its disk only, while it runs)")
    save([dc])
    say(f"writing on {dc} after the checkpoint: OU={DRILL_OU} and {DRILL_USERS} users, pushed to its partners")
    ok, out = run(dc, DRILL, 300)
    if not ok:
        raise RollbackError(f"the drill writes failed on {dc}: {(out or '').strip()[:200]}")
    say(f"waiting until {partner} has them")
    waited = 0
    while True:
        ok, out = run(partner, COUNT, 120)
        if ok and out.strip().splitlines() and out.strip().splitlines()[-1].strip() == str(DRILL_USERS):
            break
        if waited >= wait_s:
            raise RollbackError(f"{partner} never received the drill users from {dc}: is replication healthy? "
                                "(repadmin /replsummary) The checkpoint was taken; nothing was reverted")
        sleep(15)
        waited += 15
    say(f"reverting {dc} to the checkpoint: it restarts on a disk that never made those changes")
    restore([dc])
    return (f"{dc} was reverted to a checkpoint taken before it wrote OU={DRILL_OU} and {DRILL_USERS} users, "
            f"which {partner} already holds. It came back under the same invocation ID ({inv}): a USN rollback. "
            f"Give it a few minutes to start, then read its Directory Service log.")


# ----------------------------------------------------- the real machines
def _runner(lab_name: str):
    from .guestctl import GuestChannel, GuestError

    def run(node: str, script: str, timeout: int = 300) -> tuple[bool, str]:
        st = state.load(lab_name)
        ns = st.nodes.get(node) if st else None
        if not ns or not state.pid_alive(ns.pid):
            return False, f"{node} is not running"
        try:
            ch = GuestChannel(ns.serial_port).connect(retries=10, delay=2)
        except GuestError as exc:
            return False, str(exc)
        try:
            res = ch.run(script, shell="powershell", timeout=timeout)
        except GuestError as exc:
            return False, str(exc)
        finally:
            ch.close()
        return res.ok, res.out if res.ok else (res.err or res.out)
    return run


def host_break(lab_name: str, node: str, clear: bool = False, say=print) -> tuple[bool, str]:
    """`winlab break <dc> usn-rollback` and the Break button. There is no
    undo: a rolled-back DC is rebuilt, which is the lesson."""
    if clear:
        return False, ("no undo for a USN rollback: force-demote the DC, clean up its metadata on a healthy DC "
                       "and promote it again (or restore a real system state backup); the lesson has the steps")
    from . import schema, snapshots
    try:
        lab = schema.load(lab_name)
    except Exception as exc:  # noqa: BLE001 - a lab that does not load cannot be broken
        return False, str(exc)

    def running() -> list[str]:
        st = state.load(lab_name)
        return list(st.running()) if st else []

    try:
        msg = rollback(lab, node, run=_runner(lab_name),
                       save=lambda nodes: snapshots.save(lab_name, TAG, only=nodes),
                       restore=lambda nodes: snapshots.restore(lab_name, TAG, only=nodes),
                       running=running, say=say)
    except Exception as exc:  # noqa: BLE001 - RollbackError, or a checkpoint's ImageError
        return False, str(exc)
    return True, msg
