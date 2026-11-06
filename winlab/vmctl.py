"""Hyper-V Manager's verbs for one machine, and the management side of its
Settings dialog.

The verbs are what the Action menu and a machine's right-click menu offer:
Pause and Resume (QMP stop and cont: the machine freezes where it is),
Reset (QMP system_reset: the reset button), Shut Down (the ACPI power
button, which the guest answers by shutting down) and the lab's own Shut
Down: every running machine in reverse boot order, each given time to
finish before the next, so members go before their domain controller.
Turn Off is the existing power-cut; Save is the suspend job.

The Settings dialog's management pages are kept on the machine itself:
- Integration Services: three a student can switch off, each gating what
  winlab really does through the machine's agent: Operating system
  shutdown (Shut Down from here), Time synchronization (the lab clock
  setting its time) and Guest services (files dropped on its screen).
- Automatic Stop Action: what happens to a running machine when the
  desktop stops (Save, Turn off or Shut down), as Hyper-V does when its
  host shuts down.
- Checkpoints: on or off for the machine.
- Firmware boot order and boot mode (UEFI or legacy BIOS), Security's
  Secure Boot and its template (winlab/firmware.py), processor
  virtualization extensions (nestedvirt),
  a network adapter's static MAC address.
Nothing here configures the guest: these are the virtual machine's own
settings, the ones Hyper-V keeps outside the guest too.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import naming, paths, state

STOP_ACTIONS = ("save", "off", "shutdown")
STOP_DEFAULT = "save"
STOP_TITLES = {"save": "Save the virtual machine state", "off": "Turn off the virtual machine",
               "shutdown": "Shut down the guest operating system"}
SERVICES = (("shutdown", "Operating system shutdown"), ("time", "Time synchronization"),
            ("files", "Guest services"))
SERVICES_OFF = "integration_off"   # node.vars: the services switched off
CHECKPOINTS_OFF = "checkpoints_off"
SHUTDOWN_WAIT = 180.0               # one machine's clean shutdown, in the lab's Shut Down
PAUSED = "paused.pid"


class VmError(Exception):
    pass


# ------------------------------------------------------------- pure logic
def services(node) -> dict[str, bool]:
    off = (getattr(node, "vars", None) or {}).get(SERVICES_OFF) or []
    return {key: key not in off for key, _t in SERVICES}


def service_on(node, key: str) -> bool:
    return services(node).get(key, True)


def set_services(node, wanted: dict[str, bool]) -> None:
    now = services(node)
    now.update({k: bool(v) for k, v in wanted.items() if k in now})
    off = [k for k, _t in SERVICES if not now[k]]
    if off:
        node.vars[SERVICES_OFF] = off
    else:
        node.vars.pop(SERVICES_OFF, None)


def stop_action(node) -> str:
    v = str(node.vars.get("stop_action") or "")
    return v if v in STOP_ACTIONS else STOP_DEFAULT


def checkpoints_on(node) -> bool:
    return not node.vars.get(CHECKPOINTS_OFF)


def shutdown_order(lab, running) -> list[str]:
    """Running machines in reverse boot order: clients and members first,
    the domain controller last, as an admin shuts a site down."""
    return [n.id for n in reversed(lab.node_list()) if n.id in running]


def exit_plan(lab, running) -> dict[str, list[str]]:
    """What the desktop does with each running machine when it stops,
    grouped by stop action, each group in reverse boot order."""
    out: dict[str, list[str]] = {a: [] for a in STOP_ACTIONS}
    for nid in shutdown_order(lab, running):
        out[stop_action(lab.nodes[nid])].append(nid)
    return out


def check_mac(mac: str) -> str:
    """A static MAC address as Hyper-V takes it (00-15-5D-01-02-03 or with
    colons): unicast, not all zeros. Returns it lower case with colons."""
    from .schema import MAC
    m = (mac or "").strip().lower().replace("-", ":")
    if len(m) == 12 and ":" not in m:
        m = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    if not MAC.match(m) or m == "00:00:00:00:00:00":
        raise VmError(f"{mac!r} is not a MAC address: six pairs of hex digits, like 00-15-5D-0A-01-02")
    if int(m[:2], 16) & 1:
        raise VmError(f"{mac} is a multicast address: the first byte must be even")
    return m


def static_mac(lab, node, idx: int) -> str:
    """An adapter's MAC address when it is set by hand, '' when it is the
    one winlab derives (Hyper-V's Dynamic): the derived one is written into
    the lab file too once the network is compiled, so it is told apart by
    value."""
    from .model import stable_mac
    mac = node.nics[idx].mac
    return "" if not mac or mac == stable_mac(lab.name, node.id, idx) else mac


# ------------------------------------------------------------ live state
def _node_dir(lab_name: str, node_id: str) -> Path:
    return paths.lab_dir(lab_name) / node_id


def _ns(lab_name: str, node_id: str):
    st = state.load(lab_name)
    ns = st.nodes.get(node_id) if st else None
    if not ns or not ns.pid or not state.pid_alive(ns.pid):
        return None
    return ns


def is_paused(lab_name: str, node_id: str, pid: int) -> bool:
    """Paused from here (the marker holds the pid it was paused under, so a
    machine started again later is not taken for paused)."""
    try:
        return bool(pid) and int((_node_dir(lab_name, node_id) / PAUSED).read_text()) == pid
    except (OSError, ValueError):
        return False


def _mark(lab_name: str, node_id: str, pid: int) -> None:
    f = _node_dir(lab_name, node_id) / PAUSED
    if pid:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(str(pid))
    else:
        f.unlink(missing_ok=True)


def _qmp(port: int, *commands: str) -> None:
    from .qmp import Qmp, QmpError
    try:
        with Qmp(port, timeout=10) as mon:
            for c in commands:
                mon.call(c)
    except QmpError as exc:
        raise VmError(f"the machine's monitor did not answer: {exc}") from exc


def pause(lab, node_id: str) -> str:
    ns = _running_or_fail(lab, node_id)
    _qmp(ns.qmp_port, "stop")
    _mark(lab.name, node_id, ns.pid)
    return f"{naming.display(lab, node_id)} is paused: its processors stop where they are"


def resume(lab, node_id: str) -> str:
    from . import labclock
    ns = _running_or_fail(lab, node_id)
    c = labclock.load(lab.name)
    if c.paused and node_id in c.held:
        raise VmError(f"the lab clock is paused and holds {naming.display(lab, node_id)}: "
                      f"resume the clock to run it again")
    _qmp(ns.qmp_port, "cont")
    _mark(lab.name, node_id, 0)
    return f"{naming.display(lab, node_id)} is running again"


def reset(lab, node_id: str) -> str:
    ns = _running_or_fail(lab, node_id)
    _qmp(ns.qmp_port, "system_reset", "cont")
    _mark(lab.name, node_id, 0)
    return f"{naming.display(lab, node_id)} was reset: it starts again from its firmware"


def shut_down(lab, node_id: str) -> str:
    node = lab.nodes[node_id]
    ns = _running_or_fail(lab, node_id)
    name = naming.display(lab, node_id)
    if not service_on(node, "shutdown"):
        raise VmError(f"Operating system shutdown is off in {name}'s settings (Integration "
                      f"Services): shut it down inside the machine, or Turn Off to cut its power")
    if is_paused(lab.name, node_id, ns.pid):
        raise VmError(f"{name} is paused: resume it first, then shut it down")
    from .orchestrator import _acpi_powerdown
    err = _acpi_powerdown(ns.qmp_port)
    if err:
        raise VmError(err)
    return f"{name} is shutting down"


def discard_saved(lab, node_id: str) -> str:
    """Hyper-V's Delete Saved State: the memory file goes and the next start
    is a cold boot, as after a power cut."""
    from .orchestrator import SAVED_STATE
    if node_id not in lab.nodes:
        raise VmError(f"no machine {node_id!r} in this lab")
    f = _node_dir(lab.name, node_id) / SAVED_STATE
    st = state.load(lab.name)
    ns = st.nodes.get(node_id) if st else None
    if not f.exists() or not ns or ns.phase != state.SUSPENDED:
        raise VmError(f"{naming.display(lab, node_id)} has no saved state")
    f.unlink()
    ns.phase = "stopped"
    state.save(st)
    return f"{naming.display(lab, node_id)}: saved state deleted; it starts fresh, as after a power cut"


def _running_or_fail(lab, node_id: str):
    if node_id not in lab.nodes:
        raise VmError(f"no machine {node_id!r} in this lab")
    ns = _ns(lab.name, node_id)
    if ns is None:
        raise VmError(f"{naming.display(lab, node_id)} is not running")
    return ns


def shut_down_lab(lab, emit=lambda _l: None, wait: float = SHUTDOWN_WAIT,
                  press=None, alive=None, sleep=time.sleep) -> list[str]:
    """The lab's Shut Down: each running machine's power button in reverse
    boot order, waiting up to `wait` for each to go before the next.
    Returns the machines still running (left for Turn Off)."""
    from .orchestrator import _acpi_powerdown
    st = state.load(lab.name)
    running = st.running() if st else {}
    press = press or (lambda ns: _acpi_powerdown(ns.qmp_port))
    alive = alive or (lambda ns: state.pid_alive(ns.pid))
    left: list[str] = []
    for nid in shutdown_order(lab, running):
        ns, node, name = running[nid], lab.nodes[nid], naming.display(lab, nid)
        if not service_on(node, "shutdown"):
            emit(f"{name}: Operating system shutdown is off in its settings; left running")
            left.append(nid)
            continue
        if is_paused(lab.name, nid, ns.pid):
            emit(f"{name}: paused; left as it is")
            left.append(nid)
            continue
        emit(f"{name}: shutting down…")
        err = press(ns)
        if err:
            emit(f"{name}: {err}")
            left.append(nid)
            continue
        deadline = time.monotonic() + wait
        while alive(ns) and time.monotonic() < deadline:
            sleep(1.0)
        if alive(ns):
            emit(f"{name}: still running after {int(wait)} s")
            left.append(nid)
        else:
            emit(f"{name}: off")
            ns.pid, ns.phase = 0, "stopped"
    if st:
        fab = st.nodes.get("fabric")
        if not left and fab and fab.pid and state.pid_alive(fab.pid):
            from .orchestrator import _kill
            _kill(fab.pid)
            fab.pid, fab.phase = 0, "stopped"
            emit("the lab switch and router: off")
        state.save(st)
    return left


def stop_on_exit(lab, accel: str, emit=print, wait: float = SHUTDOWN_WAIT) -> dict[str, list[str]]:
    """The desktop is stopping: each running machine's Automatic Stop
    Action, as Hyper-V runs them when its host shuts down. Returns the plan
    that was carried out."""
    from .orchestrator import Orchestrator, OrchestratorError, _acpi_powerdown, _kill
    st = state.load(lab.name)
    running = st.running() if st else {}
    plan = exit_plan(lab, running)
    if not any(plan.values()):
        return plan
    for nid in plan["off"]:
        emit(f"{naming.display(lab, nid)}: turning off")
        _kill(running[nid].pid)
    for nid in plan["shutdown"]:
        emit(f"{naming.display(lab, nid)}: shutting down")
        _acpi_powerdown(running[nid].qmp_port)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline and any(state.pid_alive(running[n].pid) for n in plan["shutdown"]):
        time.sleep(1.0)
    for nid in plan["shutdown"]:
        if state.pid_alive(running[nid].pid):
            emit(f"{naming.display(lab, nid)}: did not shut down in time; turning off")
            _kill(running[nid].pid)
    st = state.load(lab.name)
    if st:
        for nid in plan["off"] + plan["shutdown"]:
            if nid in st.nodes:
                st.nodes[nid].pid, st.nodes[nid].phase = 0, "stopped"
        state.save(st)
    orch = Orchestrator(lab, accel=accel or (st.accel if st else "") or "tcg", display="none")
    if plan["save"]:
        emit(f"saving {', '.join(naming.display(lab, n) for n in plan['save'])}…")
        try:
            orch.suspend(only=plan["save"], emit=emit)
        except OrchestratorError as exc:
            emit(str(exc))
    if not orch.running_states() or set(orch.running_states()) <= {"fabric"}:
        orch.down()
    return plan


def view(lab, node, alive: bool, pid: int, accel: str = "") -> dict:
    """The Settings dialog's extra fields for one machine."""
    from . import mediashelf, nestedvirt
    nd = _node_dir(lab.name, node.id)
    can, why = _nested_support(accel)
    return {
        "paused": alive and is_paused(lab.name, node.id, pid),
        "saved_state": (nd / "saved.vmstate").exists(),
        "services": services(node),
        "stop_action": stop_action(node),
        "checkpoints_on": checkpoints_on(node),
        "boot": mediashelf.boot_first(nd),
        "dvd_drives": mediashelf.drives(node),
        "nested": bool(node.nested),
        "nested_fitted": nestedvirt.fitted(node),
        "nested_can": can, "nested_why": why,
        "firmware": _firmware_view(lab, node, accel),
        "min_memory_mb": node.memory_floor_mb,
        "macs": [static_mac(lab, node, i) for i in range(len(node.nics))],
        "trunks": [list(n.trunk) for n in node.nics],
        "installed": naming.installed(lab.name, node.id),
    }


def _firmware_view(lab, node, accel: str) -> dict | None:
    """The Security page and the Firmware page's boot mode (winlab/firmware.py)."""
    from . import firmware
    try:
        return firmware.view(lab, node, accel or "tcg")
    except Exception as exc:  # noqa: BLE001 - a probe must not break the desktop
        return {"error": str(exc)}


_SUPPORT: dict[str, tuple[bool, str]] = {}


def _nested_support(accel: str) -> tuple[bool, str]:
    if accel not in _SUPPORT:
        from .nestedvirt import host_support
        try:
            _SUPPORT[accel] = host_support(accel or "tcg")
        except Exception as exc:  # noqa: BLE001 - a probe must not break the desktop
            _SUPPORT[accel] = (False, str(exc))
    return _SUPPORT[accel]


# ------------------------------------------------------------ the dialog
def apply_settings(dash, node_id: str, params: dict) -> list[str]:
    """The management pages and the firmware, processor and adapter
    settings the older node-set does not carry. Returns what changed."""
    from . import editor, mediashelf, nestedvirt
    lab = dash.lab
    node = lab.nodes.get(node_id)
    if node is None:
        raise VmError(f"no machine {node_id!r} in this lab")
    st = state.load(lab.name)
    running = set(st.running()) if st else set()
    done: list[str] = []

    def flag(key: str) -> bool | None:
        v = params.get(key)
        return None if v in (None, "") else str(v) in ("1", "true", "True")

    want = {k: flag("svc_" + k) for k, _t in SERVICES}
    want = {k: v for k, v in want.items() if v is not None}
    if want and want != {k: v for k, v in services(node).items() if k in want}:
        set_services(node, want)
        done.append("integration services")
    act = params.get("stop_action")
    if act not in (None, "") and act != stop_action(node):
        if act not in STOP_ACTIONS:
            raise VmError("the automatic stop action is save, off or shutdown")
        node.vars["stop_action"] = act
        done.append("automatic stop action")
    cp = flag("checkpoints")
    if cp is not None and cp != checkpoints_on(node):
        if cp:
            node.vars.pop(CHECKPOINTS_OFF, None)
        else:
            node.vars[CHECKPOINTS_OFF] = True
        done.append("checkpoints " + ("on" if cp else "off"))
    nested = flag("nested")
    if nested is not None and nested != bool(node.nested):
        from .nestedvirt import NestedError
        try:
            done.append(nestedvirt.set_vtx(lab, node_id, nested, dash.accel or "tcg", running))
        except NestedError as exc:
            raise VmError(str(exc)) from exc
    fw, tpl = params.get("firmware"), params.get("secure_boot_template")
    if fw not in (None, "") or tpl not in (None, ""):
        from . import firmware
        try:
            msg = firmware.set_firmware(lab, node_id, str(fw or firmware.wanted(node, firmware._uefi_default(node))),
                                        dash.accel or "tcg", running, str(tpl or ""))
        except firmware.FirmwareError as exc:
            raise VmError(str(exc)) from exc
        if "unchanged" not in msg:
            done.append(msg.split(": ", 1)[1] if ": " in msg else msg)
    for key, val in params.items():
        if not str(key).startswith("mac"):
            continue
        idx = int(str(key)[3:] or 0)
        if not 0 <= idx < len(node.nics):
            raise VmError(f"{node_id} has no network adapter {idx + 1}")
        mac = check_mac(val) if val else ""
        if mac != static_mac(lab, node, idx):
            node.nics[idx].mac = mac
            done.append(f"adapter {idx + 1} MAC address " + (mac or "dynamic"))
    boot = params.get("boot")
    nd = _node_dir(lab.name, node_id)
    if boot not in (None, "") and boot != mediashelf.boot_first(nd):
        try:
            mediashelf.set_boot(lab.name, node, boot)
        except mediashelf.ShelfError as exc:
            raise VmError(str(exc)) from exc
        done.append("boot order: " + ("DVD drive" if boot == mediashelf.BOOT_DVD else "hard drive") + " first")
    if done:
        try:
            editor.save(lab)
        except editor.EditError as exc:
            dash.reload()
            raise VmError(str(exc)) from exc
        dash.reload()
    return done


def act(dash, action: str, params: dict) -> dict:
    lab = dash.lab
    node_id = naming.resolve(lab, str(params.get("node") or "")) if params.get("node") else ""
    try:
        if action == "vm-pause":
            return {"ok": True, "message": pause(lab, node_id)}
        if action == "vm-resume":
            return {"ok": True, "message": resume(lab, node_id)}
        if action == "vm-reset":
            return {"ok": True, "message": reset(lab, node_id)}
        if action == "vm-shutdown":
            return {"ok": True, "message": shut_down(lab, node_id)}
        if action == "vm-discard":
            return {"ok": True, "message": discard_saved(lab, node_id)}
        if action == "vm-settings":
            done = apply_settings(dash, node_id, params)
            live = _ns(lab.name, node_id) is not None
            return {"ok": True, "message": (f"{naming.display(lab, node_id)}: {', '.join(done)}"
                                            + ("; the rest at its next start" if live else ""))
                    if done else "nothing to change"}
        if action == "vm-lab-shutdown":
            def run(emit):
                left = shut_down_lab(dash.lab, emit)
                emit("still running: " + ", ".join(left) if left else "the lab is shut down")
            jid = dash.jobs.start("shutdown", run)
            return {"ok": True, "job": jid, "message": "shutting the lab down, one machine at a time…"}
    except VmError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": f"unknown action {action!r}"}
