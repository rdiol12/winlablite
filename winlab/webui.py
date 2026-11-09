"""Unified local control plane. Stdlib http.server on loopback, zero deps.

One dashboard drives everything: host check, runtime bootstrap, image import +
base preparation, lab lifecycle, machine consoles, role application, live lab
editing, exercises + grading, network faults, snapshots and licensing. Long
operations (bootstrap, install, role apply) stream their log over Server-Sent
Events so the page shows progress live.

The CLI remains the scriptable backend; the GUI calls the same functions.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import re
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, appwindow, drawio, edition, hardware, hostprobe, images, media, naming, netplan, paths, state, viewer, wsbridge
from . import trialparts as _trialparts
from .providers.qemu import hardware_of
from .model import Lab
from .schema import LabError
from .schema import load as load_lab

LAST_LAB = paths.VAR / "last-lab"
FALLBACK_LAB = "ad-ds-basics"


EDIT_WAIT = 60.0  # seconds a change waits for the one before it


def _file_stamp(p) -> tuple:
    """What changes when a file is written: its size and modification time."""
    try:
        st = Path(p).stat()
    except (OSError, TypeError):
        return ()
    return (st.st_mtime_ns, st.st_size)


def lab_names() -> list[str]:
    """Labs in the content pack, by name."""
    from . import content
    return sorted(p.stem for p in content.glob(paths.CONTENT / "labs", "*.toml"))


def default_lab() -> str:
    """The lab the desktop opens with no argument: the last one opened on
    this PC if it still exists, otherwise the starter lab."""
    try:
        name = LAST_LAB.read_text(encoding="utf-8").strip()
    except OSError:
        name = ""
    if name and name in lab_names():
        return name
    names = lab_names()
    return FALLBACK_LAB if FALLBACK_LAB in names else (names[0] if names else FALLBACK_LAB)


DESKTOP_PREFS = paths.VAR / "desktop.json"


def desktop_prefs() -> dict:
    try:
        return json.loads(DESKTOP_PREFS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def set_desktop_pref(key: str, value) -> None:
    prefs = desktop_prefs()
    if value in (None, "", False):
        prefs.pop(key, None)
    else:
        prefs[key] = value
    DESKTOP_PREFS.parent.mkdir(parents=True, exist_ok=True)
    DESKTOP_PREFS.write_text(json.dumps(prefs, indent=2), encoding="utf-8")


def remember_lab(name: str) -> None:
    try:
        LAST_LAB.parent.mkdir(parents=True, exist_ok=True)
        LAST_LAB.write_text(name + "\n", encoding="utf-8")
    except OSError:
        pass

PAGE_PATH = Path(__file__).resolve().parent / "webui_page.html"


def page_bytes() -> bytes:
    """The desktop page; winlab core tells it which windows to leave out
    before its script runs (winlab/edition.py)."""
    page = PAGE_PATH.read_bytes()
    if not edition.is_core():
        return page
    tag = ("<script>window.WINLAB_EDITION='core';window.WINLAB_HIDDEN="
           + json.dumps(list(edition.CORE_HIDDEN_WINDOWS)) + ";</script>")
    return page.replace(b"<head>", b"<head>" + tag.encode(), 1)

DOCS = {"README": "README.md", "CURRICULUM": "CURRICULUM.md", "LICENSING": "LICENSING.md", "EULA": "EULA.txt"}

_MIME = {".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".html": "text/html; charset=utf-8",
         ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png",
         ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8"}


# Long jobs by name: a label for the tray and the Setup window, and how long
# they usually take, so the bar can estimate when the job itself cannot report.
JOB_INFO = {
    "bootstrap": (("Set up QEMU from this PC's packages" if sys.platform.startswith("linux")
                   else "Fetch the QEMU runtime"), 300),
    "install-qemu": ("Install QEMU with the package manager", 300),
    "kvm-access": ("Give this user access to KVM", 60),
    "prepare-fabric": ("Prepare the network fabric base", 600),
    "viewer": ("Fetch the console viewer", 60),
    "virtio-fetch": ("Fetch the virtio drivers", 600),
    "appliance-fetch": ("Fetch the appliance image", 600),
    "pack-fetch": ("Fetch the package pack", 180),
    "app-update": ("Download and install the winlab update", 300),
    "exporter-fetch": ("Fetch the Windows exporter", 60),
    "wac-fetch": ("Fetch Windows Admin Center", 420),
    "mailclient-fetch": ("Fetch Thunderbird", 240),
    "wireshark-fetch": ("Fetch Wireshark", 240),
    "toolkit-fetch": ("Fetch the admin toolkit", 120),
    "toolkit-sysinternals-fetch": ("Fetch the Sysinternals Suite", 90),
    "toolkit-windbg-fetch": ("Fetch WinDbg", 240),
    "webmin-fetch": ("Fetch Webmin", 180),
    "termshark-fetch": ("Fetch Termshark", 60),
    "ctrimages-fetch": ("Fetch the container images", 300),
    "k3s-fetch": ("Fetch k3s", 300),
    "dockerwin-fetch": ("Fetch Docker for Windows", 90),
    "kubeadm-fetch": ("Fetch Kubernetes for kubeadm", 900),
    "helm-fetch": ("Fetch Helm", 60),
    "dbclients-fetch": ("Fetch the database clients", 420),
    "idsrules-fetch": ("Fetch the ET Open rules", 120),
    "azure-fetch": ("Fetch the lab's Azure (floci-az, restic, rest-server, the Azure CLI, AzCopy, Bicep)", 420),
    "aws-fetch": ("Fetch the lab's AWS (moto, the AWS CLI)", 300),
    "wireguard-fetch": ("Fetch WireGuard for Windows", 60),
    "dscmodules-fetch": ("Fetch the DSC modules", 120),
    "glpiagent-fetch": ("Fetch the GLPI Agent", 60),
    "softphone-fetch": ("Fetch MicroSIP, the softphone", 60),
    "secops-fetch": ("Fetch security operations media", 900),
    "drop": ("Copy a file into a machine", 60),
    "roles": ("Apply roles", 900),
    "roles-test": ("Test for drift", 120),
    "export": ("Export the lab", 900),
    "import": ("Import a lab", 600),
    "up": ("Start the lab", 600),
    "suspend": ("Save the lab", 300),
    "shutdown": ("Shut down the lab", 600),
    "get-ready": ("Get everything ready", 1500),
    "iso-import": ("Import the Windows ISO", 240),
    "linuxiso-fetch": ("Fetch a Linux installer DVD", 900),
    "fwiso-fetch": ("Fetch a firewall installer", 600),
    "netos-fetch": ("Fetch a vendor router image", 600),
    "netos-import": ("Import a vendor router image", 600),
    "mecm-prepare": ("Build the Configuration Manager disc", 1800),
    "inherited-handover": ("Hand over the company", 5400),
    "aidc-handover": ("Hand over the data center", 3600),
    "enable-whp": ("Turn on Windows Hypervisor Platform", 120),
}
# A job reports its own overall percent with this prefix (Jobs records it and
# shows nobody the line): Get everything ready runs steps that each count
# from 0 to 100 and must not move the bar backwards.
PCT_LINE = "\x00pct:"


def _toolkit_summary() -> dict:
    from . import toolkit  # PuTTY, WinSCP, Notepad++, Sysinternals: the admin toolkit stick
    return toolkit.summary()


def _wireshark_summary() -> dict:
    from . import wireshark  # Wireshark, for the Wireshark stick
    return wireshark.summary()
# The Setup steps Get everything ready runs by itself, in Setup's order: all
# of them download from a publisher or build from what is already on this PC.
AUTO_JOBS = ("bootstrap", "prepare", "virtio-fetch", "appliance-fetch", "pack-fetch", "exporter-fetch",
            "wac-fetch", "linuxiso-fetch", "fwiso-fetch", "netos-fetch", "mailclient-fetch", "ctrimages-fetch", "k3s-fetch",
            "dockerwin-fetch", "kubeadm-fetch", "helm-fetch", "dbclients-fetch", "dscmodules-fetch", "idsrules-fetch",
            "azure-fetch", "aws-fetch", "wireguard-fetch",
            "wireshark-fetch", "webmin-fetch", "glpiagent-fetch", "secops-fetch", "termshark-fetch",
            "softphone-fetch")
for _img in images.WINDOWS_IMAGES:
    JOB_INFO[f"prepare-{_img}"] = (f"Prepare the {images.CATALOG[_img].short} base",
                                   1800 if _img.endswith("-core") else 2700)
_PCT = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d)?)\s?%")
_NM = re.compile(r"\[(\d+)/(\d+)\]")
KEEP_DONE = 900.0  # finished jobs stay listed this long, so the desktop can notice them


class Jobs:
    """Tracks running streamed operations so SSE clients can attach, and keeps
    a record per job (progress, elapsed, outcome) for the desktop's tray."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queues: dict[str, queue.Queue] = {}
        self._records: dict[str, dict] = {}
        self._seq = 0

    def start(self, name: str, target) -> str:
        with self._lock:
            self._seq += 1  # two clicks in the same millisecond are two jobs
            job_id = f"{name}-{int(time.time() * 1000)}-{self._seq}"
        q: queue.Queue = queue.Queue()
        label, typical = JOB_INFO.get(name, (name.replace("-", " "), 600))
        rec = {"id": job_id, "name": name, "label": label, "typical": typical,
               "started": time.time(), "finished": 0.0, "ok": None, "percent": None, "last": "",
               "params": {}}
        with self._lock:
            self._queues[job_id] = q
            self._records[job_id] = rec
            self._prune()

        def emit(line: str) -> None:
            if line.startswith(PCT_LINE):
                try:
                    rec["percent"] = max(0, min(100, int(line[len(PCT_LINE):])))
                except ValueError:
                    pass
                return
            q.put(line)
            text = line.strip()
            if text:
                rec["last"] = text[-160:]
                m = _NM.search(text)
                if m and int(m.group(2)):
                    rec["percent"] = round(100 * int(m.group(1)) / int(m.group(2)))
                else:
                    m = _PCT.search(text)
                    if m:
                        rec["percent"] = min(100, int(float(m.group(1))))

        def run() -> None:
            # This job's downloads report to its own bar and print whole,
            # named lines, so parallel fetches don't overwrite each other.
            from .bootstrap import set_progress_sink
            set_progress_sink(emit)
            try:
                target(emit)
                rec["ok"] = True
                q.put("__done__:0")
            except Exception as exc:  # noqa: BLE001 surface any failure to the UI
                from . import applog
                applog.write(f"job {rec.get('name', '')}", str(exc), exc)
                rec["ok"] = False
                rec["last"] = f"error: {exc}"[:160]
                q.put(f"error: {exc}")
                q.put("__done__:1")
            finally:
                rec["finished"] = time.time()

        threading.Thread(target=run, daemon=True).start()
        return job_id

    @staticmethod
    def what(params: dict | None) -> dict:
        """What a job works on (its image, pack or kind), so the same fetch
        pressed twice, or pressed and then reached by Get everything ready,
        is known to be one job."""
        return {k: str(params[k]) for k in ("image", "pack", "kind") if params and params.get(k)}

    def tag(self, job_id: str, params: dict | None) -> None:
        with self._lock:
            rec = self._records.get(job_id)
            if rec is not None:
                rec["params"] = self.what(params)

    def find_running(self, name: str, params: dict | None = None) -> dict | None:
        """The running job of that name working on the same thing, or None."""
        want = self.what(params)
        with self._lock:
            for rec in self._records.values():
                if rec["name"] == name and not rec["finished"] and rec["params"] == want:
                    return rec
        return None

    def record(self, job_id: str) -> dict | None:
        with self._lock:
            return self._records.get(job_id)

    def _prune(self) -> None:
        cut = time.time() - KEEP_DONE
        for jid, rec in list(self._records.items()):
            if rec["finished"] and rec["finished"] < cut:
                self._records.pop(jid, None)
                # A job nobody streamed keeps its whole log in its queue.
                self._queues.pop(jid, None)

    def list(self) -> list[dict]:
        """Every running job and the recently finished ones, newest last, with
        a percent that is real when the job reported one and estimated from
        the typical duration otherwise."""
        now = time.time()
        out = []
        with self._lock:
            self._prune()
            recs = sorted(self._records.values(), key=lambda r: r["started"])
        for r in recs:
            end = r["finished"] or now
            elapsed = int(end - r["started"])
            if r["finished"]:
                pct, est = (100 if r["ok"] else r["percent"]), False
            elif r["percent"] is not None:
                pct, est = r["percent"], False
            else:
                pct, est = min(95, int(100 * elapsed / max(1, r["typical"]))), True
            out.append({"id": r["id"], "name": r["name"], "label": r["label"], "elapsed": elapsed,
                        "typical": r["typical"], "done": bool(r["finished"]), "ok": r["ok"],
                        "percent": pct, "estimated": est, "last": r["last"]})
        return out

    def stream(self, job_id: str):
        with self._lock:
            q = self._queues.get(job_id)
        if q is None:
            yield "error: no such job"
            return
        while True:
            try:
                line = q.get(timeout=30)
            except queue.Empty:
                yield ":keepalive"
                continue
            if line.startswith("__done__:"):
                yield line
                break
            yield line
        with self._lock:
            self._queues.pop(job_id, None)


def _glpiagent_summary() -> dict:
    from . import doctools  # the GLPI Agent MSI: the GLPI Agent stick
    return doctools.summary()["agent"]


def _softphone_summary() -> dict:
    from . import softphone  # MicroSIP: the softphone stick for the lab's Windows PCs
    return softphone.summary()


def _vpnclient_summary() -> dict:
    from . import remoteaccess  # WireGuard for Windows: the VPN client stick
    return remoteaccess.summary()


def _dbclients_summary() -> dict:
    from . import databases  # pgAdmin, HeidiSQL, psqlODBC: the database clients stick
    return databases.summary()


def _secops_summary() -> dict:
    from . import secops  # Greenbone, 7-Zip and Chocolatey, the Wazuh agent, the SCT zips
    return secops.summary()


def _azure_summary() -> dict:
    from . import azure  # the lab's Azure on cloud01: floci-az, restic, rest-server
    return azure.summary()


def _aws_summary() -> dict:
    from . import aws  # the lab's AWS: moto on cloud01, the AWS CLI on ops01
    return aws.summary()


def _idsrules_summary() -> dict:
    from . import ids  # ET Open for the Suricata sensor: the Suricata rules stick
    return ids.summary()


class Dashboard:
    def __init__(self, lab: Lab, accel: str = "") -> None:
        self.lab = lab
        self.plan = netplan.compile_topology(lab, check_ports=False)
        self._accel = accel
        self.jobs = Jobs()
        self._lock = threading.Lock()
        # One change at a time: the desktop answers requests on many threads,
        # and two edits of the same lab at once lose one of them.
        self._edit_lock = threading.RLock()
        self._stamp = _file_stamp(lab.source_path)
        from .procstats import Meter
        self.meter = Meter()
        from .workbench import Live
        self.wb_live = Live()

    # -------------------------------------------------------------- reload
    def reload(self) -> None:
        """Re-read the lab TOML after an edit so the GUI reflects changes."""
        self.lab = load_lab(self.lab.source_path or self.lab.name)
        self.plan = netplan.compile_topology(self.lab, check_ports=False)
        self._stamp = _file_stamp(self.lab.source_path)

    def refresh(self) -> bool:
        """Read the lab file again if something else changed it since the
        desktop last did (`winlab node add` in a terminal, a hand edit), so
        the next change made here builds on it instead of writing over it.
        True when it was read again."""
        now = _file_stamp(self.lab.source_path)
        if not now or now == self._stamp:
            return False
        try:
            self.reload()
        except LabError as exc:  # a half-typed hand edit: keep what we have, say so once
            if getattr(self, "_bad_stamp", None) != now:
                self._bad_stamp = now
                from . import applog
                applog.write("lab file", f"{self.lab.name}: not read again, it does not load: {exc}")
            return False
        return True

    def refresh_if_idle(self) -> None:
        """refresh() for the windows' polling, skipped while a change runs."""
        if self._edit_lock.acquire(blocking=False):
            try:
                self.refresh()
            finally:
                self._edit_lock.release()

    @property
    def accel(self) -> str:
        if not self._accel:
            self._accel = hostprobe.probe().accel
        return self._accel

    # --------------------------------------------------------------- state
    def _post_screen(self, node, alive: bool, pid: int):
        from . import pcbuild
        try:
            return pcbuild.screen(self.lab.name, node.id, alive, pid) if pcbuild.form_of(node) else None
        except Exception:  # noqa: BLE001 - a bad record never breaks the desktop
            return None

    def snapshot(self) -> dict:
        from . import debpacks, evaluation, vmctl
        from . import images as im
        st = state.load(self.lab.name)
        clocks = evaluation.cached(self.lab.name)
        tpl_ids = set(im.templates())
        nodes = []
        for node_id in ["fabric"] + [n.id for n in self.lab.node_list()]:
            node = self.lab.nodes.get(node_id)
            ns = st.nodes.get(node_id) if st else None
            alive = bool(ns and ns.pid and state.pid_alive(ns.pid))
            if node_id == "fabric":
                kind, roles, addr = "fabric", ["switch", "router"], "lab0"
            else:
                assert node is not None
                primary = node.primary_nic
                addr = (primary.ip if primary and primary.ip else "dhcp") if primary else "-"
                kind, roles = node.kind, node.roles
            devices = ([{"kind": d.kind, "name": d.name} for d in node.devices]
                       if node else [])
            clock = clocks.get(node_id)
            usage = self.meter.usage(ns.pid, node.cpus if node else self.plan.fabric_cpus) \
                if alive else None
            nodes.append({
                "id": node_id, "kind": kind, "roles": roles, "addr": addr,
                "name": naming.hostname_of(node) if node else "fabric",
                "name_default": naming.default_hostname(node_id) if node else "fabric",
                "name_fixed": bool(node and naming.keeps_its_name(node)
                                   and naming.installed(self.lab.name, node_id)),
                "running": alive, "phase": ns.phase if ns else "stopped",
                "suspended": bool(ns and not alive and ns.phase == state.SUSPENDED),
                "wait_ready": bool(node and node.wait_ready),
                "start_delay": node.start_delay if node else 0,
                "serial": ns.serial_port if ns else 0,
                "vnc": (ns.vnc_port if ns and alive else 0),
                "term": bool(ns and alive and ns.term_port),
                "wterm": bool(ns and alive and getattr(ns, "wterm_port", 0)),
                "devices": devices,
                "image": node.image if node else "alpine",
                "os": self._os_name(node),
                "template": bool(node and node.image in tpl_ids),
                "core": bool(node and node.is_server_core),
                "cpus": node.cpus if node else self.plan.fabric_cpus,
                "memory_mb": node.memory_mb if node else self.plan.fabric_memory_mb,
                "boot_order": node.boot_order if node else 0,
                "data_disks_gb": list(node.data_disks_gb) if node else [],
                "nics": ([{"network": n.network, "ip": n.ip or ""} for n in node.nics]
                         if node else []),
                "iso": str(node.vars.get("iso") or "") if node else "",
                "usb_gb": int(node.vars.get("usb_storage_gb") or 0) if node else 0,
                "gpu": bool(node.vars.get("gpu")) if node else False,
                "hardware": (hardware_of(node) if node else "virtio"),
                "hardware_set": node.hardware if node else "",
                "lean": bool(node and node.lean),
                "stick": bool(node and media.stick_path(self.lab.name, node.id).exists()),
                "pulled": (sorted(hardware.pulled(self.lab.name, node.id, len(node.data_disks_gb)))
                           if node else []),
                "packs": ([{"id": p.id, "title": p.title, "ready": debpacks.ready(p.id)}
                           for p in debpacks.PACKS.values() if p.image == node.image]
                          if node and node.kind == "linux" else []),
                "description": node.description if node else "",
                # The Settings dialog's own pages (winlab/vmctl.py).
                "vm": vmctl.view(self.lab, node, alive, ns.pid if ns else 0, self._accel) if node else None,
                # What its screen shows before Windows: POST, beeps, no signal (winlab/pcbuild.py).
                "post": self._post_screen(node, alive, ns.pid if ns else 0) if node else None,
                "usage": ({"cpu_pct": usage.cpu_pct, "rss_mb": usage.rss_mb}
                          if usage else None),
                "eval": ({"days": clock.days_left, "rearms": clock.rearms_left,
                          "warn": clock.warn, "text": evaluation.describe(clock)}
                         if clock and clock.evaluation else None),
            })
        return {
            "lab": self.lab.name, "domain": self.lab.domain,
            "description": self.lab.description, "accel": self._accel or "?",
            "sandbox": self.lab.sandbox,
            "workbench": self.lab.workbench,
            # The inherited company scenario and the locked server room
            # (winlab/inherited.py, winlab/serverroom.py).
            "inherited": self.lab.inherited,
            # The AI data center scenario (winlab/aidc.py): pre-built too.
            "aidc": self._is_aidc(),
            "room": self._room_view(),
            "lean": self.lab.lean,
            "running": sum(1 for n in nodes if n["running"]), "total": len(nodes),
            "suspended": sum(1 for n in nodes if n["suspended"]),
            "autostart": desktop_prefs().get("autostart") == self.lab.name,
            "nodes": nodes, "exercises": edition.lab_exercises(self.lab.exercises),
            "names": naming.as_lab_names(self.lab),
            # The lab's own Administrator password: the dashboard is loopback
            # only and the person at the keyboard is the one who owns the lab.
            "admin_password": self.lab.admin_password,
            "viewer_ready": viewer.ready(),
            "version": __version__,
            "host": self._host_memory(),
        }

    def _room_view(self) -> dict | None:
        from . import serverroom
        return serverroom.view(self.lab) if self.lab.server_room else {"on": False}

    def inherited(self) -> dict:
        """The Inherited company window: the handover and its notes, the 30 days' lessons."""
        from . import inherited
        return inherited.view(self.lab)

    def _is_aidc(self) -> bool:
        from . import aidc
        return aidc.is_aidc(self.lab)

    def aidc(self) -> dict:
        """The AI data center window: the handover, the machines, the notes, the drills."""
        from . import aidc
        return aidc.view(self.lab)

    def stream_aidc_handover(self):
        def run(emit):
            from . import aidc, oncall
            aidc.handover(self.lab, aidc.guest_runner(self.lab.name), aidc.role_builder(self.lab, self.plan),
                          oncall.running_nodes(self.lab), emit=emit)
        return run

    def stream_inherited_handover(self):
        def run(emit):
            from . import inherited, oncall
            inherited.handover(self.lab, inherited.guest_runner(self.lab.name),
                               inherited.role_builder(self.lab, self.plan), oncall.running_nodes(self.lab), emit=emit)
        return run

    def _host_memory(self) -> dict:
        total, avail = hostprobe._memstatus()
        return {"total_mb": int(total / (1024**2)), "free_mb": int(avail / (1024**2)),
                "cores": os.cpu_count() or 0}

    def host(self) -> dict:
        r = hostprobe.probe()
        self._accel = r.accel
        return {
            "accel": r.accel, "confirmed": r.accel_confirmed,
            "ram_gb": round(r.ram_gb, 1), "cores": r.cores,
            "free_gb": round(r.free_gb, 1), "qemu": r.qemu_present,
            "blockers": r.blockers, "warnings": r.warnings,
            "findings": [{"key": f.key, "value": f.value, "status": f.status,
                          "note": f.note} for f in r.findings],
        }

    def images(self) -> dict:
        from . import images as im
        out = []
        for image_id in im.CATALOG:   # the catalog's order: newest first, Desktop before Core
            s = im.status(image_id)
            e = s["entry"]
            out.append({
                "id": image_id, "title": e.title, "short": e.short, "kind": e.kind,
                "license": e.license, "mode": e.mode, "page": e.page,
                "edition": s.get("edition", ""),
                "base": bool(s["base"]), "base_gb": round(s["base_gb"], 1),
                "installer": bool(s["installer"]), "installer_gb": round(s["installer_gb"], 1),
                "installer_retired": bool(s.get("installer_retired")),
                "virtio": bool(s.get("virtio")),
                "appliance": bool(s.get("appliance")), "fetched": s.get("fetched", ""),
                "note": e.note,
            })
        custom = [{"id": c.id, "title": c.title, "firmware": c.firmware,
                   "disk_gb": c.disk_gb, "present": c.iso.exists()}
                  for c in im.custom_images().values()]
        tpls = [{"id": t.id, "title": t.title, "kind": t.kind, "source": t.source,
                 "size": t.size_text, "present": t.disk.exists(),
                 "generalized": t.generalized, "cpus": t.cpus, "memory_mb": t.memory_mb,
                 "disk_gb": t.disk_gb, "data_disks_gb": t.data_disks_gb,
                 "created": t.created}
                for t in im.templates().values()]
        from . import debpacks, exporters, virtio, wac
        vman = virtio.manifest()
        packs = [debpacks.status(pid) for pid in debpacks.PACKS]
        from . import containers, mail  # Thunderbird; container images, k3s, Docker for Windows
        return {"store": str(paths.images_dir()), "images": out, "custom": custom,
                "templates": tpls, "packs": packs, "pack_store": str(paths.RUNTIME / "packs"),
                "exporter": exporters.summary(), "wac": wac.summary(), "mailclient": mail.summary(),
                "wireshark": _wireshark_summary(),
                "toolkit": _toolkit_summary(),
                "containers": containers.summary(),
                "dbclients": _dbclients_summary(),
                "idsrules": _idsrules_summary(),
                "azure": _azure_summary(),
                "aws": _aws_summary(),
                "vpnclient": _vpnclient_summary(),
                "glpiagent": _glpiagent_summary(),
                "softphone": _softphone_summary(),
                "secops": _secops_summary(),
                "virtio": {"ready": all(virtio.ready(i) for i in virtio.IMAGE_DIRS),
                           "version": vman.get("version", ""),
                           "fetched": vman.get("fetched", ""), "url": virtio.URL}}

    def segments(self) -> list[dict]:
        return [{"id": s.network.id, "cidr": s.network.cidr, "vlan": s.vid,
                 "gateway": s.network.router_ip}
                for s in sorted(self.plan.segments.values(), key=lambda x: x.vid)]

    def topology(self) -> dict:
        """The Network map: every cable, switch port and router interface the
        fabric is built from, plus each machine's complete setup, so the map
        can show the whole lab the way a network diagram and a device's
        properties sheet would. Live state (running, phase, screen) stays in
        /api/state; the map joins the two by machine id."""
        from . import images as im
        from . import mapview
        plan, lab = self.plan, self.lab
        from . import sites as _sites
        # Sites keep their segments together on the map, the WAN between them.
        site_rank = {sid: i * 2 for i, sid in enumerate(lab.sites)}
        segs = sorted(plan.segments.values(),
                      key=lambda s: (1 if s.network.wan and lab.sites else site_rank.get(s.network.site, 0), s.vid))
        tpl_ids = set(im.templates())
        running = set()
        st = state.load(lab.name)
        if st:
            running = {nid for nid, ns in st.nodes.items() if ns.pid and state.pid_alive(ns.pid)}
        fabric_up = "fabric" in running

        switches = []
        for seg in segs:
            net = seg.network
            ports = []
            for i, link in enumerate(seg.members):
                ports.append({"port": i + 1, "node": link.node_id, "nic": link.nic_index,
                              "iface": link.fabric_iface, "mode": link.mode,
                              "trunk": list(link.trunk_vlans), "tcp": link.port,
                              "up": link.node_id in running})
            tagged = [{"node": l.node_id, "nic": l.nic_index, "iface": l.fabric_iface,
                       "native": l.network_id}
                      for l in plan.links if net.id in l.trunk_vlans]
            imp = net.impair
            switches.append({
                "id": net.id, "vlan": seg.vid, "vlan_auto": not net.vlan,
                "cidr": net.cidr, "netmask": net.netmask, "prefixlen": net.prefixlen,
                "gateway": net.router_ip, "svi": seg.svi, "wan": net.wan,
                "site": net.site, "description": net.description,
                "dhcp": netplan.dhcp_mode(plan, seg),
                "relay_to": sorted(set(seg.relay_to)),
                "ports": ports, "tagged": tagged,
                "impair": ({"delay_ms": imp.delay_ms, "jitter_ms": imp.jitter_ms,
                            "loss_pct": imp.loss_pct, "rate_mbit": imp.rate_mbit}
                           if imp.active else None),
            })

        interfaces = [{"name": seg.svi, "network": seg.network.id, "vlan": seg.vid,
                       "ip": seg.network.router_ip, "prefixlen": seg.network.prefixlen,
                       "cidr": seg.network.cidr, "up": fabric_up}
                      for seg in segs]
        routes = [{"destination": seg.network.cidr, "via": "connected",
                   "interface": seg.svi, "vlan": seg.vid}
                  for seg in segs]
        dhcp = []
        for seg in segs:
            net = seg.network
            mode = netplan.dhcp_mode(plan, seg)
            entry = {"network": net.id, "mode": mode, "interface": seg.svi}
            if mode == "fabric":
                lo, hi = netplan.dhcp_range(net)
                entry.update({"range": f"{lo} - {hi}", "lease": "8h", "router": net.router_ip,
                              "dns": netplan.dns_for(plan, net), "domain": lab.domain})
            elif mode == "relay":
                entry.update({"relay_to": sorted(set(seg.relay_to)), "relay_via": seg.relay_via})
            elif mode == "server":
                entry["servers"] = sorted(
                    n.id for n in lab.nodes.values()
                    if "dhcp" in n.roles and any(x.network == net.id for x in n.nics))
            dhcp.append(entry)
        site_entries, site_routes = [], []
        for site in lab.sites.values():
            gw = _sites.gateway_of(lab, site.id)
            tun = _sites.tunnel_for(lab, gw.node.id) if gw else None
            site_entries.append({
                "id": site.id, "description": site.description, "gateway": site.gateway,
                "prefixes": _sites.prefixes_of(lab, site.id),
                "networks": [n.id for n in _sites.networks_of(lab, site.id)],
                "table": netplan.site_table(lab, site.id),
                "inside_ip": gw.inside_ip if gw else "", "inside_network": gw.inside_network if gw else "",
                "outside_ip": gw.outside_ip if gw else "", "outside_network": gw.outside_network if gw else "",
                "peer": tun.peer_node if tun else "", "peer_site": tun.peer_site if tun else "",
                "peer_ip": tun.peer_outside_ip if tun else "",
                "gateway_os": ("Windows RRAS, IKEv2 site-to-site" if gw and gw.node.is_windows
                               else "strongSwan, IKEv2" if gw else ""),
            })
            for other in lab.sites.values():
                if other.id == site.id:
                    continue
                for cidr in _sites.prefixes_of(lab, other.id):
                    site_routes.append({
                        "table": netplan.site_table(lab, site.id), "site": site.id,
                        "destination": cidr, "to_site": other.id,
                        "via": gw.inside_ip if gw else "", "gateway": gw.node.id if gw else "",
                        "interface": plan.segment_of(gw.inside_network).svi if gw else "",
                    })
        fwv = self.firewall_view()
        own_by_seg = {t["id"]: t["own"] for t in fwv["segments"]}
        for sw in switches:
            sw["nsg"] = {"enabled": fwv["enabled"] and not sw["wan"],
                         "own": own_by_seg.get(sw["id"], 0)}
        router = {
            "id": "fabric", "title": "lab router and switch", "os": "Alpine Linux (diskless)",
            "cpus": plan.fabric_cpus, "memory_mb": plan.fabric_memory_mb,
            "bridge": netplan.BRIDGE, "ports": plan.fabric_link_count,
            "running": fabric_up,
            "interfaces": interfaces, "routes": routes,
            "default_route": None,
            "dhcp": dhcp,
            "impairments": [{"network": s["id"], **s["impair"]} for s in switches if s["impair"]],
            "zones": [s["id"] for s in switches if s["wan"]],
            "sites": site_entries, "site_routes": site_routes,
            "firewall": fwv,
            "script": netplan.render_fabric_setup(plan),
        }

        machines = []
        for node in lab.node_list():
            nics = []
            for link in plan.links_for(node.id):
                nic = node.nics[link.nic_index]
                net = lab.networks[nic.network]
                seg = plan.segment_of(nic.network)
                dns = list(nic.dns)
                if not dns and nic.dhcp:
                    dns = netplan.dns_for(plan, net)
                nics.append({
                    "index": link.nic_index, "network": nic.network,
                    "ip": nic.ip or "", "dhcp": nic.dhcp, "prefixlen": net.prefixlen,
                    "netmask": net.netmask, "gateway": net.router_ip, "dns": dns,
                    "mac": nic.mac, "trunk": list(nic.trunk), "mode": link.mode,
                    "vlan": seg.vid, "iface": link.fabric_iface, "tcp": link.port,
                    "port": seg.members.index(link) + 1,
                })
            virtio = (node.is_windows and node.vars.get("virtio") is not False
                      and im.base_virtio(node.image)) or node.kind == "linux"
            os_name = Dashboard._os_name(node)
            if node.kind != "custom" and node.image in tpl_ids:
                os_name = f"{os_name} (from template {node.image})"
            machines.append({
                "id": node.id, "kind": node.kind, "core": node.is_server_core,
                "image": node.image, "template": node.image in tpl_ids, "os": os_name,
                "hostname": naming.hostname_of(node), "domain": lab.domain,
                "site": _sites.site_of_node(lab, node.id),
                "gateway_of": next((x.id for x in lab.sites.values() if x.gateway == node.id), ""),
                "cpus": node.cpus, "memory_mb": node.memory_mb,
                "memory_floor_mb": node.trim_floor_mb,
                "recommended": dict(zip(("cpus", "memory_mb"), node.recommended_hardware)),
                "min_memory_mb": node.memory_floor_mb,
                "data_disks_gb": list(node.data_disks_gb),
                "roles": list(node.roles),
                "devices": [{"kind": d.kind, "name": d.name, "shared": d.shared,
                             "location": d.location} for d in node.devices],
                "boot_order": node.boot_order, "lean": node.lean,
                "virtio": bool(virtio), "description": node.description,
                "iso": str(node.vars.get("iso") or ""),
                "usb_gb": int(node.vars.get("usb_storage_gb") or 0),
                "gpu": bool(node.vars.get("gpu")),
                "vars": {k: v for k, v in node.vars.items()
                         if isinstance(v, (str, int, float, bool))},
                "nics": nics,
            })

        return {
            "lab": lab.name, "domain": lab.domain, "description": lab.description,
            "sandbox": lab.sandbox, "router": router, "switches": switches,
            "machines": machines, "map_layout": mapview.positions(lab),
            "isolation": {"links": plan.fabric_link_count, "host_bridged": 0, "user_mode": 0,
                          "text": f"{plan.fabric_link_count} loopback cables, no path to this PC or the internet"},
        }

    def roles_catalog(self) -> dict:
        from . import roles
        man = roles.load_manifest()
        # Which roles each node requests, for the UI to show "who gets what".
        by_node = {n.id: list(n.roles) for n in self.lab.node_list()}
        return {
            "roles": [{"id": r.name, "description": r.description,
                       "needs": r.needs, "reboots": r.reboots}
                      for r in sorted(man.values(), key=lambda x: x.name)],
            "by_node": by_node,
        }

    def labs(self) -> list[dict]:
        """Every lab in the content pack, for the Start menu; the ones a
        licence unlocks are listed too, marked locked."""
        from . import content, mylabs
        out = []
        for name in lab_names():
            try:
                lab = load_lab(name)
            except LabError as exc:
                out.append({"name": name, "description": f"broken: {exc}", "machines": 0,
                            "running": 0, "active": False, "broken": True, "mine": not mylabs.shipped(name)})
                continue
            st = state.load(name)
            running = sum(1 for ns in (st.nodes.values() if st else [])
                          if ns.pid and state.pid_alive(ns.pid))
            out.append({"name": name, "description": lab.description, "domain": lab.domain,
                        "mine": not mylabs.shipped(name),
                        "sandbox": lab.sandbox, "workbench": lab.workbench,
                        "machines": len(lab.nodes), "running": running,
                        "suspended": len(st.suspended()) if st else 0,
                        "active": name == self.lab.name})
        for p in content.locked_in(paths.CONTENT / "labs"):
            out.append({"name": p.stem, "description": content.meta(p).get("description", ""),
                        "machines": 0, "running": 0, "suspended": 0, "active": False, "locked": True})
        return out

    def exercises(self) -> list[dict]:
        from . import exercises as ex
        return [{"id": e.id, "title": e.title, "checks": len(e.checks),
                 "lab": e.lab, "brief": e.brief, "tasks": e.tasks}
                for e in ex.list_available()]

    @staticmethod
    def _os_name(node) -> str:
        """What the machine runs, for its tile and console title."""
        if node is None:
            return "Alpine Linux (switch, router)"
        from . import imaging
        if imaging.is_netboot(node):
            return "No operating system (boots from the network)"
        from . import netos
        if netos.is_disk_router(node):
            return f"{images.CATALOG[node.image].short} (the vendor's own OS)"
        if images.is_hand_install(node):
            return f"{images.CATALOG[node.image].short} (installed by hand)"
        if node.kind == "custom":
            return f"Your ISO: {node.image}"
        root = images.catalog_root(node.image)
        if root:
            return root.short
        return {"linux": "Linux"}.get(node.kind, node.kind)

    def running_job(self, name: str) -> str:
        """The id of a job of that name still running, or ''."""
        for j in self.jobs.list():
            if j["name"] == name and not j["done"]:
                return j["id"]
        return ""

    def same_job(self, name: str, params: dict) -> str:
        """The job already doing this fetch: the same one pressed earlier, or
        Get everything ready on that very step. '' when there is none."""
        if name not in AUTO_JOBS:
            return ""
        rec = self.jobs.find_running(name, params)
        if rec is not None:
            return rec["id"]
        plan = getattr(self, "ready", None) or {}
        gr = self.running_job("get-ready")
        if gr and plan.get("job") == [name, Jobs.what(params)]:
            return gr
        return ""

    def _mark_running(self, steps: list[dict]) -> list[dict]:
        """Each step a job is doing right now carries that job's percent, so
        Setup shows it running instead of offering its button again."""
        plan = getattr(self, "ready", None) or {}
        gr = self.running_job("get-ready")
        for st in steps:
            if not st.get("job") or st.get("done"):
                continue
            rec = self.jobs.find_running(st["job"], st)
            if rec is not None:
                st["running"] = rec["percent"] or 0
            elif gr and plan.get("job") == [st["job"], Jobs.what(st)]:
                st["running"] = int(100 * plan.get("part", 0))
        return steps

    def setup_state(self, quick: bool = False) -> dict:
        out = self._setup_state(quick)
        self._mark_running(out["steps"])
        return out

    def _setup_state(self, quick: bool = False) -> dict:
        """What's configured vs. what the first-run flow should prompt for.
        quick skips the host probe (PowerShell, the accelerator test) and only
        looks for the files each step leaves behind."""
        from . import images as im
        if quick:
            r = hostprobe.HostReport(accel=self._accel or hostprobe.ACCEL_TCG)
            r.qemu_present = paths.qemu_exe().exists()
        else:
            r = hostprobe.probe()
            self._accel = r.accel
        alp = im.status("alpine")
        st = state.load(self.lab.name)
        running = bool(st and st.running())
        # The Windows bases this lab's machines boot from: the first one (the
        # forest root DC's, in boot order) is the main step; the rest, Server
        # Core, another Server version or a client, each get their own.
        wanted: list[str] = []
        for n in self.lab.node_list():
            if n.is_windows and n.image in im.CATALOG and n.image not in wanted:
                wanted.append(n.image)
        primary = wanted[0] if wanted else "ws2025"
        ws = im.status(primary)
        main = im.CATALOG[primary]
        extra_steps = []
        for img in wanted[1:]:
            cur = im.status(img)
            who = ", ".join(n.id for n in self.lab.node_list() if n.image == img)
            shared = im.SHARES_INSTALLER.get(img, img)
            retired = bool(cur.get("installer_retired")) or (
                shared != img and bool(im.status(shared).get("installer_retired")))
            if cur["installer"] or cur["base"]:
                hint = f"{who} boot from it"
            elif retired:
                hint = (f"{who} boot from it; it installs from the {shared} ISO, whose copy was "
                        f"removed after that base was prepared: import your download again")
            else:
                hint = f"{who} boot from it; import the {shared} ISO first"
            extra_steps.append({
                "id": f"prepare-{img}", "label": f"Prepare the {im.CATALOG[img].title} base",
                "done": bool(cur["base"]),
                "blocked": not cur["installer"] and not cur["base"],
                "hint": hint, "link": im.CATALOG[img].page, "image": img,
                "job": "prepare" if cur["installer"] else "import",
            })
        from . import virtio
        virtio_ready = all(virtio.ready(i) for i in wanted) if wanted else True
        extra_steps += self._appliance_steps()
        extra_steps += self._media_steps()
        extra_steps += self._download_steps()
        from . import linuxiso  # the Linux installer DVDs this lab's machines boot
        extra_steps += linuxiso.setup_steps(self.lab)
        from . import bsdfw  # the firewall installers this lab's firewalls boot
        extra_steps += bsdfw.setup_steps(self.lab)
        from . import netos  # the vendor router images this lab's routers run
        extra_steps += netos.setup_steps(self.lab)
        from . import android  # the Android-x86 installer this lab's phones and tablets boot
        extra_steps += android.setup_steps(self.lab)
        from . import mail  # packs installed by hand, Thunderbird for the PCs
        extra_steps += mail.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import webmin, wireshark  # the appliances' Webmin, Wireshark for the PCs
        extra_steps += webmin.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import termshark  # the capture probe's packet view
        extra_steps += termshark.setup_steps(self.lab, {s["id"] for s in extra_steps})
        extra_steps += wireshark.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import containers  # images, k3s and Docker for Windows for the containers lab
        extra_steps += containers.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import databases  # pgAdmin, HeidiSQL and psqlODBC for the Windows machines
        extra_steps += databases.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import ids  # the ET Open rules for the Suricata sensor
        extra_steps += ids.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import azure  # floci-az, restic and rest-server for the azure-hybrid lab's cloud01
        extra_steps += azure.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import aws  # moto and the AWS CLI for the aws-cloud lab
        extra_steps += aws.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import remoteaccess  # WireGuard for Windows for the home worker's laptop
        extra_steps += remoteaccess.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import softphone  # MicroSIP for the PCs that answer the lab's phone system
        extra_steps += softphone.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import automation  # the DSC modules for the automation lab's admin box
        extra_steps += automation.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import doctools  # the GLPI Agent for the it-docs lab's Windows machines
        extra_steps += doctools.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import secops  # Greenbone, the software to deploy, the toolkit for the security-ops lab
        extra_steps += secops.setup_steps(self.lab, {s["id"] for s in extra_steps})
        from . import itops  # the Windows exporter stick for the servers the student's Prometheus watches
        extra_steps += itops.setup_steps(self.lab, {s["id"] for s in extra_steps})
        return {
            "qemu": r.qemu_present,
            "accel": r.accel,
            "virtio": virtio_ready,
            "fabric_base": bool(alp["base"]),
            "windows_base": bool(ws["base"]),
            "windows_installer": bool(ws["installer"]),
            "lab_running": running,
            "steps": [
                {"id": "bootstrap", "label": JOB_INFO["bootstrap"][0],
                 "done": r.qemu_present, "job": "bootstrap",
                 "hint": ("QEMU, the UEFI firmware and swtpm from your distribution (installed with its "
                          "package manager if missing; it asks for your password), and the viewers the "
                          "desktop uses" if sys.platform.startswith("linux") else
                          "the portable QEMU build and the tools of the lab router, fetched "
                          "onto this PC once (nothing is shipped inside winlab)")},
                {"id": "fabric", "label": "Prepare the network fabric base",
                 "done": bool(alp["base"]), "job": "prepare", "image": "fabric",
                 "blocked": not r.qemu_present,
                 "hint": "the Alpine Linux switch and router every lab runs on, about 60 MB"},
                {"id": "virtio", "label": "Fetch the virtio drivers (Red Hat)",
                 "done": virtio_ready, "job": "virtio-fetch",
                 "hint": "network and disk drivers the Windows bases get at preparation; "
                         "fetched on its own when a base is prepared, about 600 MB once"},
                {"id": "windows", "label": f"Import + prepare the {main.short} base",
                 "done": bool(ws["base"]),
                 "blocked": not ws["installer"] and not ws["base"],
                 "hint": (main.note if primary == "win10" else
                          f"Download the free {main.short} evaluation ISO from Microsoft, "
                          f"then import it as {primary}"),
                 "link": main.page, "image": primary,
                 "job": "prepare" if ws["installer"] else "import"},
                *extra_steps,
                {"id": "up", "label": "Start the lab",
                 "done": running},
            ],
            "bases_ready": bool(ws["base"]) and all(s["done"] for s in extra_steps),
            "media": self._windows_media(wanted or [primary]),
            "linux_media": linuxiso.setup_rows(self.lab),
            "fw_media": bsdfw.setup_rows(self.lab),
            "router_media": netos.setup_rows(self.lab),
            "get_ready_job": self.running_job("get-ready"),
        }

    def _windows_media(self, wanted: list[str]) -> list[dict]:
        """The Windows downloads this lab needs from Microsoft, one per ISO
        (a Server ISO serves its Desktop and its Core base): Setup's
        "Get Windows" part."""
        from . import images as im
        out: list[dict] = []
        for img in wanted:
            iso = im.SHARES_INSTALLER.get(img, img)
            row = next((m for m in out if m["image"] == iso), None)
            who = [n.id for n in self.lab.node_list() if n.image == img]
            if row:
                row["who"] += [w for w in who if w not in row["who"]]
                row["base"] = row["base"] and bool(im.status(img)["base"])
                continue
            e = im.CATALOG[iso]
            cur = im.status(iso)
            out.append({"image": iso, "title": e.title, "short": e.short, "page": e.page,
                        "note": e.note if iso == "win10" else "",
                        "iso": bool(cur["installer"]), "base": bool(im.status(img)["base"]),
                        "who": who})
        for m in out:
            m["needed"] = not m["iso"] and not m["base"]
        return out

    def _appliance_steps(self) -> list[dict]:
        """Setup steps for this lab's Linux appliances: the image from its
        publisher, then the packs its roles install from."""
        from . import appliances, debpacks, roles
        steps = []
        apps: list[str] = []
        for n in self.lab.node_list():
            if n.kind == "linux" and appliances.is_appliance(n.image) and n.image not in apps:
                apps.append(n.image)
        try:
            manifest = roles.load_manifest()
        except roles.RoleError:
            manifest = {}
        for image_id in apps:
            app = appliances.get_or_raise(image_id)
            who = ", ".join(n.id for n in self.lab.node_list() if n.image == image_id)
            steps.append({
                "id": f"appliance-{image_id}", "label": f"Fetch the {app.short} image ({app.publisher})",
                "done": appliances.ready(image_id), "blocked": False,
                "hint": f"{who} boot from it: {app.publisher}'s own image, verified against "
                        f"their checksum file, {'about 30 MB with its packages' if image_id == 'openwrt' else 'about 600 MB'} once",
                "link": app.page, "image": image_id,
                "job": "appliance-fetch",
            })
            packs: list[str] = []
            for n in self.lab.node_list():
                if n.image != image_id:
                    continue
                for r in roles.effective_roles(n):
                    rd = manifest.get(r)
                    # a stick source (the aws pack) has its own fetch step, not a Debian pack's
                    if rd and rd.pack and rd.pack in debpacks.PACKS and rd.pack not in packs:
                        packs.append(rd.pack)
            for pack_id in packs:
                pk = debpacks.PACKS[pack_id]
                users = ", ".join(n.id for n in self.lab.node_list()
                                  if any(manifest.get(r) and manifest[r].pack == pack_id
                                         for r in roles.effective_roles(n)))
                steps.append({
                    "id": f"pack-{pack_id}", "label": f"Fetch the {pack_id} pack ({app.short.split()[0]} archive{' + the vendor repository' if pk.repos else ''})",
                    "done": debpacks.ready(pack_id), "blocked": not appliances.ready(image_id),
                    "hint": f"{pk.title}: packages {users} install offline from a stick, "
                            f"about {pk.typical_mb} MB; needs the {app.short} image first",
                    "pack": pack_id, "job": "pack-fetch",
                })
        return steps

    def _download_steps(self) -> list[dict]:
        """Setup steps for what a Windows role installs from a download
        winlab makes onto this PC (the Prometheus Windows exporter): fetched
        here, carried to the machines on their provisioning volume."""
        from . import roles
        try:
            manifest = roles.load_manifest()
        except roles.RoleError:
            return []
        users: dict[str, list[str]] = {}
        for n in self.lab.node_list():
            if not n.is_windows:
                continue
            try:
                plan = roles.order_roles(roles.effective_roles(n), manifest)
            except roles.RoleError:
                continue
            for download_id in roles.downloads_for(plan):
                users.setdefault(download_id, []).append(n.id)
        steps = []
        for download_id, who in users.items():
            if download_id not in roles.DOWNLOADS:
                continue
            mod = roles.download_module(download_id)
            use = ("run it for the monitoring appliance" if download_id == "windows-exporter"
                   else "install it")
            check = ("verified against its checksum file" if download_id == "windows-exporter"
                     else "its Microsoft signature checked inside the machine")
            steps.append({
                "id": f"download-{download_id}",
                "label": mod.STEP_LABEL,
                "done": mod.ready(), "blocked": False,
                "hint": f"{', '.join(who)} {use}: {mod.LICENSE}, fetched from the publisher onto this PC, "
                        f"{check}, {mod.SIZE_TEXT} once",
                "link": mod.PAGE, "download": download_id, "job": mod.JOB,
            })
        return steps

    def _media_steps(self) -> list[dict]:
        """Setup steps for installation media this lab's roles install from
        inside a machine (the SQL Server ISO): the user downloads and imports
        it; nothing is prepared."""
        from . import images as im, roles
        try:
            manifest = roles.load_manifest()
        except roles.RoleError:
            return []
        steps = []
        for n in self.lab.node_list():
            if not n.is_windows:
                continue
            try:
                plan = roles.order_roles(roles.effective_roles(n), manifest)
            except roles.RoleError:
                continue
            for image_id in roles.media_for(plan, n):
                if any(s["image"] == image_id for s in steps):
                    steps[[s["image"] for s in steps].index(image_id)]["who"].append(n.id)
                    continue
                e = im.CATALOG[image_id]
                steps.append({"id": f"media-{image_id}", "label": f"Import the {e.short} installation media",
                              "done": im.installer_path(image_id).exists(), "blocked": False,
                              "link": e.page, "image": image_id, "who": [n.id], "note": e.note})
        for s in steps:
            who = ", ".join(s.pop("who"))
            note = s.pop("note")
            s["hint"] = f"{who} install{'s' if ',' not in who else ''} from it: {note}"
            s["blocked"] = not s["done"]
            if s["image"] == "mecm" and not s["done"]:
                self._mecm_step(s, who)
        return steps

    def _mecm_step(self, s: dict, who: str) -> None:
        """Configuration Manager media is built here from the student's own
        Microsoft downloads: the step says what is still missing, and once
        everything is found its button builds the disc."""
        from . import mecm
        st = mecm.status()
        s["label"] = "Build the Configuration Manager disc"
        sql = sorted({n for site in self.lab.node_list() if "mecm" in site.roles
                      for n in [str(site.vars.get("sql_server") or "")] if n})
        db = (f" Its database lives on {', '.join(sql)}, so the SQL Server media is needed too." if sql else "")
        names = {"cm": "the Configuration Manager evaluation (run it once so it unpacks to a folder)",
                 "adk": "the Windows ADK installer", "winpe": "its Windows PE add-on",
                 "odbc": "the ODBC Driver 18 for SQL Server (x64 MSI)"}
        still = [v for k, v in names.items() if not st["found"].get(k)]
        if st["missing"]:
            s["hint"] = (f"{who} installs from a disc winlab builds out of your Microsoft downloads. Still to "
                         f"download into Downloads: {', '.join(still) or 'nothing'}; the ADK pages are linked by "
                         "winlab mecm status." + db) if still else (
                         f"{who}: " + "; ".join(st["missing"]) + "." + db)
        else:
            s["hint"] = f"Everything for {who} is in your Downloads: build the disc (about 20 minutes).{db}"
            s["blocked"] = False
            s["job"] = "mecm-prepare"

    def faults(self) -> list[dict]:
        from . import faults as fl
        from . import progress
        done = progress.load()["problems"]
        out = []
        for s in fl.SCENARIOS.values():
            e = done.get("net:" + s.id) or {}
            opened = int(e.get("hints_open") or 0)
            cause = self._cause(True, s.id, opened)
            w = fl.words(s.id)
            out.append({"id": s.id, "title": cause or w["symptom"], "cause": cause, "symptom": w["symptom"],
                        "category": s.category, "teaches": w["teaches"] if cause else "",
                        "hints": len(s.hints), "hints_open": opened, "broken_on": str(e.get("broken_on") or "")})
        return out

    def guest_faults(self) -> list[dict]:
        from . import guestfaults as gf
        from . import progress
        done = progress.load()["problems"]
        params = self._fault_defaults()
        # A card is titled by its symptom; the cause (title, what it teaches)
        # only once solved or the second hint is open.
        out = []
        for s in gf.SCENARIOS.values():
            e = done.get(s.id) or {}
            solved, opened = int(e.get("solved") or 0), int(e.get("hints_open") or 0)
            cause = self._cause(False, s.id, opened, bool(solved))
            w = gf.words(s.id, params)
            out.append({"id": s.id, "title": cause or w["symptom"][:1].upper() + w["symptom"][1:],
                        "cause": cause, "os": s.os, "teaches": w["teaches"] if cause else "",
                        "symptom": w["symptom"], "hints": len(s.hints), "verify": bool(s.verify),
                        "images": list(s.images), "roles": list(s.roles), "solved": solved,
                        "hints_open": opened, "tries": int(e.get("tries") or 0),
                        "broken_on": str(e.get("broken_on") or ""),
                        "break_error": str(e.get("break_error") or "")})
        return out

    def _fault_fits(self, scenario: str, node: str) -> str:
        """Empty when the scenario can run on the machine, else why not."""
        from . import guestfaults as gf
        f = gf.SCENARIOS.get(scenario)
        n = self.lab.nodes.get(node)
        if f is None:
            return f"unknown scenario {scenario}"
        if n is None:
            return f"{node} is not a machine of this lab"
        title = gf.words(scenario, self._fault_defaults())["title"]   # never a raw {placeholder}
        if not gf.applies_to(f, n.kind, n.image):
            where = ", ".join(f.images) if f.images else f.os
            return f"'{title}' is a problem for {where} machines; {node} runs {self._os_name(n)}"
        from . import roles as rl
        if not gf.applies_to(f, n.kind, n.image, rl.effective_roles(n)):
            return f"'{title}' needs a machine with the {' or '.join(f.roles)} role; {node} has none of them"
        return ""

    # ------------------------------------------------------------- lessons
    def _lesson_row(self, lesson, entry: dict) -> dict:
        steps_done = len(entry.get("steps") or [])
        return {
            "id": lesson.id, "title": lesson.title, "summary": lesson.summary,
            "module": lesson.module, "minutes": lesson.minutes, "lab": lesson.lab,
            "node": lesson.node, "role": lesson.role, "exercise": lesson.exercise,
            "problem": lesson.problem, "check": lesson.check_kind,
            "status": entry.get("status", "new"), "best": int(entry.get("best") or 0),
            "attempts": int(entry.get("attempts") or 0),
            "steps_done": steps_done, "steps_total": len(lesson.steps),
            "this_lab": lesson.lab == self.lab.name,
            "nodes": lesson.needed_nodes(),
            "browser": lesson.browser,
            "quiz_total": len(lesson.quiz), "quiz_best": int(entry.get("quiz_best") or 0),
            "quiz_tries": int(entry.get("quiz_tries") or 0),
        }

    def exam(self, exam_id: str) -> dict:
        from . import exams
        try:
            r = exams.readiness(exams.load(exam_id or "az-802"))
        except exams.ExamError as exc:
            return {"error": str(exc)}
        r["exams"] = [{"id": e.id, "title": e.title} for e in exams.list_available()]
        return r

    # ------------------------------------------------------------- exam prep
    def exam_tracks(self) -> dict:
        """The Exam prep page: every track's readiness, its bank, this
        student's last results, and whether a practice exam is open."""
        from . import practice_exam as pe
        self._practice_expire()
        return pe.tracks_view(self.lab.name, self._running())

    def _practice_grader(self):
        from . import practice_exam as pe
        return pe.default_grader(self.lab.name)

    def _practice_expire(self) -> None:
        from . import practice_exam as pe
        s = pe.load_session()
        if s and not s.get("done"):
            pe.expire(s, self._practice_grader())

    def practice(self) -> dict:
        """The open practice exam as the page may see it: no answers before
        submit. A clock that ran out submits it first."""
        from . import practice_exam as pe
        self._practice_expire()
        return pe.client_view(pe.load_session())

    def _practice_act(self, action: str, params: dict) -> dict:
        from . import practice_exam as pe
        grader = self._practice_grader()
        try:
            if action == "practice-start":
                running = self._running()
                labs = str(params.get("labs", "1")) not in ("", "0", "false")
                pe.start(str(params.get("track", "")), int(params.get("questions") or 0) or None,
                         int(params.get("minutes") or 0) or None, lab=self.lab.name,
                         lab_ok=(lambda q: pe.lab_ready(q, self.lab.name, running)) if labs else None)
                return {"ok": True, "message": "the practice exam has started", "exam": pe.client_view(pe.load_session())}
            s = pe.load_session()
            if not s:
                return {"ok": False, "message": "no practice exam is open"}
            if action in ("practice-answer", "practice-flag"):
                picked = params.get("picked")
                flagged = params.get("flagged")
                ok, msg = pe.answer(s, int(params.get("n") or 0),
                                    picked=[int(x) for x in picked] if isinstance(picked, list) else None,
                                    flagged=bool(flagged) if flagged is not None else None, grader=grader)
                v = pe.client_view(s)
                return {"ok": ok, "message": msg, "left": v.get("left", 0), "done": v.get("done", False)}
            if action == "practice-submit":
                pe.submit(s, grader)
                return {"ok": True, "message": "submitted", "exam": pe.client_view(s)}
            if action in ("practice-abandon", "practice-close"):
                pe.abandon()
                return {"ok": True, "message": "closed" if s.get("done") else "the practice exam was abandoned"}
        except (pe.PracticeError, ValueError, TypeError) as exc:
            return {"ok": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001  (an unknown track)
            return {"ok": False, "message": str(exc)}
        return {"ok": False, "message": f"unknown action {action}"}

    # ------------------------------------------------------------- on call
    def _guest_runner(self):
        from . import oncall
        return oncall.guest_runner(self.lab.name)

    def _running(self) -> list[str]:
        from . import oncall
        return oncall.running_nodes(self.lab)

    def oncall(self) -> dict:
        from . import oncall
        shift = oncall.load()
        if shift and not shift.get("done"):
            oncall.check_desk(shift, self._guest_runner())   # closed in the lab's osTicket
            oncall.expire(shift, self._guest_runner(), oncall._now())
        v = oncall.view(shift)
        v["candidates"] = len(oncall.candidates(self.lab, self._running()))
        return v

    def _oncall_act(self, action: str, params: dict) -> dict:
        from . import oncall
        run = self._guest_runner()
        shift = oncall.load()
        if action == "oncall-start":
            if shift and shift.get("done"):
                oncall.save(None)
            try:
                oncall.start(self.lab, self._running(), int(params.get("minutes") or 45),
                             int(params.get("count") or 4), run)
            except (RuntimeError, ValueError) as exc:
                return {"ok": False, "message": str(exc)}
            return {"ok": True, "message": "shift started: the first call is in"}
        if not shift:
            return {"ok": False, "message": "no shift running"}
        if action == "oncall-resolve":
            fixed, msg = oncall.resolve(shift, run)
            return {"ok": True, "fixed": fixed, "message": msg}
        if action == "oncall-escalate":
            return {"ok": True, "message": oncall.escalate(shift, run)}
        if action == "oncall-end":
            if shift.get("done"):
                oncall.save(None)
                return {"ok": True, "message": "shift closed"}
            r = oncall.end(shift, run)
            return {"ok": True, "message": f"shift over: {r['fixed']} of {r['tickets']} fixed, {r['score']} points"}
        return {"ok": False, "message": f"unknown action {action}"}

    # ------------------------------------------------------------- break and fix
    def breakfix(self) -> dict:
        """The Troubleshooting window's Break and fix tab (winlab/breakfix.py)."""
        from . import breakfix
        run = breakfix.load()
        return breakfix.view(run, self.lab, self._running() if not run or run.get("done") else None)

    # ------------------------------------------------------------- job interview
    def interview(self) -> dict:
        """The Troubleshooting window's Job interview tab (winlab/interview.py).
        Each poll hands in a round whose clock ran out and picks up the
        practical's result once break and fix has finished it."""
        from . import interview
        run = interview.load()
        if run:
            interview.expire(run)
            interview.practical_sync(run)
        idle = not run or run.get("done") or interview.current(run) == "practical"
        return interview.view(run, self.lab, self._running() if idle else None)
    # ------------------------------------------------------------- security incident drills
    def incidents(self) -> dict:
        """The Troubleshooting window's Security incidents tab (winlab/incidents.py):
        while a drill runs, each look reads Wazuh and osTicket (at most every 20 s)."""
        from . import incidents
        run = incidents.load()
        running = self._running()
        return incidents.view(run, self.lab, running, self._guest_runner() if run and not run.get("done") else None)

    # ------------------------------------------------------------- the helpdesk queue
    def helpdesk(self) -> dict:
        """The queue for the Helpdesk window and the tray badge. Each poll is
        a beat of the queue (winlab/helpdesk.py tick): callers answer, and
        while it is on a ticket comes in when one is due."""
        from . import helpdesk
        helpdesk.tick(self.lab, self._guest_runner())
        return helpdesk.view(self.lab)

    # ------------------------------------------------------------- help and support
    def help_topics(self) -> dict:
        from . import helptopics
        return helptopics.view()

    def _support_act(self, action: str) -> dict:
        from . import support
        if action == "support-bundle":
            try:
                b = support.make_bundle()
            except OSError as exc:
                return {"ok": False, "message": f"the support file could not be written: {exc}"}
            return {"ok": True, "message": "support file ready", "path": str(b.path),
                    "folder": str(b.path.parent), "name": b.path.name, "kb": round(b.size / 1024),
                    "files": len(b.files), "truncated": len(b.truncated), "email": support.SUPPORT_EMAIL}
        if action == "support-open-folder":
            try:
                support.open_folder()
            except OSError as exc:
                return {"ok": False, "message": f"could not open the folder: {exc}"}
            return {"ok": True, "message": "opened the support folder"}
        return {"ok": False, "message": f"unknown action {action}"}

    # ------------------------------------------------------------- scenario days
    def scenario(self) -> dict:
        from . import scenarios
        st = scenarios.load_state()
        scn = None
        if st:
            try:
                scn = scenarios.load(st["id"])
            except scenarios.ScenarioError:
                scn = None
        if st and scn and not st.get("done"):
            lab = self.lab if self.lab.name == st["lab"] else load_lab(st["lab"])
            from . import oncall
            if scenarios.tick(st, scn, lab, oncall.guest_runner(lab.name)):
                scenarios.save_state(st)
        v = scenarios.view(st, scn)
        v["catalog"] = scenarios.catalog(self.lab.name)
        v["here"] = self.lab.name
        return v

    def _scenario_act(self, action: str, params: dict) -> dict:
        from . import oncall, scenarios
        st = scenarios.load_state()
        if action == "scenario-start":
            try:
                scn = scenarios.load(str(params.get("id", "")))
                if scn.lab != self.lab.name:
                    return {"ok": False, "message": f"{scn.title} runs on the {scn.lab} lab: switch the desktop to it first"}
                if st and st.get("done"):
                    scenarios.save_state(None)
                scenarios.start(scn, self.lab, oncall.running_nodes(self.lab), oncall.guest_runner(self.lab.name))
            except scenarios.ScenarioError as exc:
                return {"ok": False, "message": str(exc)}
            return {"ok": True, "message": f"{scn.title}: the day has started, check your inbox"}
        if not st:
            return {"ok": False, "message": "no scenario running"}
        try:
            scn = scenarios.load(st["id"])
            lab = self.lab if self.lab.name == st["lab"] else load_lab(st["lab"])
        except (scenarios.ScenarioError, LabError) as exc:
            return {"ok": False, "message": str(exc)}
        run = oncall.guest_runner(lab.name)
        if action == "scenario-check":
            res = scenarios.check(st, scn, lab, run)
            n = sum(1 for r in res if r["passed"])
            return {"ok": True, "results": res,
                    "message": f"{n} of {len(res)} open task{'s' if len(res) != 1 else ''} done" if res
                    else "nothing open to check"}
        if action == "scenario-read":
            i = int(params.get("i", -1))
            if 0 <= i < len(st["inbox"]):
                st["inbox"][i]["read"] = True
                scenarios.save_state(st)
            return {"ok": True, "silent": True}
        if action == "scenario-stop":
            if st.get("done"):
                scenarios.save_state(None)
                return {"ok": True, "message": "scenario closed"}
            d = scenarios.finish(st, scn, lab, run, reason="ended")
            return {"ok": True, "message": f"day over: {d['score']} of {d['max']} points"}
        return {"ok": False, "message": f"unknown action {action}"}

    def lessons(self) -> dict:
        from . import lessons as ls
        from . import progress
        allx = ls.list_available()
        data = progress.load()
        modules = []
        for m in ls.by_module(allx):
            rows = [self._lesson_row(l, data["lessons"].get(l.id) or {}) for l in m["lessons"]]
            modules.append({"id": m["id"], "title": m["title"], "blurb": m["blurb"],
                            "lessons": rows,
                            "done": sum(1 for r in rows if r["status"] == "done")})
        from . import review, tracks
        return {"modules": modules, "summary": progress.summary(allx, data),
                "paths": tracks.paths_status(data, allx), "lab": self.lab.name,
                "review": review.status(prog=data, sizes={l.id: len(l.quiz) for l in allx})}

    def firewall_view(self) -> dict:
        """The zone firewall as the router sheet shows it: every segment's
        two tables in evaluation order, defaults included."""
        from . import firewall as fw
        lab = self.lab

        def row(r):
            return {"name": r.name, "priority": r.priority, "direction": r.direction,
                    "segment": r.segment, "source": r.source, "destination": r.destination,
                    "ports": r.ports, "protocol": r.protocol, "action": r.action,
                    "description": r.description, "builtin": r.builtin}
        segments = []
        for net in fw.filtered_segments(lab):
            segments.append({
                "id": net.id, "cidr": net.cidr, "wan": net.wan,
                "own": sum(1 for r in lab.firewall.rules if r.segment == net.id),
                "inbound": [row(r) for r in fw.rules_for(lab, net.id, fw.INBOUND)],
                "outbound": [row(r) for r in fw.rules_for(lab, net.id, fw.OUTBOUND)],
            })
        return {"enabled": lab.firewall.enabled, "vnet": fw.vnet_cidrs(lab),
                "tags": list(fw.TAGS), "priority": [fw.PRIORITY_MIN, fw.PRIORITY_MAX],
                "segments": segments, "own": len(lab.firewall.rules)}

    def _fabric_runner(self):
        from .cli import _fabric_runner
        return _fabric_runner(self.lab.name)

    def _fw_action(self, action: str, params: dict) -> dict:
        from . import editor
        from . import firewall as fw
        from .cli import fw_push
        lab = self.lab
        if action == "fw-verify":
            try:
                v = fw.evaluate(lab, params.get("source", ""), params.get("destination", ""),
                                int(params.get("port") or 0), params.get("protocol", "Tcp"))
            except (fw.FirewallError, ValueError) as exc:
                return {"ok": False, "message": str(exc)}
            return {"ok": True, "message": v.reason, "verdict": v.as_dict()}
        if action == "fw-live":
            run, why = self._fabric_runner()
            if not run:
                return {"ok": False, "message": why}
            try:
                live = fw.read_live(run, lab)
            finally:
                run.close()
            return {"ok": True, "message": "" if live["present"] else
                    "the router has no firewall tables: it booted with the firewall off; "
                    "turn it on and Apply", "live": live}
        try:
            if action == "fw-set":
                on = params.get("enabled") in ("1", "true", "on", True)
                lab.firewall.enabled = on
                msg = "zone firewall on" if on else "zone firewall off"
            elif action == "fw-add":
                r = fw.add_rule(lab, name=params.get("name", ""),
                                priority=int(params.get("priority") or 0),
                                direction=params.get("direction", "inbound"),
                                segment=params.get("segment", ""),
                                source=params.get("source", "Any"),
                                destination=params.get("destination", "Any"),
                                ports=params.get("ports", "*"),
                                protocol=params.get("protocol", "Any"),
                                action=params.get("action", "Allow"),
                                description=params.get("description", ""))
                msg = f"added {r.priority} {r.name} to {r.segment} {r.direction}"
            elif action == "fw-rm":
                name = params.get("name", "")
                try:
                    r = fw.remove_rule(lab, name, params.get("segment", ""))
                    msg = f"removed {r.priority} {r.name} from {r.segment} {r.direction}"
                except fw.FirewallError as exc:
                    run, why = self._fabric_runner()
                    if not run:
                        return {"ok": False, "message": str(exc)}
                    try:
                        n = fw.remove_live(run, lab, name)
                    finally:
                        run.close()
                    if not n:
                        return {"ok": False, "message": f"{exc}; not on the running router either"}
                    return {"ok": True, "message": f"removed {name} from the running router; "
                            f"it was never in the lab definition"}
            elif action == "fw-apply":
                ok, note = fw_push(lab)
                return {"ok": ok, "message": note}
            else:
                return {"ok": False, "message": f"unknown firewall action {action}"}
            editor.save(lab)
        except (fw.FirewallError, editor.EditError, ValueError) as exc:
            self.reload()
            return {"ok": False, "message": str(exc)}
        self.reload()
        ok, note = fw_push(self.lab)
        return {"ok": True, "message": f"{msg}: {note}", "applied": ok}

    def lesson(self, lesson_id: str) -> dict:
        from . import exercises as ex
        from . import guestfaults as gf
        from . import lessons as ls
        from . import progress
        lesson = ls.load(lesson_id)
        entry = progress.load()["lessons"].get(lesson.id) or {}
        out = self._lesson_row(lesson, entry)
        out.update({
            "why": lesson.why, "concepts": lesson.concepts, "steps": lesson.steps,
            "verify": [{"label": v.label, "node": v.node, "cmd": v.cmd} for v in lesson.verify],
            "pitfalls": lesson.pitfalls, "further": lesson.further,
            "steps_ticked": [int(i) for i in (entry.get("steps") or [])],
            # The lesson's machines by what the student called them.
            "names": {n.id: naming.hostname_of(n)
                      for n in naming.for_lab(lesson.lab).lab.nodes.values()},
            "last": int(entry.get("last") or 0),
            "quiz": ls.quiz_view(lesson),
        })
        if lesson.exercise:
            e = ex.load(lesson.exercise)
            out["exercise_detail"] = {"id": e.id, "title": e.title, "brief": e.brief.strip(),
                                      "tasks": e.tasks, "checks": len(e.checks),
                                      "nodes": e.needed_nodes()}
        probs = progress.load()["problems"]
        if lesson.problem:
            f = gf.SCENARIOS[lesson.problem]
            pe = probs.get(f.id) or {}
            opened = int(pe.get("hints_open") or 0)
            # Filled from the lesson's own lab ({subzone} is dev.corp.lab in
            # linux-in-the-domain), whichever lab the app was opened on.
            lp = self._lesson_fault_params(lesson)
            w = gf.words(f.id, lp)
            cause = self._cause(False, f.id, opened, out["status"] == progress.STATUS_DONE, lp)
            out["problem_detail"] = {"id": f.id, "title": cause, "symptom": w["symptom"],
                                     "teaches": w["teaches"] if cause else "", "hints": len(f.hints),
                                     "hints_open": opened, "tries": int(pe.get("tries") or 0),
                                     "broken": pe.get("broken_on") == lesson.node,
                                     "hint_text": [gf.hint(f.id, i, lp)
                                                   for i in range(1, opened + 1)]}
        if lesson.fault:
            from . import faults as fl
            f = fl.SCENARIOS[lesson.fault]
            pe = probs.get("net:" + f.id) or {}
            opened = int(pe.get("hints_open") or 0)
            cause = self._cause(True, f.id, opened, out["status"] == progress.STATUS_DONE)
            fw = fl.words(f.id)
            out["fault_detail"] = {"id": f.id, "title": cause, "symptom": fw["symptom"],
                                   "teaches": fw["teaches"] if cause else "",
                                   "on": lesson.fault_on, "hints": len(f.hints), "hints_open": opened,
                                   "hint_text": [fl.hint(f.id, i) for i in range(1, opened + 1)],
                                   "broken": bool(entry.get("fault_broken")) and not entry.get("fault_restored")}
        # The worked answer opens after a pass or failed gradings, like the
        # last rung of a hint ladder; opening it is kept on the record.
        out["answer_open"] = self._answer_open(entry)
        out["answer_viewed"] = bool(entry.get("answer_viewed"))
        fp = ls.footprint(lesson)
        if fp and fp[0]:
            st = state.load(lesson.lab)
            alive = sorted(st.running()) if st else []
            out["boot"] = {"nodes": fp[0], "need_mb": fp[1], "floor_mb": fp[2],
                           "running": [n for n in fp[0] if n in alive]}
        return out

    ANSWER_AFTER = 3   # failed gradings before the worked answer opens

    def _answer_open(self, entry: dict) -> bool:
        from . import progress
        return entry.get("status") == progress.STATUS_DONE or int(entry.get("failed") or 0) >= self.ANSWER_AFTER

    def model_answer(self, lesson_id: str = "", node_id: str = "") -> dict:
        from . import lessons as ls
        if lesson_id:
            from . import progress
            lesson = ls.load(lesson_id)
            entry = progress.load()["lessons"].get(lesson.id) or {}
            if not self._answer_open(entry):
                return {"id": lesson.id, "role": lesson.role, "node": lesson.node, "text": "",
                        "error": f"the worked answer opens once the lesson is passed, or after "
                                 f"{self.ANSWER_AFTER} failed Check my work"}
            progress.answer_viewed(lesson.id)
            return {"id": lesson.id, "role": lesson.role, "node": lesson.node,
                    "text": ls.model_answer(lesson)}
        # The whole configuration winlab generates for a machine of this lab.
        from . import dsc, roles
        node = self.lab.nodes.get(node_id)
        if node is None:
            raise LabError(f"no such machine: {node_id}")
        names = [rd.name for rd in roles.order_roles(roles.effective_roles(node), roles.load_manifest())
                 if rd.engine == "dsc"]
        if not names:
            return {"node": node_id, "role": "", "text": f"{node_id} has no desired-state roles"}
        cfg = dsc.compile_node(node, self.lab, self.plan, names)
        return {"node": node_id, "role": ",".join(names), "text": dsc.render(cfg)}

    def progress(self) -> dict:
        from . import lessons as ls
        from . import progress
        data = progress.load()
        return {"summary": progress.summary(ls.list_available(), data), "data": data}

    def viewer_state(self) -> dict:
        from . import castplayer, chartview, elkview, mapview, pixiview, termview
        return {"ready": viewer.ready(), "version": viewer.VERSION,
                "missing": len(viewer.missing()), "total": len(viewer.FILES),
                "dir": str(viewer.viewer_dir()), "term_ready": termview.ready(),
                "term_version": termview.VERSION, "map_ready": mapview.ready(),
                "map_version": mapview.VERSION, "chart_ready": chartview.ready(),
                "chart_version": chartview.VERSION, "cast_ready": castplayer.ready(),
                "cast_version": castplayer.VERSION, "elk_ready": elkview.ready(),
                "elk_version": elkview.VERSION, "elk_adapter_version": elkview.ADAPTER_VERSION,
                "drawio_ready": drawio.ready(), "drawio_version": drawio.VERSION,
                "pixi_ready": pixiview.ready(), "pixi_version": pixiview.VERSION}

    def doc(self, name: str) -> dict:
        fn = DOCS.get(name.upper())
        if not fn:
            raise LabError(f"no such document: {name}")
        names = [fn]
        if fn == "EULA.txt":
            # The licence terms in the student's language when there is a
            # translation (EULA.es.txt ...); the English text governs.
            from . import i18n
            lang = i18n.current()
            if lang and lang != "en":
                names.insert(0, f"EULA.{lang}.txt")
        for f in names:
            for base in (paths.ROOT, paths.APP_DIR, paths.BUNDLE):
                if base and (base / f).exists():
                    return {"name": name.upper(), "text": (base / f).read_text(encoding="utf-8")}
        return {"name": name.upper(), "text": f"{fn} is not next to this winlab install."}

    def update_check(self) -> dict:
        """Help > About's button: ask the feed now and remember the answer."""
        from . import update
        r = update.check()
        update.remember(r)
        return {k: v for k, v in r.items() if k != "manifest"}

    def update_state(self) -> dict:
        from . import update
        return update.view()

    def stream_app_update(self, emit) -> None:
        """Download the newer winlab the last check found, check it, and
        hand over to its installer (Windows), which starts winlab again."""
        from . import update
        manifest = update.settings().get("manifest") or {}
        if not manifest:
            raise update.UpdateError("check for updates first")
        if update.exam_running():
            raise update.UpdateError("an activity with a time limit is running; install the update after it")
        emit(f"downloading winlab {manifest.get('version', '')}")
        last = [-1]

        def progress(got: int, total: int) -> None:
            pct = int(100 * got / total) if total else 0
            if pct != last[0]:
                last[0] = pct
                emit(f"{PCT_LINE}{pct}")
        exe = update.download(manifest, progress=progress)
        emit(f"checked: size and SHA-256 match the signed release ({exe.name})")
        emit("stopping the running labs and starting the installer; winlab starts again when it is done")
        update.install(exe)
        threading.Timer(2.0, lambda: os._exit(0)).start()

    def license(self) -> dict:
        from . import content, licensing
        from .licensing import client
        s = licensing.status()
        try:
            pending = json.loads(client.PENDING_STATE.read_text(encoding="utf-8")).get("message", "")
        except (OSError, ValueError):
            pending = ""
        lifetime = bool(s.expires) and s.expires - time.time() > 50 * 365 * 86400
        return {"state": s.state, "ok": s.ok, "key": s.key, "plan": s.plan, "kind": s.kind, "org": s.org,
                "seats": s.seats, "seats_used": s.seats_used, "message": s.message,
                "expires": 0 if lifetime else s.expires, "lifetime": lifetime or (s.ok and not s.expires),
                "features": s.features, "teacher": licensing.has_feature("teacher", s),
                "fingerprint": licensing.fingerprint(), "buy_url": client.buy_url(),
                "site": client.site_url(), "content": content.mode(), "trial_lab": content.TRIAL_LAB,
                "locked_labs": len(content.locked_in(paths.LABS)), "pending": pending}

    # ------------------------------------------------------------- actions
    def act(self, action: str, params: dict) -> dict:
        if not self._edit_lock.acquire(timeout=EDIT_WAIT):
            return {"ok": False, "busy": True,
                    "message": "winlab is still busy with the change before this one; try again in a moment"}
        try:
            self.refresh()
            from . import history  # disks, media and machine edits outside the workbench
            if action in history.WATCHED:
                return history.recorded(self, action, params, lambda: self._act(action, params))
            return self._act(action, params)
        except LabError as exc:
            return {"ok": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            # Something broke half way: what is in memory may be half changed,
            # so the next change must not save it. Read the file back.
            from . import applog
            applog.write(f"action {action}", str(exc), exc)
            try:
                self.reload()
            except Exception:  # noqa: BLE001
                pass
            return {"ok": False, "message": str(exc)}
        finally:
            self._edit_lock.release()

    def _act(self, action: str, params: dict) -> dict:
        node = params.get("node", "")
        if action == "map-move":
            # The Network map: where the student dragged its devices to.
            from . import mapview
            return mapview.move(self.lab, str(params.get("view", "")), params.get("positions"),
                                reset=bool(params.get("reset")))
        if action in ("lab-up", "boot-node"):
            # The memory check answers right away; the boot itself is a job,
            # since a lab with start-order waits takes minutes to come up.
            return self.start_up([node] if action == "boot-node" else None,
                                 force=bool(params.get("force")))
        if action == "lab-down":
            from .orchestrator import Orchestrator
            orch = Orchestrator(self.lab, accel=self.accel)
            stopped = orch.down()
            kept = state.suspended(self.lab.name)
            return {"ok": True, "message": f"stopped {', '.join(stopped) or 'nothing'}"
                    + (f"; {', '.join(sorted(kept))} stay suspended and resume at their "
                       f"next start" if kept else "")}
        if action in ("lab-suspend", "suspend-node"):
            jid = self.jobs.start("suspend", self.stream_suspend(
                [node] if action == "suspend-node" else None))
            return {"ok": True, "job": jid,
                    "message": f"suspending {node or 'the lab'}…"}
        if action == "firmware-setup":
            from .orchestrator import firmware_setup
            st = state.load(self.lab.name)
            ns = st.nodes.get(node) if st else None
            if not ns or not ns.pid or not state.pid_alive(ns.pid):
                return {"ok": False, "message": f"{node} is off: power it on, then restart it into "
                                                f"its firmware"}
            err = firmware_setup(ns.qmp_port)
            return {"ok": not err, "message": err or f"{naming.display(self.lab, node)} restarts with "
                    f"Esc held: its firmware setup opens on its screen"}
        if action in ("power-button", "power-cut", "power-reset", "power-hold"):
            # The machine's own power button (the OS shuts down, as when it
            # is pressed on a PC), its reset button (it restarts at once),
            # holding the power button four seconds (off at once, as the
            # ATX power supply does) or pulling its plug (off at once).
            from .orchestrator import _acpi_powerdown, _kill
            st = state.load(self.lab.name)
            ns = st.nodes.get(node) if st else None
            if not ns or not ns.pid or not state.pid_alive(ns.pid):
                return {"ok": False, "message": f"{node} is not running"}
            if action == "power-button":
                err = _acpi_powerdown(ns.qmp_port)
                return {"ok": not err, "message": err or f"pressed {naming.display(self.lab, node)}'s "
                        f"power button: it shuts down"}
            if action == "power-reset":
                from . import power
                from .qmp import Qmp, QmpError
                try:
                    with Qmp(ns.qmp_port) as mon:
                        mon.call("system_reset")
                        mon.call("cont")
                except (QmpError, OSError) as exc:
                    return {"ok": False, "message": str(exc)}
                power._unhang(self.lab.name, node)
                power.record(self.lab.name, node, "reset button pressed: it restarts at once", "front panel")
                return {"ok": True, "message": f"pressed {naming.display(self.lab, node)}'s reset button: "
                        f"it restarts at once, unsaved work is lost"}
            _kill(ns.pid)
            ns.pid, ns.phase = 0, "stopped"
            state.save(st)
            if action == "power-hold":
                from . import power
                power._unhang(self.lab.name, node)
                power.record(self.lab.name, node, "power button held four seconds: off at once", "front panel")
                return {"ok": True, "message": f"{naming.display(self.lab, node)} is off: the power button "
                        f"held down cuts it at once, as on a PC"}
            return {"ok": True, "message": f"{naming.display(self.lab, node) if node != 'fabric' else 'the router'} "
                    f"is off (power cut)"}
        if action.startswith("vm-"):
            # Hyper-V Manager's verbs and the Settings dialog (winlab/vmctl.py).
            from . import vmctl
            return vmctl.act(self, action, params)
        if action == "autostart":
            on = params.get("on") in ("1", "true", True)
            set_desktop_pref("autostart", self.lab.name if on else "")
            return {"ok": True, "message": (f"{self.lab.name} starts when winlab opens"
                                            if on else "the lab waits for you to start it")}
        if action == "lesson-up":
            from . import lessons as ls
            lesson = ls.load(params["id"])
            if lesson.browser:
                return {"ok": True, "message": f"{lesson.title} runs in your own browser, "
                                               f"on your own cloud tenant: no machine to start"}
            if lesson.lab != self.lab.name:
                return {"ok": False, "message": f"{lesson.id} runs on lab {lesson.lab}; "
                                                f"this desktop is on {self.lab.name}"}
            return self.start_up(lesson.needed_nodes() or None, force=bool(params.get("force")))
        if action.startswith("wb-"):
            from . import workbench
            return workbench.act(self, action, params)
        if action.startswith("room-"):  # the locked server room (winlab/serverroom.py)
            from . import serverroom
            r = serverroom.act(self.lab, action, params)
            if action == "room-set":
                self.reload()
            return r
        if action == "aidc-handover":  # the AI data center scenario's one pre-built step (winlab/aidc.py)
            if not self._is_aidc():
                return {"ok": False, "message": "only the AI data center scenario is handed over this way: this lab starts empty"}
            jid = self.running_job("aidc-handover") or self.jobs.start("aidc-handover", self.stream_aidc_handover())
            return {"ok": True, "job": jid, "message": "handing over the data center: each machine's role, then the keys, the nodes and the run"}
        if action == "inherited-handover":  # the inherited company scenario's one pre-built step (winlab/inherited.py)
            if not self.lab.inherited:
                return {"ok": False, "message": "only the inherited company scenario is handed over: this lab starts empty"}
            jid = self.running_job("inherited-handover") or self.jobs.start("inherited-handover", self.stream_inherited_handover())
            return {"ok": True, "job": jid, "message": "handing over the company: the domain first, then the predecessor's years"}
        if action.startswith("activity-"):
            from . import activity
            return activity.act(self, action, params)
        if action.startswith("class-"):
            from . import classes
            return classes.act(self, action, params)
        if action.startswith("rec-"):
            # Terminal session recordings (winlab/recordings.py).
            from . import recordings
            return recordings.act(self, action, params)
        if action.startswith("perf-"):
            # Alert rules and the alerts list (winlab/perfmon.py).
            from . import perfmon
            return perfmon.act(self, action, params)
        if action.startswith("remote-"):
            # Remote administration between lab machines (winlab/remoteadmin.py).
            from . import remoteadmin
            return remoteadmin.act(self, action, params)
        if action.startswith("ups-"):
            # The UPS on the bench, the mains, the power-cut drill (winlab/ups.py).
            from . import ups
            return ups.act(self, action, params)
        if action.startswith("power-"):
            # Servers' management ports, a hang, the power history (winlab/power.py).
            from . import power
            return power.act(self, action, params)
        if action.startswith("con-"):
            # The console cable and the serial terminal on its PC (winlab/consolecable.py).
            from . import consolecable
            return consolecable.act(self, action, params)
        if action.startswith("time-"):
            # One machine's clock off lab time; the NTP server's panel (winlab/timesync.py).
            from . import timesync
            return timesync.act(self, action, params)
        if action.startswith("guide-"):
            from . import guide
            return guide.act(self, action, params)
        if action.startswith("san-"):
            # The storage array's front panel (winlab/san.py).
            from . import san
            return san.act(self, action, params)
        if action.startswith("disk-"):
            from . import disks
            return disks.act(self, action, params)
        if action.startswith("bl-"):
            # BitLocker's hardware: the TPM, key sticks, a disk carried off, drills (winlab/bitlocker.py).
            from . import bitlocker
            return bitlocker.act(self, action, params)
        if action.startswith("sysdisk-"):
            # The system disk dies and is replaced (winlab/sysdisk.py).
            from . import sysdisk
            return sysdisk.act(self, action, params)
        if action.startswith("wsb-"):
            # Windows Server Backup and the bare-metal drill (winlab/wsbackup.py).
            from . import wsbackup
            return wsbackup.act(self, action, params)
        if action.startswith("upd-"):
            # The Updates window: packages onto a stick or a disc (winlab/updates.py).
            from . import updates
            return updates.act(self, action, params)
        if action == "node-add":
            from . import editor
            created = editor.add_node(
                self.lab, params["id"], kind=params.get("kind", "windows-server"),
                network=params.get("net", ""), ip=params.get("ip", ""),
                roles=[r for r in params.get("roles", "").split(",") if r],
                image=params.get("image", ""),
                count=int(params.get("count", 1) or 1))
            editor.save(self.lab); self.reload()
            return {"ok": True, "message": f"added {', '.join(n.id for n in created)}"}
        if action == "lab-names":
            return self._names(params)
        if action in ("vswitch-list", "vswitch-set"):  # the Virtual Switch Manager (winlab/vswitch.py)
            from . import vswitch
            if action == "vswitch-set":
                ports = params.get("host_ports")
                if isinstance(ports, str):
                    ports = [p for p in re.split(r"[\s,]+", ports) if p]
                try:
                    vswitch.set_kind(self.lab, str(params.get("network", "")), str(params.get("kind", "")), ports)
                except vswitch.VSwitchError as exc:
                    return {"ok": False, "message": str(exc)}
                self.reload()
            running = "fabric" in self._running()
            return {"ok": True, "switches": vswitch.view(self.lab), "titles": vswitch.TITLES, "text": vswitch.TEXT,
                    "message": ("Saved. The lab router picks it up at its next start." if action == "vswitch-set" else ""),
                    "router_running": running}
        if action == "node-set":
            from . import editor

            if params.get("hostname"):
                return self._rename({node: params["hostname"]})

            def num(key):
                v = params.get(key)
                return int(v) if v not in (None, "") else None

            gpu = params.get("gpu")
            wait = params.get("wait_ready")
            lean = params.get("lean")
            changes = dict(
                cpus=num("cpus"), memory_mb=num("memory_mb"),
                boot_order=num("boot_order"), add_disk_gb=num("add_disk_gb"),
                rm_disk=params.get("rm_disk") in ("1", "true", True),
                add_nic=params.get("add_nic", ""), rm_nic=num("rm_nic"),
                iso=params.get("iso"), usb_storage_gb=num("usb_storage_gb"),
                start_delay=num("start_delay") if "start_delay" in params else None,
                wait_ready=(wait in ("1", "true", True)) if wait is not None else None,
                hardware=params.get("hardware"),
                lean=(lean in ("1", "true", True)) if lean not in (None, "") else None,
                gpu=(gpu in ("1", "true", True)) if gpu is not None else None,
                description=params.get("description"),
            )
            # Only what really differs from the machine as it is: a dialog
            # that sends every field must not count the untouched ones.
            target = self.lab.nodes.get(node)
            if target is None:
                return {"ok": False, "message": f"no such machine {node}"}
            changes = editor.drop_unchanged(target, changes)
            if not changes.get("add_nic"):
                changes.pop("add_nic", None)
            if not changes.get("rm_disk"):
                changes.pop("rm_disk", None)
            if not changes:
                return {"ok": True, "message": "nothing to change"}
            hw = editor.hardware_changes({k: (True if v in ("", False) else v) for k, v in changes.items()})
            if hw and node in state.suspended(self.lab.name):
                return {"ok": False, "message": f"{node} is suspended (saved): resume it "
                        f"before changing {', '.join(hw)}, or it cannot wake"}
            editor.set_node(self.lab, node, **changes)
            editor.save(self.lab); self.reload()
            st = state.load(self.lab.name)
            live = bool(st and node in st.running())
            note = ": takes effect at its next start" if live and set(changes) - {"description"} else ""
            if live and set(changes) - {"description"} == {"iso"}:
                # Only the disc changed: that works on a running machine.
                from . import media
                from .providers.qemu import QemuProvider
                iso = str(self.lab.nodes[node].vars.get("iso") or "")
                try:
                    if iso:
                        media.insert(self.lab.name, node, QemuProvider.iso_path(iso))
                        note = f": {iso} is in the drive"
                    else:
                        media.eject(self.lab.name, node)
                        note = ": the drive is empty"
                except media.MediaError as exc:
                    note = f": {exc}"
            return {"ok": True, "message": f"{node} updated{note}"}
        if action == "nic-set":
            # The Network map's edits: a drag or the machine's sheet.
            from . import editor
            node = naming.resolve(self.lab, node)
            idx = params.get("nic", 0) or 0
            done = []
            if params.get("network"):
                nic = editor.cable(self.lab, node, idx, params["network"], ip=params.get("ip") or None)
                done.append(f"cabled to {nic.network} ({nic.ip or 'DHCP'})")
            if params.get("tag"):
                editor.tag(self.lab, node, idx, params["tag"])
                done.append(f"VLAN {params['tag']} tagged")
            if params.get("untag"):
                editor.untag(self.lab, node, idx, params["untag"])
                done.append(f"VLAN {params['untag']} untagged")
            if not done:
                return {"ok": False, "message": "nothing to change: give a network to cable to, "
                                                "a VLAN to tag or one to untag"}
            editor.save(self.lab); self.reload()
            st = state.load(self.lab.name)
            live = bool(st and node in st.running())
            return {"ok": True, "message": f"{naming.display(self.lab, node)} nic{idx} {', '.join(done)}"
                    + (": takes effect at its next start" if live else "")}
        if action == "lab-lean":
            from . import editor
            on = params.get("on") in ("1", "true", True)
            editor.set_lab_lean(self.lab, on)
            editor.save(self.lab); self.reload()
            return {"ok": True, "message": ("Low-memory profile on: every Windows machine is trimmed at "
                                           "its next configuration" if on else
                                           "stock Windows: the profile is removed at the next configuration")}
        if action in ("net-savepoint", "net-savepoints", "net-restore", "net-point-rm"):
            from . import netfile
            try:
                if action == "net-savepoint":
                    pt = netfile.savepoint(self.lab, str(params.get("note") or ""))
                    return {"ok": True, "message": f"saved this version of {self.lab.name}", "point": pt}
                if action == "net-point-rm":
                    netfile.delete_point(self.lab.name, str(params.get("id") or ""))
                    return {"ok": True, "message": "save point deleted"}
                if action == "net-restore":
                    st = state.load(self.lab.name)
                    netfile.restore(self.lab, str(params.get("id") or ""), bool(st and st.running()))
                    self.reload()
                    return {"ok": True, "message": f"{self.lab.name} is back as it was; "
                            "the version you had is a save point now"}
                return {"ok": True, "points": netfile.savepoints(self.lab.name)}
            except netfile.NetFileError as exc:
                return {"ok": False, "message": str(exc)}
        if action in ("hw-pull", "hw-back", "hw-replace"):
            from . import hardware
            n = self.lab.nodes.get(node)
            if n is None:
                return {"ok": False, "message": f"no such machine {node}"}
            try:
                i = int(params.get("disk", -1))
                if action == "hw-pull":
                    live = hardware.pull(self.lab.name, n, i)
                    return {"ok": True, "message": f"data disk {i + 1} pulled out of {node}"
                            + (": it stops answering now" if live else "; its bay is empty at the next start")}
                if action == "hw-back":
                    hardware.put_back(self.lab.name, n, i)
                    return {"ok": True, "message": f"data disk {i + 1} back in {node}, with its data"}
                from . import disks
                disks.replace(self.lab.name, n, i)  # a new drive: its own serial number
                return {"ok": True, "message": f"a new blank {n.data_disks_gb[i]} GB disk in bay {i + 1} of {node}"}
            except (ValueError, hardware.HardwareError) as exc:
                return {"ok": False, "message": str(exc)}
        if action == "media-blank":
            from . import media
            if node not in self.lab.nodes:
                return {"ok": False, "message": f"no such machine {node}"}
            try:
                r = media.plug_blank(self.lab.name, node, int(params.get("gb", 16)))
            except (ValueError, media.MediaError) as exc:
                return {"ok": False, "message": str(exc)}
            return {"ok": True, "message": f"a blank {r['size_mb'] >> 10} GB stick plugged into {node}"
                    + ("" if r["live"] else " (in the port at its next start)")}
        if action in ("media-drivers", "media-plug", "media-unplug", "media-pack"):
            from . import media
            n = self.lab.nodes.get(node)
            if n is None:
                return {"ok": False, "message": f"no such machine {node}"}
            try:
                if action == "media-unplug":
                    out = media.unplug(self.lab.name, node)
                    return {"ok": True, "message": "stick out" if out else "no stick was plugged in"}
                if action == "media-pack":
                    from . import debpacks, roles
                    pack = debpacks.PACKS.get(params.get("pack", ""))
                    if pack is None or pack.image != n.image:
                        return {"ok": False, "message": "no such package stick for this machine"}
                    try:
                        files = debpacks.pack_files(pack.id)
                    except debpacks.PackError as exc:
                        return {"ok": False, "message": str(exc)}
                    for role_name in pack.roles:
                        files.update(roles.role_stick_files(self.lab, n, role_name))
                    r = media.plug(self.lab.name, node, files, debpacks.STICK_LABEL)
                    from . import editor, openwisp, unifi
                    ctl = {unifi.PACK: unifi, openwisp.PACK: openwisp}.get(pack.id)
                    if ctl is not None and ctl.mark(n):   # the controller's page beside the machine
                        editor.save(self.lab); self.reload()
                elif action == "media-drivers":
                    files = media.driver_files(n.image)
                    if len(files) <= 1:
                        return {"ok": False, "message": "no drivers on this PC yet: fetch the virtio drivers "
                                "in Setup, and put your own packages under images/drivers"}
                    r = media.plug(self.lab.name, node, files, media.STICK_LABEL_DRIVERS)
                else:
                    r = media.plug(self.lab.name, node, media.folder_files(params.get("folder", "")))
                return {"ok": True, "message": f"stick plugged into {node}: {r['files']} files, {r['size_mb']} MB"
                        + ("" if r["live"] else " (in the port at its next start)")}
            except media.MediaError as exc:
                return {"ok": False, "message": str(exc)}
        if action == "node-rm":
            from . import editor
            editor.remove_node(self.lab, node); editor.save(self.lab); self.reload()
            return {"ok": True, "message": f"removed {node}"}
        if action == "net-add":
            from . import editor
            net = editor.add_network(
                self.lab, params["id"], cidr=params.get("cidr", ""),
                vlan=int(params["vlan"]) if params.get("vlan") else None,
                dhcp=params.get("dhcp") in ("1", "true", "on"))
            editor.save(self.lab); self.reload()
            return {"ok": True, "message": f"added network {net.id} {net.cidr}"}
        if action == "net-rm":
            from . import editor
            editor.remove_network(self.lab, params["id"]); editor.save(self.lab); self.reload()
            return {"ok": True, "message": f"removed network {params['id']}"}
        if action == "device-add":
            from . import editor
            d = editor.add_device(self.lab, node, params["kind"], params["name"],
                                  driver=params.get("driver", ""),
                                  location=params.get("location", ""))
            editor.save(self.lab); self.reload()
            return {"ok": True, "message": f"added {d.kind} '{d.name}' to {node}"}
        if action == "device-rm":
            from . import editor
            editor.remove_device(self.lab, node, params["name"])
            editor.save(self.lab); self.reload()
            return {"ok": True, "message": f"removed '{params['name']}' from {node}"}
        if action == "fault":
            return self._fault(params)
        if action.startswith("fw-"):
            return self._fw_action(action, params)
        if action == "guest-fault":
            return self._guest_fault(params)
        if action == "exec":
            from .access import run_exec
            import io, contextlib
            n = self.lab.nodes.get(node)
            shell = "sh" if n is not None and n.kind == "linux" else "powershell"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_exec(self.lab.name, node, params.get("cmd", ""), shell=shell)
            return {"ok": rc == 0, "message": buf.getvalue()[:4000] or f"rc={rc}"}
        if action.startswith("building-"):  # the Building window: put the machines in their rooms
            from . import building
            return building.act(self, action, params)
        if action.startswith("campus-"):  # the Site window: a client job's buildings (winlab/campus.py)
            from . import campus
            return campus.act(self, action, params)
        if action.startswith("rack-"):  # the Rack window (winlab/rack.py)
            from . import rack
            return rack.act(self, action, params)
        if action.startswith("toolkit-"):  # the admin toolkit stick onto the shelf (winlab/toolkit.py)
            from . import toolkit
            return toolkit.act(self, action, params)
        if action.startswith("oncall-"):
            return self._oncall_act(action, params)
        if action.startswith("breakfix-"):
            from . import breakfix
            return breakfix.act(self.lab, action, params, self._guest_runner(), self._running())
        if action.startswith("interview-"):   # job interview mode (winlab/interview.py)
            from . import interview
            return interview.act(self.lab, action, params, self._guest_runner(), self._running())
        if action.startswith("incident-"):
            from . import incidents
            return incidents.act(self.lab, action, params, self._guest_runner(), self._running())
        if action == "itops-add":   # the IT ops server: osTicket and Alertmanager (winlab/itops.py)
            from . import editor, itops
            try:
                node = itops.add(self.lab)
                editor.save(self.lab)
            except (itops.OpsError, editor.EditError) as exc:
                return {"ok": False, "message": str(exc)}
            self.reload()
            return {"ok": True, "message": f"{node.id} added: the IT ops server (osTicket, Prometheus, "
                                           f"Alertmanager); start it, then start taking calls"}
        if action == "itops-stick":  # the Windows exporter for the servers (winlab/itops.py)
            from . import itops
            try:
                r = itops.exporter_stick(self.lab)
            except itops.OpsError as exc:
                return {"ok": False, "message": str(exc)}
            return {"ok": True, "message": f"{r['title']} is on the shelf: plug it into each Windows server",
                    "stick": r["id"]}
        if action.startswith("helpdesk-"):
            from . import helpdesk
            return helpdesk.act(self.lab, action, params, self._guest_runner())
        if action.startswith("practice-"):
            return self._practice_act(action, params)
        if action.startswith("support-"):
            return self._support_act(action)
        if action.startswith("scenario-"):
            return self._scenario_act(action, params)
        if action.startswith(("workday-", "staff-")):
            # The Office window (winlab/workday.py): the staff's working day.
            from . import workday
            return workday.act(self, action, params)
        if action.startswith("load-"):
            # The load engine (winlab/traffic.py): the day's pace, busy days, the servers' own work.
            from . import traffic
            return traffic.act(self, action, params)
        if action.startswith("alerts-"):
            from . import alerts  # on-call alerting: ack, notes, the rota, sources, test page, night shift
            return alerts.act(self, action, params)
        if action.startswith("ops-"):
            from . import company  # the company run, the start of shift and wear (winlab/company.py)
            return company.act(self, action, params)
        if action == "clock":
            # The lab clock (winlab/labclock.py): the time moves at once, the
            # machines' own clocks follow over their agents in a job.
            from . import labclock
            verb, arg = str(params.get("verb", "")), str(params.get("arg", ""))
            if verb not in labclock.VERBS:
                return {"ok": False, "message": f"unknown clock command {verb!r}"}
            if verb in ("jump", "set") and arg.strip().lower() not in ("real", "normal", "now"):
                # A time that does not parse answers now, not in a job.
                labclock.target(arg, labclock.load(self.lab.name), time.time(), ahead_only=verb == "jump")
            jid = self.jobs.start("lab-clock", lambda emit: emit(
                labclock.change(self.lab, verb, arg, emit=emit)))
            return {"ok": True, "job": jid, "message": "moving the lab clock…"}
        if action == "notes-save":
            from . import notes
            r = notes.save(self.lab.name, str(params.get("text", "")))
            return {"ok": True, "message": "notes saved", **r}
        if action == "grade":
            return self._grade(params["id"])
        if action == "lesson-grade":
            from . import lessons as ls
            lesson = ls.load(params["id"])
            if not lesson.exercise:
                return {"ok": False, "message": f"{lesson.id} has no graded exercise"}
            if lesson.fault:
                # A find-the-fault lesson grades only a network the student
                # broke and mended: never one Restore put back.
                from . import progress
                e = progress.load()["lessons"].get(lesson.id) or {}
                if e.get("status") != progress.STATUS_DONE and (not e.get("fault_broken") or e.get("fault_restored")):
                    return {"ok": False, "message": "break the network first (Break the network above), then find "
                            "and fix it yourself: a network put back with Restore is not graded"}
                r = self._grade(lesson.exercise, lesson_id=lesson.id)
                if not r.get("ok"):
                    progress.problem_try("net:" + lesson.fault)
                return r
            return self._grade(lesson.exercise, lesson_id=lesson.id)
        if action == "lesson-quiz":
            from . import lessons as ls
            from . import progress
            lesson = ls.load(params["id"])
            if not lesson.quiz:
                return {"ok": False, "message": f"{lesson.id} has no recall questions"}
            picked = params.get("picked") or []
            if not isinstance(picked, list):
                return {"ok": False, "message": "picked must be a list"}
            r = ls.grade_quiz(lesson, [str(p or "") for p in picked])
            e = progress.record_quiz(lesson.id, r["right"], r["total"])
            return {"ok": True, **r, "best": e["quiz_best"],
                    "message": f"{r['right']} of {r['total']} right"}
        if action == "review-answer":
            from . import review
            picked = params.get("picked") or []
            if not isinstance(picked, (list, dict)):
                return {"ok": False, "message": "picked must be a list"}
            r = review.answer(picked)
            return {"ok": True, **r, "message": f"{r['right']} of {r['total']} right"}
        if action == "lesson-step":
            from . import lessons as ls
            from . import progress
            lesson = ls.load(params["id"])
            e = progress.set_step(lesson.id, int(params.get("index", 0)),
                                  params.get("done") in ("1", "true", "on", True),
                                  total_steps=len(lesson.steps) if lesson.check_kind == "steps" else 0)
            return {"ok": True, "message": "", "status": e["status"], "steps": e["steps"]}
        if action == "lesson-verify":
            from . import lessons as ls
            from .access import run_exec
            import io, contextlib
            lesson = ls.load(params["id"])
            v = lesson.verify[int(params.get("index", 0))]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = run_exec(self.lab.name, v.node or node, v.cmd, shell=v.shell)
            return {"ok": rc == 0, "message": buf.getvalue()[:4000] or f"rc={rc}"}
        if action in ("cert-share", "cert-withdraw"):
            from . import certshare
            try:
                if action == "cert-share":
                    c = certshare.share(str(params.get("track", "")), str(params.get("name", "")))
                    return {"ok": True, "url": c.get("url", ""),
                            "message": "shared: anyone with the link can check this certificate"}
                certshare.withdraw(str(params.get("track", "")))
                return {"ok": True, "message": "the verification link is withdrawn"}
            except certshare.ShareError as exc:
                return {"ok": False, "message": str(exc)}
        if action == "student-name":
            from . import progress
            progress.set_student(str(params.get("name", "")))
            return {"ok": True, "message": "name saved"}
        if action == "lesson-reset":
            from . import progress
            progress.reset(params.get("id", ""))
            return {"ok": True, "message": "progress reset" if not params.get("id")
                    else f"{params['id']} reset"}
        if action in ("guest-fault-hint", "fault-hint"):
            return self._hint_ladder(action == "fault-hint", params)
        if action == "guest-fault-verify":
            return self._guest_fault_verify(params)
        if action == "snap-save":
            from . import snapshots, vmctl
            if node in self.lab.nodes and not vmctl.checkpoints_on(self.lab.nodes[node]):
                return {"ok": False, "message": f"checkpoints are off in {naming.display(self.lab, node)}'s "
                                                f"settings (Checkpoints): turn them on to take one"}
            done = snapshots.save(self.lab.name, params.get("tag", "snap"),
                                  only=[node] if node else None)
            return {"ok": True, "message": f"checkpoint saved on {', '.join(done)}"}
        if action == "snap-restore":
            from . import snapshots
            done = snapshots.restore(self.lab.name, params.get("tag", "snap"),
                                     only=[node] if node else None)
            return {"ok": True, "message": f"reverted {', '.join(done)}"}
        if action == "snap-rm":
            # From one machine's list only that machine's; the whole-lab
            # panel (no node) deletes it everywhere.
            from . import snapshots
            done = snapshots.delete(self.lab.name, params.get("tag", ""),
                                    only=[node] if node else None)
            return {"ok": True, "message": f"deleted from {', '.join(done) or 'nothing'}"}
        if action == "snap-rename":
            from . import snapshots
            name = snapshots.rename(self.lab.name, node, params.get("tag", ""), params.get("name", ""))
            return {"ok": True, "message": f"renamed to {name}"}
        if action == "snap-list":
            from . import snapshots
            return {"ok": True, "message": "", "checkpoints": snapshots.listing(self.lab.name),
                    "tree": snapshots.details(self.lab.name)}
        if action == "node-reset":
            from .orchestrator import Orchestrator
            done = Orchestrator(self.lab, accel=self.accel).reset([node])
            return {"ok": True, "message": f"{node} will be rebuilt from its image on next start"
                    if done else f"{node} had not been built yet"}
        if action == "eval-check":
            from . import evaluation
            c = evaluation.check(self.lab.name, node)
            return {"ok": True, "message": f"{node}: {evaluation.describe(c)}"}
        if action == "eval-rearm":
            from . import evaluation
            return {"ok": True, "message": evaluation.rearm(self.lab.name, node)}
        if action == "template-rm":
            from . import images as im
            im.remove_template(params["image"])
            return {"ok": True, "message": f"removed template {params['image']}"}
        if action == "image-add":
            from . import images as im
            e = im.add_custom(params["image"], params["path"], title=params.get("title", ""),
                              firmware=params.get("firmware", "bios"),
                              disk_gb=int(params.get("disk_gb") or 32))
            return {"ok": True, "message": f"added {e.id}; add a machine of kind custom to use it"}
        if action == "license-activate":
            from . import licensing
            try:
                s = licensing.activate(str(params.get("key", "")))
            except licensing.LicenseError as exc:
                return {"ok": False, "message": str(exc)}
            return {"ok": s.ok, "message": "winlab is activated. Every lab is unlocked." if s.ok else s.message}
        if action == "license-deactivate":
            from . import licensing
            try:
                return {"ok": True, "message": licensing.deactivate(online=not params.get("local"))}
            except licensing.LicenseError as exc:
                return {"ok": False, "message": f"{exc}. The license stays on this PC; try again when it is online."}
        if action == "update-auto":
            from . import update
            update.set_auto(bool(params.get("on")))
            return {"ok": True, "auto": update.auto_enabled()}
        if action == "find-isos":
            from . import readiness
            return {"ok": True, "isos": readiness.find_isos(**({"min_bytes": 100 << 20} if params.get("linux") else {})),
                    "searched": [str(d) for d in readiness.search_dirs()]}
        if action == "pick-folder":
            from . import readiness
            try:
                return {"ok": True, "path": readiness.pick_folder()}
            except (RuntimeError, OSError) as exc:
                return {"ok": False, "message": str(exc)}
        if action == "find-router-files":
            from . import netos, readiness
            return {"ok": True, "files": netos.find_downloads(),
                    "searched": [str(d) for d in readiness.search_dirs()]}
        if action == "pick-iso":
            from . import readiness
            try:
                if params.get("router"):  # a vendor router's disk image or ISO
                    return {"ok": True, "path": readiness.pick_file(
                        "Choose the router image you downloaded",
                        "Router images (*.img;*.zip;*.qcow2;*.vmdk;*.vdi;*.vhdx;*.iso)|"
                        "*.img;*.zip;*.qcow2;*.vmdk;*.vdi;*.vhdx;*.iso|All files (*.*)|*.*")}
                return {"ok": True, "path": readiness.pick_file()}
            except (RuntimeError, OSError) as exc:
                return {"ok": False, "message": str(exc)}
        if action == "restart-pc":
            from . import readiness
            ok, msg = readiness.restart(firmware=bool(params.get("firmware")))
            return {"ok": ok, "message": msg}
        if action == "image-import":
            from . import images as im
            dest = im.import_media(params["image"], params["path"])
            return {"ok": True, "message": f"imported -> {dest}"}
        return {"ok": False, "message": f"unknown action {action!r}"}

    # --------------------------------------------------------------- names
    def _rename(self, wanted: dict, changed: list[str] | None = None) -> dict:
        """New computer names ({machine: name}) and the lab's other names
        already set in `changed`: saved together, then running Windows
        machines rename themselves."""
        from . import editor, naming
        done: list[tuple[str, str, str]] = []
        try:
            for key, name in wanted.items():
                nid = naming.resolve(self.lab, str(key))
                if nid not in self.lab.nodes:
                    raise editor.EditError(f"no such machine {key}")
                name = str(name).strip()
                before = naming.hostname_of(self.lab.nodes[nid])
                if name and name != before:
                    editor.set_node(self.lab, nid, hostname=name)
                    done.append((nid, before, name))
            if done or changed:
                editor.save(self.lab)
        except (editor.EditError, LabError) as exc:
            self.reload()
            return {"ok": False, "message": str(exc)}
        self.reload()
        notes = list(changed or [])
        for nid, before, name in done:
            line = f"{before} is now {name}"
            if self.lab.nodes[nid].is_windows and naming.installed(self.lab.name, nid):
                # Once Windows is installed the name is the student's to
                # change inside it (System > About, or Rename-Computer):
                # winlab only relabels the machine.
                line += (" in winlab; Windows keeps its computer name until you rename it "
                         "inside the machine")
            notes.append(line)
        if not notes:
            return {"ok": True, "message": "nothing to change"}
        return {"ok": True, "message": "; ".join(notes)}

    def _names(self, params: dict) -> dict:
        from . import editor

        def table(key):
            v = params.get(key) or {}
            return {str(k): str(x) for k, x in v.items()} if isinstance(v, dict) else {}

        try:
            changed = editor.set_lab_names(
                self.lab, domain=params.get("domain"), netbios=params.get("netbios"),
                share=params.get("share"), sites=table("sites"), scopes=table("scopes"))
        except editor.EditError as exc:
            self.reload()
            return {"ok": False, "message": str(exc)}
        return self._rename(table("machines"), changed)

    def _grade(self, exercise_id: str, lesson_id: str = "") -> dict:
        from . import exercises as ex
        from . import lessons as ls
        from . import progress
        e = ex.load(exercise_id)
        g = ex.grade(e, self.lab.name)
        if not lesson_id:
            # The Exercises tab graded it directly: credit the lesson it belongs to.
            lesson_id = next((l.id for l in ls.list_available() if l.exercise == e.id), "")
        # A grading where no check could reach its machine is not a try: it
        # neither counts toward the hints nor opens the worked answer.
        ran = any(not r.detail.startswith("check could not run") for r in g.results)
        entry = progress.record_grade(lesson_id, g.percent, g.passed) if lesson_id and ran else {}
        # A failed check's hint (often the command) is the hint ladder's last
        # rung: it shows only after failed gradings (progress.CHECK_HINT_AFTER).
        hints_open = not lesson_id or progress.check_hints_open(lesson_id)
        if not hints_open:
            for r in g.results:
                r.detail = r.detail.split("  |  hint: ")[0]
        try:  # kept with each check's output for a class hand-in (winlab/classes.py)
            from . import classes
            classes.note_grade(e.id, g, self.lab.name)
        except OSError:
            pass
        return {
            "ok": g.passed, "message": ex.render_grade(g, e), "percent": g.percent,
            "earned": g.earned, "total": g.total, "lesson": lesson_id,
            "status": entry.get("status", ""), "hints_open": hints_open,
            "hints_after": progress.CHECK_HINT_AFTER,
            "results": [{"name": r.check.name, "passed": r.passed, "detail": r.detail,
                         "hint": r.check.hint if hints_open else "", "weight": r.check.weight,
                         "node": r.check.node}
                        for r in g.results],
        }

    def _fault_defaults(self) -> dict:
        """Scenario parameters from this lab (guestfaults.lab_params)."""
        from . import guestfaults as gf
        return gf.lab_params(self.lab)

    def _lesson_fault_params(self, lesson) -> dict:
        """Scenario parameters from the lesson's own lab, so its problem card
        names that lab's machines and zones; this lab's when it cannot load."""
        from . import guestfaults as gf
        from . import naming
        lab = self.lab
        if lesson.lab and lesson.lab != self.lab.name:
            try:
                lab = naming.for_lab(lesson.lab).lab
            except Exception:  # noqa: BLE001 - a lab file that no longer loads: this lab's names
                pass
        out = gf.lab_params(lab)
        nd = lab.nodes.get(lesson.node) if lesson.node else None
        if nd is not None:
            out.setdefault("node", nd.hostname or nd.id)   # ladders that say "on {node}"
        return out

    def _hint_ladder(self, network: bool, params: dict) -> dict:
        """The next hint of a problem's ladder, served in order by the server:
        each opens after one more failed try (progress.next_hint). With
        list=1, only the hints already open (to redraw a card)."""
        from . import faults as fl
        from . import guestfaults as gf
        from . import progress
        sc = str(params.get("scenario", ""))
        key = "net:" + sc if network else sc
        try:
            total = len((fl.SCENARIOS if network else gf.SCENARIOS)[sc].hints)
        except KeyError:
            return {"ok": False, "message": f"unknown scenario {sc}"}
        fp = self._fault_defaults()
        if not network and params.get("lesson"):
            from . import lessons as ls
            try:
                fp = self._lesson_fault_params(ls.load(str(params["lesson"])))
            except Exception:  # noqa: BLE001 - an unknown lesson id: this lab's names
                pass
        e = progress.load()["problems"].get(key) or {}
        if not network and "node" not in fp:
            # Some ladders say "on {node}": the machine it was broken on.
            bn = str(e.get("broken_on") or "")
            nd = self.lab.nodes.get(bn)
            fp = {**fp, "node": (nd.hostname or nd.id) if nd is not None else (bn or "the broken machine")}
        fill = (lambda n: fl.hint(sc, n)) if network else (lambda n: gf.hint(sc, n, fp))
        opened = int(e.get("hints_open") or 0)
        if params.get("list") not in ("1", "true", True):
            # A network fault outside a lesson has nothing to verify: its
            # ladder opens once the network is broken.
            gate = not (network and not params.get("lesson"))
            n, why = progress.next_hint(key, total, min_tries=gate)
            if network and not gate and not e.get("broken_on"):
                n, why = 0, "break it first: the hints are about a network that misbehaves"
            if not n:
                return {"ok": False, "message": why, "open": opened, "total": total,
                        "hints": [fill(i) for i in range(1, opened + 1)]}
            progress.hint_used(key, n)
            opened = n
        return {"ok": True, "message": fill(opened) if opened else "", "n": opened, "open": opened,
                "total": total, "hints": [fill(i) for i in range(1, opened + 1)],
                "cause": self._cause(network, sc, opened)}

    def _cause(self, network: bool, sc: str, hints_open: int, solved: bool = False,
               params: dict | None = None) -> str:
        """The problem's real title (its cause): shown once it is fixed or the
        second hint is open; before that the card names only the symptom."""
        from . import faults as fl
        from . import guestfaults as gf
        if not (solved or hints_open >= 2):
            return ""
        if network:
            return fl.words(sc)["title"]
        return gf.words(sc, self._fault_defaults() if params is None else params)["title"]

    def _guest_fault_verify(self, params: dict) -> dict:
        from . import guestfaults as gf
        from . import problemengine as pe_
        from . import progress
        node = params.get("node", "")
        sc = params.get("scenario", "")
        if sc not in gf.SCENARIOS:
            return {"ok": False, "message": f"unknown scenario {sc}"}
        extra = {k: v for k, v in params.items() if k not in ("do", "node", "scenario")}
        p = self._fault_defaults(); p.update(extra)
        why = self._fault_fits(sc, node)
        if why:
            return {"ok": False, "message": why}
        st = state.load(self.lab.name)
        ns = st.nodes.get(node) if st else None
        if not ns or not state.pid_alive(ns.pid):
            return {"ok": False, "message": f"{node} is not running"}
        res = pe_.verify_fix(pe_.guest_runner(self.lab.name), self.lab.name, sc, node, p)
        if res.status not in (pe_.FIXED, pe_.NOT_FIXED):
            # The check never ran (the machine did not answer, a value is
            # missing, another check is running): nothing is counted.
            return {"ok": False, "fixed": False, "status": res.status, "message": res.message}
        fixed = res.status == pe_.FIXED
        pe = progress.load()["problems"].get(sc) or {}
        hints = int(pe.get("hints_open") or 0)
        f = gf.SCENARIOS[sc]
        # Healthy only counts once the problem was broken on this machine:
        # a machine that was never broken is not a fix.
        was_broken = pe.get("broken_on") == node
        if fixed and not was_broken:
            return {"ok": True, "fixed": False,
                    "message": f"{node} checks out healthy, but this problem is not broken on it: "
                               "press Break first, then find and fix it"}
        progress.record_problem(sc, node, fixed, hints)
        if fixed:
            progress.problem_broken(sc, node, False)
            done = self._problem_lessons_done(sc, node)
            return {"ok": True, "fixed": True, "lessons_done": done, "cause": self._cause(False, sc, hints, True),
                    "message": f"fixed: {gf.words(sc, self._fault_defaults())['symptom'].rstrip('.')}: no longer on {node}. The cause was: "
                               f"{self._cause(False, sc, hints, True)}"
                               + (f". Lesson done: {', '.join(done)}" if done else "")}
        tries = int(progress.problem_try(sc).get("tries") or 0)
        # The raw output of the check stays out of the answer: it often names
        # the cause. The student sees that it is not fixed, and how many tries.
        return {"ok": True, "fixed": False, "tries": tries,
                "message": f"not fixed yet: {node} still shows the problem (try {tries})"
                           + ("; the next hint is open to you" if tries > hints and hints < len(f.hints) else "")}

    def _problem_lessons_done(self, sc: str, node: str) -> list[str]:
        """Marks done every lesson of this lab whose problem is sc on this
        machine, once the fix verified (a problem lesson has no exercise)."""
        from . import lessons as ls
        from . import progress
        out = []
        for lesson in ls.list_available():
            if lesson.problem == sc and lesson.lab == self.lab.name and (not lesson.node or lesson.node == node):
                progress.mark(lesson.id, progress.STATUS_DONE)
                out.append(lesson.id)
        return out

    def _guest_fault(self, params: dict) -> dict:
        from . import guestfaults as gf
        from . import problemengine as pe_
        from . import progress
        node = params.get("node", "")
        sc = params.get("scenario", "")
        if sc not in gf.SCENARIOS:
            return {"ok": False, "message": f"unknown scenario {sc}"}
        clear = params.get("clear") in ("1", "true", "on")
        extra = {k: v for k, v in params.items()
                 if k not in ("do", "node", "scenario", "clear")}
        p = self._fault_defaults(); p.update(extra)
        why = self._fault_fits(sc, node)
        if why:
            return {"ok": False, "message": why}
        st = state.load(self.lab.name)
        ns = st.nodes.get(node) if st else None
        if not ns or not state.pid_alive(ns.pid):
            return {"ok": False, "message": f"{node} is not running"}
        f = gf.SCENARIOS[sc]
        if f.host:
            # Broken from outside the machine (a checkpoint reverted): minutes of
            # work, so it runs beside the request; the verify runs inside as usual.
            if clear:
                msg = gf.host_break(sc, self.lab.name, node, True)[1]
                self.reload()   # a break that wrote the lab file (winlab/netbasics.py): the consoles read it again
                return {"ok": False, "message": msg}
            if gf.host_break_is_quick(sc):
                try:
                    ok, msg = gf.host_break(sc, self.lab.name, node)
                except Exception as exc:  # noqa: BLE001 - said, not a crashed request
                    ok, msg = False, f"could not break {node}: {exc}"
                self.reload()
                if ok:
                    progress.problem_broken(sc, node, True)
                return {"ok": ok, "broken": ok,
                        "message": msg if not ok else f"{msg} — symptom: {gf.words(sc, p)['symptom']}"}
            progress.problem_broken(sc, node, True)

            def done(ok: bool, msg: str) -> None:
                if not ok:   # the card must not claim a problem that never arrived
                    progress.problem_broken(sc, node, False)
                    progress.problem_break_failed(sc, node, msg)
            pe_.host_break_in_background(self.lab.name, sc, node, on_done=done)
            return {"ok": True, "broken": True,
                    "message": f"breaking {node} from outside it: it takes a few "
                               f"minutes and the machine restarts — symptom: {gf.words(sc, p)['symptom']}"}
        run = pe_.guest_runner(self.lab.name)
        pe = progress.load()["problems"].get(sc) or {}
        if clear:
            res = pe_.restore(run, self.lab.name, sc, node, p)
            if res.ok:
                # Put back by winlab, not fixed by the student: the try is given
                # up (it scores nothing) and the cause is told, as a debrief.
                if pe.get("broken_on") == node:
                    progress.record_problem(sc, node, False, int(pe.get("hints_open") or 0))
                progress.problem_broken(sc, node, False)
                return {"ok": True, "broken": False, "status": res.status,
                        "message": f"put {node} back as it was (given up, not solved): the cause was "
                                   f"{self._cause(False, sc, 0, True)}"}
            return {**res.as_dict(), "broken": True}
        res = pe_.apply_break(run, self.lab.name, sc, node, p, known_broken=pe.get("broken_on") == node)
        if res.broken and res.status != pe_.ALREADY_BROKEN:
            progress.problem_broken(sc, node, True)
        elif not res.broken and pe.get("broken_on") == node:
            progress.problem_broken(sc, node, False)
        return res.as_dict()

    def _fault(self, params: dict) -> dict:
        from . import faults as fl
        sc = params["scenario"]
        seg_id = params.get("on", "")
        clear = params.get("clear") in ("1", "true", "on")
        seg = self.plan.segments.get(seg_id) or next(iter(self.plan.segments.values()))
        p = {"dev": seg.svi, "gw": seg.network.router_ip,
             "prefix": str(seg.network.prefixlen),
             "victim": str(list(seg.network.net.hosts())[20]),
             "rogue_lo": str(list(seg.network.net.hosts())[180]),
             "rogue_hi": str(list(seg.network.net.hosts())[189]),
             "spoof_name": f"intranet.{self.lab.domain}",
             "target_cidr": seg.network.cidr, "target_host": seg.network.router_ip,
             "port": params.get("port", "445"),
             "fabric_iface": seg.members[0].fabric_iface if seg.members else "eth1"}
        from .cli import fault_firewall_params
        p.update(fault_firewall_params(self.lab, seg.network.id))
        if sc not in fl.SCENARIOS:
            return {"ok": False, "message": f"unknown scenario {sc}"}
        if fl.SCENARIOS[sc].needs_firewall and not self.lab.firewall.enabled:
            return {"ok": False, "message": "this scenario needs the zone firewall on: "
                    "turn it on from the router's sheet in the Network map first"}
        cmds = fl.build_commands(sc, p, clear)
        st = state.load(self.lab.name)
        fab = st.nodes.get("fabric") if st else None
        if not fab or not state.pid_alive(fab.pid):
            return {"ok": False, "message": "fabric not running; start the lab first"}
        from .guestctl import GuestChannel
        ch = GuestChannel(fab.serial_port).connect(retries=8, delay=2)
        try:
            for c in cmds:
                ch.run(c, shell="sh", timeout=60)
        finally:
            ch.close()
        from . import progress
        progress.problem_broken("net:" + sc, seg.network.id, not clear)
        if params.get("lesson"):
            progress.lesson_fault(str(params["lesson"]), not clear)
        if clear:
            return {"ok": True, "message": f"put {seg.network.id} back as it was: the cause was "
                                           f"{fl.SCENARIOS[sc].title}"}
        return {"ok": True, "message": f"broke the network on {seg.network.id} — symptom: {fl.words(sc)['symptom']}"}

    # -------------------------------------------------- streamed long jobs
    def stream_bootstrap(self, emit) -> None:
        from . import bootstrap as bs
        if bs.is_linux():
            bs.bootstrap(progress=emit)
            emit("runtime ready")
            return
        emit("resolving packages…")
        db = bs.load_db()
        closure = bs.resolve(db, bs.ROOT_PACKAGES)
        emit(f"{len(closure)} packages, {sum(p.csize for p in closure)//1048576} MiB")
        bs.bootstrap(progress=emit)
        emit("runtime ready")

    @staticmethod
    def _step_seconds(st: dict) -> int:
        """How long a Setup step usually takes: weights the one bar."""
        name = f"prepare-{st.get('image', 'fabric')}" if st.get("job") == "prepare" else st.get("job", "")
        return JOB_INFO.get(name, ("", 300))[1]

    def stream_get_ready(self, emit) -> None:
        """Get everything ready: every Setup step winlab can do by itself, in
        Setup's order, re-read after each one so an ISO imported meanwhile
        gets its base prepared in the same run. Stops at the first failure;
        the steps that need the student (the Microsoft ISO) are named at the end.

        The bar is weighted by how long each step usually takes (a Windows
        base is most of an hour, the console viewer a minute), and the plan
        it works through is kept in self.ready for the setup screen."""
        runners = {"bootstrap": lambda st: self.stream_bootstrap,
                   "prepare": lambda st: self.stream_prepare(st.get("image", "fabric")),
                   "virtio-fetch": lambda st: self.stream_virtio,
                   "appliance-fetch": lambda st: self.stream_appliance(st.get("image", "ubuntu")),
                   "pack-fetch": lambda st: self.stream_pack(st.get("pack", "sssd")),
                   "exporter-fetch": lambda st: self.stream_exporter,
                   "wac-fetch": lambda st: self.stream_wac,
                   "linuxiso-fetch": lambda st: self.stream_appliance(st.get("image", "")),
                   "fwiso-fetch": lambda st: self.stream_appliance(st.get("image", "")),
                   "netos-fetch": lambda st: self.stream_appliance(st.get("image", "")),
                   "mailclient-fetch": lambda st: self.stream_mailclient,
                   "wireshark-fetch": lambda st: self.stream_wireshark,
                   "webmin-fetch": lambda st: self.stream_webmin,
                   "termshark-fetch": lambda st: self.stream_termshark,
                   "ctrimages-fetch": lambda st: self.stream_containers("images"),
                   "k3s-fetch": lambda st: self.stream_containers("k3s"),
                   "dockerwin-fetch": lambda st: self.stream_containers("docker-win"),
                   "kubeadm-fetch": lambda st: self.stream_containers("kubeadm"),
                   "helm-fetch": lambda st: self.stream_containers("helm"),
                   "dbclients-fetch": lambda st: self.stream_dbclients,
                   "idsrules-fetch": lambda st: self.stream_idsrules,
                   "azure-fetch": lambda st: self.stream_azure,
                   "aws-fetch": lambda st: self.stream_aws,
                   "wireguard-fetch": lambda st: self.stream_vpnclient,
                   "dscmodules-fetch": lambda st: self.stream_dscmodules,
                   "glpiagent-fetch": lambda st: self.stream_glpiagent,
                   "softphone-fetch": lambda st: self.stream_softphone,
                   "secops-fetch": lambda st: self.stream_secops(st.get("kind", "software"))}

        def todo() -> list[dict]:
            steps = self.setup_state(quick=True)["steps"]
            return [st for st in steps if not st["done"] and not st.get("blocked")
                    and st.get("job") in AUTO_JOBS]

        done: list[dict] = []
        tried: set[str] = set()
        shown = [0]
        plan = {"steps": [], "current": -1, "started": time.time(), "step_started": time.time(),
                "part": 0.0, "detail": "", "finished": False, "error": "", "percent": 0}
        self.ready = plan

        def publish(cur: dict | None, pending: list[dict]) -> None:
            rows = [{"label": st["label"], "state": "done", "seconds": self._step_seconds(st)} for st in done]
            if cur is not None:
                rows.append({"label": cur["label"], "state": "running", "seconds": self._step_seconds(cur)})
            rows += [{"label": st["label"], "state": "waiting", "seconds": self._step_seconds(st)}
                     for st in pending]
            plan["steps"], plan["current"] = rows, (len(done) if cur is not None else -1)

        def bar() -> None:
            # Weighted by typical duration; a step that turns up mid-run
            # grows the total, and the bar waits rather than going backwards.
            weights = [r["seconds"] for r in plan["steps"]] or [1]
            got = sum(w for w, r in zip(weights, plan["steps"]) if r["state"] == "done")
            if plan["current"] >= 0:
                got += weights[plan["current"]] * plan["part"]
            shown[0] = max(shown[0], min(100, int(100 * got / max(1, sum(weights)))))
            plan["percent"] = shown[0]
            emit(PCT_LINE + str(shown[0]))

        try:
            while True:
                nxt = next((st for st in todo() if st["id"] not in tried), None)
                if nxt is None:
                    break
                tried.add(nxt["id"])
                publish(nxt, [st for st in todo() if st["id"] not in tried])
                plan["part"], plan["step_started"], plan["detail"] = 0.0, time.time(), ""
                bar()
                n, total = len(done) + 1, len(plan["steps"])
                emit(f"[step {n} of {total}] {nxt['label']}")
                plan["job"] = [nxt["job"], Jobs.what(nxt)]

                def inner(line: str) -> None:
                    if line.startswith(PCT_LINE):
                        return
                    emit(line)
                    if line.strip():
                        plan["detail"] = line.strip()[-140:]
                    m = _NM.search(line)
                    part = (int(m.group(1)) / int(m.group(2))) if m and int(m.group(2)) else None
                    if part is None:
                        m = _PCT.search(line)
                        part = min(1.0, float(m.group(1)) / 100) if m else None
                    if part is not None:
                        plan["part"] = max(plan["part"], part)
                        bar()
                own = self.jobs.find_running(nxt["job"], nxt)
                if own is not None:
                    self._follow(own, inner)
                else:
                    runners[nxt["job"]](nxt)(inner)
                plan["job"] = None
                done.append(nxt)
                publish(None, [st for st in todo() if st["id"] not in tried])
                bar()
        except Exception as exc:
            plan["error"] = str(exc)
            raise
        finally:
            plan["finished"] = True
        shown[0] = plan["percent"] = 100
        emit(PCT_LINE + "100")
        n = len(done)
        left = [st for st in self.setup_state(quick=True)["steps"]
                if not st["done"] and st["id"] != "up"]
        if n == 0 and not left:
            emit("everything is ready")
        elif left:
            emit("still to do: " + "; ".join(st["label"] for st in left))
        else:
            emit(f"done: {n} step{'s' if n != 1 else ''}; everything is ready")

    def _follow(self, rec: dict, inner, poll: float = 0.5) -> None:
        """Get everything ready reaching a step whose fetch the user already
        started: it waits for that job instead of fetching the same file a
        second time, and shows its progress as the step's own."""
        inner(f"already running on its own: {rec['label']}; following it")
        last = None
        while not rec["finished"]:
            now = (rec["percent"], rec["last"])
            if now != last:
                last = now
                inner(f"{rec['last'] or rec['label']} ({rec['percent'] or 0}%)")
            time.sleep(poll)
        if rec["ok"] is False:
            raise RuntimeError(rec["last"].replace("error: ", "", 1) or f"{rec['label']} failed")
        inner(f"{rec['label']}: done")

    def ready_screen(self) -> dict:
        """The setup screen's data: the run's plan, its bar and time left,
        and what is left for the student (the Windows downloads)."""
        plan = getattr(self, "ready", None)
        job = next((j for j in reversed(self.jobs.list()) if j["name"] == "get-ready"), None)
        out = {"running": bool(job and not job["done"]), "job": job, "steps": [], "percent": 0,
               "eta": None, "detail": "", "error": "", "finished": False}
        if plan:
            out.update(steps=plan["steps"], percent=plan["percent"], detail=plan["detail"],
                       error=plan["error"], finished=plan["finished"])
            if not plan["finished"] and plan["current"] >= 0:
                cur = plan["steps"][plan["current"]]
                spent = time.time() - plan["step_started"]
                part = plan["part"]
                # The step's own pace once it has said how far it is, its usual length before.
                left_now = spent * (1 - part) / part if part >= 0.05 and spent > 20 else cur["seconds"] * (1 - part)
                out["eta"] = int(left_now + sum(r["seconds"] for r in plan["steps"][plan["current"] + 1:]))
        st = self.setup_state(quick=True)
        out["media"] = [m for m in st["media"] if m["needed"] or (m["iso"] and not m["base"])]
        out["all_done"] = all(s_["done"] for s_ in st["steps"] if s_["id"] != "up")
        return out

    def stream_iso_import(self, image_id: str, path: str):
        def run(emit):
            from . import images as im
            src = Path(path.strip().strip('"'))
            emit(f"reading {src.name}…")
            got, dest, note = im.import_any(src, wanted=image_id, progress=emit)
            if note:
                emit(f"note: {note}")
            emit(f"imported {src.name} as {got} -> {dest}")
        return run

    def stream_netos_import(self, image_id: str, path: str):
        """A vendor router image the user downloaded (winlab/netos.py): the
        vendor read off its name when none is given."""
        def run(emit):
            from . import images as im
            src = Path(path.strip().strip('"'))
            emit(f"reading {src.name}…")
            dest = im.import_media(image_id or "router", src, progress=emit)
            emit(f"imported {src.name} -> {dest}")
        return run

    def stream_mecm_prepare(self, emit) -> None:
        from . import mecm, readiness
        parts = mecm.find_parts(readiness.search_dirs())
        mecm.prepare(parts, progress=emit)
        emit(f"Configuration Manager disc ready -> {images.installer_path(mecm.MEDIA_ID)}")

    def stream_enable_whp(self, emit) -> None:
        from . import readiness
        readiness.enable_hypervisor_platform(emit)

    def stream_install_qemu(self, emit) -> None:
        """Linux: QEMU, the firmware and swtpm from the distribution (polkit asks for the password)."""
        from . import linuxhost
        if not linuxhost.install_packages(say=emit):
            raise RuntimeError("QEMU was not installed: " + linuxhost.install_hint())
        emit("installed")

    def stream_kvm_access(self, emit) -> None:
        from . import linuxhost
        if not linuxhost.grant_kvm(say=emit):
            raise RuntimeError("this user was not added to the kvm group")

    def pc_checks(self) -> dict:
        from . import readiness
        r = hostprobe.probe()
        self._accel = r.accel
        items = readiness.checks(r)
        return {"checks": items, "summary": readiness.summary(items), "accel": r.accel,
                "root": str(paths.ROOT), "store": str(paths.images_dir())}

    def stream_prepare(self, image_id: str):
        def run(emit):
            from . import prepare
            emit(f"preparing {image_id}…")
            if image_id == "fabric":
                prepare.prepare_fabric(); emit("fabric base ready")
            else:
                prepare.prepare_windows(image_id)
                emit(f"{image_id} base ready")
        return run

    def stream_appliance(self, image_id: str):
        def run(emit):
            from . import images as im
            emit(f"fetching {image_id} from its publisher…")
            im.fetch(image_id, progress=emit)
        return run

    def stream_pack(self, pack_id: str):
        def run(emit):
            from . import debpacks
            emit(f"resolving the {pack_id} pack against the archive index…")
            debpacks.fetch(pack_id, progress=emit)
        return run

    def stream_toolkit(self, which):
        def run(emit) -> None:
            from . import toolkit
            if which == "windbg":
                emit("fetching WinDbg from Microsoft's download host (you accepted Microsoft's licence)…")
                toolkit.fetch(("windbg",), accept_windbg=True, progress=emit)
            elif which:
                emit("fetching the Sysinternals Suite from download.sysinternals.com (you accepted Microsoft's licence)…")
                toolkit.fetch(("sysinternals",), accept_sysinternals=True, progress=emit)
            else:
                emit("fetching PuTTY, WinSCP and Notepad++ from their publishers, each checksum-verified…")
                toolkit.fetch(progress=emit)
        return run

    def stream_wireshark(self, emit) -> None:
        from . import wireshark
        emit(f"fetching Wireshark from wireshark.org ({wireshark.SIZE_TEXT}); Npcap is never fetched…")
        wireshark.fetch(progress=emit)

    def stream_termshark(self, emit) -> None:
        from . import termshark
        emit(f"fetching Termshark {termshark.VERSION} from its GitHub release ({termshark.SIZE_TEXT})…")
        termshark.fetch_onto_volume(progress=emit)

    def stream_webmin(self, emit) -> None:
        from . import webmin
        emit(f"fetching Webmin {webmin.VERSION} from its GitHub release ({webmin.SIZE_TEXT})…")
        webmin.fetch_onto_volume(progress=emit)

    def stream_containers(self, kind: str):
        def run(emit):
            from . import containers
            emit({"images": "pulling the container images from Docker Hub and Microsoft's registry…",
                  "k3s": "fetching k3s from its GitHub release…",
                  "docker-win": "fetching Docker for Windows from download.docker.com…",
                  "kubeadm": "fetching Kubernetes for kubeadm from dl.k8s.io, registry.k8s.io and GitHub releases…",
                  "helm": "fetching Helm from get.helm.sh…"}[kind])
            containers.fetch(kind, progress=emit)
        return run

    def stream_dscmodules(self, emit) -> None:
        from . import automation
        emit(f"fetching NetworkingDsc and ComputerManagementDsc from the PowerShell Gallery ({automation.SIZE_TEXT})…")
        automation.fetch_modules()
        emit("DSC modules ready: the media shelf writes them onto a DSC modules stick")

    def stream_dbclients(self, emit) -> None:
        from . import databases
        emit(f"fetching pgAdmin 4, HeidiSQL and psqlODBC from their projects' releases ({databases.SIZE_TEXT})…")
        databases.fetch(progress=emit)

    def stream_idsrules(self, emit) -> None:
        from . import ids
        emit(f"fetching the ET Open rules from rules.emergingthreats.net ({ids.SIZE_TEXT})…")
        ids.fetch(progress=emit)

    def stream_azure(self, emit) -> None:
        from . import azure
        emit(f"fetching floci-az from its registry, restic and rest-server from their releases ({azure.SIZE_TEXT})…")
        azure.fetch(progress=emit)

    def stream_aws(self, emit) -> None:
        from . import aws
        emit(f"fetching moto from its registry and the AWS CLI from Amazon's download host ({aws.SIZE_TEXT})…")
        aws.fetch(progress=emit)

    def stream_secops(self, kind: str):
        def run(emit) -> None:
            from . import secops
            emit({"software": f"fetching 7-Zip and Chocolatey, pinned ({secops.SOFTWARE_SIZE_TEXT})…",
                  "greenbone": f"pulling Greenbone Community Edition from its registry ({secops.GB_SIZE_TEXT})…"}
                 .get(kind, f"fetching {kind}…"))
            secops.fetch(kind, progress=emit)
        return run

    def stream_vpnclient(self, emit) -> None:
        from . import remoteaccess
        emit(f"fetching WireGuard for Windows from download.wireguard.com ({remoteaccess.SIZE_TEXT})…")
        remoteaccess.fetch("client", progress=emit)

    def stream_glpiagent(self, emit) -> None:
        from . import doctools
        emit(f"fetching the GLPI Agent from its GitHub release ({doctools.AGENT_SIZE_TEXT})…")
        doctools.fetch_agent(progress=emit)

    def stream_softphone(self, emit) -> None:
        from . import softphone
        emit(f"fetching MicroSIP from microsip.org ({softphone.SIZE_TEXT})…")
        softphone.fetch(progress=emit)

    def stream_mailclient(self, emit) -> None:
        from . import mail
        emit(f"fetching Thunderbird from Mozilla's release archive ({mail.SIZE_TEXT})…")
        mail.fetch(progress=emit)

    def stream_exporter(self, emit) -> None:
        from . import exporters
        emit(f"fetching the Prometheus Windows exporter from {exporters.PAGE} (about 11 MB)…")
        exporters.fetch(progress=emit)

    def stream_wac(self, emit) -> None:
        from . import wac
        emit(f"fetching Windows Admin Center from Microsoft ({wac.SIZE_TEXT})…")
        wac.fetch(progress=emit)

    def stream_virtio(self, emit) -> None:
        from . import virtio
        emit("fetching the stable virtio-win ISO from Red Hat (about 600 MB; removed after)…")
        virtio.fetch(progress=emit)

    def stream_viewer(self, emit) -> None:
        from . import termview
        emit(f"fetching noVNC {viewer.VERSION} ({len(viewer.FILES)} files) from GitHub…")
        viewer.fetch(progress=emit)
        emit(f"fetching xterm.js {termview.VERSION} from the npm registry…")
        termview.fetch(progress=emit)
        from . import mapview
        emit(f"fetching Cytoscape.js {mapview.VERSION} from the npm registry…")
        mapview.fetch(progress=emit)
        from . import castplayer, chartview, elkview
        emit(f"fetching uPlot {chartview.VERSION} from the npm registry…")
        chartview.fetch(progress=emit)
        emit(f"fetching asciinema-player {castplayer.VERSION} from the npm registry…")
        castplayer.fetch(progress=emit)
        emit(f"fetching ELK {elkview.VERSION} (EPL-2.0, unmodified) and cytoscape-elk {elkview.ADAPTER_VERSION} from the npm registry…")
        elkview.fetch(progress=emit)
        emit(f"fetching the diagrams.net viewer {drawio.VERSION} (Apache-2.0) from diagrams.net's GitHub tag…")
        drawio.fetch(progress=emit)
        from . import pixiview
        emit(f"fetching PixiJS {pixiview.VERSION} (MIT) from the npm registry…")
        pixiview.fetch(progress=emit)

    def stream_template(self, params: dict):
        def run(emit):
            from . import templates
            t = templates.create(
                self.lab, params.get("node", ""), params.get("id", ""),
                title=params.get("title", ""),
                generalize_=None if params.get("generalize") in (None, "") else
                params.get("generalize") in ("1", "true", True),
                full=params.get("full") in ("1", "true", True), accel=self.accel, emit=emit)
            emit(f"template {t.id} ready: {templates.describe(t)}")
        return run

    def stream_clone(self, params: dict):
        def run(emit):
            from . import templates
            with self._lock:
                try:
                    n = templates.clone_machine(
                        self.lab, params.get("node", ""), params.get("id", ""),
                        ip=params.get("ip", ""),
                        generalize_=None if params.get("generalize") in (None, "") else
                        params.get("generalize") in ("1", "true", True),
                        accel=self.accel, emit=emit)
                finally:
                    self.reload()
            emit(f"{n.id} is in the lab: start it from the Machines window")
        return run

    def start_up(self, only: list[str] | None, force: bool = False) -> dict:
        """Memory check now, boot as a job."""
        from . import membudget
        from .orchestrator import Orchestrator, OrchestratorError

        # No QEMU window of its own: the desktop's Connect window shows the
        # screen over VNC, like Virtual Machine Connection.
        orch = Orchestrator(self.lab, accel=self.accel, display="none")
        try:
            b = orch.checked_budget(only, force=force)
        except OrchestratorError as exc:
            return {"ok": False, "message": " ".join(str(exc).split())}
        from . import ups
        why = ups.blocked(self.lab, list(b.nodes))  # a power cut: no power at its plug
        if why:
            return {"ok": False, "message": why}
        from . import poe  # a powered device its switch gives no PoE stays dark
        dark = poe.blocked(self.lab, self.plan, list(b.nodes))
        if dark and only and all(n in dark for n in b.nodes):
            return {"ok": False, "message": "; ".join(f"{n} has no power: {why}" for n, why in dark.items())}
        if dark:
            b.nodes = [n for n in b.nodes if n not in dark]
        from . import pcbuild  # the power button of a PC that cannot start (no supply, no memory...)
        dead = pcbuild.blocked(self.lab, list(b.nodes))
        if dead and only and all(n in dead for n in b.nodes):
            return {"ok": False, "post": True,
                    "message": "; ".join(f"{naming.display(self.lab, n)}: {why}" for n, why in dead.items())}
        if dead:
            b.nodes = [n for n in b.nodes if n not in dead]
            dark = {**dark, **dead}
        notes = " ".join(line.strip() for line in membudget.explain(self.lab, b))
        if dark:
            notes = (notes + " " if notes else "") + "; ".join(f"{n} stays dark: {why}" for n, why in dark.items())
        if not b.nodes or all(n in orch.running() for n in b.nodes):
            return {"ok": True, "message": "already running"}
        jid = self.jobs.start("up", self.stream_up(orch, b))
        return {"ok": True, "job": jid,
                "message": f"starting {', '.join(b.nodes)}" + (f". {notes}" if notes else "")}

    def stream_up(self, orch, budget):
        def run(emit):
            from . import membudget
            membudget.apply(self.lab, budget)
            rep = orch.up(only=budget.nodes, emit=emit)
            if rep.resumed:
                emit(f"{', '.join(rep.resumed)}: resuming from hibernation")
            emit(f"up: {', '.join(rep.started) or 'nothing new'}")
            self._provider_side(rep.started, emit)
            if rep.failed:
                # The job ends red with the reason, not "up" over a machine that is off.
                raise RuntimeError("; ".join(f"{naming.display(self.lab, n)} did not start: {why}"
                                             for n, why in rep.failed.items()))
        return run

    def _provider_side(self, started: list[str], emit) -> None:
        """Brings up the machines that play another company (roles.PROVIDER_ROLES)."""
        from . import roles
        from .guestctl import GuestChannel
        for node_id in started:
            node = self.lab.nodes.get(node_id)
            if node is None or not node.roles or not set(node.roles) <= set(roles.SELF_STARTING):
                continue
            st = state.load(self.lab.name)
            ns = st.nodes.get(node_id) if st else None
            if not ns:
                continue
            emit(f"{node_id}: starting {', '.join(node.roles)}")
            try:
                ch = GuestChannel(ns.serial_port).connect(retries=40, delay=3)
                try:
                    res = roles.apply_roles(node, ch, topology=self.plan, lab=self.lab)
                finally:
                    ch.close()
                emit(f"{node_id}: {', '.join(res.applied) or 'nothing to do'}")
            except Exception as exc:  # the lab is up either way; say what failed
                emit(f"{node_id}: {', '.join(node.roles)} did not come up: {exc}")

    def stream_suspend(self, only: list[str] | None):
        def run(emit):
            from .orchestrator import Orchestrator
            rep = Orchestrator(self.lab, accel=self.accel, display="none").suspend(only=only, emit=emit)
            if rep.saved:
                emit(f"saved: {', '.join(rep.saved)} (they carry on where they were at the next start)")
            if rep.hibernated:
                emit(f"hibernated: {', '.join(rep.hibernated)}")
            if rep.shut_down:
                emit(f"shut down cleanly: {', '.join(rep.shut_down)}")
            if rep.powered_off:
                emit(f"powered off after the timeout: {', '.join(rep.powered_off)}")
            if rep.failed:
                raise RuntimeError("; ".join(f"{n} still running: {w}" for n, w in rep.failed.items()))
        return run

    def autostart_if_asked(self) -> None:
        """`Start this lab when winlab opens`, from the Start menu."""
        if desktop_prefs().get("autostart") != self.lab.name:
            return
        st = state.load(self.lab.name)
        if st and st.running():
            return
        r = self.start_up(None)
        print(f"autostart: {r.get('message')}")

    def stream_export(self, params: dict):
        def run(emit):
            from . import transfer
            transfer.export_lab(self.lab, params.get("folder", ""),
                                thin=params.get("thin") in ("1", "true", True),
                                compress=params.get("compress") in ("1", "true", True), emit=emit)
        return run

    def stream_import(self, params: dict):
        def run(emit):
            from . import transfer
            lab = transfer.import_lab(params.get("folder", ""),
                                      new_name=params.get("as", ""), emit=emit)
            emit(f"{lab.name} is in the Start menu's lab list")
        return run

    def stream_roles_test(self, node_id: str):
        def run(emit):
            from . import roles
            from .guestctl import GuestChannel
            st = state.load(self.lab.name)
            ns = st.nodes.get(node_id) if st else None
            if not ns or not state.pid_alive(ns.pid):
                emit("node not running"); return
            node = self.lab.nodes[node_id]
            emit(f"testing {node_id} against its desired state ({', '.join(node.roles)})…")
            ch = GuestChannel(ns.serial_port).connect(retries=20, delay=3)
            try:
                status = roles.test_roles(node, ch, topology=self.plan, lab=self.lab)
            finally:
                ch.close()
            for line in roles.render_status(node, status).splitlines():
                emit(line)
        return run

    def stream_roles(self, node_id: str):
        def run(emit):
            from . import roles
            from .guestctl import GuestChannel
            st = state.load(self.lab.name)
            ns = st.nodes.get(node_id) if st else None
            if not ns or not state.pid_alive(ns.pid):
                emit("node not running"); return
            node = self.lab.nodes[node_id]
            emit(f"applying roles to {node_id}: {', '.join(node.roles)}")
            ch = GuestChannel(ns.serial_port).connect(retries=20, delay=3)
            try:
                res = roles.apply_roles(node, ch, topology=self.plan, lab=self.lab)
                for line in res.log:
                    emit(line)
                emit(f"applied: {', '.join(res.applied) or 'none'}")
            finally:
                ch.close()
        return run


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    dash: Dashboard = None  # type: ignore[assignment]

    def log_message(self, *_a) -> None:
        pass

    def _send(self, code, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200) -> None:
        # A part the trial leaves out answers null (winlab/trialparts.py).
        self._send(code, json.dumps(obj, default=_trialparts.as_json).encode(), "application/json")

    def _from_this_desktop(self, path: str) -> bool:
        """Only the desktop's own page may drive it. The server is on
        loopback, but any web page the browser has open can still send it
        requests: a foreign Host is DNS rebinding, a foreign Origin or a
        cross-site fetch is another site posting actions or opening a
        machine's screen. The page itself may be opened from anywhere."""
        port = self.server.server_address[1]
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        if (self.headers.get("Host") or "").lower() not in hosts:
            return False
        if path in ("/", "/favicon.ico"):
            return True
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in {f"http://{h}" for h in hosts}:
            return False
        return self.headers.get("Sec-Fetch-Site", "") != "cross-site"

    def do_GET(self) -> None:
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._from_this_desktop(u.path):
            self._json({"error": "forbidden"}, 403)
            return
        try:
            if u.path == "/":
                self._send(200, page_bytes(), "text/html; charset=utf-8")
            elif u.path == "/api/state":
                self.dash.refresh_if_idle()
                self._json(self.dash.snapshot())
                from . import workday
                workday.kick(self.dash.lab)  # the staff's working day moves on with the desktop's poll
                from . import freeload
                freeload.kick(self.dash.lab)  # Start-OfficeLoad typed inside a guest: read through its agent
            elif u.path == "/api/workday":
                from . import workday
                self._json(workday.view(self.dash.lab))
            elif u.path == "/api/load":
                from . import traffic  # the Office window's Load tab: pace, server jobs, activity, cables
                self._json(traffic.view(self.dash.lab, self.dash))
            elif u.path == "/api/host":
                self._json(self.dash.host())
            elif u.path == "/api/images":
                self._json(self.dash.images())
            elif u.path == "/api/segments":
                self._json(self.dash.segments())
            elif u.path == "/api/workbench":
                from . import workbench
                self.dash.refresh_if_idle()
                self._json(workbench.view(self.dash))
            elif u.path == "/api/workbench/live":
                from . import workbench
                self._json(workbench.live(self.dash, self.dash.wb_live))
            elif u.path == "/api/workbench/packets":
                from . import workbench
                self._json(workbench.packets(self.dash, self.dash.wb_live))
            elif u.path == "/api/perf":
                # Every machine's meters, the cables' load and the alerts (winlab/perfmon.py).
                from . import perfmon
                self._json(perfmon.view(self.dash))
            elif u.path == "/api/guide":
                from . import guide
                self._json(guide.view(self.dash))
            elif u.path == "/api/topology":
                self._json(self.dash.topology())
            elif u.path == "/favicon.ico":
                from . import appicon
                self._send(200, appicon.ico_bytes(), "image/x-icon")
            elif u.path == "/api/roles":
                self._json(self.dash.roles_catalog())
            elif u.path == "/api/getready":
                self._json(self.dash.ready_screen())
            elif u.path == "/api/setup":
                self._json(self.dash.setup_state(quick=bool(parse_qs(u.query).get("quick"))))
            elif u.path == "/api/checks":
                self._json(self.dash.pc_checks())
            elif u.path == "/api/exercises":
                self._json(self.dash.exercises())
            elif u.path == "/api/faults":
                self._json(self.dash.faults())
            elif u.path == "/api/guestfaults":
                self._json(self.dash.guest_faults())
            elif u.path == "/api/license":
                self._json(self.dash.license())
            elif u.path == "/api/lessons":
                self._json(self.dash.lessons())
            elif u.path == "/api/review":
                # spaced review: today's recall questions from finished lessons (winlab/review.py)
                from . import review
                self._json(review.todays_set())
            elif u.path == "/api/lesson":
                self._json(self.dash.lesson(q.get("id", [""])[0]))
            elif u.path == "/api/answer":
                self._json(self.dash.model_answer(q.get("id", [""])[0], q.get("node", [""])[0]))
            elif u.path == "/api/progress":
                self._json(self.dash.progress())
            elif u.path == "/api/dashboard":
                # the Progress window (winlab/dashboard.py, winlab/tracks.py)
                from . import certshare, dashboard
                d = dashboard.collect()
                for t in d["tracks"]:
                    c = t["certificate"]
                    if c.get("code"):
                        c["linkedin"] = certshare.linkedin_url({**c, "title": t["title"], "completed": t["finished"]})
                self._json(d)
            elif u.path == "/api/exam":
                self._json(self.dash.exam(q.get("id", ["az-802"])[0]))
            elif u.path == "/api/exams":
                self._json(self.dash.exam_tracks())
            elif u.path == "/api/practice":
                self._json(self.dash.practice())
            elif u.path == "/api/oncall":
                self._json(self.dash.oncall())
            elif u.path == "/api/breakfix":
                self._json(self.dash.breakfix())
            elif u.path == "/api/interview":
                self._json(self.dash.interview())
            elif u.path == "/api/incidents":
                self._json(self.dash.incidents())
            elif u.path == "/api/inherited":
                self._json(self.dash.inherited())
            elif u.path == "/api/aidc":
                self._json(self.dash.aidc())
            elif u.path == "/api/helpdesk":
                self._json(self.dash.helpdesk())
            elif u.path == "/api/help":
                self._json(self.dash.help_topics())
            elif u.path == "/api/i18n":
                from . import i18n
                self._json(i18n.view((parse_qs(u.query).get("lang") or [None])[0]))
            elif u.path == "/api/scenario":
                self._json(self.dash.scenario())
            elif u.path == "/api/alerts":
                # On-call alerting (winlab/alerts.py): the poll ticks the
                # monitoring in a thread and answers with the view at once.
                from . import alerts
                self._json(alerts.poll(self.dash))
            elif u.path == "/api/ops":
                # The company run, today's shift and wear; wear moves on in a thread.
                from . import company
                self._json(company.view_all(self.dash))
            elif u.path == "/api/clock":
                from . import labclock
                self._json(labclock.view(self.dash.lab.name))
            elif u.path == "/api/commands":
                from . import commands
                self._json({"kinds": [{"id": k, "title": t} for k, t in commands.KINDS],
                            "commands": [commands.as_dict(c) for c in commands.catalog()]})
            elif u.path == "/api/notes":
                from . import notes
                self._json(notes.load(self.dash.lab.name))
            elif u.path == "/transcript":
                from . import transcript
                self._send(200, transcript.render(q.get("name", [""])[0]).encode("utf-8"),
                           "text/html; charset=utf-8")
            elif u.path == "/netcheck":
                # A machine's "Test the network from here": run from inside it
                # over its agent (winlab/netcheck.py), shown in the Viewer.
                from . import naming, netcheck
                lab = self.dash.lab
                try:
                    res, err = netcheck.check(lab, naming.resolve(lab, q.get("node", [""])[0]),
                                              netcheck.guest_runner(lab.name)), ""
                except ValueError as exc:
                    res, err = None, str(exc)
                self._send(200, netcheck.render_html(res, err).encode("utf-8"), "text/html; charset=utf-8")
            elif u.path == "/api/viewer":
                self._json(self.dash.viewer_state())
            elif u.path == "/api/doc":
                self._json(self.dash.doc(q.get("name", ["README"])[0]))
            elif u.path == "/api/update":
                self._json(self.dash.update_check())
            elif u.path == "/api/update/state":
                self._json(self.dash.update_state())
            elif u.path.startswith("/novnc/"):
                self._static(viewer.viewer_dir(), u.path[len("/novnc/"):], viewer.ready())
            elif u.path.startswith("/xterm/"):
                from . import termview
                self._static(termview.term_dir(), u.path[len("/xterm/"):], termview.ready())
            elif u.path.startswith("/cytoscape/"):
                from . import mapview
                self._static(mapview.map_dir(), u.path[len("/cytoscape/"):], mapview.ready())
            elif u.path.startswith("/drawio/"):
                self._static(drawio.viewer_dir(), u.path[len("/drawio/"):], drawio.ready())
            elif u.path.startswith("/pixi/"):
                from . import pixiview
                self._static(pixiview.pixi_dir(), u.path[len("/pixi/"):], pixiview.ready())
            elif u.path.startswith("/uplot/"):
                from . import chartview
                self._static(chartview.chart_dir(), u.path[len("/uplot/"):], chartview.ready())
            elif u.path.startswith("/asciinema/"):
                from . import castplayer
                self._static(castplayer.player_dir(), u.path[len("/asciinema/"):], castplayer.ready())
            elif u.path.startswith("/elk/"):
                from . import elkview
                self._static(elkview.elk_dir(), u.path[len("/elk/"):], elkview.ready())
            elif u.path == "/api/recording":
                # One terminal recording, as asciicast v2 for the player (winlab/recordings.py).
                self._recording(q.get("name", [""])[0])
            elif u.path == "/ws/console":
                self._console(q.get("node", [""])[0])
            elif u.path == "/ws/term":
                self._console(q.get("node", [""])[0], term=True)
            elif u.path == "/ws/winterm":
                self._winterm(q)
            elif u.path == "/api/labs":
                self._json(self.dash.labs())
            elif u.path == "/api/jobs":
                self._json(self.dash.jobs.list())
            elif u.path == "/certificate":
                from . import certificate, progress
                name = q.get("name", [""])[0].strip() or progress.student()
                try:
                    track = q.get("track", [""])[0]
                    page = (certificate.issue(name, track)[0] if track
                            else certificate.render(name, q.get("module", [""])[0]))
                except certificate.NotYet as exc:
                    self._send(403, f"<!doctype html><meta charset=utf-8><title>winlab</title>"
                               f"<p style='font:15px system-ui;padding:40px'>Not yet: {exc}.</p>".encode(),
                               "text/html; charset=utf-8")
                else:
                    if name:
                        progress.set_student(name)
                    self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            elif u.path == "/api/building":
                # The Building window: the lab's place and where its machines stand (winlab/building.py).
                from . import building
                self._json(building.view(self.dash))
            elif u.path == "/api/building-live":
                # The building as a live picture of the lab (winlab/buildlive.py).
                from . import buildlive
                self._json(buildlive.view(self.dash))
            elif u.path == "/api/building-screen":
                # A running machine's real screen, small, for its desk's monitor.
                from . import buildlive
                try:
                    body = buildlive.screen(self.dash.lab.name, q.get("node", [""])[0],
                                            int(q.get("w", ["320"])[0] or 320))
                except (buildlive.LiveError, ValueError) as exc:
                    self._json({"ok": False, "message": str(exc)}, 404)
                else:
                    self._send(200, body, "image/png")
            elif u.path == "/api/building-export":
                # The floors for the wiki: diagrams.net, or a DokuWiki page.
                from . import buildlive, buildsys
                fmt = q.get("format", ["drawio"])[0]
                body = (buildlive.dokuwiki(self.dash.lab) if fmt == "dokuwiki"
                        else buildsys.floorplan_drawio(self.dash.lab)).encode("utf-8")
                name = f"{self.dash.lab.name}-floors.{'txt' if fmt == 'dokuwiki' else 'drawio'}"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8" if fmt == "dokuwiki"
                                 else "application/xml")
                self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif u.path == "/api/building-systems":
                # The lab's own open source systems as the building sees them (winlab/buildsys.py).
                from . import buildsys
                self._json(buildsys.view(self.dash.lab))
            elif u.path == "/api/campus":
                # The Site window: the job's site, its cabling and work order (winlab/campus.py).
                from . import campus
                self._json(campus.view(self.dash))
            elif u.path in ("/api/rack", "/api/rack/labels", "/api/rack/export"):
                # The Rack window, its label sheet and the diagram's export (winlab/rack.py).
                from . import rack
                v = rack.view(self.dash)
                if u.path == "/api/rack":
                    self._json(v)
                elif u.path == "/api/rack/labels":
                    self._send(200, rack.label_sheet(v).encode("utf-8"), "text/html; charset=utf-8")
                else:
                    png = q.get("format", ["svg"])[0] == "png"
                    body = rack.png(v) if png else rack.svg(v).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "image/png" if png else "image/svg+xml")
                    self.send_header("Content-Disposition",
                                     f'attachment; filename="{self.dash.lab.name}-rack.{"png" if png else "svg"}"')
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            elif u.path == "/api/diagram":
                # The network diagram, drawn by diagrams.net's viewer (winlab/drawio.py).
                self._send(200, drawio.page(self.dash.plan).encode("utf-8"), "text/html; charset=utf-8")
            elif u.path == "/api/diagram.drawio":
                body = drawio.dumps(self.dash.plan).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.jgraph.mxfile")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{self.dash.lab.name}{drawio.EXT}"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif u.path == "/api/netfile":
                from . import netfile
                body = netfile.dumps(self.dash.lab)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{self.dash.lab.name}{netfile.EXT}"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            elif u.path == "/api/progress/export":
                # The Progress window's Export: one file to take to another PC (winlab/progressfile.py).
                from . import progressfile
                b = progressfile.bundle()
                body = progressfile.dumps(b)
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{progressfile.file_name(b)}"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            elif u.path == "/api/stream":
                self._sse(q.get("job", [""])[0])
            else:
                self._json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            from . import applog
            applog.write(f"GET {u.path}", str(exc), exc)
            self._json({"error": str(exc), "trace": traceback.format_exc()[-800:]}, 500)

    def _switch_lab(self, name: str) -> dict:
        """Point the running desktop at another lab (labs keep running)."""
        if name not in lab_names():
            from . import content
            if content.locked(paths.CONTENT / "labs" / f"{name}.toml"):
                return {"ok": False, "locked": True,
                        "message": f"{name} is part of the full version of winlab. Unlock it with a license key."}
            return {"ok": False, "message": f"no lab named '{name}'"}
        if name == self.dash.lab.name:
            return {"ok": True, "message": f"already on {name}", "lab": name}
        try:
            lab = load_lab(name)
        except LabError as exc:
            return {"ok": False, "message": str(exc)}
        new = Dashboard(lab, accel=self.dash._accel or "")
        # Jobs keep running across the switch (a base prepares for every
        # lab), so the tray and Setup keep showing them.
        new.jobs, new.meter = self.dash.jobs, self.dash.meter
        type(self).dash = new
        remember_lab(name)
        return {"ok": True, "message": f"switched to {name}", "lab": name}

    def _my_lab(self, what: str, name: str, new_name: str) -> dict:
        """Delete or rename one of the user's own labs (winlab/mylabs.py).
        The lab open on the desktop can be renamed (the desktop moves with
        it), not deleted."""
        from . import mylabs
        dash = self.dash
        with dash._edit_lock:
            try:
                if what == "lab-delete":
                    if name == dash.lab.name:
                        return {"ok": False, "message": f"{name} is open: open another lab from Start first, "
                                                        f"then delete it"}
                    mylabs.delete(name)
                    return {"ok": True, "message": f"{name} deleted, with its machines' disks"}
                dest = mylabs.rename(name, new_name)
            except (mylabs.MyLabError, LabError, OSError) as exc:
                return {"ok": False, "message": str(exc)}
            if name == dash.lab.name:
                lab = load_lab(dest.stem)
                new = Dashboard(lab, accel=dash._accel or "")
                new.jobs, new.meter = dash.jobs, dash.meter
                type(self).dash = new
                remember_lab(dest.stem)
            return {"ok": True, "lab": dest.stem, "reload": name == dash.lab.name,
                    "message": f"{name} is now called {dest.stem}"}

    def _open_netfile(self, q: dict, length: int) -> None:
        """A network file the user opened or dropped on the workbench: a new
        lab from it, and the desktop moves to it."""
        from . import netfile
        if length > netfile.MAX_BYTES:
            self.close_connection = True
            self._json({"ok": False, "message": "that is not a network file: it is far too big"}, 400)
            return
        try:
            lab = netfile.open_bytes(self.rfile.read(length), q.get("name", [""])[0])
        except netfile.NetFileError as exc:
            self._json({"ok": False, "message": str(exc)})
            return
        out = self._switch_lab(lab.name)
        out["message"] = (f"opened as {lab.name}: {len(lab.nodes)} machine{'s' if len(lab.nodes) != 1 else ''}, "
                          "built fresh on this PC when you power them on")
        self._json(out)

    def _import_progress(self, length: int) -> None:
        """A progress file from another PC, opened in the Progress window:
        merged into this PC's progress (winlab/progressfile.py)."""
        from . import progressfile
        if length > progressfile.MAX_BYTES:
            self.close_connection = True
            self._json({"ok": False, "message": "that is not a progress file: it is far too big"}, 400)
            return
        try:
            rep = progressfile.import_bytes(self.rfile.read(length))
        except progressfile.ProgressFileError as exc:
            self._json({"ok": False, "message": str(exc)})
            return
        self._json({"ok": True, **rep})

    def _drop(self, q: dict, length: int) -> None:
        """A file dropped on a machine's window: the raw bytes, then a job
        that writes them into the machine over its serial agent."""
        from . import dropin
        node_id = q.get("node", [""])[0]
        name = q.get("name", [""])[0]
        node = self.dash.lab.nodes.get(node_id)
        try:
            if node is None:
                raise dropin.DropError(f"no machine {node_id!r} in this lab")
            dropin.check(node, length)
            dropin.safe_name(name)
            dropin.running(self.dash.lab.name, node_id)
        except dropin.DropError as exc:
            # Refused before reading: say so and close, rather than read megabytes.
            self.close_connection = True
            self._json({"ok": False, "message": str(exc)}, 400)
            return
        data = self.rfile.read(length)
        lab_name = self.dash.lab.name

        def run(emit) -> None:
            dropin.send(lab_name, node_id, name, data, emit, core=core)
        core = node.is_server_core
        jid = self.dash.jobs.start("drop", run)
        self._json({"ok": True, "job": jid, "message": f"copying {dropin.safe_name(name)} to {node_id}…",
                    "path": dropin.dest_path(name, core)})

    def do_POST(self) -> None:
        u = urlparse(self.path)
        if not self._from_this_desktop(u.path):
            self._json({"error": "forbidden"}, 403)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if u.path == "/api/drop":
            self._drop(parse_qs(u.query), length)
            return
        if u.path == "/api/netfile":
            self._open_netfile(parse_qs(u.query), length)
            return
        if u.path == "/api/progress/import":
            self._import_progress(length)
            return
        if u.path.startswith("/api/activity/"):
            from . import activity
            activity.http_post(self, u.path, length)
            return
        if u.path.startswith("/api/class/"):
            from . import classes
            classes.http_post(self, u.path, parse_qs(u.query), length)
            return
        try:
            body = json.loads(self.rfile.read(length).decode() or "{}")
        except (json.JSONDecodeError, ValueError):
            body = {}
        try:
            if u.path == "/api/action" and body.get("do") == "switch-lab":
                self._json(self._switch_lab(body.get("lab", "")))
            elif u.path == "/api/action" and body.get("do") in ("lab-delete", "lab-rename"):
                self._json(self._my_lab(body.get("do"), str(body.get("lab") or ""), str(body.get("name") or "")))
            elif u.path == "/api/action" and body.get("do") == "language":
                from . import i18n
                self._json(i18n.choose(str(body.get("lang", ""))))
            elif u.path == "/api/action":
                self._json(self.dash.act(body.get("do", ""), body))
            elif u.path == "/api/job":
                name = body.get("job", "")
                same = self.dash.same_job(name, body)
                if same:
                    self._json({"job": same})
                    return
                if name == "bootstrap":
                    jid = self.dash.jobs.start("bootstrap", self.dash.stream_bootstrap)
                elif name == "prepare":
                    image = body.get("image", "fabric")
                    jid = self.dash.jobs.start(
                        f"prepare-{image}", self.dash.stream_prepare(image))
                elif name == "roles":
                    jid = self.dash.jobs.start(
                        "roles", self.dash.stream_roles(body.get("node", "")))
                elif name == "roles-test":
                    jid = self.dash.jobs.start(
                        "roles-test", self.dash.stream_roles_test(body.get("node", "")))
                elif name == "viewer":
                    jid = self.dash.jobs.start("viewer", self.dash.stream_viewer)
                elif name == "template":
                    jid = self.dash.jobs.start("template", self.dash.stream_template(body))
                elif name == "clone":
                    jid = self.dash.jobs.start("clone", self.dash.stream_clone(body))
                elif name == "up":
                    r = self.dash.start_up(None, force=bool(body.get("force")))
                    jid = r.get("job")
                    if not jid:
                        return self._json({"ok": r["ok"], "error": r.get("message", "")})
                elif name == "suspend":
                    jid = self.dash.jobs.start("suspend", self.dash.stream_suspend(None))
                elif name == "export":
                    jid = self.dash.jobs.start("export", self.dash.stream_export(body))
                elif name == "import":
                    jid = self.dash.jobs.start("import", self.dash.stream_import(body))
                elif name == "virtio-fetch":
                    jid = self.dash.jobs.start("virtio-fetch", self.dash.stream_virtio)
                elif name == "appliance-fetch":
                    jid = self.dash.jobs.start(
                        "appliance-fetch", self.dash.stream_appliance(body.get("image", "ubuntu")))
                elif name == "linuxiso-fetch":
                    jid = self.dash.jobs.start(
                        "linuxiso-fetch", self.dash.stream_appliance(body.get("image", "")))
                elif name == "fwiso-fetch":
                    jid = self.dash.jobs.start(
                        "fwiso-fetch", self.dash.stream_appliance(body.get("image", "")))
                elif name == "netos-fetch":
                    jid = self.dash.jobs.start(
                        "netos-fetch", self.dash.stream_appliance(body.get("image", "")))
                elif name == "netos-import":
                    jid = self.dash.jobs.start("netos-import", self.dash.stream_netos_import(
                        body.get("image", ""), body.get("path", "")))
                elif name == "pack-fetch":
                    jid = self.dash.jobs.start(
                        "pack-fetch", self.dash.stream_pack(body.get("pack", "sssd")))
                elif name == "exporter-fetch":
                    jid = self.dash.jobs.start("exporter-fetch", self.dash.stream_exporter)
                elif name == "wac-fetch":
                    jid = self.dash.jobs.start("wac-fetch", self.dash.stream_wac)
                elif name == "mailclient-fetch":
                    jid = self.dash.jobs.start("mailclient-fetch", self.dash.stream_mailclient)
                elif name == "wireshark-fetch":
                    jid = self.dash.jobs.start("wireshark-fetch", self.dash.stream_wireshark)
                elif name in ("toolkit-fetch", "toolkit-sysinternals-fetch", "toolkit-windbg-fetch"):
                    jid = self.dash.jobs.start(name, self.dash.stream_toolkit(
                        "windbg" if name == "toolkit-windbg-fetch" else name != "toolkit-fetch"))
                elif name == "webmin-fetch":
                    jid = self.dash.jobs.start("webmin-fetch", self.dash.stream_webmin)
                elif name == "termshark-fetch":
                    jid = self.dash.jobs.start("termshark-fetch", self.dash.stream_termshark)
                elif name in ("ctrimages-fetch", "k3s-fetch", "dockerwin-fetch", "kubeadm-fetch", "helm-fetch"):
                    kind = {"ctrimages-fetch": "images", "k3s-fetch": "k3s", "dockerwin-fetch": "docker-win",
                            "kubeadm-fetch": "kubeadm", "helm-fetch": "helm"}[name]
                    jid = self.dash.jobs.start(name, self.dash.stream_containers(kind))
                elif name == "dbclients-fetch":
                    jid = self.dash.jobs.start("dbclients-fetch", self.dash.stream_dbclients)
                elif name == "azure-fetch":
                    jid = self.dash.jobs.start("azure-fetch", self.dash.stream_azure)
                elif name == "aws-fetch":
                    jid = self.dash.jobs.start("aws-fetch", self.dash.stream_aws)
                elif name == "idsrules-fetch":
                    jid = self.dash.jobs.start("idsrules-fetch", self.dash.stream_idsrules)
                elif name == "wireguard-fetch":
                    jid = self.dash.jobs.start("wireguard-fetch", self.dash.stream_vpnclient)
                elif name == "dscmodules-fetch":
                    jid = self.dash.jobs.start("dscmodules-fetch", self.dash.stream_dscmodules)
                elif name == "glpiagent-fetch":
                    jid = self.dash.jobs.start("glpiagent-fetch", self.dash.stream_glpiagent)
                elif name == "softphone-fetch":
                    jid = self.dash.jobs.start("softphone-fetch", self.dash.stream_softphone)
                elif name == "secops-fetch":
                    jid = self.dash.jobs.start("secops-fetch", self.dash.stream_secops(str(body.get("kind") or "software")))
                elif name == "get-ready":
                    # One at a time: a second press joins the run already going.
                    jid = self.dash.running_job("get-ready") or self.dash.jobs.start(
                        "get-ready", self.dash.stream_get_ready)
                elif name == "iso-import":
                    jid = self.dash.jobs.start("iso-import", self.dash.stream_iso_import(
                        body.get("image", ""), body.get("path", "")))
                elif name == "mecm-prepare":
                    jid = self.dash.running_job("mecm-prepare") or self.dash.jobs.start(
                        "mecm-prepare", self.dash.stream_mecm_prepare)
                elif name == "app-update":
                    jid = self.dash.running_job("app-update") or self.dash.jobs.start(
                        "app-update", self.dash.stream_app_update)
                elif name == "enable-whp":
                    jid = self.dash.jobs.start("enable-whp", self.dash.stream_enable_whp)
                elif name == "install-qemu":
                    jid = self.dash.running_job("install-qemu") or self.dash.jobs.start(
                        "install-qemu", self.dash.stream_install_qemu)
                elif name == "kvm-access":
                    jid = self.dash.jobs.start("kvm-access", self.dash.stream_kvm_access)
                else:
                    self._json({"error": "unknown job"}, 400); return
                self.dash.jobs.tag(jid, body)
                self._json({"job": jid})
            else:
                self._json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            from . import applog
            applog.write(f"POST {u.path}", str(exc), exc)
            self._json({"error": str(exc)}, 500)

    def _static(self, root: Path, rel: str, ready: bool) -> None:
        """Serves one file from a fetched viewer tree; nothing outside it."""
        if not ready:
            self._json({"error": "console viewer not fetched; run winlab bootstrap "
                                 "or press Fetch viewer in the Console tab"}, 404)
            return
        root = root.resolve()
        target = (root / rel).resolve()
        if root not in target.parents or not target.is_file() or ".." in rel:
            self._json({"error": "not found"}, 404)
            return
        ctype = _MIME.get(target.suffix.lower(), "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    def _recording(self, name: str) -> None:
        from . import recordings
        try:
            p = recordings.path_of(self.dash.lab.name, name)
        except recordings.RecordingError as exc:
            self._json({"error": str(exc)}, 404)
            return
        self._send(200, p.read_bytes(), "application/x-asciicast")

    def _console(self, node_id: str, term: bool = False) -> None:
        """Upgrades to a WebSocket and bridges it to the machine's VNC port,
        or with term to its serial console (a Linux machine's terminal)."""
        from . import serverroom  # a server in the locked server room: its screen is not on the desk
        ok, why = serverroom.allowed(self.dash.lab, node_id)
        if not ok:
            self._json({"error": why, "server_room": True}, 403)
            return
        st = state.load(self.dash.lab.name)
        ns = st.nodes.get(node_id) if st else None
        port = (ns.term_port if term else ns.vnc_port) if ns else 0
        if not ns or not port or not state.pid_alive(ns.pid):
            self._json({"error": f"{node_id or '(no node)'} is not running or has no "
                                 + ("terminal" if term else "screen")}, 404)
            return
        code, reason, headers = wsbridge.handshake_response(self.headers)
        self.send_response(code, reason)
        for k, v in headers:
            self.send_header(k, v)
        if code != 101:
            self.send_header("Content-Length", "0")
        self.end_headers()
        self.wfile.flush()
        if code != 101:
            return
        self.close_connection = True
        try:
            tap = None
            if term:  # a Terminal window's recording, when one is on (winlab/recordings.py)
                from . import recordings
                lab_name = self.dash.lab.name
                tap = lambda data: recordings.tap(lab_name, node_id, data)  # noqa: E731
            wsbridge.bridge(self.connection, self.rfile.read1 if hasattr(self.rfile, "read1")
                            else self.rfile.read, self._ws_write, "127.0.0.1", port, tap=tap)
        except wsbridge.BridgeError:
            pass

    def _winterm(self, q: dict) -> None:
        """Upgrades to a WebSocket for one Command Prompt or PowerShell window
        of a Windows machine, over its COM3 console host (winterm.py)."""
        from . import serverroom, winterm
        node_id = q.get("node", [""])[0]
        ok, why = serverroom.allowed(self.dash.lab, node_id)
        if not ok:
            self._json({"error": why, "server_room": True}, 403)
            return
        node = self.dash.lab.nodes.get(node_id)
        st = state.load(self.dash.lab.name)
        ns = st.nodes.get(node_id) if st else None
        if not winterm.fitted(node) or not ns or not state.pid_alive(ns.pid):
            self._json({"error": f"{node_id or '(no node)'} is not a running Windows machine"}, 404)
            return
        shell = q.get("shell", ["cmd"])[0]
        if shell not in winterm.SHELLS:
            self._json({"error": f"no shell called {shell}"}, 400)
            return

        def num(key: str, default: int) -> int:
            try:
                return int(q.get(key, [default])[0])
            except (TypeError, ValueError):
                return default
        code, reason, headers = wsbridge.handshake_response(self.headers)
        self.send_response(code, reason)
        for k, v in headers:
            self.send_header(k, v)
        if code != 101:
            self.send_header("Content-Length", "0")
        self.end_headers()
        self.wfile.flush()
        if code != 101:
            return
        self.close_connection = True
        winterm.serve_ws(self.connection, self.rfile.read1 if hasattr(self.rfile, "read1") else self.rfile.read,
                         self._ws_write, ns, shell, q.get("admin", ["0"])[0] == "1",
                         num("cols", 120), num("rows", 30))

    def _ws_write(self, data: bytes) -> None:
        self.wfile.write(data)
        self.wfile.flush()

    def _sse(self, job_id: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            for line in self.dash.jobs.stream(job_id):
                self.wfile.write(f"data: {line}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionError, OSError):
            pass


def _licence_and_updates_at_start() -> None:
    """Once per start, in the background: a key typed into the installer is
    activated; a subscription past its paid period renews; and, when the
    setting is on, the once-a-day update check. None of these runs for an
    unlicensed copy except the installer's key, and the update check never
    during a timed activity."""
    from . import update
    from .licensing import client
    try:
        client.activate_pending()
        client.renew_if_due()
        update.auto_check()
    except Exception:  # noqa: BLE001 - never let this take the desktop down
        pass


def _clean_leftovers() -> None:
    """Half files from a winlab closed mid-download or mid-import."""
    from .bootstrap import clean_leftovers
    for f in clean_leftovers():
        print(f"removed a leftover half file: {f}", file=sys.stderr)


def serve(target: str = "", port: int = 8780, accel: str = "", open_browser: bool = True) -> None:
    lab = load_lab(target or default_lab())
    url = f"http://127.0.0.1:{port}/"
    dash = Dashboard(lab, accel=accel)
    threading.Thread(target=lambda: dash.accel, daemon=True).start()
    _Handler.dash = dash
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    except OSError as exc:
        # winlab.exe double-clicked twice: the desktop is already up, so
        # just bring it to the browser instead of failing on the port.
        print(f"winlab is already running on {url} ({exc.strerror or exc}); opening it")
        if open_browser:
            appwindow.open_window(url, paths.VAR / "appwindow")
        return
    remember_lab(lab.name)
    threading.Thread(target=_clean_leftovers, daemon=True).start()
    threading.Timer(1.5, dash.autostart_if_asked).start()
    threading.Thread(target=_licence_and_updates_at_start, daemon=True).start()
    from . import power  # management-port requests and magic packets, carried out on the machines
    power.watch_desktop(lambda: _Handler.dash)
    from . import azure  # what the student made in the lab's Azure becomes lab equipment
    azure.watch_desktop(lambda: _Handler.dash)
    from . import consolecable  # the console cables' serial lines, bridged to the devices' consoles
    consolecable.watch_desktop(lambda: _Handler.dash)
    from . import iosssh  # SSH sessions to the router and switches, from the router's ttyS2 to their consoles
    iosssh.watch_desktop(lambda: _Handler.dash)
    from . import ups  # the UPS's battery and USB cable, the mains during a power cut
    ups.watch_desktop(lambda: _Handler.dash)
    print(f"winlab control plane for '{lab.name}' on {url}")
    print("bound to loopback only; Ctrl-C to stop")
    if open_browser:
        # Its own app window (Edge or Chrome app mode), not a browser tab.
        threading.Timer(0.6, lambda: appwindow.open_window(url, paths.VAR / "appwindow")).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        # Like Hyper-V when its host shuts down: each running machine's
        # Automatic Stop Action (Settings > Automatic Stop Action).
        print("\nstopping the desktop: each running machine's automatic stop action…")
        try:
            from . import vmctl
            vmctl.stop_on_exit(_Handler.dash.lab, _Handler.dash.accel)
        except Exception as exc:  # noqa: BLE001 - the desktop still stops
            print(f"could not stop the machines: {exc}; use 'winlab lab down'")
    finally:
        httpd.server_close()
