"""Export a lab to a folder and import it again: on this PC, on another one,
or from a backup.

An export folder holds the lab definition, every machine's disks and
firmware state, the lab's Administrator password and its evaluation-clock
cache, and a manifest that says what is in it. Two shapes:

* **full** (the default): every system disk is flattened into a standalone
  image, so the folder boots on any PC with winlab and QEMU, whether or not
  that PC has the base image the machines were made from. Checkpoints do
  not survive flattening (a qcow2 internal snapshot cannot be carried into
  a new file), so a full export is the machines as they are now.
* **thin**: the machines' own disks are copied as they are, deltas over the
  base and template images they were cloned from, checkpoints included. It
  is fast and small, and it only works on a PC with the very same base
  images (the manifest fingerprints them, and import checks). Templates the
  lab uses travel inside the folder.

Importing under a new name keeps every machine's MAC addresses, so Windows
inside does not see a new network adapter and lose its address settings.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
import tomllib
from pathlib import Path
from typing import Callable

from . import __version__, editor, images, paths, schema, secrets, state
from .images import ImageError, Template
from .model import Lab
from .netplan import compile_topology

Emit = Callable[[str], None]

FORMAT = 1
MANIFEST = "manifest.json"
LAB_NAME = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
MACHINE_FILES = ("system.qcow2", "data*.qcow2", "usb0.qcow2", "uefi-vars.fd")


class TransferError(Exception):
    pass


def _say(line: str) -> None:
    print(f"  {line}")


def _size(n: float) -> str:
    return f"{n / 1024**3:.1f} GiB" if n >= 1024**3 else f"{int(n / 1024**2)} MiB"


# ------------------------------------------------------------ fingerprints
def fingerprint(path: Path, sample_mb: int = 4) -> str:
    """Cheap identity of a large image: its size and four samples of its
    content, so a base prepared from the same ISO on another PC (a different
    install, different bytes) is told apart without reading 20 GB."""
    size = path.stat().st_size
    h = hashlib.sha256(str(size).encode())
    chunk = sample_mb * 1024 * 1024
    with path.open("rb") as fh:
        for off in sorted({0, size // 3, (2 * size) // 3, max(0, size - chunk)}):
            fh.seek(off)
            h.update(fh.read(chunk))
    return h.hexdigest()[:32]


def _qemu_info(disk: Path) -> dict:
    try:
        return json.loads(images._run_img(["info", "--output=json", "-U", str(disk)]))
    except (ImageError, json.JSONDecodeError) as exc:
        raise TransferError(f"cannot read {disk}: {exc}") from exc


def _chain_size(disk: Path) -> int:
    """Bytes a flattened copy could need: every layer's allocated size."""
    total = 0
    seen = 0
    p: Path | None = disk
    while p is not None and seen < 8:
        info = _qemu_info(p)
        total += int(info.get("actual-size") or p.stat().st_size)
        nxt = info.get("full-backing-filename") or info.get("backing-filename")
        p = Path(nxt) if nxt else None
        seen += 1
    return total


def _backing_of(disk: Path) -> Path | None:
    info = _qemu_info(disk)
    full = info.get("full-backing-filename") or info.get("backing-filename")
    return Path(full) if full else None


def _copy_flat(src: Path, dest: Path, compress: bool) -> None:
    args = ["convert", "-O", "qcow2"] + (["-c"] if compress else []) + [str(src), str(dest)]
    try:
        images._run_img(args)
    except ImageError as exc:
        raise TransferError(str(exc)) from exc


def _rebase(disk: Path, backing: Path) -> None:
    try:
        images._run_img(["rebase", "-u", "-b", str(backing), "-F", "qcow2", str(disk)])
    except ImageError as exc:
        raise TransferError(str(exc)) from exc


# ------------------------------------------------------------------ export
def _machine_dirs(lab: Lab) -> dict[str, Path]:
    out = {}
    for node in lab.node_list():
        d = paths.lab_dir(lab.name) / node.id
        if (d / "system.qcow2").exists():
            out[node.id] = d
    return out


def _has_virtio(node) -> bool:
    """Whether the machine carries the virtio drivers (Linux always; Windows
    when its base or template was prepared with them and the node does not
    say `virtio = false`). Recorded in the manifest so an import on another
    PC never boots a Windows disk from a virtio device it has no driver for."""
    if not node.is_windows:
        return True
    return node.vars.get("virtio") is not False and images.base_virtio(node.image)


def _backing_identity(node_image: str) -> dict:
    """What a thin machine disk sits on: the image id, whether it is a base
    or a template, and the fingerprint import must find on the other PC."""
    tpl = images.templates().get(node_image)
    if tpl is not None:
        if not tpl.disk.exists():
            raise TransferError(f"template '{node_image}' has no disk on this PC")
        return {"id": node_image, "kind": "template", "fingerprint": fingerprint(tpl.disk),
                "chain": _backing_identity(tpl.image) if tpl.image else None}
    base = images.base_path(node_image)
    if not base.exists():
        raise TransferError(f"no prepared base for '{node_image}' on this PC")
    return {"id": node_image, "kind": "base", "fingerprint": fingerprint(base), "chain": None}


def export_lab(lab: Lab, dest: str | Path, thin: bool = False, compress: bool = False,
               emit: Emit = _say) -> Path:
    """Writes the lab into a new folder `dest`. The lab must be stopped."""
    dest = Path(dest).expanduser()
    if dest.exists() and any(dest.iterdir()):
        raise TransferError(f"{dest} exists and is not empty; export into a new folder")
    st = state.load(lab.name)
    if st and st.running():
        raise TransferError(
            f"stop lab '{lab.name}' first: disks of running machines are not consistent")
    machines = _machine_dirs(lab)
    if not machines:
        raise TransferError(f"lab '{lab.name}' has no built machines to export; "
                            f"its definition alone is content/labs/{lab.name}.toml")
    if thin and compress:
        raise TransferError("--compress applies to full exports (thin copies the files as they are)")

    # The MAC addresses the machines have had so far, so an import under a
    # new name can keep them (they are otherwise derived from the lab name).
    plan = compile_topology(lab, check_ports=False)
    macs = {n.id: [link.mac for link in plan.ports_for(n.id)] for n in lab.node_list()}

    needed = 0
    entries: dict[str, dict] = {}
    carried: dict[str, Template] = {}
    for node_id, ndir in machines.items():
        node = lab.nodes[node_id]
        files = [f for pat in MACHINE_FILES for f in sorted(ndir.glob(pat))]
        entry = {"image": node.image, "files": [f.name for f in files], "backing": None,
                 "virtio": _has_virtio(node)}
        system = ndir / "system.qcow2"
        if thin:
            needed += sum(f.stat().st_size for f in files)
            if _backing_of(system) is not None:
                entry["backing"] = _backing_identity(node.image)
                tpl = images.templates().get(node.image)
                if tpl is not None:
                    carried[tpl.id] = tpl
                    needed += tpl.disk.stat().st_size
        else:
            needed += _chain_size(system)
            needed += sum(f.stat().st_size for f in files if f.name != "system.qcow2")
        entries[node_id] = entry

    probe = dest if dest.exists() else dest.parent
    probe.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(probe).free
    if needed > free:
        raise TransferError(
            f"not enough space at {dest}: about {_size(needed)} needed, {_size(free)} free"
            + ("" if thin else "; --thin is much smaller when the other PC has the same images"))

    dest.mkdir(parents=True, exist_ok=True)
    (dest / "lab.toml").write_text(editor.emit(lab), encoding="utf-8")
    pw = secrets.password_path(lab.name)
    if pw.exists():
        shutil.copy2(pw, dest / secrets.PASSWORD_FILE)
    ev = paths.STATE / f"{lab.name}.evaluation.json"
    if ev.exists():
        shutil.copy2(ev, dest / "evaluation.json")

    for node_id, ndir in machines.items():
        out = dest / "machines" / node_id
        out.mkdir(parents=True, exist_ok=True)
        for name in entries[node_id]["files"]:
            src = ndir / name
            size = _size(src.stat().st_size)
            if name == "system.qcow2" and not thin:
                emit(f"{node_id}: writing a standalone system disk"
                     + (" (compressed)" if compress else "") + "…")
                _copy_flat(src, out / name, compress)
            elif name.endswith(".qcow2") and not thin:
                emit(f"{node_id}: {name} ({size})…")
                _copy_flat(src, out / name, compress)
            else:
                emit(f"{node_id}: {name} ({size})…")
                shutil.copy2(src, out / name)
    if carried:
        tdir = dest / "templates"
        tdir.mkdir(exist_ok=True)
        for tpl in carried.values():
            emit(f"template {tpl.id} ({tpl.size_text})…")
            shutil.copy2(tpl.disk, tdir / tpl.disk.name)
            if tpl.nvram.exists():
                shutil.copy2(tpl.nvram, tdir / tpl.nvram.name)

    manifest = {
        "format": FORMAT, "winlab": __version__, "lab": lab.name,
        "description": lab.description, "exported_at": time.time(),
        "thin": thin, "compressed": compress, "machines": entries, "macs": macs,
        "templates": {t.id: t.__dict__ for t in carried.values()},
    }
    (dest / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    total = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file())
    emit(f"exported '{lab.name}' to {dest} ({_size(total)}, "
         f"{'thin: needs the same images' if thin else 'standalone'})")
    return dest


# ------------------------------------------------------------------ import
def read_manifest(src: Path) -> dict:
    f = src / MANIFEST
    if not f.exists():
        raise TransferError(f"{src} is not a winlab export (no {MANIFEST})")
    try:
        man = json.loads(f.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TransferError(f"{f}: {exc}") from exc
    if int(man.get("format") or 0) > FORMAT:
        raise TransferError(
            f"this export was written by a newer winlab ({man.get('winlab')}); update first")
    return man


def _local_backing(ident: dict, src: Path, emit: Emit) -> Path:
    """The file on this PC a thin disk must sit on, fingerprint-checked;
    a template the export carries is installed when it is missing."""
    image_id, kind, want = ident["id"], ident["kind"], ident["fingerprint"]
    if kind == "template":
        tpl = images.templates().get(image_id)
        if tpl is None:
            raw = read_manifest(src)["templates"].get(image_id)
            packed = src / "templates" / f"{image_id}.qcow2"
            if not raw or not packed.exists():
                raise TransferError(f"template '{image_id}' is neither on this PC nor in the export")
            if ident.get("chain"):
                _local_backing(ident["chain"], src, emit)
            tpl = Template(**raw)
            tpl.disk.parent.mkdir(parents=True, exist_ok=True)
            emit(f"installing template {image_id} from the export…")
            shutil.copy2(packed, tpl.disk)
            vars_fd = src / "templates" / f"{image_id}.vars.fd"
            if vars_fd.exists():
                shutil.copy2(vars_fd, tpl.nvram)
            if ident.get("chain"):
                _rebase(tpl.disk, _local_backing(ident["chain"], src, emit))
            entries = images.templates()
            entries[image_id] = tpl
            images.save_templates(entries)
        path = tpl.disk
    else:
        path = images.base_path(image_id)
        if not path.exists():
            raise TransferError(
                f"this is a thin export: machine disks sit on the prepared base '{image_id}', "
                f"which this PC does not have. Prepare it from the same winlab image store "
                f"(copy, not a new install), or export in full on the source PC")
    if fingerprint(path) != want:
        raise TransferError(
            f"this is a thin export made on a different '{image_id}' image than this PC "
            f"has ({'template' if kind == 'template' else 'base'} fingerprints differ); "
            f"a delta on the wrong base is garbage. Export in full on the source PC")
    return path


def import_lab(src: str | Path, new_name: str = "", emit: Emit = _say) -> Lab:
    """Brings an export folder in as lab `new_name` (default: its own name)."""
    src = Path(src).expanduser()
    man = read_manifest(src)
    name = new_name or str(man.get("lab") or "")
    if not LAB_NAME.match(name):
        raise TransferError(
            f"'{name}': a lab name is 2-32 lower-case letters, digits and dashes")
    toml_path = paths.LABS / f"{name}.toml"
    from . import content
    if toml_path.exists() or content.locked(toml_path) or content.exists(toml_path):
        raise TransferError(
            f"lab '{name}' already exists on this PC; import it under another name "
            f"with --as, or remove {toml_path} first")
    if _machine_dirs_exist(name):
        raise TransferError(
            f"{paths.lab_dir(name)} still holds machine disks of a lab once called '{name}'; "
            f"delete that folder or import under another name with --as")
    lab_toml = src / "lab.toml"
    if not lab_toml.exists():
        raise TransferError(f"{src}: lab.toml missing")

    with lab_toml.open("rb") as fh:
        raw = tomllib.load(fh)
    raw.setdefault("lab", {})["name"] = name
    lab = schema._build(raw, lab_toml)
    renamed = name != man.get("lab")
    if renamed:
        for node in lab.nodes.values():
            for i, nic in enumerate(node.nics):
                known = (man.get("macs") or {}).get(node.id) or []
                if i < len(known) and not nic.mac:
                    nic.mac = known[i]
    for node_id, entry in (man.get("machines") or {}).items():
        node = lab.nodes.get(node_id)
        if node is not None and node.is_windows and not entry.get("virtio"):
            # Exported without the virtio drivers, or by a winlab that did not
            # record them: the emulated disk and NIC are what this Windows
            # has drivers for, whatever the base on this PC carries.
            node.vars["virtio"] = False
    pw = src / secrets.PASSWORD_FILE
    if pw.exists():
        lab.admin_password = pw.read_text(encoding="utf-8").strip()
    schema.validate(lab)

    # Disks first, then the definition, so a failed copy leaves no half lab.
    lab_dir = paths.lab_dir(name)
    try:
        for node_id, entry in (man.get("machines") or {}).items():
            if node_id not in lab.nodes:
                continue
            out = lab_dir / node_id
            out.mkdir(parents=True, exist_ok=True)
            for fname in entry.get("files") or []:
                f = src / "machines" / node_id / fname
                if not f.exists():
                    raise TransferError(f"{f} is missing from the export")
                emit(f"{node_id}: {fname} ({_size(f.stat().st_size)})…")
                shutil.copy2(f, out / fname)
            if entry.get("backing"):
                local = _local_backing(entry["backing"], src, emit)
                _rebase(out / "system.qcow2", local)
        lab_dir.mkdir(parents=True, exist_ok=True)
        if pw.exists():
            shutil.copy2(pw, secrets.password_path(name))
        ev = src / "evaluation.json"
        if ev.exists():
            paths.STATE.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ev, paths.STATE / f"{name}.evaluation.json")
        lab.source_path = str(toml_path)
        paths.LABS.mkdir(parents=True, exist_ok=True)
        editor.save(lab, toml_path)
    except Exception:
        shutil.rmtree(lab_dir, ignore_errors=True)
        toml_path.unlink(missing_ok=True)
        raise
    emit(f"imported '{name}'"
         + (f" (was '{man.get('lab')}'; machines keep their MAC addresses)" if renamed else "")
         + f": winlab lab up {name}")
    return lab


def _machine_dirs_exist(name: str) -> bool:
    d = paths.lab_dir(name)
    return d.exists() and any((p / "system.qcow2").exists() for p in d.iterdir() if p.is_dir())


def describe_export(src: Path) -> str:
    man = read_manifest(src)
    machines = man.get("machines") or {}
    total = sum(f.stat().st_size for f in src.rglob("*") if f.is_file())
    lines = [f"lab '{man.get('lab')}' exported {time.strftime('%Y-%m-%d %H:%M', time.localtime(man.get('exported_at') or 0))} "
             f"by winlab {man.get('winlab')}: {len(machines)} machines, {_size(total)}, "
             f"{'thin (needs the same images)' if man.get('thin') else 'standalone'}"]
    for node_id, entry in machines.items():
        lines.append(f"  {node_id:<12} {entry.get('image')}  {', '.join(entry.get('files') or [])}")
    return "\n".join(lines)
