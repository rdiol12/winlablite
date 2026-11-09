"""Stdlib test suite (no pytest). Run: python -m tests.test_winlab

Covers the logic that can be checked without booting a VM: schema validation,
topology compilation, FAT image round-trip, Ed25519, license keys/tokens,
role ordering, fault resolution, the apkovl overlay, and lab editing.
"""

from __future__ import annotations

import re
import sys
import ipaddress
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PASS = 0
FAIL = 0
CURRENT = ""
FAILED: list[str] = []  # repeated at the end, so a log's tail names every failure


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        FAILED.append(f"{CURRENT}: {name}  {detail}"[:400])
        print(f"  FAIL {name}  {detail}")


def winlab_cli(*args: str, env: dict | None = None):
    """`python -m winlab <args>` run in this process: cli.main with its
    output captured, for checks that are about what a command does rather
    than about a fresh interpreter. Returns what subprocess.run would
    (returncode, stdout, stderr); env entries are set for the call only,
    and an uncaught exception comes back as a traceback on stderr."""
    import contextlib
    import io
    import os
    import traceback
    from types import SimpleNamespace
    from winlab import cli
    out, err = io.StringIO(), io.StringIO()
    saved = {k: os.environ.get(k) for k in (env or {})}
    os.environ.update(env or {})
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = cli.main(list(args))
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
                if not isinstance(exc.code, (int, type(None))):
                    print(exc.code, file=sys.stderr)
            except Exception:  # noqa: BLE001 - a crash is what the caller checks for
                traceback.print_exc()
                rc = 1
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return SimpleNamespace(returncode=0 if rc is None else rc, stdout=out.getvalue(), stderr=err.getvalue())




def test_schema_rejects_bad():
    from winlab import schema
    from winlab.schema import LabError

    bad = """
[lab]
name = "bad"
[[network]]
id = "n1"
cidr = "10.0.0.0/24"
[[node]]
id = "dc"
image = "ws2025"
roles = ["ad-ds"]
  [[node.nic]]
  network = "n1"
"""  # DC on DHCP -> must fail (DC needs static)
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(bad)
        path = f.name
    try:
        schema.load(path)
        check("rejects DHCP domain controller", False, "no error raised")
    except LabError:
        check("rejects DHCP domain controller", True)
    finally:
        Path(path).unlink(missing_ok=True)


def test_fatfs():
    from winlab import fatfs

    f = fatfs.floppy("WLPROV")
    f.add_file("autounattend.xml", "<?xml version='1.0'?><x/>")
    f.add_file("winlab-agent.ps1", "# agent\n" * 50)
    with tempfile.TemporaryDirectory() as td:
        p = f.write(Path(td) / "a.img")
        data = p.read_bytes()
        check("floppy is 1.44MB", len(data) == 1474560, str(len(data)))
        check("boot signature", data[510] == 0x55 and data[511] == 0xAA)
        # long filename present as UTF-16LE in the directory region
        check("LFN autounattend", "autounattend.xml".encode("utf-16-le")[:10] in data)


def test_ed25519():
    from winlab.licensing import ed25519 as e

    sk = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    pk = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    msg = bytes.fromhex("72")
    sig = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    check("KAT pubkey", e.publickey(sk) == pk)
    check("KAT sign", e.sign(msg, sk) == sig)
    check("KAT verify", e.verify(sig, msg, pk))
    check("tamper rejected", not e.verify(sig, msg + b"x", pk))








def test_faults():
    from winlab import faults

    check("9 scenarios", len(faults.SCENARIOS) >= 9, str(len(faults.SCENARIOS)))
    cmds = faults.build_commands(
        "rogue-dhcp",
        {"dev": "lab0.30", "victim": "10.30.10.21", "rogue_lo": "10.30.10.181",
         "rogue_hi": "10.30.10.190", "gw": "10.30.10.1"},
        clear=False,
    )
    check("rogue-dhcp renders dnsmasq", any("dnsmasq" in c for c in cmds))
    clear = faults.build_commands("rogue-dhcp", {"dev": "lab0.30"}, clear=True)
    check("rogue-dhcp clear kills it", any("kill" in c for c in clear))


def test_apkovl():
    from winlab import alpineovl

    with tempfile.TemporaryDirectory() as td:
        p = alpineovl.build_apkovl(Path(td) / "o.tar.gz")
        info = alpineovl.verify(p)
        check("overlay has agent", info["has_agent"])
        check("overlay has service", info["has_service"])
        check("overlay lists packages", info["packages"] >= 10, str(info["packages"]))


def test_editor():
    from winlab import editor, schema

    lab = schema.load("ad-ds-basics")
    before = len(lab.nodes)
    editor.add_node(lab, "web", kind="windows-server", network="corp", count=2)
    check("added 2 nodes", len(lab.nodes) == before + 2, str(len(lab.nodes)))
    net = editor.add_network(lab, "dmz", vlan=50)
    check("auto-allocated subnet", net.cidr.endswith("/24"))
    text = editor.emit(lab)
    # round-trip: emitted TOML must re-parse and re-validate
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(text)
        path = f.name
    try:
        reloaded = schema.load(path)
        check("emitted TOML re-parses", len(reloaded.nodes) == before + 2)
    finally:
        Path(path).unlink(missing_ok=True)


def test_devices():
    from winlab import editor, roles, schema

    lab = schema.load("ad-ds-basics")
    editor.add_device(lab, "fs01", "printer", "Office-Printer", location="Floor 1")
    editor.add_device(lab, "fs01", "scanner", "Office-Scanner")
    editor.add_device(lab, "fs01", "nas", "BulkStore")
    fs = lab.nodes["fs01"]
    check("3 devices attached", len(fs.devices) == 3, str(len(fs.devices)))
    eff = roles.effective_roles(fs)
    check("hosting a device implies the devices role", "devices" in eff)
    # round-trip through emitted TOML
    text = editor.emit(lab)
    check("devices survive TOML emit", text.count("[[node.device]]") == 3)
    import tempfile
    from pathlib import Path as _P
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write(text); path = f.name
    try:
        reloaded = schema.load(path)
        check("devices re-parse", len(reloaded.nodes["fs01"].devices) == 3)
    finally:
        _P(path).unlink(missing_ok=True)
    # unknown kind rejected
    try:
        editor.add_device(lab, "fs01", "teleporter", "X")
        check("rejects unknown device kind", False)
    except editor.EditError:
        check("rejects unknown device kind", True)


def test_hardware_args():
    from winlab import netplan, schema
    from winlab.providers.qemu import QemuProvider
    from winlab.model import Node, Nic

    lab = schema.load("ad-ds-basics")
    lab.nodes["gfx"] = Node(id="gfx", image="win11", kind="windows-client",
                            nics=[Nic(network="corp", ip="10.10.10.60")],
                            vars={"gpu": True, "usb_storage_gb": 4})
    plan = netplan.compile_topology(lab, check_ports=False)
    prov = QemuProvider(plan, accel="tcg")
    argv = " ".join(prov.build_node(lab.nodes["gfx"]).argv)
    check("gpu emulated, 2D so QEMU starts without gl=on", "virtio-vga," not in argv and "-device virtio-vga " in argv + " " and "virtio-vga-gl" not in argv)
    check("usb controller present", "qemu-xhci" in argv)
    check("usb storage present", "usb-storage" in argv)
    check("bios boot menu enabled", "menu=on" in argv)
    # A regular PC: Intel devices Windows drives itself, a sound card, an
    # empty DVD drive for discs that go in later, no paravirtual device.
    pc = prov.build_node(lab.nodes["pc01"]).argv
    joined = " ".join(pc)
    check("Intel nic and SATA, nothing virtio", "e1000e" in joined and "ich9-ahci" in joined
          and "virtio" not in joined.replace("virtio-vga", ""), joined[-400:])
    check("Intel HD Audio with no host backend", "intel-hda,id=hda" in joined
          and "hda-duplex,bus=hda.0,audiodev=snd0" in joined and "none,id=snd0" in joined)
    check("an empty DVD drive on the SATA controller", "id=cdattach,if=none,media=cdrom" in pc
          and any(a.startswith("ide-cd,bus=ahci.") and a.endswith("drive=cdattach") for a in pc))
    check("no balloon on a pc", "virtio-balloon-pci" not in pc)
    nics = [x for x in pc if x.startswith("e1000e,")]
    check("each network card is in the boot order after the disks (PXE when nothing else boots)",
          nics and all("bootindex=2" in x for x in nics)
          and all(int(x.split("bootindex=")[1]) >= 20 for x in pc if "bootindex=" in x and x.startswith("e1000e")))
    check("no stick until one is plugged in", "wlstick" not in joined)
    lx = " ".join(prov.build_node(lab.nodes["lx01"]).argv) if "lx01" in lab.nodes else ""
    check("still isolated", not __import__("winlab.providers.qemu", fromlist=["check_isolation"]).check_isolation(pc))
    from winlab.providers.qemu import hardware_of
    check("the plan names it a pc", hardware_of(lab.nodes["pc01"]) == "pc" and hardware_of(lab.nodes["dc01"]) == "pc")
    fab = " ".join(prov.build_fabric().argv)
    check("the fabric keeps its balloon", "virtio-balloon-pci" in fab)


def test_guest_faults():
    from winlab import guestfaults as gf
    check("12+ guest problems", len(gf.SCENARIOS) >= 12, str(len(gf.SCENARIOS)))
    apply_cmd, shell = gf.build_command("service-stopped", {"service": "DNS"}, False)
    check("apply stops the service", "Stop-Service" in apply_cmd and "DNS" in apply_cmd)
    clear_cmd, _ = gf.build_command("service-stopped", {"service": "DNS"}, True)
    check("clear restarts it", "Start-Service" in clear_cmd)
    lin, lsh = gf.build_command("linux-disk-full", {}, False)
    check("linux fault uses sh", lsh == "sh")
    # every scenario builds both directions without crashing
    ok = True
    for sid in gf.SCENARIOS:
        try:
            gf.build_command(sid, {}, False); gf.build_command(sid, {}, True)
        except KeyError:
            ok = False
    check("all scenarios render", ok)
    # A problem is offered only on a machine it can run on: its OS, and for Linux its flavour.
    pf, rc, sd = gf.SCENARIOS["pf-disabled"], gf.SCENARIOS["linux-service-stopped"], gf.SCENARIOS["systemd-service-stopped"]
    check("the packet-filter problem is for the OPNsense appliance only",
          gf.applies_to(pf, "linux", "opnsense") and not gf.applies_to(pf, "linux", "alpine")
          and not gf.applies_to(pf, "windows-server", "ws2025"))
    check("OpenRC problems need Alpine, systemd problems Ubuntu",
          gf.applies_to(rc, "linux", "alpine") and not gf.applies_to(rc, "linux", "ubuntu")
          and gf.applies_to(sd, "linux", "ubuntu") and not gf.applies_to(sd, "linux", "opnsense"))
    check("a Windows problem fits any Windows kind, never Linux",
          gf.applies_to(gf.SCENARIOS["service-stopped"], "windows-client", "win11")
          and not gf.applies_to(gf.SCENARIOS["service-stopped"], "linux", "ubuntu"))
    check("the firewall sees only its own problems",
          [f.id for f in gf.for_machine("linux", "opnsense")] == ["pf-disabled", "opn-wg-down", "opn-ids-stopped"])
    check("the catalog names the flavour", "[opnsense]" in gf.render_catalog())


def test_role_count():
    from winlab import roles
    m = roles.load_manifest()
    check("28+ roles in library", len(m) >= 28, str(len(m)))
    from winlab import paths
    missing = [r.script for r in m.values() if r.script and not (paths.ROLES / r.script).exists()]
    check("every script role has its script", not missing, str(missing))
    check("no Windows role is a script any more",
          all(rd.engine == "dsc" or rd.script.endswith(".sh") for rd in m.values()))


def test_lab_exercises_exist():
    from winlab import exercises, paths, schema

    have = {ex.id for ex in exercises.list_available()}
    for f in sorted(paths.LABS.glob("*.toml")):
        lab = schema.load(f.stem)
        missing = [e for e in lab.exercises if e not in have]
        check(f"{f.stem}: every listed exercise exists", not missing, str(missing))
    nodes_ok = []
    for ex in exercises.list_available():
        lab = schema.load(ex.lab)
        bad = [c.node for c in ex.checks if c.node not in lab.nodes and c.node not in ("fabric", "winlab")]
        nodes_ok.append((ex.id, bad))
    bad = [(i, b) for i, b in nodes_ok if b]
    check("every check targets a node in its lab", not bad, str(bad))


def test_exercise_matching():
    from winlab.exercises import Check, output_matches

    exact = Check(name="x", node="n", script="s", expect="10.10.10.10")
    check("exact matches", output_matches(exact, "10.10.10.10\r\n"))
    check("exact rejects a longer address", not output_matches(exact, "10.10.10.100"))
    check("exact is case-insensitive", output_matches(
        Check(name="x", node="n", script="s", expect="True"), "true"))
    contains = Check(name="x", node="n", script="s", expect="corp", match="contains")
    check("contains matches a substring", output_matches(contains, "corp.lab"))
    rx = Check(name="x", node="n", script="s", expect=r"^10\.20\.20\.25$", match="regex")
    check("regex is multiline", output_matches(rx, "10.20.20.24\n10.20.20.25"))
    check("no expect passes on rc alone", output_matches(
        Check(name="x", node="n", script="s"), "anything"))






class _FakeGuest:
    """Stands in for GuestChannel: a tiny model of a guest with marker files,
    a reboot counter, and a scripted behaviour per role/apply pass."""

    def __init__(self, behaviour, dsc_behaviour=None):
        self.done: set[str] = set()
        self.files: dict[str, bytes] = {}
        self.reboots = 0
        self.passes: dict[str, int] = {}
        self.behaviour = behaviour
        self.dsc_behaviour = dsc_behaviour

    def wait_responsive(self, shell="powershell", timeout=0):
        return None

    def put_file(self, path, data):
        self.files[path] = data

    def wait_for_reboot(self, timeout=0):
        self.reboots += 1
        return {"event": "ready"}

    def close(self):
        pass

    def connect(self, retries=1, delay=1):
        return self

    def run(self, command, shell="powershell", timeout=0, reboot_ok=False):
        import re
        from winlab.guestctl import Result

        if "Test-Path" in command:
            name = command.replace("'", "").rstrip("}").split("\\")[-1].split()[0]
            present = name in self.done or name in {
                p.split("\\")[-1] for p in self.files}
            return Result(0, "True" if present else "False", "")
        if "test -f" in command:
            name = command.split("/")[-1].split()[0]
            return Result(0, "True" if name in self.done else "False", "")
        if "winlab\\done" in command and "foreach" in command:
            self.done.update(re.findall(r"'([^']+)'", command.split("@(", 1)[1].split(")", 1)[0]))
            return Result(0, "", "")
        return Result(0, "", "")

    def run_script(self, command, timeout=0, reboot_ok=False):
        from winlab.guestctl import Result

        if "apply-dsc.ps1" in command:
            n = self.passes["dsc"] = self.passes.get("dsc", 0) + 1
            return self.dsc_behaviour(self, "-Status" in command, n)
        name = command.split("\\")[-1].removesuffix(".ps1")
        n = self.passes[name] = self.passes.get(name, 0) + 1
        return self.behaviour(self, name, n) or Result(0, "", "")






def test_psmodules_zip():
    import io
    import zipfile
    from winlab import psmodules

    m = psmodules.Module("FakeDsc", "1.2.3", "test")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("_rels/.rels", "<xml/>")
        zf.writestr("[Content_Types].xml", "<xml/>")
        zf.writestr("FakeDsc.nuspec", "<xml/>")
        zf.writestr("package/services/metadata/core-properties/x.psmdcp", "<xml/>")
        zf.writestr("FakeDsc.psd1", "@{\n    ModuleVersion = '1.2.3'\n}".encode("utf-16"))  # New-ModuleManifest writes UTF-16
        zf.writestr("DSCResources/Thing/Thing.psm1", "function Get-TargetResource {}")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        vdir = psmodules.unpack_nupkg(buf.getvalue(), m, root)
        check("module lands at Name/Version", vdir == root / "FakeDsc" / "1.2.3")
        check("nuget metadata stripped",
              not (vdir / "FakeDsc.nuspec").exists() and not (vdir / "_rels").exists())
        check("module files kept", (vdir / "DSCResources" / "Thing" / "Thing.psm1").exists())
        out = psmodules.build_zip(root, root / "bundle.zip", (m,))
        with zipfile.ZipFile(out) as zf:
            names = sorted(zf.namelist())
        check("bundle rooted at Name/Version for Expand-Archive",
              names == ["FakeDsc/1.2.3/DSCResources/Thing/Thing.psm1", "FakeDsc/1.2.3/FakeDsc.psd1"],
              str(names))
    wrong = io.BytesIO()
    with zipfile.ZipFile(wrong, "w") as zf:
        zf.writestr("FakeDsc.psd1", "@{\n    ModuleVersion = '9.9.9'\n}")
    try:
        with tempfile.TemporaryDirectory() as td:
            psmodules.unpack_nupkg(wrong.getvalue(), m, Path(td))
        check("manifest version mismatch is rejected", False)
    except psmodules.ModuleError:
        check("manifest version mismatch is rejected", True)
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("other.psd1", "")
    try:
        with tempfile.TemporaryDirectory() as td:
            psmodules.unpack_nupkg(bad.getvalue(), m, Path(td))
        check("nupkg without the manifest is rejected", False)
    except psmodules.ModuleError:
        check("nupkg without the manifest is rejected", True)


def test_data_disk_carries_dsc():
    from winlab import netplan, provision, schema

    lab = schema.load("ad-ds-basics")
    plan = netplan.compile_topology(lab, check_ports=False)
    with tempfile.TemporaryDirectory() as td:
        img = provision.build_data_disk(lab.nodes["dc01"], lab, plan, Path(td) / "payload.img")
        check("data disk builds with the config on it", img.exists() and img.stat().st_size > 0)
    files = provision._dsc_files(lab.nodes["dc01"], lab, plan)
    check("generated config goes on the data disk", "node.dsc.ps1" in files, str(list(files)))
    check("apply script ships with the agent", "apply-dsc.ps1" in provision._agent_files())
    check("legacy role scripts for dsc roles are gone",
          not any(n in provision._role_files() for n in ("ad-ds.ps1", "dns.ps1", "dhcp.ps1", "domain-join.ps1")))




def test_frozen_layout():
    """paths.seed_content lays the bundled content pack out next to the exe:
    adds missing files, upgrades files the user never touched, keeps edits."""
    import os
    from winlab import paths

    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "bundle" / "content"
        dest = Path(td) / "content"
        (bundle / "labs").mkdir(parents=True)
        (bundle / "roles").mkdir()
        (bundle / "labs" / "a.toml").write_text("v1\n")
        (bundle / "roles" / "r.ps1").write_text("v1\n")

        rep = paths.seed_content(bundle, dest)
        check("seed adds every file", len(rep.added) == 2 and not rep.updated and not rep.kept)
        check("seed manifest written", (dest / paths.SEED_MANIFEST).exists())
        rep = paths.seed_content(bundle, dest)
        check("seed is idempotent", rep.changed == 0 and not rep.kept)

        # Customer edits the lab; vendor ships a new exe with both files changed.
        (dest / "labs" / "a.toml").write_text("mine\n")
        (bundle / "labs" / "a.toml").write_text("v2\n")
        (bundle / "roles" / "r.ps1").write_text("v2\n")
        (bundle / "exercises").mkdir()
        (bundle / "exercises" / "e.toml").write_text("new\n")
        rep = paths.seed_content(bundle, dest)
        check("edited lab kept", (dest / "labs" / "a.toml").read_text() == "mine\n"
              and rep.kept == [dest / "labs" / "a.toml"])
        check("untouched role upgraded", (dest / "roles" / "r.ps1").read_text() == "v2\n"
              and rep.updated == [dest / "roles" / "r.ps1"])
        check("new exercise added", rep.added == [dest / "exercises" / "e.toml"])

        check("no bundle from source", paths.seed_content().changed == 0 and paths.BUNDLE is None)
        check("WINLAB_HOME overrides root",
              paths.compute_root({"WINLAB_HOME": td}) == Path(td).resolve())
        check("root is the checkout", paths.compute_root({}) == Path(__file__).resolve().parent.parent)
        check("writable probe", paths.writable(Path(td) / "new") and not (Path(td) / "new" / f".winlab-write-{os.getpid()}").exists())








def test_schema_rejects_low_memory():
    from winlab import schema
    from winlab.schema import LabError

    src = (Path(__file__).resolve().parent.parent / "content/labs/ad-ds-basics.toml").read_text()
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "lean.toml"
        p.write_text(src.replace("memory_mb = 2048", "memory_mb = 1536", 1))
        try:
            schema.load(str(p))
            check("desktop server under 2 GiB rejected", False)
        except LabError as exc:
            check("desktop server under 2 GiB rejected", "2048" in str(exc), str(exc))
        p.write_text(src.replace('image = "ws2025"\nkind = "windows-server"\ncpus = 2\n'
                                 'memory_mb = 2048', 'image = "ws2025-core"\n'
                                 'kind = "windows-server"\ncpus = 2\nmemory_mb = 1024', 1))
        lab = schema.load(str(p))
        check("server core at 1 GiB accepted", lab.nodes["dc01"].memory_mb == 1024)


# ----------------------------------------------------------------- learning app




def test_progress_store():
    import tempfile
    from winlab import lessons, progress
    orig = progress.progress_file
    with tempfile.TemporaryDirectory() as tmp:
        progress.progress_file = lambda: Path(tmp) / "progress.json"
        try:
            ls = lessons.list_available()
            e = progress.set_step("tour-of-the-lab", 0, True, total_steps=3)
            check("first tick starts the lesson", e.get("status") == "started", str(e))
            for i in (1, 2):
                e = progress.set_step("tour-of-the-lab", i, True, total_steps=3)
            check("every tick completes a steps lesson", e.get("status") == "done", str(e))
            g = progress.record_grade("promote-first-dc", 100, True)
            check("a pass records best and done", g.get("best") == 100 and g.get("status") == "done", str(g))
            g = progress.record_grade("promote-first-dc", 40, False)
            check("best score survives a worse attempt", g.get("best") == 100 and g.get("attempts") == 2, str(g))
            progress.hint_used("dns-wrong", 2)
            pr = progress.record_problem("dns-wrong", "dc01", True, hints_used=2)
            check("solved problems are counted", pr.get("solved") == 1, str(pr))
            s = progress.summary(ls)
            check("summary", s["done"] == 2 and s["total"] >= 40 and s["problems_solved"] == 1 and s["next"], str(s))
            check("stored under the override", (Path(tmp) / "progress.json").exists())
            progress.reset("promote-first-dc")
            check("one lesson reset", progress.summary(ls)["done"] == 1)
            progress.reset()
            check("everything reset", progress.summary(ls)["done"] == 0)
        finally:
            progress.progress_file = orig


def test_guest_fault_hints():
    from winlab import guestfaults as gf
    cat = gf.catalog()
    check("26+ scenarios", len(cat) >= 26, str(len(cat)))
    bad = []
    for s in cat:
        if len(s.hints) != 3 or not s.verify:
            bad.append(s.id)
        h1, h3 = gf.hint(s.id, 1), gf.hint(s.id, 3)
        if not h1 or not h3 or h1 == h3:
            bad.append(s.id + ":hints")
        cmd, shell, expect = gf.verify_command(s.id, {})
        if not cmd or not shell or not expect:
            bad.append(s.id + ":verify")
    check("every scenario has a 3-hint ladder and a verify", not bad, ", ".join(bad))
    check("verify reads the guest's True/False", gf.is_fixed("True\r\n") and not gf.is_fixed("False") and not gf.is_fixed(""))
    dns = next(s.id for s in cat if "dns" in s.id)
    cmd, _, _ = gf.verify_command(dns, {"dns": "10.10.10.10"})
    check("parameters fill the verify command", "10.10.10.10" in cmd, cmd)
    share = next(s.id for s in cat if "share" in s.id)
    brk, _ = gf.build_command(share, {"share": "Company"}, clear=False)
    fix, _ = gf.build_command(share, {"share": "Company"}, clear=True)
    check("share path is saved when broken and read back when fixed",
          "share-Company.path" in brk and "share-Company.path" in fix)


def test_wsbridge():
    import socket
    import struct
    import threading
    from winlab import wsbridge as ws
    check("RFC 6455 accept key", ws.accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    f = ws.encode_frame(b"hello", mask=True)
    d = ws.decode_frame(f)
    check("masked frame round-trips", d is not None and d[0] and d[1] == ws.OP_BINARY and d[2] == b"hello" and d[3] == len(f), str(d))
    big = bytes(range(256)) * 300
    f = ws.encode_frame(big)
    d = ws.decode_frame(f + b"tail")
    check("64-bit length frame", bool(d) and d[2] == big and d[3] == len(f))
    check("incomplete frame waits", ws.decode_frame(f[:5]) is None)
    frag = ws.encode_frame(b"ab", fin=False) + ws.encode_frame(b"cd", opcode=ws.OP_CONT)
    chunks = [frag[:3], frag[3:]]
    reader = ws.FrameReader(lambda n: chunks.pop(0) if chunks else b"")
    check("fragments reassemble", reader.next_message() == (ws.OP_BINARY, b"abcd"))
    hdr = {"Upgrade": "websocket", "Connection": "keep-alive, Upgrade", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
           "Sec-WebSocket-Version": "13", "Sec-WebSocket-Protocol": "binary"}
    code, _, headers = ws.handshake_response(hdr)
    hd = dict(headers)
    check("handshake 101 with the binary subprotocol",
          code == 101 and hd.get("Sec-WebSocket-Accept") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" and hd.get("Sec-WebSocket-Protocol") == "binary",
          f"{code} {hd}")
    check("missing key is 400", ws.handshake_response({"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Version": "13"})[0] == 400)
    check("wrong version is 426", ws.handshake_response(dict(hdr, **{"Sec-WebSocket-Version": "8"}))[0] == 426)

    # End to end: a TCP echo target behind the bridge, closed by the browser side.
    echo = socket.socket()
    echo.bind(("127.0.0.1", 0))
    echo.listen(1)
    port = echo.getsockname()[1]

    def serve():
        c, _ = echo.accept()
        while True:
            b = c.recv(4096)
            if not b:
                break
            c.sendall(b)
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    browser, handler = socket.socketpair()
    rfile = handler.makefile("rb")
    t = threading.Thread(target=ws.bridge, args=(handler, rfile.read1, handler.sendall, "127.0.0.1", port), daemon=True)
    t.start()
    browser.sendall(ws.encode_frame(b"ping-data", mask=True))
    browser.settimeout(5)
    got = ws.decode_frame(browser.recv(4096))
    check("bytes cross the bridge and come back unmasked", bool(got) and got[1] == ws.OP_BINARY and got[2] == b"ping-data", str(got))
    browser.sendall(ws.encode_frame(struct.pack("!H", 1000), opcode=ws.OP_CLOSE, mask=True))
    t.join(5)
    check("bridge returns after the close", not t.is_alive())
    # The server closes the connection after the handler returns; the
    # makefile keeps the socket open until it is closed too.
    rfile.close()
    handler.close()
    buf = b""
    try:
        while True:
            chunk = browser.recv(4096)
            if not chunk:
                break
            buf += chunk
    except OSError:
        pass
    frames = []
    while buf:
        d = ws.decode_frame(buf)
        if not d:
            break
        frames.append(d[1])
        buf = buf[d[3]:]
    check("exactly one close frame back", frames == [ws.OP_CLOSE], str(frames))
    browser.close()
    echo.close()


def test_vnc_display():
    from winlab import netplan, schema
    from winlab.providers.qemu import QemuProvider, VNC_BASE
    lab = schema.load("ad-ds-basics")
    plan = netplan.compile_topology(lab, check_ports=False)
    prov = QemuProvider(plan, accel="tcg")
    rts = [prov.build_node(lab.nodes[n]) for n in ("dc01", "fs01")]
    ports = [rt.vnc_port for rt in rts]
    check("each machine gets its own VNC display", len(set(ports)) == 2 and all(p >= VNC_BASE for p in ports), str(ports))
    argv = rts[0].argv
    i = argv.index("-vnc")
    check("display bound to loopback only", argv[i + 1] == f"127.0.0.1:{ports[0] - VNC_BASE}", argv[i + 1])


def test_update_check():
    from winlab import update
    check("parse_version", update.parse_version("v1.2.3") == (1, 2, 3))
    check("is_newer", update.is_newer("0.3.0", "0.2.0") and update.is_newer("v0.2.1", "0.2.0")
          and not update.is_newer("0.2.0", "0.2.0") and not update.is_newer("0.1.9", "0.2.0"))
    r = update.check("http://127.0.0.1:9/nothing", timeout=2)
    check("unreachable feed is an error, not a crash", bool(r.get("error")) and not r.get("newer") and bool(r.get("current")), str(r))
    check("default feed is the vendor site's signed feed", update.feed_url() == "https://smartcartapp.net/api/updates/app/latest")


def test_viewer_manifest():
    import re
    from winlab import viewer
    check("60 pinned files", len(viewer.FILES) == 60, str(len(viewer.FILES)))
    check("sha256 pins", all(re.fullmatch(r"[0-9a-f]{64}", h) for h in viewer.FILES.values()))
    check("ES module entry and licences pinned", {"core/rfb.js", "LICENSE.txt", "docs/LICENSE.MPL-2.0"} <= set(viewer.FILES))
    check("fetched from the tagged release", viewer.BASE == f"https://raw.githubusercontent.com/novnc/noVNC/v{viewer.VERSION}/")
    check("verify lists what is missing", isinstance(viewer.verify(), list))
    check("status renders", "noVNC" in viewer.render_status())




def test_app_icon():
    """winlab's own icon: a multi-size .ico and .png written with the standard
    library only, so the exe build and the browser tab need no image library."""
    import struct
    import tempfile
    import zlib
    from winlab import appicon
    ico = appicon.ico_bytes()
    count = struct.unpack("<HHH", ico[:6])
    check("ico header: reserved 0, type 1, seven sizes", count == (0, 1, 7), str(count))
    seen = []
    for k in range(7):
        w, h, _cc, _res, planes, bpp, size, off = struct.unpack("<BBBBHHII", ico[6 + 16 * k:22 + 16 * k])
        data = ico[off:off + size]
        dim = w or 256
        seen.append(dim)
        if dim >= 64:
            check(f"{dim} px entry is PNG", data[:8] == b"\x89PNG\r\n\x1a\n"
                  and struct.unpack(">II", data[16:24]) == (dim, dim))
        else:
            bih = struct.unpack("<IiiHHI", data[:20])
            check(f"{dim} px entry is a 32-bit BMP with its mask", bih[0] == 40 and bih[1] == dim and bih[2] == dim * 2
                  and bih[4] == 32 and size == 40 + dim * dim * 4 + dim * (((dim + 31) // 32) * 4), str(bih))
        check(f"{dim} px entry sane", planes == 1 and bpp == 32 and off + size <= len(ico))
    check("sizes 16 to 256", seen == [16, 24, 32, 48, 64, 128, 256], str(seen))
    px = appicon.render(32)
    centre = px[(13 * 32 + 16) * 4:(13 * 32 + 16) * 4 + 4]  # the dot on the screen
    corner = px[:4]
    check("a tile with a transparent corner and a white glyph on the screen",
          corner[3] == 0 and centre[3] == 255 and min(centre[:3]) > 200, f"{corner.hex()} {centre.hex()}")
    edge = px[(16 * 32 + 1) * 4:(16 * 32 + 1) * 4 + 4]
    check("the tile is winlab blue", edge[3] == 255 and edge[2] > edge[0] + 80, edge.hex())
    png = appicon.png(16)
    ihdr = struct.unpack(">IIBBBBB", png[16:29])
    check("png is 16x16 RGBA 8-bit", ihdr[:4] == (16, 16, 8, 6))
    check("png chunk crc", struct.unpack(">I", png[29:33])[0] == zlib.crc32(png[12:29]) & 0xFFFFFFFF)
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "winlab.ico"
        r = winlab_cli("icon", str(out))
        check("winlab icon writes the exe icon", r.returncode == 0 and out.read_bytes() == ico, r.stderr[-300:])
        r = winlab_cli("icon", "--size", "48", str(Path(td) / "w.png"))
        check("winlab icon writes a png", r.returncode == 0 and (Path(td) / "w.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n", r.stderr[-300:])
    build = (Path(__file__).resolve().parents[1] / "packaging" / "build-exe.ps1").read_text(encoding="utf-8")
    check("the exe build renders the icon and hands it to PyInstaller",
          "-m winlab icon $ico" in build and "'--icon', $ico," in build)


def test_access_commands_dispatch():
    """--cmd on exec and shell must not overwrite the top-level command name."""
    from winlab import cli
    p = cli.build_parser()
    a = p.parse_args(["exec", "dc01", "--lab", "x", "--cmd", "cmd", "--", "Get-Service", "-Name", "DNS"])
    check("exec keeps its command name with --cmd", a.cmd == "exec" and a.shell == "cmd", str(a))
    check("exec takes options after the machine and the command after --",
          a.lab == "x" and a.command == ["Get-Service", "-Name", "DNS"], str(a))
    a = p.parse_args(["shell", "dc01", "--cmd"])
    check("shell keeps its command name with --cmd", a.cmd == "shell" and a.use_cmd, str(a))
    r = winlab_cli("exec", "dc01", "--lab", "no-such-lab", "--", "hostname")
    check("winlab exec reaches the access code instead of crashing",
          r.returncode == 5 and "Traceback" not in r.stderr, r.stderr[-300:])


def test_guest_channel_lines():
    """The serial channel: noise skipped, two replies in one read kept apart,
    and a reply of many megabytes (get_file) read in linear time."""
    import base64
    import json
    import socket
    import threading
    import time as _t
    from winlab import guestctl, qmp

    def b64(s):
        return base64.b64encode(s.encode()).decode()

    big = "A" * (6 << 20)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    script = [b"boot noise {not json\n" + (json.dumps({"id": 1, "rc": 0, "out": b64("one")}) + "\n"
                                             + json.dumps({"id": 2, "rc": 3, "out": "", "err": b64("two")}) + "\n").encode(),
              (json.dumps({"id": 3, "rc": 0, "out": b64(big)}) + "\n").encode()]

    read_all = threading.Event()

    def serve():
        c, _ = srv.accept()
        c.recv(4096)
        c.sendall(script[0])
        data = script[1]  # buffered until request 3 asks for it
        for i in range(0, len(data), 1000):
            c.sendall(data[i:i + 1000])
        read_all.wait(30)  # hang up only once the client has its replies
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    with guestctl.GuestChannel(port, timeout=30).connect() as ch:
        r1 = ch.run("a", timeout=10)
        r2 = ch.run("b", timeout=10)
        check("with ...connect() keeps its one connection; noise skipped, two replies in one read kept apart",
              (r1.rc, r1.out, r2.rc, r2.err) == (0, "one", 3, "two"), str((r1, r2)))
        t0 = _t.perf_counter()
        r3 = ch.run("c", timeout=60)
        took = _t.perf_counter() - t0
        check("a 6 MB file reply in 1 KB pieces arrives whole, in linear time", r3.out == big and took < 10, f"{took:.1f}s")
    read_all.set()
    srv.close()

    # The monitor: a greeting that never comes leaves no socket behind.
    m = socket.socket()
    m.bind(("127.0.0.1", 0))
    m.listen(1)
    mport = m.getsockname()[1]
    threading.Thread(target=lambda: m.accept()[0].close(), daemon=True).start()
    mon = qmp.Qmp(mport, timeout=5)
    try:
        with mon:
            pass
        check("a monitor that hangs up is an error", False)
    except qmp.QmpError:
        check("a monitor that hangs up is an error, and its socket is closed",
              mon._sock is not None and mon._sock.fileno() == -1)
    m.close()






def test_custom_images_and_machines():
    """Bring-your-own ISO: the registry, the machine kind, and what QEMU gets."""
    import os
    import tempfile

    from winlab import editor, images, netplan, paths, schema
    from winlab.images import ImageError
    from winlab.providers.qemu import QemuProvider
    from winlab.schema import LabError

    with tempfile.TemporaryDirectory() as td:
        os.environ["WINLAB_IMAGES"] = td
        try:
            iso = Path(td) / "OPNsense-25.1-dvd-amd64.iso"
            iso.write_bytes(b"\0" * 4096)
            for bad in ("Ubuntu", "x", "ws2025", "a b"):
                try:
                    images.add_custom(bad, iso)
                    check(f"rejects custom id {bad!r}", False)
                except ImageError:
                    check(f"rejects custom id {bad!r}", True)
            try:
                images.add_custom("pfsense", iso, firmware="efi")
                check("rejects unknown firmware", False)
            except ImageError:
                check("rejects unknown firmware", True)

            entry = images.add_custom("pfsense", iso, firmware="uefi", disk_gb=16)
            check("iso copied into the image store",
                  entry.iso.exists() and entry.iso.parent == paths.downloads_dir())
            check("custom registry round-trips",
                  images.custom_images()["pfsense"].firmware == "uefi"
                  and images.custom_image("pfsense").disk_gb == 16
                  and entry.title == "OPNsense-25.1-dvd-amd64")
            check("custom media listed", "pfsense" in images.render_status())

            lab = schema.load("ad-ds-basics")
            # the editor: a custom machine takes the only ISO by default, no roles
            made = editor.add_node(lab, "fw01", kind="custom", network="corp", ip="10.10.10.70")
            check("editor picks the single custom image",
                  made[0].image == "pfsense" and made[0].roles == [])
            try:
                editor.add_node(lab, "fw02", kind="custom", network="corp", image="nope")
                check("editor refuses an unknown custom image", False)
            except editor.EditError:
                check("editor refuses an unknown custom image", True)
            schema.validate(lab)
            check("custom machine validates", True)
            lab.nodes["fw01"].roles = ["dns"]
            try:
                schema.validate(lab)
                check("roles on a custom machine are refused", False)
            except LabError as exc:
                check("roles on a custom machine are refused", "no winlab agent" in str(exc))
            lab.nodes["fw01"].roles = []
            check("custom machines are never trimmed below their memory",
                  lab.nodes["fw01"].trim_floor_mb == lab.nodes["fw01"].memory_mb)

            # the provider: installer stays in the drive, after the disk
            plan = netplan.compile_topology(lab, check_ports=False)
            rt = QemuProvider(plan, accel="tcg").build_node(lab.nodes["fw01"])
            argv = " ".join(rt.argv)
            check("custom machine boots from its own ISO",
                  rt.install_iso == entry.iso and f"file={entry.iso},if=none,media=cdrom" in argv)
            check("disk boots before the installer",
                  argv.index("drive=sys,bootindex=0") < argv.index("drive=cdinst,bootindex=1"))
            check("custom machine has lab nics only",
                  argv.count("-netdev") == 1 and ("connect=127.0.0.1" in argv or "server=off,addr.type=inet,addr.host=127.0.0.1" in argv)
                  and "user" not in argv.split("-netdev")[1].split()[0])

            images.remove_custom("pfsense")
            check("custom image removed with its ISO",
                  not entry.iso.exists() and "pfsense" not in images.custom_images())
            try:
                editor.add_node(lab, "fw03", kind="custom", network="corp")
                check("custom machine needs an ISO", False)
            except editor.EditError:
                check("custom machine needs an ISO", True)
        finally:
            os.environ.pop("WINLAB_IMAGES", None)


def test_machines_keep_their_disks():
    """`lab up` builds a machine once; only `lab reset` rebuilds it."""
    import os
    import tempfile

    from winlab import images, netplan, paths, schema, state
    from winlab.model import Nic, Node
    from winlab.orchestrator import Orchestrator, OrchestratorError

    lab = schema.load("ad-ds-basics")
    lab.nodes["lx01"] = Node(id="lx01", image="alpine", kind="linux", memory_mb=512,
                             nics=[Nic(network="corp", ip="10.10.10.71")])
    clones: list[Path] = []

    def fake_clone(image_id, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f"clone {len(clones)} of {image_id}")
        clones.append(dest)
        return dest

    saved = (paths.VAR, paths.STATE, images.clone)
    with tempfile.TemporaryDirectory() as td:
        paths.VAR = Path(td) / "var"
        paths.STATE = paths.VAR / "state"
        images.clone = fake_clone
        try:
            orch = Orchestrator(lab, accel="tcg", display="none")
            orch._stage_disks("lx01")
            disk = orch.provider.disk_path("lx01")
            first = disk.read_text()
            orch._stage_disks("lx01")
            check("second boot keeps the disk", disk.read_text() == first and len(clones) == 1)
            (disk.parent / "uefi-vars.fd").write_bytes(b"nvram")

            st = state.new(lab.name, "tcg", "none")
            st.nodes["lx01"] = state.NodeState(node_id="lx01", pid=os.getpid())
            state.save(st)
            try:
                orch.reset(["lx01"])
                check("reset refuses a running machine", False)
            except OrchestratorError as exc:
                check("reset refuses a running machine", "stop lx01 first" in str(exc))
            try:
                orch.reset(["nope"])
                check("reset refuses an unknown machine", False)
            except OrchestratorError:
                check("reset refuses an unknown machine", True)
            state.clear(lab.name)

            check("reset deletes disks and nvram",
                  orch.reset(["lx01"]) == ["lx01"] and not disk.exists()
                  and not (disk.parent / "uefi-vars.fd").exists())
            check("reset of an unbuilt machine is a no-op", orch.reset(["lx01"]) == [])
            orch._stage_disks("lx01")
            check("next boot rebuilds from the image", disk.read_text() != first and len(clones) == 2)

            # a machine started beside a running fabric dials the fabric's ports
            st = state.new(lab.name, "tcg", "none")
            st.nodes["fabric"] = state.NodeState(node_id="fabric", pid=os.getpid())
            state.save(st)
            plan = Orchestrator(lab, accel="tcg", display="none").plan
            link = plan.links_for("lx01")[0]
            check("links reuse the running fabric's stable ports",
                  link.port == netplan.stable_port(lab.name, "lx01", 0))
            state.clear(lab.name)
        finally:
            paths.VAR, paths.STATE, images.clone = saved


def test_checkpoints():
    import shutil
    import subprocess
    import tempfile
    import time

    from winlab import paths, snapshots, state
    from winlab.images import ImageError

    for bad in ("", "a/b", "x" * 41, "-dash", "with space"):
        try:
            snapshots._check_tag(bad)
            check(f"rejects checkpoint name {bad!r}", False)
        except ImageError:
            check(f"rejects checkpoint name {bad!r}", True)
    snapshots._check_tag("before-gpo_2")
    check("drive ids match the provider",
          snapshots._drive_id(Path("x/system.qcow2")) == "sys"
          and snapshots._drive_id(Path("x/data1.qcow2")) == "data1")

    qimg = shutil.which("qemu-img")
    qsys = shutil.which("qemu-system-x86_64")
    if not qimg:
        print("  skip real checkpoints: no qemu-img on this host")
        return
    saved = (paths.VAR, paths.STATE, paths.qemu_img)
    with tempfile.TemporaryDirectory() as td:
        paths.VAR = Path(td) / "var"
        paths.STATE = paths.VAR / "state"
        paths.qemu_img = lambda: Path(qimg)
        try:
            ndir = paths.lab_dir("cp-lab") / "vm01"
            ndir.mkdir(parents=True)
            base = Path(td) / "base.qcow2"
            subprocess.run([qimg, "create", "-f", "qcow2", str(base), "64M"],
                           check=True, capture_output=True)
            for name in ("system.qcow2", "data0.qcow2"):
                subprocess.run([qimg, "create", "-f", "qcow2", "-b", str(base), "-F", "qcow2",
                                str(ndir / name)], check=True, capture_output=True)
            (ndir / "uefi-vars.fd").write_bytes(b"v1")

            check("offline checkpoint saved", snapshots.save("cp-lab", "clean") == ["vm01"])
            check("checkpoint listed on the machine", snapshots.listing("cp-lab")["vm01"] == ["clean"])
            check("nvram copied with it", (ndir / "uefi-vars.clean.fd").read_bytes() == b"v1")
            (ndir / "uefi-vars.fd").write_bytes(b"v2")
            snapshots.save("cp-lab", "clean")
            check("saving the same name replaces it", snapshots.listing("cp-lab")["vm01"] == ["clean"])
            check("offline revert restores nvram",
                  snapshots.restore("cp-lab", "clean") == ["vm01"]
                  and (ndir / "uefi-vars.fd").read_bytes() == b"v2")
            try:
                snapshots.restore("cp-lab", "nope", only=["vm01"])
                check("revert to a missing checkpoint fails", False)
            except ImageError:
                check("revert to a missing checkpoint fails", True)
            try:
                snapshots.save("cp-lab", "x", only=["vm99"])
                check("checkpoint of an unbuilt machine fails", False)
            except ImageError:
                check("checkpoint of an unbuilt machine fails", True)
            check("checkpoint deleted", snapshots.delete("cp-lab", "clean") == ["vm01"]
                  and snapshots.listing("cp-lab")["vm01"] == []
                  and not (ndir / "uefi-vars.clean.fd").exists())

            if not qsys:
                print("  skip live checkpoints: no qemu-system-x86_64 on this host")
                return
            import socket
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            proc = subprocess.Popen([
                qsys, "-accel", "tcg", "-machine", "q35", "-m", "64", "-nodefaults",
                "-display", "none", "-no-user-config", "-device", "ich9-ahci,id=ahci",
                "-drive", f"id=sys,file={ndir / 'system.qcow2'},if=none,format=qcow2",
                "-device", "ide-hd,bus=ahci.0,drive=sys",
                "-drive", f"id=data0,file={ndir / 'data0.qcow2'},if=none,format=qcow2",
                "-device", "ide-hd,bus=ahci.1,drive=data0",
                "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off",
            ], stdout=subprocess.DEVNULL, stderr=(Path(td) / "qemu.err").open("wb"))
            try:
                st = state.new("cp-lab", "tcg", "none")
                st.nodes["vm01"] = state.NodeState(node_id="vm01", pid=proc.pid, qmp_port=port)
                state.save(st)
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=1).close()
                        break
                    except OSError:
                        time.sleep(0.02)
                check("test machine is running", proc.poll() is None,
                      (Path(td) / "qemu.err").read_text(errors="replace")[:300])
                check("live checkpoint saved while running",
                      snapshots.save("cp-lab", "live") == ["vm01"] and proc.poll() is None)
                check("live checkpoint visible on every disk",
                      snapshots._tags(ndir / "system.qcow2") == ["live"]
                      and snapshots._tags(ndir / "data0.qcow2") == ["live"])
                snapshots.save("cp-lab", "live")
                check("live save of the same name replaces it",
                      snapshots._tags(ndir / "system.qcow2") == ["live"])
                from winlab.qmp import Qmp
                with Qmp(port) as mon:
                    check("machine resumed after the checkpoint",
                          mon.call("query-status")["running"] is True)
                check("live checkpoint deleted through the monitor",
                      snapshots.delete("cp-lab", "live") == ["vm01"]
                      and snapshots._tags(ndir / "system.qcow2") == [])
            finally:
                proc.kill()
                proc.wait(timeout=10)
                state.clear("cp-lab")
        finally:
            paths.VAR, paths.STATE, paths.qemu_img = saved


def test_evaluation_clock():
    from winlab import evaluation as ev

    c = ev.parse("dc01", "1|251234|1001|Windows(R), ServerStandardEval edition\n", now=10.0)
    check("evaluation days parsed", c.evaluation and c.days_left == 174 and c.rearms_left == 1001)
    check("far from expiry is no warning", not c.warn and "174 days left" in ev.describe(c))
    c = ev.parse("dc01", "1|20000|1|Windows(R), ServerStandardEval edition")
    check("two weeks left warns", c.warn and c.days_left == 13)
    c = ev.parse("dc01", "1|0|0|Windows(R), ServerStandardEval edition")
    check("expired is described", c.warn and ev.describe(c).startswith("expired"))
    c = ev.parse("pc01", "noise\n1|0|1001|Windows(R), Enterprise edition")
    check("a licensed machine is not an evaluation",
          not c.evaluation and c.days_left == -1 and ev.describe(c) == "not an evaluation")
    try:
        ev.parse("dc01", "garbage")
        check("bad answer raises", False)
    except ev.EvaluationError:
        check("bad answer raises", True)






def test_job_records():
    import threading
    import time as _t
    from winlab import webui
    jobs = webui.Jobs()
    go, hold = threading.Event(), threading.Event()

    def work(emit):
        emit("[1/4] first")
        emit("downloading 62.5%")
        go.wait(10)   # still running until the test has looked at it
        emit("done")

    def rec_of(job_id, until=lambda r: True, within=5.0):
        """The job's record, polled until `until` holds (or the time is up)."""
        end = _t.monotonic() + within
        while True:
            rec = next(j for j in jobs.list() if j["id"] == job_id)
            if until(rec) or _t.monotonic() > end:
                return rec
            _t.sleep(0.005)

    jid = jobs.start("prepare-ws2025", work)
    rec = next(j for j in jobs.list() if j["id"] == jid)
    check("job labelled from its name", rec["label"] == "Prepare the Windows Server 2025 base" and rec["typical"] == 2700, str(rec))
    rec = rec_of(jid, lambda r: r["percent"] == 62)
    check("percent read from the log", rec["percent"] in (25, 62) and rec["estimated"] is False, str(rec))
    go.set()
    rec = rec_of(jid, lambda r: r["done"])
    check("finished job recorded as ok", rec["done"] and rec["ok"] and rec["percent"] == 100, str(rec))
    jid2 = jobs.start("viewer", lambda emit: (_ for _ in ()).throw(RuntimeError("boom")))
    rec = rec_of(jid2, lambda r: r["done"])
    check("failure recorded with its message", rec["done"] and rec["ok"] is False and "boom" in rec["last"], str(rec))
    silent = jobs.start("bootstrap", lambda emit: hold.wait(10))
    rec = next(j for j in jobs.list() if j["id"] == silent)
    check("silent job gets an estimate", rec["estimated"] and 0 <= rec["percent"] <= 95, str(rec))
    a, b = jobs.start("viewer", lambda emit: None), jobs.start("viewer", lambda emit: None)
    check("two starts of one job in the same millisecond are two jobs", a != b and len({a, b} & {j["id"] for j in jobs.list()}) == 2)
    rec_of(a, lambda r: r["done"])
    rec_of(b, lambda r: r["done"])
    for r in jobs._records.values():
        r["finished"] = r["finished"] and r["finished"] - webui.KEEP_DONE - 1
    jobs.list()
    check("a finished job nobody streamed lets go of its log",
          jid not in jobs._queues and a not in jobs._queues and jid not in jobs._records)
    hold.set()

    # A state file written by a newer winlab still loads.
    import json as _json
    from winlab import paths, state
    f = state.state_file("zz-newer-state")
    paths.STATE.mkdir(parents=True, exist_ok=True)
    f.write_text(_json.dumps({"name": "zz-newer-state", "nodes": {"dc01": {"node_id": "dc01", "pid": 0,
                                                                            "a_field_from_later": 1}}}),
                 encoding="utf-8")
    try:
        st = state.load("zz-newer-state")
        check("state from a newer version loads, unknown fields dropped", st is not None and st.nodes["dc01"].node_id == "dc01")
    finally:
        f.unlink(missing_ok=True)






def test_base_trim_and_seal():
    """The base shrinks itself before sysprep, is sealed compressed, and the
    ISO copy retires once the base exists."""
    import os
    import tempfile

    from winlab import basetrim, images, paths, prepare, provision, unattend
    from winlab.images import ImageError
    from winlab.model import Lab, Nic, Node

    check("trim command fits an unattend command line", len(basetrim.command()) < 259, str(len(basetrim.command())))
    for needle in ("hibernate off", "Win32_PageFileSetting", "StartComponentCleanup", "CompactOS:always",
                   "Optimize-Volume", "trim-base.log"):
        check(f"trim script has {needle}", needle in basetrim.SCRIPT)
    node = Node(id="base", image="ws2025", kind="windows-server", nics=[Nic(network="prep")])
    lab = Lab(name="prep", domain="prep.local")
    xml = unattend.render(node, lab, prep=True)
    trim_at, seal_at = xml.find(basetrim.FILE), xml.find("sysprep.exe")
    check("trim runs before sysprep in base-prep mode", 0 < trim_at < seal_at, f"{trim_at} {seal_at}")
    check("normal nodes do not trim", basetrim.FILE not in unattend.render(node, lab))

    with tempfile.TemporaryDirectory() as td:
        os.environ["WINLAB_IMAGES"] = td
        calls = []
        real_run = images._run_img

        def fake_run(args, timeout=7200):
            calls.append(list(args))
            if args[0] == "convert" and "compression_type=zstd" in args and fake_run.no_zstd:
                raise ImageError("qemu-img convert failed: Invalid parameter 'zstd'")
            Path(args[-1]).write_bytes(b"sealed")
            return ""
        fake_run.no_zstd = False
        images._run_img = fake_run
        try:
            work = Path(td) / "ws2025.building.qcow2"
            base = Path(td) / "ws2025.qcow2"
            work.write_bytes(b"installed")
            prepare._seal_base(work, base, compress=True)
            check("sealed with zstd compression", calls[-1][:1] == ["convert"] and "-c" in calls[-1]
                  and "compression_type=zstd" in calls[-1] and base.read_bytes() == b"sealed" and not work.exists(), str(calls[-1]))
            work.write_bytes(b"installed")
            fake_run.no_zstd = True
            prepare._seal_base(work, base, compress=True)
            check("falls back to zlib when zstd is missing", "compression_type=zlib" in calls[-1], str(calls[-1]))
            work.write_bytes(b"installed")
            prepare._seal_base(work, base, compress=False)
            check("uncompressed seal is a rename", base.read_bytes() == b"installed" and not work.exists())

            # the ISO copy retires after a prepare, and the same download is recognised
            paths.downloads_dir().mkdir(parents=True, exist_ok=True)
            paths.bases_dir().mkdir(parents=True, exist_ok=True)
            src = Path(td) / "download" / "server2025.iso"
            src.parent.mkdir()
            src.write_bytes(os.urandom(3 * 1024 * 1024) + b"\0" * 4096)
            images.CATALOG["ws2025"].min_gb = 0.0
            try:
                copied = images.import_media("ws2025", src)
                check("import copies the ISO", copied.exists() and copied.name == "ws2025.iso")
                images.base_path("ws2025").write_bytes(b"base")
                meta = images.retire_installer("ws2025")
                check("retire removes the copy and keeps its fingerprint",
                      meta is not None and not copied.exists() and images.retired_installer("ws2025")["fingerprint"] == images.fingerprint(src))
                st = images.status("ws2025")
                check("status says the ISO retired", st["base"] and not st["installer"] and st["installer_retired"])
                check("render_status mentions it", "ISO copy removed" in images.render_status())
                again = images.import_media("ws2025", src)
                check("re-importing the same download is a no-op", again == images.base_path("ws2025") and not copied.exists())
                other = Path(td) / "download" / "other.iso"
                other.write_bytes(os.urandom(2 * 1024 * 1024))
                images.import_media("ws2025", other)
                check("a different ISO is copied again", copied.exists())
                copied.unlink()
                images.base_path("ws2025").unlink()
                try:
                    prepare.prepare_windows("ws2025")
                    check("prepare after retire explains the missing ISO", False)
                except prepare.PrepareError as exc:
                    check("prepare after retire explains the missing ISO", "removed after" in str(exc), str(exc))
            finally:
                images.CATALOG["ws2025"].min_gb = 20.0
        finally:
            images._run_img = real_run
            os.environ.pop("WINLAB_IMAGES", None)

    # the prep data disk carries the trim script
    from winlab.netplan import compile_topology
    from winlab.model import Network
    lab.networks["prep"] = Network(id="prep", cidr="10.255.255.0/24")
    lab.nodes["base"] = node
    plan = compile_topology(lab, check_ports=False)
    with tempfile.TemporaryDirectory() as td:
        out = provision.build_data_disk(node, lab, plan, Path(td) / "d.img",
                                        extra={basetrim.FILE: basetrim.SCRIPT.encode()})
        check("prep data disk carries the trim script", basetrim.FILE.upper().encode()[:8] in out.read_bytes().upper()
              or b"Optimize-Volume" in out.read_bytes())

    from winlab import hostprobe
    check("disk floor is 40 GB", hostprobe.MIN_FREE_GB == 40.0 and hostprobe.SERVER_ONLY_FREE_GB == 25.0)


def test_process_usage():
    import os

    from winlab import procstats as ps

    s = ps.sample(os.getpid())
    if s is None:
        print("  skip process usage: no numbers on this platform")
    else:
        check("own process has memory and cpu time", s.rss_mb > 0 and s.cpu_seconds >= 0)
    check("dead pid gives nothing", ps.sample(2**22 - 7) is None and ps.sample(0) is None)
    a = ps.Sample(cpu_seconds=10.0, rss_mb=100, at=100.0)
    b = ps.Sample(cpu_seconds=11.0, rss_mb=100, at=101.0)
    check("cpu share of the machine's vcpus", ps.cpu_percent(a, b, 2) == 50
          and ps.cpu_percent(a, b, 1) == 100)
    c = ps.Sample(cpu_seconds=15.0, rss_mb=100, at=101.0)
    check("cpu clamps at 100", ps.cpu_percent(a, c, 1) == 100)
    check("no time passed is 0", ps.cpu_percent(a, a, 1) == 0)
    m = ps.Meter()
    first = m.usage(os.getpid(), 2)
    check("first reading reports memory only", first is None or first.cpu_pct == 0)
    check("meter forgets a dead process", m.usage(2**22 - 7, 1) is None)


def test_machine_settings():
    import os
    import tempfile
    import tomllib

    from winlab import editor, images, netplan, paths, schema
    from winlab.orchestrator import Orchestrator, OrchestratorError
    from winlab.providers.qemu import QemuProvider

    lab = schema.load("ad-ds-basics")
    with tempfile.TemporaryDirectory() as td:
        os.environ["WINLAB_IMAGES"] = td
        try:
            iso = Path(td) / "tools.iso"
            iso.write_bytes(b"\0" * 4096)
            images.add_custom("tools", iso)
            paths.downloads_dir().mkdir(parents=True, exist_ok=True)
            images.installer_path("alpine").write_bytes(b"\0" * 4096)

            fs = editor.set_node(lab, "fs01", add_disk_gb=40, boot_order=55,
                                 description="files", usb_storage_gb=8, gpu=True)
            check("disk, boot order, stick and gpu set",
                  fs.data_disks_gb[-1] == 40 and fs.boot_order == 55 and fs.description == "files"
                  and fs.vars["usb_storage_gb"] == 8 and fs.vars["gpu"] is True)
            editor.set_node(lab, "fs01", usb_storage_gb=0, gpu=False)
            check("zero and false remove the vars",
                  "usb_storage_gb" not in fs.vars and "gpu" not in fs.vars)
            n_disks = len(fs.data_disks_gb)
            editor.set_node(lab, "fs01", rm_disk=True)
            check("last disk removed", len(fs.data_disks_gb) == n_disks - 1)
            n_nics = len(fs.nics)
            editor.set_node(lab, "fs01", add_disk_gb=0, rm_nic=0, cpus=0)
            check("zero means no change", len(fs.nics) == n_nics and fs.cpus == 2)
            for bad in ({"add_disk_gb": -3}, {"add_disk_gb": 5000}, {"rm_nic": 7},
                        {"add_nic": "nowhere"}, {"iso": "nope"}):
                try:
                    editor.set_node(lab, "fs01", **bad)
                    check(f"refuses {bad}", False)
                except editor.EditError:
                    check(f"refuses {bad}", True)
            editor.set_node(lab, "fs01", add_nic="corp:10.10.10.90")
            check("nic added with an address",
                  fs.nics[-1].network == "corp" and fs.nics[-1].ip == "10.10.10.90")
            editor.set_node(lab, "fs01", rm_nic=len(fs.nics) - 1)
            check("nic removed", all(n.ip != "10.10.10.90" for n in fs.nics))
            editor.set_node(lab, "fs01", iso="tools")
            check("own ISO attached", fs.vars["iso"] == "tools")
            editor.set_node(lab, "fs01", iso="alpine")
            check("catalog ISO attached", fs.vars["iso"] == "alpine")
            schema.validate(lab)
            raw = tomllib.loads(editor.emit(lab))
            node = next(x for x in raw["node"] if x["id"] == "fs01")
            check("settings round-trip through TOML",
                  node["boot_order"] == 55 and node["vars"]["iso"] == "alpine"
                  and node["description"] == "files")

            plan = netplan.compile_topology(lab, check_ports=False)
            rt = QemuProvider(plan, accel="tcg").build_node(fs)
            argv = rt.argv
            joined = " ".join(argv)
            check("attached ISO rides in the drive without booting",
                  f"file={images.installer_path('alpine')},if=none,media=cdrom" in joined
                  and "drive=cdattach" in joined and "drive=cdattach,bootindex" not in joined)
            slot = QemuProvider.next_ahci_slot(argv)
            check("next ahci slot follows every drive",
                  slot == 1 + len(fs.data_disks_gb) + 1 and f"bus=ahci.{slot}" not in joined)
            editor.set_node(lab, "fs01", iso="none")
            check("ISO ejected", "iso" not in fs.vars)

            # a missing attached ISO is refused before the machine starts
            fs.vars["iso"] = "tools"
            images.remove_custom("tools")
            try:
                Orchestrator(lab, accel="tcg", display="none")._check_attached_iso("fs01")
                check("missing attached ISO refused", False)
            except OrchestratorError as exc:
                check("missing attached ISO refused", "not in the image store" in str(exc))
            fs.vars.pop("iso")
        finally:
            os.environ.pop("WINLAB_IMAGES", None)


def test_templates_and_clones():
    """A machine turned into an image, and machines made from machines."""
    import os
    import shutil
    import subprocess
    import tempfile

    from winlab import editor, images, paths, schema, state, templates
    from winlab.images import ImageError
    from winlab.model import Nic, Node
    from winlab.orchestrator import Orchestrator
    from winlab.providers.qemu import check_isolation
    from winlab.templates import TemplateError

    # the one boot that generalises a Windows copy is sealed like any machine
    nvram = Path("x/uefi-vars.fd")
    argv = templates.generalize_argv(Path("x/system.qcow2"), nvram, 2, 1024, "tcg",
                                     34100, 34101)
    joined = " ".join(argv)
    check("generalise boot has no network device",
          "-netdev" not in argv and "-nic" not in argv and "e1000e" not in joined)
    check("generalise boot passes the isolation guard", check_isolation(argv) == [])
    check("generalise boot keeps the lab's disk controller and agent channel",
          "ide-hd,bus=ahci.0,drive=sys,bootindex=0" in argv and "chardev:ser0" in argv
          and "port=34100" in joined and f"if=pflash,format=raw,unit=1,file={nvram}" in joined,
          joined)
    check("generalise boot never runs sysprep on less than 2 GB", "-m 2048" in joined)
    check("sysprep keeps the evaluation clock and the drivers",
          "<SkipRearm>1</SkipRearm>" in templates.SYSPREP_UNATTEND
          and "PersistAllDeviceInstalls" in templates.SYSPREP_UNATTEND)

    qimg = shutil.which("qemu-img")
    saved = (paths.VAR, paths.STATE, paths.qemu_img, templates.virtual_gb)
    with tempfile.TemporaryDirectory() as td:
        os.environ["WINLAB_IMAGES"] = str(Path(td) / "images")
        paths.VAR = Path(td) / "var"
        paths.STATE = paths.VAR / "state"
        if qimg:
            paths.qemu_img = lambda: Path(qimg)
        else:
            # No qemu-img on this host: copies are plain file copies and the
            # chain bookkeeping is skipped, which still exercises everything
            # around it.
            print("  no qemu-img on this host: disk copies are stand-ins")
            templates.copy_disk = lambda src, dest, full=False: (
                dest.parent.mkdir(parents=True, exist_ok=True), shutil.copy2(src, dest), dest)[2]
            templates.virtual_gb = lambda disk: 1
            images.clone = lambda image_id, dest: (
                dest.parent.mkdir(parents=True, exist_ok=True),
                dest.write_text(f"clone of {image_id}"), dest)[2]
            images.create_data_disk = lambda dest, size_gb: (
                dest.parent.mkdir(parents=True, exist_ok=True),
                dest.write_text(f"data {size_gb}G"), dest)[2]
        try:
            for bad in ("Gold", "ws2025", "x"):
                try:
                    images.check_template_id(bad)
                    check(f"rejects template name {bad!r}", False)
                except ImageError:
                    check(f"rejects template name {bad!r}", True)

            lab = schema.load("ad-ds-basics")
            lab.source_path = str(Path(td) / "lab.toml")
            lab.nodes["lx01"] = Node(id="lx01", image="alpine", kind="linux", memory_mb=512,
                                     data_disks_gb=[1], description="tuned alpine",
                                     nics=[Nic(network="corp", ip="10.10.10.71")])
            orch = Orchestrator(lab, accel="tcg", display="none")
            if qimg:
                images.create_base("alpine", size_gb=1)
                subprocess.run([qimg, "create", "-f", "qcow2", str(images.base_path("alpine"))],
                               capture_output=True)
                subprocess.run(["qemu-io", "-c", "write -P 0xaa 0 8M",
                                str(images.base_path("alpine"))], capture_output=True)
            else:
                images.base_path("alpine").parent.mkdir(parents=True, exist_ok=True)
                images.base_path("alpine").write_text("base")

            for who, why in (("dc01", "domain controller"), ("fabric", "no machine"),
                             ("fs01", "never been started")):
                try:
                    templates.create(lab, who, "t-" + who)
                    check(f"refuses a template of {who}", False)
                except TemplateError as exc:
                    check(f"refuses a template of {who}", why in str(exc), str(exc))

            orch._stage_disks("lx01")
            disk = orch.provider.disk_path("lx01")
            if qimg:
                subprocess.run(["qemu-io", "-c", "write -P 0xbb 256M 2M", str(disk)],
                               capture_output=True)
            (disk.parent / "uefi-vars.fd").write_bytes(b"nvram")

            st = state.new(lab.name, "tcg", "none")
            st.nodes["lx01"] = state.NodeState(node_id="lx01", pid=os.getpid())
            state.save(st)
            try:
                templates.create(lab, "lx01", "alpine-gold")
                check("refuses a template of a running machine", False)
            except TemplateError as exc:
                check("refuses a template of a running machine", "stop lx01 first" in str(exc))
            state.clear(lab.name)
            try:
                templates.create(lab, "lx01", "alpine-gold", generalize_=True)
                check("refuses to generalise a machine without the agent", False)
            except TemplateError as exc:
                check("refuses to generalise a machine without the agent", "no winlab agent" in str(exc))

            lines: list[str] = []
            tpl = templates.create(lab, "lx01", "alpine-gold", title="Alpine, tuned",
                                   emit=lines.append)
            check("template registered with the machine's hardware",
                  images.template("alpine-gold").title == "Alpine, tuned"
                  and tpl.kind == "linux" and tpl.memory_mb == 512 and tpl.data_disks_gb == [1]
                  and tpl.source == "ad-ds-basics/lx01" and not tpl.generalized
                  and tpl.firmware == "uefi" and tpl.description == "tuned alpine")
            check("template disk and nvram in the image store",
                  tpl.disk.exists() and tpl.nvram.read_bytes() == b"nvram"
                  and tpl.disk.parent == paths.images_dir() / "templates")
            check("the machine itself is untouched", disk.exists())
            check("template listed", "alpine-gold" in images.render_status()
                  and templates.describe(tpl).startswith("linux, from ad-ds-basics/lx01"))
            if qimg:
                info = templates.disk_info(tpl.disk)
                check("thin template shares the base by a relative path",
                      info.get("backing-filename") == "../bases/alpine.qcow2"
                      and tpl.disk.stat().st_size < images.base_path("alpine").stat().st_size)
                try:
                    images.check_template_id("alpine-gold")
                    templates.create(lab, "lx01", "alpine-gold")
                    check("refuses a duplicate template name", False)
                except TemplateError as exc:
                    check("refuses a duplicate template name", "exists" in str(exc))

            # a machine from the template: kind and hardware come with it
            made = editor.add_node(lab, "lx02", kind="windows-server", network="corp",
                                   image="alpine-gold")[0]
            check("add_node takes kind, hardware and disks from the template",
                  made.kind == "linux" and made.memory_mb == 512 and made.data_disks_gb == [1]
                  and made.image == "alpine-gold" and made.description == "tuned alpine"
                  and made.roles == [])
            schema.validate(lab)
            orch = Orchestrator(lab, accel="tcg", display="none")
            check("no installer for a machine made from a template",
                  orch._needs_install_iso("lx02") is None)
            orch._stage_disks("lx02")
            d2 = orch.provider.disk_path("lx02")
            check("machine from a template starts from the template's nvram",
                  (d2.parent / "uefi-vars.fd").read_bytes() == b"nvram"
                  if orch.provider._uses_uefi(made) else True)
            if qimg:
                check("machine disk is a thin clone of the template",
                      Path(templates.disk_info(d2)["full-backing-filename"]).resolve()
                      == tpl.disk.resolve())
                r = subprocess.run(["qemu-io", "-c", "read -P 0xbb 256M 2M",
                                    "-c", "read -P 0xaa 0 8M", str(d2)],
                                   capture_output=True, text=True)
                check("clone sees the template's and the base's data",
                      r.returncode == 0 and "verification failed" not in r.stdout + r.stderr)
            rt = orch.provider.build_node(made)
            check("template machine of kind custom would get no installer in the drive",
                  rt.install_iso is None)

            # a clone: definition plus disks, nothing left behind on failure
            try:
                templates.clone_machine(lab, "lx01", "lx02")
                check("clone refuses a taken name", False)
            except TemplateError as exc:
                check("clone refuses a taken name", "already exists" in str(exc))
            try:
                templates.clone_machine(lab, "lx01", "lx03", generalize_=True)
                check("clone of a machine without the agent cannot be generalised", False)
            except TemplateError:
                check("clone of a machine without the agent cannot be generalised", True)
            check("a failed clone leaves no machine behind",
                  "lx03" not in lab.nodes and not templates.node_dir(lab.name, "lx03").exists())
            n = templates.clone_machine(lab, "lx01", "lx03", emit=lines.append)
            files = sorted(f.name for f in templates.node_dir(lab.name, "lx03").iterdir())
            check("clone copies system, data disks and nvram",
                  files == ["data0.qcow2", "system.qcow2", "uefi-vars.fd"], str(files))
            check("clone gets its own static address and the source's roles and disks",
                  n.nics[0].ip not in ("", None, "10.10.10.71") and n.data_disks_gb == [1]
                  and n.hostname == "LX03" and n.description.startswith("clone of lx01"))
            saved_lab = schema.load(lab.source_path)
            check("clone is saved in the lab definition", "lx03" in saved_lab.nodes)
            if qimg:
                check("clone disk shares the source's base, not the source",
                      Path(templates.disk_info(templates.node_dir(lab.name, "lx03")
                                               / "system.qcow2")["full-backing-filename"])
                      .resolve() == images.base_path("alpine").resolve())
            try:
                editor.clone_node(lab, "dc01", "dc02")
                check("editor refuses to clone a domain controller", False)
            except editor.EditError:
                check("editor refuses to clone a domain controller", True)
            try:
                templates.clone_machine(lab, "lx01", "lx03")
                check("clone refuses an existing machine", False)
            except TemplateError:
                check("clone refuses an existing machine", True)

            images.remove_template("alpine-gold")
            check("template removed with its files",
                  not tpl.disk.exists() and not tpl.nvram.exists()
                  and "alpine-gold" not in images.templates())
            check("a machine made from a removed template is still defined",
                  "lx02" in lab.nodes and d2.exists())
        finally:
            os.environ.pop("WINLAB_IMAGES", None)
            paths.VAR, paths.STATE, paths.qemu_img, templates.virtual_gb = saved
            if not qimg:
                import importlib
                importlib.reload(templates)
                importlib.reload(images)


def test_lab_export_import():
    """A lab moves between PCs as a folder; thin exports insist on the same images."""
    import json
    import os
    import shutil
    import subprocess
    import tempfile

    from winlab import editor, images, paths, schema, secrets, snapshots, state, transfer
    from winlab.model import Nic, Node
    from winlab.orchestrator import Orchestrator
    from winlab.transfer import TransferError

    qimg = shutil.which("qemu-img")
    base_lab = schema.load("ad-ds-basics")
    saved = (paths.VAR, paths.STATE, paths.LABS, paths.qemu_img)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        paths.LABS.mkdir(parents=True)
        if qimg:
            paths.qemu_img = lambda: Path(qimg)
        else:
            print("  no qemu-img on this host: disk copies are stand-ins")
            images.clone = lambda image_id, dest: (
                dest.parent.mkdir(parents=True, exist_ok=True),
                dest.write_text(f"clone of {image_id}"), dest)[2]
            images.create_data_disk = lambda dest, size_gb: (
                dest.parent.mkdir(parents=True, exist_ok=True),
                dest.write_text(f"data {size_gb}G"), dest)[2]
            transfer._copy_flat = lambda src, dest, compress: shutil.copy2(src, dest)
            transfer._chain_size = lambda disk: disk.stat().st_size
            transfer._backing_of = lambda disk: (images.base_path("alpine")
                                                 if disk.name == "system.qcow2" else None)
            transfer._rebase = lambda disk, backing: None
        try:
            if qimg:
                images.create_base("alpine", size_gb=1)
                subprocess.run(["qemu-io", "-c", "write -P 0xaa 0 8M",
                                str(images.base_path("alpine"))], capture_output=True)
            else:
                images.base_path("alpine").parent.mkdir(parents=True, exist_ok=True)
                images.base_path("alpine").write_bytes(b"base" * 4096)

            lab = base_lab
            lab.name, lab.admin_password, lab.password_in_toml = "mini", "", False
            lab.source_path = str(paths.LABS / "mini.toml")
            lab.nodes.clear()
            lab.nodes["lx01"] = Node(id="lx01", image="alpine", kind="linux", memory_mb=512,
                                     data_disks_gb=[1],
                                     nics=[Nic(network="corp", ip="10.10.10.71")])
            lab.nodes["lx02"] = Node(id="lx02", image="alpine", kind="linux", memory_mb=512,
                                     nics=[Nic(network="corp", ip="10.10.10.72")])
            editor.save(lab, lab.source_path)
            lab = schema.load("mini")
            try:
                transfer.export_lab(lab, td / "x0")
                check("refuses to export a lab that was never built", False)
            except TransferError as exc:
                check("refuses to export a lab that was never built", "no built machines" in str(exc))
            orch = Orchestrator(lab, accel="tcg", display="none")
            for n in ("lx01", "lx02"):
                orch._stage_disks(n)
            d1 = orch.provider.disk_path("lx01")
            if qimg:
                subprocess.run(["qemu-io", "-c", "write -P 0xbb 256M 2M", str(d1)], capture_output=True)
                subprocess.run([qimg, "snapshot", "-c", "before", str(d1)], capture_output=True)
            (d1.parent / "uefi-vars.fd").write_bytes(b"nv")
            password = secrets.password_path("mini").read_text()

            st = state.new("mini", "tcg", "none")
            st.nodes["lx01"] = state.NodeState(node_id="lx01", pid=os.getpid())
            state.save(st)
            try:
                transfer.export_lab(lab, td / "x0")
                check("refuses to export a running lab", False)
            except TransferError as exc:
                check("refuses to export a running lab", "stop lab" in str(exc))
            state.clear("mini")

            lines: list[str] = []
            full = transfer.export_lab(lab, td / "full", emit=lines.append)
            files = sorted(p.relative_to(full).as_posix() for p in full.rglob("*") if p.is_file())
            expected = sorted(["lab.toml", "manifest.json", secrets.PASSWORD_FILE,
                               "machines/lx01/data0.qcow2", "machines/lx01/system.qcow2",
                               "machines/lx01/uefi-vars.fd", "machines/lx02/system.qcow2"])
            check("full export holds definition, password, disks and firmware state",
                  files == expected, str(files))
            man = json.loads((full / "manifest.json").read_text())
            check("manifest records the machines' MAC addresses and the shape",
                  man["lab"] == "mini" and not man["thin"] and len(man["macs"]["lx01"]) == 1
                  and man["machines"]["lx01"]["backing"] is None)
            if qimg:
                info = transfer._qemu_info(full / "machines" / "lx01" / "system.qcow2")
                check("full export's system disk is standalone", not info.get("backing-filename"))
            try:
                transfer.export_lab(lab, td / "full")
                check("refuses to export into a non-empty folder", False)
            except TransferError as exc:
                check("refuses to export into a non-empty folder", "not empty" in str(exc))
            thin = transfer.export_lab(lab, td / "thin", thin=True, emit=lines.append)
            tman = json.loads((thin / "manifest.json").read_text())
            check("thin export names and fingerprints the base it sits on",
                  tman["thin"] and tman["machines"]["lx01"]["backing"]["id"] == "alpine"
                  and tman["machines"]["lx01"]["backing"]["kind"] == "base"
                  and len(tman["machines"]["lx01"]["backing"]["fingerprint"]) == 32)
            check("describe reads the folder", "2 machines" in transfer.describe_export(full))

            # import under a new name: definition, disks, password, MACs
            for bad in ("Mini", "x"):
                try:
                    transfer.import_lab(full, new_name=bad)
                    check(f"import refuses lab name {bad!r}", False)
                except TransferError:
                    check(f"import refuses lab name {bad!r}", True)
            try:
                transfer.import_lab(full)
                check("import refuses a name already on this PC", False)
            except TransferError as exc:
                check("import refuses a name already on this PC", "already exists" in str(exc))
            copy = transfer.import_lab(full, new_name="mini-copy", emit=lines.append)
            check("imported lab is defined under the new name",
                  (paths.LABS / "mini-copy.toml").exists() and copy.name == "mini-copy")
            check("imported machines keep their MAC addresses",
                  copy.nodes["lx01"].nics[0].mac == man["macs"]["lx01"][0]
                  and "mac =" in (paths.LABS / "mini-copy.toml").read_text())
            reloaded = schema.load("mini-copy")
            plan = Orchestrator(reloaded, accel="tcg", display="none").plan
            check("the plan uses the kept MAC", plan.links_for("lx01")[0].mac == man["macs"]["lx01"][0])
            check("imported lab keeps the Administrator password",
                  secrets.password_path("mini-copy").read_text() == password)
            d = paths.lab_dir("mini-copy") / "lx01" / "system.qcow2"
            check("imported disks and firmware state are in place",
                  d.exists() and (d.parent / "data0.qcow2").exists()
                  and (d.parent / "uefi-vars.fd").read_bytes() == b"nv")
            if qimg:
                r = subprocess.run(["qemu-io", "-c", "read -P 0xbb 256M 2M", "-c", "read -P 0xaa 0 8M",
                                    str(d)], capture_output=True, text=True)
                check("standalone disk holds the base's and the machine's data",
                      r.returncode == 0 and "failed" not in r.stdout + r.stderr)
                check("full import carries no checkpoints", snapshots.listing("mini-copy")["lx01"] == [])

            # a Windows machine with a standalone disk needs no base on this PC
            win = Node(id="w01", image="ws2025", kind="windows-server",
                       nics=[Nic(network="corp", ip="10.10.10.90")])
            reloaded.nodes["w01"] = win
            o3 = Orchestrator(reloaded, accel="tcg", display="none")
            o3.provider.node_dir("w01").mkdir(parents=True, exist_ok=True)
            o3.provider.disk_path("w01").write_text("imported standalone disk")
            check("an imported Windows disk boots without the base or installer here",
                  o3._needs_install_iso("w01") is None)

            # an export made without the virtio drivers, or before winlab recorded
            # them, boots its Windows machines on the emulated devices they have drivers for
            check("manifest records the drivers each machine has", man["machines"]["lx01"]["virtio"] is True)
            old = td / "old"
            shutil.copytree(full, old)
            (old / "lab.toml").write_text(editor.emit(reloaded), encoding="utf-8")
            oman = json.loads((old / "manifest.json").read_text())
            oman["machines"]["w01"] = {"image": "ws2025", "files": ["system.qcow2"], "backing": None}
            (old / "machines" / "w01").mkdir()
            (old / "machines" / "w01" / "system.qcow2").write_text("standalone windows disk")
            (old / "manifest.json").write_text(json.dumps(oman))
            older = transfer.import_lab(old, new_name="mini-old", emit=lines.append)
            check("a Windows machine exported without the drivers keeps the emulated devices",
                  older.nodes["w01"].vars.get("virtio") is False
                  and schema.load("mini-old").nodes["w01"].vars.get("virtio") is False
                  and "virtio" not in older.nodes["lx01"].vars)

            # thin import on the same store: rebased onto the local base, checkpoints kept
            th = transfer.import_lab(thin, new_name="mini-thin", emit=lines.append)
            d3 = paths.lab_dir("mini-thin") / "lx01" / "system.qcow2"
            if qimg:
                check("thin import sits on this PC's base",
                      transfer._backing_of(d3).resolve() == images.base_path("alpine").resolve())
                check("thin import keeps checkpoints", snapshots.listing("mini-thin")["lx01"] == ["before"])
                # a different base of the same name: refused, nothing left behind
                images.base_path("alpine").unlink()
                images.create_base("alpine", size_gb=1)
                try:
                    transfer.import_lab(thin, new_name="mini-bad")
                    check("thin import refuses a different base", False)
                except TransferError as exc:
                    check("thin import refuses a different base", "fingerprints differ" in str(exc))
                check("a refused import leaves no half lab",
                      not (paths.LABS / "mini-bad.toml").exists()
                      and not paths.lab_dir("mini-bad").exists())
            else:
                check("thin import on the same store works", th.name == "mini-thin" and d3.exists())
            images.base_path("alpine").unlink()
            try:
                transfer.import_lab(thin, new_name="mini-none")
                check("thin import refuses when the base is missing", False)
            except TransferError as exc:
                check("thin import refuses when the base is missing", "does not have" in str(exc))
        finally:
            os.environ.pop("WINLAB_IMAGES", None)
            paths.VAR, paths.STATE, paths.LABS, paths.qemu_img = saved
            if not qimg:
                import importlib
                importlib.reload(transfer)
                importlib.reload(images)


def test_suspend_resume_and_start_order():
    """Suspend hibernates Windows machines and shuts the rest down; the next
    start resumes them. Boot order can wait for a machine's agent and pause."""
    import os
    import shutil
    import subprocess
    import sys
    import tempfile

    from winlab import editor, images, orchestrator, paths, schema, state
    from winlab.editor import EditError
    from winlab.model import Nic, Node
    from winlab.orchestrator import Orchestrator, OrchestratorError
    from winlab.schema import LabError

    # --- definition: fields, validation, round trip
    lab = schema.load("ad-ds-basics")
    check("the shipped lab waits for its domain controller",
          lab.nodes["dc01"].wait_ready and not lab.nodes["fs01"].wait_ready)
    editor.set_node(lab, "fs01", start_delay=45)
    try:
        editor.set_node(lab, "fs01", start_delay=5000)
        check("start delay is bounded", False)
    except EditError:
        check("start delay is bounded", True)
    text = editor.emit(lab)
    check("the editor writes pacing back to the definition",
          "wait_ready = true" in text and "start_delay = 45" in text)
    lx = Node(id="lx09", image="alpine", kind="linux", nics=[Nic(network="corp", ip="10.10.10.99")])
    lab.nodes["lx09"] = lx
    try:
        editor.set_node(lab, "lx09", wait_ready=True)
        check("only a machine with an agent can be waited for", False)
    except EditError:
        check("only a machine with an agent can be waited for", True)
    lx.wait_ready = True
    try:
        schema.validate(lab)
        check("the validator rejects wait_ready on a Linux machine", False)
    except LabError as exc:
        check("the validator rejects wait_ready on a Linux machine", "wait_ready" in str(exc))
    check("hardware changes are told apart from pacing and labels",
          editor.hardware_changes({"memory_mb": 4096, "start_delay": 5, "description": "x"})
          == ["memory_mb"] and editor.hardware_changes({"cpus": None, "iso": ""}) == [])

    # --- a lab with fake machines: real child processes stand in for QEMU
    qimg = shutil.which("qemu-img")
    saved = (paths.VAR, paths.STATE, paths.LABS, orchestrator._sleep, orchestrator._wait_agent,
             orchestrator._hibernate, orchestrator._acpi_powerdown, orchestrator._kill)
    saved_qimg = paths.qemu_img
    wait_fabric = orchestrator._wait_fabric
    base_lab = schema.load("ad-ds-basics")
    procs: list[subprocess.Popen] = []
    log: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        paths.LABS.mkdir(parents=True)
        if qimg:
            # A PC with qemu-img on its PATH but no fetched runtime (a dev
            # box): winlab's own lookup must find it, as the clone test does.
            paths.qemu_img = lambda: Path(qimg)
        for img in ("alpine", "ws2025"):
            if qimg:
                try:
                    images.create_base(img, size_gb=1)
                except Exception:
                    paths.qemu_img = saved_qimg
                    (paths.VAR, paths.STATE, paths.LABS) = saved[:3]
                    raise
            else:
                images.base_path(img).parent.mkdir(parents=True, exist_ok=True)
                images.base_path(img).write_bytes(b"base")
        if not qimg:
            images.clone = lambda image_id, dest: (
                dest.parent.mkdir(parents=True, exist_ok=True), dest.write_text("clone"), dest)[2]
            images.create_data_disk = lambda dest, size_gb: (
                dest.parent.mkdir(parents=True, exist_ok=True), dest.write_text("data"), dest)[2]
        from winlab import provision
        from winlab.providers.qemu import QemuProvider
        uses_uefi = QemuProvider._uses_uefi
        QemuProvider._uses_uefi = lambda self, node: False  # no firmware files needed here
        prov = (provision.build_answer_floppy, provision.build_data_disk)
        provision.build_answer_floppy = lambda node, lab, dest, firmware="": dest.write_bytes(b"a")
        provision.build_data_disk = lambda node, lab, plan, dest: dest.write_bytes(b"p")
        try:
            lab = base_lab
            lab.name, lab.admin_password, lab.password_in_toml = "pace", "", False
            lab.source_path = str(paths.LABS / "pace.toml")
            lab.nodes.clear()
            lab.nodes["dc01"] = Node(id="dc01", image="ws2025", kind="windows-server", roles=["ad-ds"],
                                     memory_mb=2048, boot_order=10, wait_ready=True, start_delay=30,
                                     nics=[Nic(network="corp", ip="10.10.10.10")])
            lab.nodes["fs01"] = Node(id="fs01", image="ws2025", kind="windows-server", memory_mb=2048,
                                     boot_order=60, nics=[Nic(network="corp", ip="10.10.10.20")])
            lab.nodes["lx01"] = Node(id="lx01", image="alpine", kind="linux", memory_mb=512,
                                     boot_order=70, nics=[Nic(network="corp", ip="10.10.10.71")])
            editor.save(lab, lab.source_path)
            lab = schema.load("pace")

            def fake_launch(node_id, argv):
                proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
                procs.append(proc)
                return proc

            waits: list[tuple[str, float]] = []
            sleeps: list[float] = []
            orchestrator._sleep = lambda secs: sleeps.append(secs)
            orchestrator._wait_agent = lambda port, timeout: (waits.append((port, timeout)), True)[1]
            orchestrator._wait_fabric = lambda port, proc, netdevs, timeout=0: ""  # the stand-ins have no monitor
            Orchestrator._launch = lambda self, node_id, argv: fake_launch(node_id, argv)
            Orchestrator.preflight = lambda self, order, st: None  # no QEMU or bases on this PC

            def reap(pid):  # the stand-in processes are our children: reap them
                for p in procs:
                    if p.pid == pid and p.poll() is None:
                        p.terminate(); p.wait()
            orchestrator._kill = reap
            orch = Orchestrator(lab, accel="tcg", display="none")
            # first boot: the domain controller is installing from an ISO, so nobody waits for it
            needs_iso = Orchestrator._needs_install_iso
            Orchestrator._needs_install_iso = lambda self, nid: Path("fake.iso") if nid == "dc01" else None
            rep = orch.up(emit=log.append)
            Orchestrator._needs_install_iso = needs_iso
            check("the fabric and every machine start, in boot order",
                  rep.started == ["fabric", "dc01", "fs01", "lx01"], str(rep.started))
            check("an installing machine holds nobody up", waits == [] and 30 not in sleeps)
            st = state.load("pace")
            check("first boots are marked installing", st.nodes["dc01"].phase == "installing")

            # pretend the installs finished and the lab was stopped
            orch.down()
            check("down stops every process", all(p.poll() is not None for p in procs))
            log.clear(); sleeps.clear(); waits.clear()
            rep = orch.up(emit=log.append)
            ports = {n: ns.serial_port for n, ns in state.load("pace").nodes.items()}
            check("on a later start the members wait for the domain controller's agent",
                  waits == [(ports["dc01"], orchestrator.READY_TIMEOUT)], str(waits))
            check("then the start delay applies", 30 in sleeps)
            check("the wait is announced", any("waiting for dc01" in line for line in log)
                  and any("dc01 is ready" in line for line in log))
            check("a machine that is already running is skipped and nothing is resumed",
                  rep.skipped == [] and rep.resumed == [] and rep.started[1] == "dc01")

            # --- suspend: Windows hibernates, Linux shuts down, the fabric stops
            st = state.load("pace")
            pids = {n: ns.pid for n, ns in st.nodes.items()}

            def fake_hibernate(serial_port):
                node_id = next(n for n, p in ports.items() if p == serial_port)
                for p in procs:
                    if p.pid == pids[node_id]:
                        p.terminate(); p.wait()
                return ""

            powered: list[int] = []

            def fake_acpi(qmp_port):
                powered.append(qmp_port)
                for p in procs:
                    if p.pid == pids["lx01"]:
                        p.terminate(); p.wait()
                return ""

            orchestrator._hibernate = fake_hibernate
            orchestrator._acpi_powerdown = fake_acpi
            orchestrator._sleep = lambda secs: None
            try:
                orch.suspend(only=["nope"])
                check("suspend refuses an unknown machine", False)
            except OrchestratorError:
                check("suspend refuses an unknown machine", True)
            log.clear()
            rep = orch.suspend(emit=log.append)
            check("Windows machines hibernate", rep.hibernated == ["dc01", "fs01"], str(rep))
            check("a machine without an agent shuts down cleanly over ACPI",
                  rep.shut_down == ["lx01"] and powered == [st.nodes["lx01"].qmp_port])
            check("nothing had to be powered off and nothing failed",
                  rep.powered_off == [] and rep.failed == {})
            st = state.load("pace")
            check("hibernated machines are marked suspended, the rest stopped",
                  st.nodes["dc01"].phase == "suspended" and st.nodes["fs01"].phase == "suspended"
                  and st.nodes["lx01"].phase == "stopped" and st.nodes["fabric"].phase == "stopped")
            check("the whole lab is down", st.running() == {} and
                  not any(state.pid_alive(p) for p in pids.values()))
            check("state.suspended names them", state.suspended("pace") == {"dc01", "fs01"})
            try:
                orch.suspend()
                check("suspending a suspended lab says so", False)
            except OrchestratorError as exc:
                check("suspending a suspended lab says so", "not running" in str(exc))

            # the desktop and the shell refuse hardware changes meanwhile
            hw = editor.hardware_changes({"memory_mb": 2048})
            check("a memory change on a suspended machine is a hardware change", hw == ["memory_mb"])
            # down keeps the state file while something is suspended
            orch.down()
            check("stopping a suspended lab keeps its suspended marks",
                  state.suspended("pace") == {"dc01", "fs01"})

            # --- resume: a plain start, reported as a resume. A machine
            # saved with its memory (saved.vmstate, the refinement pass)
            # starts from that file; one left over by a stopped machine is
            # thrown away.
            log.clear()
            argvs = {}
            launch = Orchestrator._launch
            Orchestrator._launch = lambda self, node_id, argv: (argvs.__setitem__(node_id, list(argv)),
                                                               fake_launch(node_id, argv))[1]
            restored = orchestrator._wait_restored
            orchestrator._wait_restored = lambda port, proc, timeout=0: True
            for nid in ("dc01", "lx01"):
                (paths.lab_dir("pace") / nid).mkdir(parents=True, exist_ok=True)
                (paths.lab_dir("pace") / nid / orchestrator.SAVED_STATE).write_bytes(b"state")
            rep = orch.up(emit=log.append)
            Orchestrator._launch, orchestrator._wait_restored = launch, restored
            check("a saved machine starts from its saved state, a stale file is ignored and removed",
                  "-incoming" in argvs["dc01"] and "-incoming" not in argvs["lx01"]
                  and not (paths.lab_dir("pace") / "dc01" / orchestrator.SAVED_STATE).exists()
                  and not (paths.lab_dir("pace") / "lx01" / orchestrator.SAVED_STATE).exists()
                  and any("back where it was saved" in line for line in log), str(argvs.get("dc01", ""))[-200:])
            check("the next start resumes the hibernated machines",
                  rep.resumed == ["dc01", "fs01"] and set(rep.started) == {"fabric", "dc01", "fs01", "lx01"})
            check("resumes are announced", any(line.startswith("resumed dc01") for line in log))
            check("nothing is suspended after the resume", state.suspended("pace") == set())

            # a failed hibernation leaves the machine running and reported
            orchestrator._hibernate = lambda port: "hibernation is not available"
            rep = orch.suspend(only=["dc01"], emit=log.append)
            check("a refused hibernation is reported and the machine keeps running",
                  rep.failed == {"dc01": "hibernation is not available"} and
                  "dc01" in state.load("pace").running())
            # one machine suspended on its own leaves the fabric up
            orchestrator._hibernate = fake_hibernate
            st = state.load("pace"); pids = {n: ns.pid for n, ns in st.nodes.items()}
            ports = {n: ns.serial_port for n, ns in st.nodes.items()}
            rep = orch.suspend(only=["fs01"])
            st = state.load("pace")
            check("suspending one machine leaves the rest of the lab running",
                  rep.hibernated == ["fs01"] and "fabric" in st.running() and "dc01" in st.running())

            # a hibernation that never finishes is powered off after the timeout
            orchestrator._hibernate = lambda port: ""
            rep = orch.suspend(only=["dc01"], timeout=0.5)
            check("a hibernation that hangs is powered off and not marked suspended",
                  rep.powered_off == ["dc01"] and state.load("pace").nodes["dc01"].phase == "stopped")

            # reset forgets the suspended mark along with the disk
            orch.down()
            st = state.load("pace"); st.nodes["fs01"].phase = "suspended"; state.save(st)
            orch.reset(["fs01"])
            check("a rebuilt machine is no longer suspended", state.suspended("pace") == set())
        finally:
            for p in procs:
                try:
                    p.kill(); p.wait(timeout=5)
                except Exception:  # noqa: BLE001
                    pass
            os.environ.pop("WINLAB_IMAGES", None)
            (paths.VAR, paths.STATE, paths.LABS, orchestrator._sleep, orchestrator._wait_agent,
             orchestrator._hibernate, orchestrator._acpi_powerdown, orchestrator._kill) = saved
            orchestrator._wait_fabric = wait_fabric
            paths.qemu_img = saved_qimg
            import importlib
            importlib.reload(images)
            QemuProvider._uses_uefi = uses_uefi
            provision.build_answer_floppy, provision.build_data_disk = prov
            del Orchestrator.preflight
            del Orchestrator._launch


def _make_iso(files: dict[str, bytes], volume_id: str = "TESTISO",
              split: dict[str, int] | None = None) -> bytes:
    """A small ISO 9660 image with a Joliet descriptor, enough for the
    reader: descriptors, directory extents, file extents, no path tables.
    `split` names files written as several records of that many bytes each
    (a multiple of 2048), the way a file over 4 GiB is."""
    import struct
    SECTOR = 2048
    split = split or {}

    def both(n, fmt="<I", bfmt=">I"):
        return struct.pack(fmt, n) + struct.pack(bfmt, n)

    def record(name: bytes, lba: int, size: int, is_dir: bool, flags: int = 0) -> bytes:
        body = bytearray(33)
        body[2:10] = both(lba)
        body[10:18] = both(size)
        body[25] = (2 if is_dir else 0) | flags
        body[28:32] = both(1, "<H", ">H")
        body[32] = len(name)
        rec = bytes(body) + name
        if len(rec) % 2:
            rec += b"\x00"
        rec = bytearray(rec)
        rec[0] = len(rec)
        return bytes(rec)

    # Directory tree.
    tree: dict[str, dict] = {"": {}}
    for path in files:
        parts = path.split("/")
        for i in range(1, len(parts)):
            tree.setdefault("/".join(parts[:i]), {})
    for d in tree:
        parent = d.rsplit("/", 1)[0] if "/" in d else ""
        if d:
            tree[parent][d.rsplit("/", 1)[-1]] = ("dir", d)
    for path, data in files.items():
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        tree[parent][path.rsplit("/", 1)[-1]] = ("file", path)

    dirs = sorted(tree, key=lambda x: (x.count("/"), x))
    lba = 19
    dir_lba: dict[str, int] = {}
    for d in dirs:                       # one sector per directory, twice (plain + Joliet)
        dir_lba[d] = lba
        lba += 2
    file_lba: dict[str, int] = {}
    for path, data in files.items():
        file_lba[path] = lba
        lba += max(1, (len(data) + SECTOR - 1) // SECTOR)
    total = lba

    def dir_sector(d: str, joliet: bool) -> bytes:
        me = dir_lba[d] + (1 if joliet else 0)
        parent = d.rsplit("/", 1)[0] if "/" in d else ""
        up = dir_lba[parent] + (1 if joliet else 0)
        out = record(b"\x00", me, SECTOR, True) + record(b"\x01", up, SECTOR, True)
        for name, (kind, ref) in sorted(tree[d].items()):
            if kind == "dir":
                nm = name.encode("utf-16-be") if joliet else name.upper().encode()
                out += record(nm, dir_lba[ref] + (1 if joliet else 0), SECTOR, True)
            else:
                plain = name + ";1"
                nm = plain.encode("utf-16-be") if joliet else plain.upper().encode()
                data = files[ref]
                chunk = split.get(ref, 0)
                if not chunk:
                    out += record(nm, file_lba[ref], len(data), False)
                    continue
                for off in range(0, len(data), chunk):
                    size = min(chunk, len(data) - off)
                    out += record(nm, file_lba[ref] + off // SECTOR, size, False,
                                  flags=0x80 if off + size < len(data) else 0)
        return out.ljust(SECTOR, b"\x00")

    def descriptor(kind: int, joliet: bool) -> bytes:
        vd = bytearray(SECTOR)
        vd[0] = kind
        vd[1:6] = b"CD001"
        vd[6] = 1
        vid = volume_id.encode("utf-16-be") if joliet else volume_id.encode()
        vd[40:40 + len(vid)] = vid
        vd[80:88] = both(total)
        if joliet:
            vd[88:91] = b"%/E"
        vd[120:124] = both(1, "<H", ">H")
        vd[124:128] = both(1, "<H", ">H")
        vd[128:132] = both(SECTOR, "<H", ">H")
        vd[156:190] = record(b"\x00", dir_lba[""] + (1 if joliet else 0), SECTOR, True).ljust(34, b"\x00")
        return bytes(vd)

    img = bytearray(total * SECTOR)
    img[16 * SECTOR:17 * SECTOR] = descriptor(1, False)
    img[17 * SECTOR:18 * SECTOR] = descriptor(2, True)
    term = bytearray(SECTOR); term[0] = 255; term[1:6] = b"CD001"; term[6] = 1
    img[18 * SECTOR:19 * SECTOR] = term
    for d in dirs:
        img[dir_lba[d] * SECTOR:(dir_lba[d] + 1) * SECTOR] = dir_sector(d, False)
        img[(dir_lba[d] + 1) * SECTOR:(dir_lba[d] + 2) * SECTOR] = dir_sector(d, True)
    for path, data in files.items():
        img[file_lba[path] * SECTOR:file_lba[path] * SECTOR + len(data)] = data
    return bytes(img)


def test_virtio_drivers():
    """The virtio-win drivers: read out of the ISO with the stdlib reader,
    staged at prepare, recorded on the base, and turned into virtio devices
    by the provider only for bases that carry them."""
    import os
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path
    from winlab import balloon, images, iso9660, prepare, unattend, virtio
    from winlab.model import Lab, Nic, Node

    drivers = {
        "NetKVM/2k25/amd64/netkvm.inf": b"[Version]\r\nSignature=\"$Windows NT$\"\r\n",
        "NetKVM/2k25/amd64/netkvm.sys": b"NETSYS" * 500,
        "NetKVM/2k25/amd64/netkvm.cat": b"cat",
        "NetKVM/2k25/amd64/netkvm.pdb": b"debug symbols, not wanted",
        "NetKVM/w11/amd64/netkvm.inf": b"[Version]\r\n", "NetKVM/w11/amd64/netkvm.sys": b"x",
        "NetKVM/w11/amd64/netkvm.cat": b"c",
        # no 2k25 viostor on this (older) ISO: the 2k22 one is taken
        "viostor/2k22/amd64/viostor.inf": b"[Version]\r\n", "viostor/2k22/amd64/viostor.sys": b"y",
        "viostor/2k22/amd64/viostor.cat": b"c",
        "viostor/w11/amd64/viostor.inf": b"[Version]\r\n", "viostor/w11/amd64/viostor.sys": b"y",
        "viostor/w11/amd64/viostor.cat": b"c",
        "Balloon/2k25/amd64/balloon.inf": b"[Version]\r\n", "Balloon/2k25/amd64/balloon.sys": b"z",
        "Balloon/2k25/amd64/balloon.cat": b"c", "Balloon/2k25/amd64/blnsvr.exe": b"MZ",
        "Balloon/w11/amd64/balloon.inf": b"[Version]\r\n", "Balloon/w11/amd64/balloon.sys": b"z",
        "Balloon/w11/amd64/balloon.cat": b"c",
        # no 2k22 NetKVM or Balloon: Server 2022 takes the 2k19 ones; 2019 and
        # Windows 10 have their own
        "NetKVM/2k19/amd64/netkvm.inf": b"[Version]\r\n", "NetKVM/2k19/amd64/netkvm.sys": b"x19",
        "NetKVM/2k19/amd64/netkvm.cat": b"c",
        "viostor/2k19/amd64/viostor.inf": b"[Version]\r\n", "viostor/2k19/amd64/viostor.sys": b"y19",
        "viostor/2k19/amd64/viostor.cat": b"c",
        "Balloon/2k19/amd64/balloon.inf": b"[Version]\r\n", "Balloon/2k19/amd64/balloon.sys": b"z19",
        "Balloon/2k19/amd64/balloon.cat": b"c",
        "NetKVM/w10/amd64/netkvm.inf": b"[Version]\r\n", "NetKVM/w10/amd64/netkvm.sys": b"x10",
        "NetKVM/w10/amd64/netkvm.cat": b"c",
        "viostor/w10/amd64/viostor.inf": b"[Version]\r\n", "viostor/w10/amd64/viostor.sys": b"y10",
        "viostor/w10/amd64/viostor.cat": b"c",
        "Balloon/w10/amd64/balloon.inf": b"[Version]\r\n", "Balloon/w10/amd64/balloon.sys": b"z10",
        "Balloon/w10/amd64/balloon.cat": b"c",
        "virtio-win_license.txt": b"BSD-3-Clause, Red Hat\n",
        "qemu-ga-x86_64.msi": b"not a driver",
    }
    with tempfile.TemporaryDirectory() as td:
        iso_path = Path(td) / "virtio-win-0.1.271.iso"
        iso_path.write_bytes(_make_iso(drivers, "virtio-win-0.1.271"))

        with iso9660.Iso(iso_path) as iso:
            check("Joliet descriptor found", iso.joliet and iso.volume_id() == "virtio-win-0.1.271",
                  f"{iso.joliet} {iso.volume_id()!r}")
            names = [e.name for e in iso.listdir("")]
            check("root listed with real names", "NetKVM" in names and "virtio-win_license.txt" in names, str(names))
            check("case does not matter", iso.exists("netkvm/2K25/AMD64/NETKVM.INF"))
            check("file read back", iso.read("NetKVM/2k25/amd64/netkvm.sys") == b"NETSYS" * 500)
            check("a missing path is just missing", not iso.exists("viostor/2k25/amd64"))
            try:
                iso.read("nope.txt")
                check("reading a missing file raises", False)
            except iso9660.IsoError:
                check("reading a missing file raises", True)

        dest = Path(td) / "runtime-virtio"
        real_dir = virtio.virtio_dir
        virtio.virtio_dir = lambda: dest
        try:
            lines = []
            man = virtio.extract(iso_path, progress=lines.append, source=str(iso_path))
            check("every per-version directory on the ISO is kept",
                  set(man["dirs"]) == {"2k25", "2k22", "2k19", "w11", "w10"}
                  and set(man["dirs"]["2k22"]) == {"viostor"}, str(sorted(man["dirs"])))
            check("newest server dir taken, older one when the newest is absent",
                  virtio.chosen_dirs("ws2025") == {"NetKVM": "2k25", "viostor": "2k22", "Balloon": "2k25"},
                  str(virtio.chosen_dirs("ws2025")))
            check("Server 2022 never takes a 2k25 driver: 2k19 where 2k22 is absent",
                  virtio.chosen_dirs("ws2022") == {"NetKVM": "2k19", "viostor": "2k22", "Balloon": "2k19"}
                  and virtio.chosen_dirs("ws2022-core") == virtio.chosen_dirs("ws2022"),
                  str(virtio.chosen_dirs("ws2022")))
            check("2019 and the clients take their own",
                  set(virtio.chosen_dirs("ws2019").values()) == {"2k19"}
                  and set(virtio.chosen_dirs("win11").values()) == {"w11"}
                  and set(virtio.chosen_dirs("win10").values()) == {"w10"})
            check("debug symbols left out", "netkvm.pdb" not in man["dirs"]["2k25"]["NetKVM"]["files"]
                  and set(man["dirs"]["2k25"]["NetKVM"]["files"]) == {"netkvm.cat", "netkvm.inf", "netkvm.sys"})
            check("version from the file name", man["version"] == "0.1.271", man["version"])
            check("licence kept beside the drivers", (dest / "virtio-win_license.txt").exists()
                  and man["licence_files"] == ["virtio-win_license.txt"])
            check("every image ready", all(virtio.ready(i) for i in virtio.IMAGE_DIRS)
                  and virtio.ready("ws2019-core"))
            flat = virtio.files_for("ws2025")
            check("server drivers flat for the data disk: 10 files, no pdb",
                  len(flat) == 10 and "blnsvr.exe" in flat and not any(n.endswith(".pdb") for n in flat),
                  str(sorted(flat)))
            check("Windows 10 gets the w10 files", virtio.files_for("win10")["netkvm.sys"] == b"x10")
            check("status reads", "0.1.271" in virtio.render_status() and "ready" in virtio.render_status()
                  and "ws2019" in virtio.render_status())
            (dest / "w10" / "viostor" / "viostor.sys").unlink()
            check("a missing file makes that image not ready", not virtio.ready("win10")
                  and virtio.ready("win11") and virtio.chosen_dirs("win11")["viostor"] == "w11")
            (dest / "w11" / "viostor" / "viostor.sys").unlink()
            check("with no directory left for it, Windows 11 is not ready either",
                  not virtio.ready("win11") and virtio.ready("ws2025"))

            # what prepare stages and asks for
            node = Node(id="base", image="ws2025", kind="windows-server", nics=[Nic(network="prep")])
            lab = Lab(name="prep", domain="prep.local")
            xml = unattend.render(node, lab, prep=True, virtio=True)
            check("driver step runs before the trim and sysprep",
                  "<Order>97</Order>" in xml and xml.index("<Order>97</Order>") < xml.index("<Order>98</Order>")
                  and "winlab-virtio.ps1" in xml)
            check("no driver step without drivers", "<Order>97</Order>" not in unattend.render(node, lab, prep=True))
            argv = prepare._windows_install_argv(Path(td) / "b.qcow2", iso_path, Path(td) / "a.img",
                                                 Path(td) / "d.img", 5000, 5001, "tcg", True,
                                                 virtio_disk=Path(td) / "s.qcow2", virtio_port=5002)
            check("installer boots with a virtio disk, NIC and balloon present",
                  "virtio-blk-pci,drive=vio" in argv and any("virtio-net-pci" in a for a in argv)
                  and "virtio-balloon-pci" in argv and "socket,id=vnet,listen=127.0.0.1:5002" in argv)
            plain = prepare._windows_install_argv(Path(td) / "b.qcow2", iso_path, Path(td) / "a.img",
                                                  Path(td) / "d.img", 5000, 5001, "tcg", True)
            check("none of that without drivers",
                  not any(a.startswith(("virtio-blk", "virtio-net", "virtio-balloon")) for a in plain))
            check("the guest script uses pnputil on the data volume",
                  "pnputil.exe /add-driver" in virtio.SCRIPT and "WLDATA" in virtio.SCRIPT
                  and len(virtio.command()) < 259)
            os.environ["WINLAB_IMAGES"] = td
            try:
                disk = prepare._agent_payload_disk("ws2025", "windows-server", flat)
                raw = disk.read_bytes().upper()
                check("prep data disk carries the drivers and their installer",
                      b"NETKVM" in raw and b"VIOSTOR" in raw and b"PNPUTIL.EXE /ADD-DRIVER" in raw)
                got = prepare._virtio_drivers("ws2025", True, say=lambda *_: None)
                check("prepare takes the fetched drivers", set(got) == set(flat))
                check("--no-virtio stages nothing", prepare._virtio_drivers("ws2025", False) == {})

                # the base remembers, the provider reads
                from winlab import netplan, schema
                from winlab.providers.qemu import QemuProvider
                lab2 = schema.load("ad-ds-basics")
                plan = netplan.compile_topology(lab2, check_ports=False)
                prov = QemuProvider(plan, accel="tcg")
                before = " ".join(prov.build_node(lab2.nodes["dc01"]).argv)
                check("no metadata: emulated devices", "ide-hd,bus=ahci.0,drive=sys" in before
                      and "e1000e" in before and "virtio-blk" not in before)
                images.base_path("ws2025").parent.mkdir(parents=True, exist_ok=True)
                images.base_path("ws2025").write_bytes(b"qcow")
                images.write_base_meta("ws2025", virtio=True, drivers=virtio.summary("ws2025"))
                check("metadata read back", images.base_virtio("ws2025") and images.status("ws2025")["virtio"]
                      and images.base_meta("ws2025")["drivers"]["dirs"]["viostor"] == "2k22")
                images.save_templates({
                    "gold": images.Template(id="gold", title="Gold", kind="windows-server", image="ws2025"),
                    "gold2": images.Template(id="gold2", title="Gold 2", kind="windows-server", image="gold"),
                    "own": images.Template(id="own", title="Own", kind="custom", image=""),
                })
                check("a template answers for the base its machine came from",
                      images.base_virtio("gold") and images.base_virtio("gold2")
                      and not images.base_virtio("own") and not images.base_virtio("win11"))
                images.save_templates({})
                asked_not = " ".join(prov.build_node(lab2.nodes["dc01"]).argv)
                check("drivers in the base change nothing until the machine asks (hardware = virtio)",
                      "e1000e" in asked_not and "ide-hd" in asked_not and "virtio-balloon" not in asked_not)
                lab2.nodes["dc01"].hardware = lab2.nodes["fs01"].hardware = lab2.nodes["pc01"].hardware = "virtio"
                after = " ".join(prov.build_node(lab2.nodes["dc01"]).argv)
                check("base with drivers: virtio disk and NIC, balloon, still isolated",
                      "virtio-blk-pci,drive=sys,bootindex=0" in after and "virtio-net-pci,netdev=net0" in after
                      and "virtio-balloon-pci" in after and "e1000e" not in after and "ide-hd" not in after, after[-300:])
                fs = prov.build_node(lab2.nodes["fs01"]).argv
                check("data disks go virtio too", any(a.startswith("virtio-blk-pci,drive=data0") for a in fs))
                lab2.nodes["dc01"].vars["virtio"] = False
                forced = " ".join(prov.build_node(lab2.nodes["dc01"]).argv)
                check("virtio = false on a node keeps the emulated devices", "ide-hd,bus=ahci.0" in forced and "e1000e" in forced)
                check("images list says so", "virtio drivers" in images.render_status())
                lab2.nodes["pc01"].vars.clear()
                pc = " ".join(prov.build_node(lab2.nodes["pc01"]).argv)
                check("a client whose base has no drivers stays a pc", "e1000e" in pc and "virtio-blk" not in pc)
                from winlab.providers.qemu import hardware_of
                check("the plan says who really runs virtio", hardware_of(lab2.nodes["fs01"]) == "virtio"
                      and hardware_of(lab2.nodes["pc01"]) == "pc" and hardware_of(lab2.nodes["dc01"]) == "pc")
            finally:
                os.environ.pop("WINLAB_IMAGES", None)
        finally:
            virtio.virtio_dir = real_dir

    # the balloon: who, how much, and what the host allows
    from winlab import schema
    lab3 = schema.load("ad-ds-basics")

    class _State:
        def __init__(self, port): self.qmp_port = port

    calls: list[tuple[int, str, dict]] = []
    actual = {7001: 2048 * balloon.MIB, 7002: 2048 * balloon.MIB}

    class _FakeQmp:
        def __init__(self, port, timeout=30.0): self.port = port
        def __enter__(self): return self
        def __exit__(self, *a): return None
        def call(self, cmd, **args):
            calls.append((self.port, cmd, args))
            if cmd == "balloon":
                actual[self.port] = args["value"]
                return {}
            if cmd == "query-balloon":
                return {"actual": actual[self.port]}
            return {}

    running = {"dc01": _State(7001), "fs01": _State(7002)}
    real_bv, real_host = images.base_virtio, balloon.host_can_reclaim
    try:
        images.base_virtio = lambda image_id: True
        balloon.host_can_reclaim = lambda: True
        cands = [n.id for n in balloon.candidates(lab3, running)]
        check("running Windows machines with the driver are candidates", cands == ["dc01", "fs01"], str(cands))
        targets = balloon.plan(lab3, balloon.candidates(lab3, running), 700)
        check("the ask is shared in 256 MB steps, round-robin, toward the floors",
              targets == {"dc01": 1536, "fs01": 1792}, str(targets))
        freed, notes = balloon.reclaim(lab3, running, 700, qmp_factory=_FakeQmp, wait=2.0)
        check("both machines gave memory back", freed == 768 and any("dc01: gave back 512" in n for n in notes), f"{freed} {notes}")
        check("asked over QMP in bytes", (7001, "balloon", {"value": 1536 * balloon.MIB}) in calls)
        relaxed = balloon.relax(lab3, running, qmp_factory=_FakeQmp)
        check("relax gives it all back", relaxed == ["dc01", "fs01"] and actual[7001] == 2048 * balloon.MIB)
        big = balloon.plan(lab3, balloon.candidates(lab3, running), 10000)
        check("never below the floor", big == {"dc01": 1536, "fs01": 1536}, str(big))
        balloon.host_can_reclaim = lambda: False
        freed, notes = balloon.reclaim(lab3, running, 700, qmp_factory=_FakeQmp)
        check("a Windows host is told why nothing is reclaimed", freed == 0 and notes == [balloon.WHY_NOT])
        check("and relax does nothing there", balloon.relax(lab3, running, qmp_factory=_FakeQmp) == [])
        balloon.host_can_reclaim = lambda: True
        images.base_virtio = lambda image_id: False
        freed, notes = balloon.reclaim(lab3, running, 700, qmp_factory=_FakeQmp)
        check("no driver, no candidates", freed == 0 and "balloon driver" in notes[0], str(notes))
    finally:
        images.base_virtio, balloon.host_can_reclaim = real_bv, real_host

    qsys = shutil.which("qemu-system-x86_64")
    if not qsys or not balloon.host_can_reclaim():
        print("  skip live balloon: no qemu-system-x86_64 here")
    else:
        import socket, time
        with socket.socket() as sk:
            sk.bind(("127.0.0.1", 0)); port = sk.getsockname()[1]
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.Popen([
                qsys, "-accel", "tcg", "-machine", "q35", "-m", "2048", "-nodefaults", "-display", "none",
                "-no-user-config", "-device", "virtio-balloon-pci",
                "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off",
            ], stdout=subprocess.DEVNULL, stderr=(Path(td) / "qemu.err").open("wb"))
            try:
                deadline = time.monotonic() + 20
                ok = False
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=1):
                            ok = True; break
                    except OSError:
                        time.sleep(0.02)
                check("balloon test VM up", ok)
                one = Lab(name="b", domain="b.local")
                one.nodes["vm"] = Node(id="vm", image="ws2025", kind="windows-server", memory_mb=2048)
                images.base_virtio = lambda image_id: True
                try:
                    freed, notes = balloon.reclaim(one, {"vm": _State(port)}, 64, wait=3.0)
                finally:
                    images.base_virtio = real_bv
                check("a guest without the driver keeps its memory, and the user is told",
                      freed == 0 and any("no answer" in n for n in notes), f"{freed} {notes}")
            finally:
                proc.kill(); proc.wait(timeout=10)

    # the desktop and the first-run steps
    from winlab import webui
    d = webui.Dashboard(lab3, accel="tcg")
    info = d.images()
    check("Images window knows the driver state", "virtio" in info and "ready" in info["virtio"]
          and all("virtio" in row for row in info["images"]))
    ids = [st["id"] for st in d.setup_state()["steps"]]
    check("Setup lists the driver fetch after the fabric", ids.index("virtio") == ids.index("fabric") + 1, str(ids))
    check("virtio-win is no longer an image", "virtio-win" not in images.CATALOG)


def _make_wim(xml: str) -> bytes:
    """A WIM with the real header layout and an XML block at its tail, the
    way install.wim keeps its image list; the resources are stand-ins."""
    from winlab import wim
    body = b"\0" * 6000
    data = ("﻿" + xml).encode("utf-16-le")
    hdr = bytearray(wim.HEADER)
    hdr[:8] = wim.MAGIC
    hdr[8:12] = (wim.HEADER).to_bytes(4, "little")
    off = wim.HEADER + len(body)
    hdr[0x48:0x4F] = len(data).to_bytes(7, "little")
    hdr[0x50:0x58] = off.to_bytes(8, "little")
    hdr[0x58:0x60] = len(data).to_bytes(8, "little")
    return bytes(hdr) + body + data


def _image_xml(index: int, name: str, edition: str, itype: str, build: int, display: str = "") -> str:
    return (f'<IMAGE INDEX="{index}"><NAME>{name}</NAME>'
            + (f"<DISPLAYNAME>{display}</DISPLAYNAME>" if display else "")
            + f"<WINDOWS><ARCH>9</ARCH><EDITIONID>{edition}</EDITIONID>"
            f"<INSTALLATIONTYPE>{itype}</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR>"
            f"<MINOR>0</MINOR><BUILD>{build}</BUILD></VERSION></WINDOWS></IMAGE>")


def test_windows_versions():
    """Windows Server 2022 and 2019 (Desktop and Core) and Windows 10 beside
    2025 and 11: catalog, the edition read out of the ISO at import, the
    answer file, the drivers, the editor and the desktop."""
    import os
    import tempfile
    from pathlib import Path
    from winlab import editor, images, iso9660, schema, unattend, virtio, webui, wim
    from winlab.model import Lab, Nic, Node

    # catalog
    want = ["ws2025", "ws2025-core", "ws2022", "ws2022-core", "ws2019", "ws2019-core", "win11", "win10"]
    check("eight Windows images, newest first", images.WINDOWS_IMAGES == want, str(images.WINDOWS_IMAGES))
    check("every Core base installs from its Desktop sibling's ISO",
          images.SHARES_INSTALLER == {"ws2025-core": "ws2025", "ws2022-core": "ws2022", "ws2019-core": "ws2019"}
          and images.installer_path("ws2019-core").name == "ws2019.iso")
    e = images.CATALOG
    check("Server evaluations are 180 days, clients 90, each with its own download page",
          all("180 days" in e[i].license for i in want if i.startswith("ws"))
          and all("90 days" in e[i].license for i in ("win11", "win10"))
          and e["ws2022"].page.endswith("evaluate-windows-server-2022")
          and e["ws2019-core"].page.endswith("evaluate-windows-server-2019")
          and e["win10"].page.endswith("evaluate-windows-10-enterprise"))
    check("Windows 10's note says its evaluation download is going away",
          "October 2025" in e["win10"].note and "already hold" in e["win10"].note)
    check("short names for the desktop", e["ws2019-core"].short == "Windows Server 2019 Core"
          and e["win10"].short == "Windows 10" and images.windows_images("windows-client") == ["win11", "win10"])
    check("every Windows image has a stock answer-file name",
          all(i in unattend.DEFAULT_IMAGE for i in want)
          and unattend.DEFAULT_IMAGE["ws2019-core"].endswith("SERVERSTANDARDCORE")
          and unattend.DEFAULT_IMAGE["win10"] == "Windows 10 Enterprise")
    check("every Windows image has its own driver directories, Core with its sibling",
          all(virtio.dirs_for(i) for i in want) and virtio.dirs_for("ws2022-core") == ("2k22", "2k19")
          and virtio.dirs_for("win10") == ("w10",) and "2k25" not in virtio.dirs_for("ws2022"))
    check("the image a machine runs is a catalog image or a template of one",
          images.catalog_root("ws2019-core") is e["ws2019-core"] and images.catalog_root("nope") is None)

    # the media's own image list, read through a split (multi-extent) file
    xml22 = "<WIM><TOTALBYTES>1</TOTALBYTES>" + "".join([
        _image_xml(1, "Windows Server 2022 SERVERSTANDARDCORE", "ServerStandardEvalCore", "Server Core", 20348,
                   "Windows Server 2022 Standard Evaluation"),
        _image_xml(2, "Windows Server 2022 SERVERSTANDARD", "ServerStandardEval", "Server", 20348,
                   "Windows Server 2022 Standard Evaluation (Desktop Experience)"),
        _image_xml(3, "Windows Server 2022 SERVERDATACENTERCORE", "ServerDatacenterEvalCore", "Server Core", 20348),
        _image_xml(4, "Windows Server 2022 SERVERDATACENTER", "ServerDatacenterEval", "Server", 20348),
    ]) + "</WIM>"
    blob = _make_wim(xml22)
    with tempfile.TemporaryDirectory() as td:
        iso_path = Path(td) / "SERVER_EVAL_x64FRE_en-us.iso"
        iso_path.write_bytes(_make_iso({"sources/install.wim": blob, "setup.exe": b"MZ"},
                                       "SSS_X64FREE_EN-US_DV9", split={"sources/install.wim": 4096}))
        with iso9660.Iso(iso_path) as iso:
            ent = iso.entry("sources/install.wim")
            check("a file split over records reads as one", len(ent.pieces) == 3 and ent.size == len(blob)
                  and iso.read("sources/install.wim") == blob
                  and iso.read_at("sources/install.wim", 4000, 200) == blob[4000:4200], str(ent.pieces))
            try:
                iso.read_at("sources/install.wim", len(blob) - 10, 20)
                check("reading past the end raises", False)
            except iso9660.IsoError:
                check("reading past the end raises", True)
        wim_path, found = wim.images_in_iso(iso_path)
        check("the WIM's image list is read from the ISO without mounting it",
              wim_path == "sources/install.wim" and [f["index"] for f in found] == [1, 2, 3, 4]
              and found[1]["edition"] == "ServerStandardEval" and found[0]["type"] == "Server Core"
              and found[3]["build"] == 20348, str(found))
        check("Standard before Datacenter, Desktop Experience or Core by the installation type",
              images.pick_edition("ws2022", found)["index"] == 2
              and images.pick_edition("ws2022-core", found)["index"] == 1
              and images.pick_edition("ws2025", found) is None and images.pick_edition("win11", found) is None
              and images.media_fits(found) == ["ws2022", "ws2022-core"])
        check("describe", wim.describe(found[1]) == "Windows Server 2022 Standard Evaluation (Desktop Experience), "
              "build 20348, evaluation", wim.describe(found[1]))
        # Server 2025 and Windows 11 24H2 share a build: the installation type decides
        c11 = [{"index": 1, "name": "Windows 11 Enterprise N", "edition": "EnterpriseN", "type": "Client", "build": 26100},
               {"index": 2, "name": "Windows 11 Enterprise", "edition": "EnterpriseEval", "type": "Client", "build": 26100}]
        check("a Windows 11 24H2 medium is win11, not ws2025, and Enterprise beats Enterprise N",
              images.pick_edition("win11", c11)["index"] == 2 and images.pick_edition("ws2025", c11) is None
              and images.pick_edition("win10", c11) is None)
        ltsc = [{"index": 1, "name": "Windows 10 Enterprise LTSC", "edition": "EnterpriseSEval", "type": "Client", "build": 19044}]
        check("Windows 10 LTSC 2021 counts as Windows 10", images.pick_edition("win10", ltsc)["index"] == 1
              and images.pick_edition("win11", ltsc) is None)
        srv25 = [{"index": 1, "name": "Windows Server 2025 SERVERSTANDARD", "edition": "ServerStandardEval", "type": "Server", "build": 26100}]
        check("a Server 2025 medium is ws2025, not win11", images.pick_edition("ws2025", srv25)["index"] == 1
              and images.pick_edition("win11", srv25) is None and images.pick_edition("ws2025-core", srv25) is None)
        try:
            wim.xml_location(b"\0" * 208)
            check("a WIM without a signature is refused", False)
        except wim.WimError:
            check("a WIM without a signature is refused", True)

        # import records it; the answer file and the listings use it; a wrong ISO is refused
        os.environ["WINLAB_IMAGES"] = td
        images.CATALOG["ws2022"].min_gb = images.CATALOG["ws2019"].min_gb = 0.0
        try:
            copied = images.import_media("ws2022", iso_path)
            meta = images.installer_meta("ws2022")
            check("import records the media's images", copied.name == "ws2022.iso"
                  and len(meta["images"]) == 4 and meta["wim"] == "sources/install.wim"
                  and meta["fingerprint"] == images.fingerprint(iso_path), str(meta)[:200])
            check("each catalog image installs the edition the medium really has",
                  images.edition_name("ws2022") == "Windows Server 2022 SERVERSTANDARD"
                  and images.edition_name("ws2022-core") == "Windows Server 2022 SERVERSTANDARDCORE"
                  and images.edition_name("ws2025") == "" and images.edition_name("win10") == "")
            lab = Lab(name="old", domain="old.lab")
            fs = Node(id="fs01", image="ws2022-core", kind="windows-server", nics=[Nic(network="hq")])
            xml = unattend.render(fs, lab, prep=True)
            check("the answer file names the medium's image",
                  "<Key>/IMAGE/NAME</Key>" in xml and "<Value>Windows Server 2022 SERVERSTANDARDCORE</Value>" in xml)
            dc = Node(id="dc01", image="ws2019", kind="windows-server", nics=[Nic(network="hq")])
            check("the stock name when the medium was not read",
                  "<Value>Windows Server 2019 SERVERSTANDARD</Value>" in unattend.render(dc, lab))
            dc.vars["image_name"] = "Windows Server 2019 SERVERDATACENTER"
            check("image_name on the machine still wins",
                  "<Value>Windows Server 2019 SERVERDATACENTER</Value>" in unattend.render(dc, lab))
            st = images.status("ws2022")
            check("status and the list say what the installer installs",
                  "Desktop Experience" in st["edition"] and "installs Windows Server 2022 Standard" in images.render_status())
            try:
                images.import_media("ws2019", iso_path)
                check("the 2022 ISO imported as 2019 is refused", False)
            except images.ImageError as exc:
                check("the 2022 ISO imported as 2019 is refused, naming the right id",
                      "does not hold Windows Server 2019" in str(exc) and "images import ws2022" in str(exc), str(exc))
            images.base_path("ws2022").parent.mkdir(parents=True, exist_ok=True)
            images.base_path("ws2022").write_bytes(b"base")
            retired = images.retire_installer("ws2022")
            check("retiring the ISO keeps what it held", retired and images.retired_installer("ws2022")["prepared"] == "ws2022"
                  and len(images.installer_meta("ws2022")["images"]) == 4
                  and images.status("ws2022")["installer_retired"])
            images.save_templates({
                "gold": images.Template(id="gold", title="Gold", kind="windows-server", image="ws2022"),
            })
            check("a template answers with the version it was made from",
                  images.catalog_root("gold") is images.CATALOG["ws2022"])
            images.save_templates({})

            # the editor: a version per new machine, kind checked
            lab2 = schema.load("ad-ds-basics")
            net = next(iter(lab2.networks))
            made = editor.add_node(lab2, "srv19", kind="windows-server", network=net, image="ws2019-core")
            check("a machine on another Server version", made[0].image == "ws2019-core" and made[0].is_server_core
                  and made[0].memory_floor_mb == 1024)
            made = editor.add_node(lab2, "pc10", kind="windows-client", network=net, image="win10")
            check("a Windows 10 client", made[0].image == "win10" and made[0].kind == "windows-client"
                  and "domain-join" in made[0].roles)
            for kind, image in (("windows-client", "ws2019"), ("windows-server", "win10"), ("windows-server", "nope")):
                try:
                    editor.add_node(lab2, "bad", kind=kind, network=net, image=image)
                    check(f"{image} as {kind} is refused", False)
                except editor.EditError as exc:
                    check(f"{image} as {kind} is refused", "not" in str(exc) or "no image" in str(exc), str(exc))
            schema.validate(lab2)
            check("the lab still validates with mixed versions", True)
            check("the desktop names each machine's version",
                  webui.Dashboard._os_name(lab2.nodes["srv19"]) == "Windows Server 2019 Core"
                  and webui.Dashboard._os_name(lab2.nodes["pc10"]) == "Windows 10"
                  and webui.Dashboard._os_name(lab2.nodes["dc01"]) == "Windows Server 2025"
                  and webui.Dashboard._os_name(None).startswith("Alpine"))

            # Setup: the first machine's base is the main step, the others their own
            lab3 = webui.load_lab("ad-ds-basics")
            lab3.nodes["dc01"].image = "ws2022"
            lab3.nodes["fs01"].image = "ws2022-core"
            lab3.nodes["pc01"].image = "win10"
            d = webui.Dashboard(lab3, accel="tcg")
            setup = d.setup_state()
            steps = {st["id"]: st for st in setup["steps"]}
            ids = list(steps)
            check("the main step is the forest root's version",
                  steps["windows"]["label"] == "Import + prepare the Windows Server 2022 base"
                  and steps["windows"]["link"].endswith("2022") and steps["windows"]["image"] == "ws2022"
                  and "import it as ws2022" in steps["windows"]["hint"], str(steps["windows"]))
            check("Core and Windows 10 get their own steps, in boot order, before start",
                  "prepare-ws2022-core" in ids and "prepare-win10" in ids
                  and ids.index("prepare-ws2022-core") < ids.index("prepare-win10") < ids.index("up")
                  and "prepare-ws2025" not in ids and "pc01" in steps["prepare-win10"]["hint"], str(ids))
            check("the main step's base is the 2022 one (prepared above)",
                  steps["windows"]["done"] and setup["windows_base"] and not setup["bases_ready"])
            check("the desktop labels every prepare job",
                  all(f"prepare-{i}" in webui.JOB_INFO for i in want)
                  and webui.JOB_INFO["prepare-win10"][0] == "Prepare the Windows 10 base"
                  and webui.JOB_INFO["prepare-ws2019-core"][1] == 1800)
            rows = {r["id"]: r for r in d.images()["images"]}
            check("the Images window carries kind, short name and the edition found",
                  rows["ws2019"]["kind"] == "windows-server" and rows["win10"]["short"] == "Windows 10"
                  and "Desktop Experience" in rows["ws2022"]["edition"], str(rows["ws2022"]))
            nodes = {n["id"]: n for n in d.snapshot()["nodes"]}
            check("machine tiles name the version", nodes["dc01"]["os"] == "Windows Server 2022"
                  and nodes["fs01"]["os"] == "Windows Server 2022 Core" and nodes["pc01"]["os"] == "Windows 10")
        finally:
            images.CATALOG["ws2022"].min_gb = images.CATALOG["ws2019"].min_gb = 20.0
            os.environ.pop("WINLAB_IMAGES", None)






















def test_linux_terminal():
    """A Linux machine's serial console in a Terminal window: ttyS0 on a
    loopback socket, bridged by the desktop to xterm.js, which is fetched
    pinned from the npm registry and never shipped."""
    import gzip
    import hashlib
    import io
    import tarfile
    import tempfile
    from winlab import alpineovl, state, termview

    def tgz(members):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name); info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        data = tgz({"package/lib/xterm.js": b"var Terminal;", "package/LICENSE": b"MIT",
                    "package/other.js": b"not wanted"})
        termview.unpack(data, hashlib.sha256(data).hexdigest(),
                        {"package/lib/xterm.js": "xterm.js", "package/LICENSE": "LICENSE-xterm.txt"}, d, "x.tgz")
        check("only the wanted files are kept, by name",
              sorted(p.name for p in d.iterdir()) == ["LICENSE-xterm.txt", "xterm.js"]
              and (d / "xterm.js").read_bytes() == b"var Terminal;")
        try:
            termview.unpack(data, "0" * 64, {"package/LICENSE": "L"}, d, "x.tgz"); refused = False
        except termview.TermError:
            refused = True
        check("a tarball that is not the pinned one is refused", refused and not (d / "L").exists())
        saved = termview.paths.RUNTIME
        termview.paths.RUNTIME = d / "runtime"
        try:
            pkgs = {rel: tgz({m: m.encode() for m in members}) for rel, (_, members) in termview.PACKAGES.items()}
            saved_pk = dict(termview.PACKAGES)
            for rel, (dg, members) in saved_pk.items():
                termview.PACKAGES[rel] = (hashlib.sha256(pkgs[rel]).hexdigest(), members)
            urls = []
            termview.fetch(progress=lambda _l: None, get=lambda u: urls.append(u) or pkgs[u[len(termview.REGISTRY):]])
            check("fetch takes both tarballs from the npm registry and is then ready",
                  termview.ready() and len(urls) == 2 and all(u.startswith("https://registry.npmjs.org/") for u in urls)
                  and (termview.term_dir() / "LICENSE-xterm.txt").exists())
        finally:
            termview.PACKAGES.clear(); termview.PACKAGES.update(saved_pk)
            termview.paths.RUNTIME = saved

    st = state.LabState(name="t")
    st.nodes["lx01"] = state.NodeState("lx01", term_port=31002)
    with tempfile.TemporaryDirectory() as td:
        saved = state.paths.STATE
        state.paths.STATE = Path(td)
        try:
            state.save(st)
            check("the terminal port is kept in the lab state", state.load("t").nodes["lx01"].term_port == 31002)
        finally:
            state.paths.STATE = saved
    with tempfile.TemporaryDirectory() as td:
        def inittab(**kw):
            p = alpineovl.build_apkovl(Path(td) / "o.tar.gz", hostname="probe", packages=[], **kw)
            with tarfile.open(p) as tar:
                names = tar.getnames()
                return tar.extractfile("etc/inittab").read() if "etc/inittab" in names else b""
        check("an Alpine lab machine gets a login on ttyS0, the fabric does not",
              b"ttyS0::respawn:/sbin/getty -L 115200 ttyS0" in inittab(serial_login=True)
              and inittab() == b"")
    page = (Path("winlab") / "webui_page.html").read_text(encoding="utf-8")
    check("the desktop opens a Terminal window over /ws/term with the fetched xterm.js",
          "function openTerm(" in page and "/ws/term?node=" in page and "/xterm/xterm.js" in page
          and "Set size" in page)
    lic = Path("LICENSING.md").read_text(encoding="utf-8")
    check("LICENSING lists xterm.js as fetched, MIT", "xterm.js" in lic and "registry.npmjs.org" in lic)





def test_trial_pack_and_left_out_parts():
    """The trial's lessons ship encrypted (packaging/trialpack.py): the pack
    opens with the trial's key and every lesson, exercise and translation
    reads through it; without the key nothing does. The full app's parts the
    trial leaves out are not in the tree and import as empty stand-ins."""
    import json
    import os
    import shutil
    import subprocess
    from winlab import packs, paths, trialparts
    from winlab.licensing import client

    packed, free = packs.trial_plan(paths.CONTENT)
    check("every lab, lesson, exercise and answer is packed, with their translations",
          "labs/ad-ds-basics.toml" in packed and "lessons/promote-first-dc.toml" in packed
          and "exercises/promote-first-dc.toml" in packed and "i18n/lessons/he/promote-first-dc.json" in packed
          and not any(p.startswith(("labs/", "lessons/", "exercises/", "solutions/")) for p in free))
    check("help, roles and the desktop's strings stay plain",
          "roles/_manifest.toml" in free and "i18n/he.json" in free and "commands.toml" in free)
    check("a checkout has no trial key: its content is plain files", client.pack_key(packs.TRIAL) is None
          and client.pack_key("labs-full") is None)
    root = Path(__file__).resolve().parent.parent
    probe = r'''
import json
from winlab import content, exercises, i18n, lessons, paths, webui
out = {"mode": content.mode(), "labs": webui.lab_names(), "lessons": len(lessons.list_available()),
       "exercises": len(exercises.list_available()), "plain": (paths.CONTENT / "lessons").exists()}
try:
    out["he"] = bool(i18n.lesson_table("he", "promote-first-dc").get("title"))
    out["title"] = lessons.translated(lessons.load("promote-first-dc"), "he").title
except Exception as exc:
    out["he"] = "error: " + str(exc)[:120]
print(json.dumps(out, ensure_ascii=False))
'''
    key = os.urandom(32)
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        shutil.copytree(root / "content", home / "content", ignore=shutil.ignore_patterns("packs"))
        r = packs.build(home / "content", home / "content" / "packs" / "trial.wlpack", key, pack_id=packs.TRIAL, strip=True)
        check("the build encrypts the trial content and leaves no lesson in the clear",
              r["entries"] == len(packed) and not list((home / "content" / "lessons").glob("*.toml"))
              and b"Promote" not in (home / "content" / "packs" / "trial.wlpack").read_bytes())
        env = {k: v for k, v in os.environ.items() if not k.startswith("WINLAB_")}
        env["WINLAB_HOME"] = str(home)

        def run(extra: dict) -> dict:
            pr = subprocess.run([sys.executable, "-c", probe], cwd=root, capture_output=True, text=True,
                                encoding="utf-8", env={**env, **extra}, timeout=300)
            try:
                return json.loads(pr.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                return {"err": pr.stderr[-600:]}
        on = run({packs.env_name(packs.TRIAL): key.hex()})
        check("with the key: the three labs, every lesson and exercise, in Hebrew too",
              on.get("labs") == sorted(["ad-ds-basics", "firewall-by-hand", "router-protocols"])
              and on.get("lessons") == len([p for p in packed if p.startswith("lessons/")])
              and on.get("exercises") == len([p for p in packed if p.startswith("exercises/")])
              and on.get("he") is True and on.get("title") and on.get("title") != "Promote the first domain controller",
              str(on)[:400])
        off = run({})
        check("without the key nothing of it opens", off.get("lessons") == 0 and off.get("labs") == [], str(off)[:400])
    import importlib
    gone = importlib.import_module("winlab.aws")
    check("a part the trial leaves out is not in the tree", not (root / "winlab" / "aws.py").exists()
          and getattr(gone, "TRIAL_ABSENT", False) and not gone.anything and list(gone.CHECKS) == []
          and issubclass(gone.AwsError, Exception))
    check("its calls do nothing and serialize as null",
          json.dumps({"x": gone.summary()}, default=trialparts.as_json) == '{"x": null}')
    try:
        importlib.import_module("winlab.no_such_module")
        check("a real typo still fails", False)
    except ModuleNotFoundError:
        check("only the listed parts are stood in for; a typo still fails", True)
    check("the list names no module the trial ships",
          not [n for n in trialparts.ABSENT if (root / "winlab" / f"{n}.py").exists() or (root / "winlab" / n).is_dir()])


def _run_names(names: list[str]) -> int:
    """Run the named test groups in this process, oldest serial behaviour."""
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and (not names or k in names)]
    import time
    global CURRENT
    for t in tests:
        print(t.__name__)
        CURRENT = t.__name__
        t0 = time.monotonic()
        try:
            t()
        except Exception as exc:  # noqa: BLE001 - surface any crash as a failure
            global FAIL
            FAIL += 1
            FAILED.append(f"{t.__name__}: raised {type(exc).__name__}: {exc}"[:400])
            print(f"  FAIL {t.__name__} raised {type(exc).__name__}: {exc}")
        took = time.monotonic() - t0
        if took >= 1:
            print(f"  ({took:.1f}s)")
        print()
    if FAILED:
        print("failed:")
        for f in FAILED:
            print("  " + f)
        print()
    print(f"total: {PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


def main() -> int:
    # Groups run in worker processes, one interpreter per shard, because they
    # mutate os.environ and module globals: processes isolate that, threads
    # would not. WINLAB_TEST_JOBS=1 or --serial restores the old single loop;
    # explicit group names as arguments run just those, serially.
    import os
    import re as _re
    import subprocess

    argv = sys.argv[1:]
    if argv and argv[0] == "--worker":
        # A worker gets a WINLAB_HOME with a private copy of content/: groups
        # save labs through the editor and lock packs in place, and two
        # processes doing that to the real checkout corrupt each other's
        # reads. The parent normally provisions it (one copy per slot).
        if "WINLAB_HOME" not in os.environ:
            import atexit
            import shutil
            import tempfile as _tempfile
            home = Path(_tempfile.mkdtemp(prefix="winlab-tests-"))
            shutil.copytree(Path(__file__).resolve().parent.parent / "content", home / "content")
            os.environ["WINLAB_HOME"] = str(home)
            atexit.register(lambda: shutil.rmtree(home, ignore_errors=True))
        return _run_names(argv[1:])
    names = [a for a in argv if a.startswith("test_")]
    all_names = [k for k in sorted(globals()) if k.startswith("test_")]
    unknown = [n for n in names if n not in all_names]
    if unknown:
        print("unknown groups: " + " ".join(unknown))
        return 2
    jobs_env = os.environ.get("WINLAB_TEST_JOBS", "")
    # Physical cores, not SMT threads: twice the processes just thrash the
    # caches and the laptop's power budget, measured 9x per-group inflation.
    jobs = int(jobs_env) if jobs_env.isdigit() and int(jobs_env) > 0 else max(2, (os.cpu_count() or 8) // 2)
    picked = names or all_names
    jobs = min(jobs, len(picked))
    if names or "--serial" in argv or jobs <= 1:
        print(f"winlab test suite ({len(picked)} groups)\n")
        return _run_names(picked)

    import atexit
    import queue as _queue
    import shutil
    import tempfile as _tempfile
    from concurrent.futures import ThreadPoolExecutor, as_completed

    print(f"winlab test suite ({len(picked)} groups, {jobs} processes)\n")
    # One process per GROUP, pulled from a queue: pre-sharding lets several of
    # the minutes-long groups land on one worker and cap the whole run. The
    # longest groups (by measurement) start first so none begins near the end.
    heavy = ["test_hardware_events", "test_media_shelf", "test_graded_roles_and_windows_faults",
             "test_real_guis_bmc_redfish", "test_ref_devices", "test_physical_faults",
             "test_exam_prep_tracks_and_banks", "test_dsc_compile", "test_ref_network",
             "test_srv_identity", "test_incident_drills", "test_linux_appliances"]
    order = [n for n in heavy if n in picked] + [n for n in picked if n not in heavy]
    homes = []
    for _ in range(jobs):
        h = Path(_tempfile.mkdtemp(prefix="winlab-tests-"))
        shutil.copytree(Path(__file__).resolve().parent.parent / "content", h / "content")
        homes.append(h)
    atexit.register(lambda: [shutil.rmtree(h, ignore_errors=True) for h in homes])
    slots: _queue.SimpleQueue = _queue.SimpleQueue()
    for h in homes:
        slots.put(h)

    def run_group(name: str) -> tuple[str, int, str]:
        home = slots.get()
        try:
            env = dict(os.environ, PYTHONUTF8="1", WINLAB_HOME=str(home))
            p = subprocess.run([sys.executable, __file__, "--worker", name],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, encoding="utf-8", errors="replace", env=env)
            return name, p.returncode, p.stdout
        finally:
            slots.put(home)

    passed = failed = 0
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for fut in as_completed([pool.submit(run_group, n) for n in order]):
            name, rc, out = fut.result()
            tail = _re.search(r"^total: (\d+) passed, (\d+) failed$", out, _re.M)
            body = out[:tail.start()] if tail else out
            sys.stdout.write(body.rstrip("\n") + "\n\n")
            if tail:
                passed += int(tail.group(1))
                failed += int(tail.group(2))
            if rc != 0 and (not tail or tail.group(2) == "0"):
                failed += 1
                print(f"  FAIL {name} exited {rc} without reporting a failure")
    print(f"total: {passed} passed, {failed} failed")
    return 1 if failed else 0






# ------------------------------------------------- sysadmin gaps: checks + faults
def _ps_balance_error(text: str) -> str:
    """A rough PowerShell lexer: brackets and quotes must balance. Returns ''
    when they do, else what is wrong."""
    stack: list[str] = []
    pairs = {")": "(", "}": "{", "]": "["}
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "#" and (i == 0 or text[i - 1] in " \t\n;{(") :
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "<" and text.startswith("<#", i):
            j = text.find("#>", i)
            if j < 0:
                return "unclosed <# comment"
            i = j + 2
            continue
        if ch == "@" and text[i + 1:i + 2] in ("'", '"') and text[i + 2:i + 3] == "\n":
            end = "\n" + text[i + 1] + "@"
            j = text.find(end, i + 3)
            if j < 0:
                return "unclosed here-string"
            i = j + len(end)
            continue
        if ch == "'":
            j = i + 1
            while True:
                k = text.find("'", j)
                if k < 0:
                    return f"unclosed ' at {i}: {text[i:i+40]!r}"
                if text[k + 1:k + 2] == "'":
                    j = k + 2
                    continue
                break
            i = k + 1
            continue
        if ch == '"':
            j = i + 1
            depth = 0
            while j < n:
                c = text[j]
                if c == "`":
                    j += 2
                    continue
                if c == "$" and text[j + 1:j + 2] == "(":
                    depth += 1; j += 2; continue
                if depth and c == ")":
                    depth -= 1; j += 1; continue
                if c == '"' and not depth:
                    if text[j + 1:j + 2] == '"':
                        j += 2
                        continue
                    break
                j += 1
            else:
                return f"unclosed \" at {i}: {text[i:i+40]!r}"
            i = j + 1
            continue
        if ch == "`":
            i += 2
            continue
        if ch in "({[":
            stack.append(ch)
        elif ch in ")}]":
            if not stack or stack[-1] != pairs[ch]:
                return f"unbalanced {ch} at {i}: {text[max(0,i-40):i+1]!r}"
            stack.pop()
        i += 1
    return f"unclosed {stack[-1]}" if stack else ""












def gf_title_absent(view: dict, scenario: str) -> bool:
    from winlab import guestfaults
    title = guestfaults.SCENARIOS[scenario].title
    return all(title not in str(t) for t in view["tickets"])


def test_hardware_events():
    """Hardware events: a data disk pulled out of its hot-swap bay while the
    machine runs stops answering (a mirror or a pool degrades), goes back or
    is replaced by a blank one with the machine off, and a blank USB stick
    plugs in and out live."""
    import os
    import shutil
    from pathlib import Path
    from winlab import cli, editor, hardware, media, netplan, paths, schema, state
    from winlab.model import Node, Nic
    from winlab.providers.qemu import QemuProvider

    calls: list = []

    class _FakeQmp:
        def __init__(self, port, timeout=30.0): self.port = port
        def __enter__(self): return self
        def __exit__(self, *a): return None
        def call(self, cmd, **args):
            calls.append((cmd, args))
            if cmd == "device_del":
                raise media.QmpError("Device 'wlstick' not found")
            return {}

    lab = schema.load("ad-ds-basics")
    lab.name = "hw-events-test"
    lab.nodes["fs09"] = Node(id="fs09", image="ws2022", kind="windows-server",
                             nics=[Nic(network="corp", ip="10.10.10.69")], data_disks_gb=[20, 20, 40])
    node = lab.nodes["fs09"]
    plan = netplan.compile_topology(lab, check_ports=False)
    try:
        argv = QemuProvider(plan, accel="tcg").build_node(node).argv
        drives = [a for a in argv if a.startswith("id=data")]
        check("each data disk has named nodes a pull can swap",
              len(drives) == 3 and all(f"node-name=data{i}-fmt,file.node-name=data{i}-file" in d
                                       for i, d in enumerate(drives)), str(drives))
        ports = [a.split("bus=ahci.")[1].split(",")[0] for a in argv if "drive=data" in a]

        check("a machine that is off: pulling leaves the bay empty at the next start",
              hardware.pull(lab.name, node, 1, qmp=_FakeQmp) is False and calls == []
              and hardware.pulled(lab.name, "fs09") == {1})
        argv = QemuProvider(plan, accel="tcg").build_node(node).argv
        left = [a for a in argv if "drive=data" in a]
        check("the pulled disk is not attached, and the others keep their SATA ports",
              len(left) == 2 and "drive=data1" not in " ".join(argv)
              and [a.split("bus=ahci.")[1].split(",")[0] for a in left] == [ports[0], ports[2]], str(left))
        try:
            hardware.pull(lab.name, node, 1, qmp=_FakeQmp)
            check("pulling a pulled disk is refused", False)
        except hardware.HardwareError:
            check("pulling a pulled disk is refused", True)
        try:
            hardware.pull(lab.name, node, 3, qmp=_FakeQmp)
            check("no bay 4 on a machine with three data disks", False)
        except hardware.HardwareError as exc:
            check("no bay 4 on a machine with three data disks", "bay 4" in str(exc), str(exc))
        hardware.put_back(lab.name, node, 1)
        check("put back with the machine off: in its bay again", hardware.pulled(lab.name, "fs09") == set())

        st = state.new(lab.name, "tcg", "none")
        st.nodes["fs09"] = state.NodeState(node_id="fs09", pid=os.getpid(), qmp_port=4444)
        state.save(st)
        check("a running machine: the pull is live", hardware.pull(lab.name, node, 0, qmp=_FakeQmp) is True)
        names = [c for c, _ in calls]
        add, reopen = calls[0][1], calls[1][1]
        check("the disk's image goes behind a filter that fails every request with EIO",
              names == ["blockdev-add", "blockdev-reopen"] and add["driver"] == "blkdebug"
              and add["image"] == "data0-file" and add["node-name"] == "data0-gone"
              and {r["event"] for r in add["inject-error"]} >= {"read_aio", "write_aio", "flush_to_disk"}
              and all(r["errno"] == 5 for r in add["inject-error"])
              and reopen["options"] == [{"driver": "qcow2", "node-name": "data0-fmt", "file": "data0-gone"}], str(calls))
        for fn, what in ((lambda: hardware.put_back(lab.name, node, 0), "put back"),
                         (lambda: hardware.replace(lab.name, node, 0, Path("/nonexistent/data0.qcow2")), "replaced")):
            try:
                fn()
                check(f"a disk is not {what} while the machine runs", False)
            except hardware.HardwareError as exc:
                check(f"a disk is not {what} while the machine runs", "shut fs09 down" in str(exc), str(exc))
        state.state_file(lab.name).unlink()
        disk = paths.lab_dir(lab.name) / "fs09" / "data0.qcow2"
        disk.write_bytes(b"old data")
        hardware.replace(lab.name, node, 0, disk)
        check("a new blank disk: the old image is gone (the next start makes an empty one) and the bay is full",
              not disk.exists() and hardware.pulled(lab.name, "fs09") == set())
        hardware.pull(lab.name, node, 2, qmp=_FakeQmp)
        editor.set_node(lab, "fs09", rm_disk=True)
        check("a disk taken out of the machine for good leaves no pulled bay behind",
              hardware.pulled(lab.name, "fs09") == set() and node.data_disks_gb == [20, 20])

        calls.clear()
        r = media.plug_blank(lab.name, "fs09", 16, qmp=_FakeQmp)
        stick = media.stick_path(lab.name, "fs09")
        with stick.open("rb") as fh:
            head = fh.read(512)
        check("a blank stick: 16 GB, sparse, no file system", r["size_mb"] == 16384 and r["live"] is False
              and stick.stat().st_size == 16 * 1024**3 and head == bytes(512)
              and (os.name == "nt" or stick.stat().st_blocks * 512 < 1 << 20))
        try:
            media.plug_blank(lab.name, "fs09", 3, qmp=_FakeQmp)
            check("odd stick sizes are refused", False)
        except media.MediaError:
            check("odd stick sizes are refused", True)
        state.save(st)
        r = media.plug_blank(lab.name, "fs09", 8, qmp=_FakeQmp)
        check("on a running machine the blank stick is hot-plugged", r["live"]
              and [c for c, _ in calls] == ["device_del", "blockdev-add", "device_add"], str(calls))
        st.nodes.clear()
        state.save(st)
        check("and taken out", media.unplug(lab.name, "fs09", qmp=_FakeQmp) and not stick.exists())
    finally:
        state.state_file(lab.name).unlink(missing_ok=True)
        shutil.rmtree(paths.lab_dir(lab.name), ignore_errors=True)

    p = cli.build_parser()
    a = p.parse_args(["media", "lab", "fs01", "pull", "2"])
    b = p.parse_args(["media", "lab", "fs01", "blank", "--gb", "32"])
    check("`winlab media <lab> <node> pull|back|new-disk <bay>` and `blank --gb`",
          a.mediacmd == "pull" and a.bay == 2 and b.mediacmd == "blank" and b.gb == 32)
    web = Path("winlab/webui.py").read_text(encoding="utf-8")
    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    check("the desktop has the bay and blank-stick actions",
          all(x in web for x in ('"hw-pull"', '"hw-back"', '"hw-replace"', '"media-blank"')))
    check("the Machines window shows the drive bays and the blank sticks (the workbench: the front panel's bays)",
          "function bayRows(" in page and page.count("bayRows(") >= 2 and "media-blank" in page and "function devBayMenu(" in page
          and "'pulled'" in page and "Failed Redundancy" in page)










def test_native_window():
    """winlab's own program window: a Win32 window with WebView2 (part of
    Windows) or a GTK window with WebKitGTK (Linux) drawing the desktop;
    Microsoft's loader DLL fetched from nuget.org at setup, never bundled; the
    Edge app window when it cannot start, saying why; closing it stops winlab;
    no console window beside it."""
    import io
    import json
    import os
    import struct
    import sys
    import tempfile
    import zipfile
    from pathlib import Path
    from winlab import appwindow, cli, nativewin, paths

    check("the pinned SDK version is used when the feed has it",
          nativewin.pick_version({"versions": ["1.0.1", nativewin.SDK_VERSION, "1.0.9999-prerelease"]})
          == nativewin.SDK_VERSION)
    check("else the newest stable version (no prereleases)",
          nativewin.pick_version({"versions": ["1.0.2", "1.0.10", "1.0.11-prerelease"]}, "9.9") == "1.0.10")

    def pe(machine):
        head = bytearray(0x80)
        head[:2] = b"MZ"
        head[0x3C:0x40] = struct.pack("<I", 0x40)
        head[0x40:0x44] = b"PE\0\0"
        head[0x44:0x46] = struct.pack("<H", machine)
        return bytes(head)

    def nupkg(files):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name, data in files.items():
                z.writestr(name, data)
        return buf.getvalue()

    dll = pe(0x8664)
    check("a 64-bit DLL is recognised, a 32-bit one is not",
          nativewin.is_x64_dll(dll) and not nativewin.is_x64_dll(pe(0x14C)) and not nativewin.is_x64_dll(b"junk"))
    check("the 64-bit loader comes out of the SDK package",
          nativewin.loader_from_package(nupkg({nativewin.LOADER_IN_PACKAGE: dll,
                                               "runtimes/win-x86/native/WebView2Loader.dll": pe(0x14C)})) == dll)
    for name, pkg in (("a package without it", nupkg({"lib/x.dll": dll})),
                      ("a 32-bit one under the 64-bit name", nupkg({nativewin.LOADER_IN_PACKAGE: pe(0x14C)})),
                      ("a file that is no package", b"not a zip")):
        try:
            nativewin.loader_from_package(pkg)
            ok = False
        except nativewin.NativeWindowError:
            ok = True
        check(f"refused: {name}", ok)

    old = paths.RUNTIME
    with tempfile.TemporaryDirectory() as td:
        paths.RUNTIME = Path(td)
        try:
            asked = []

            def get(url):
                asked.append(url)
                if url.endswith("index.json"):
                    return json.dumps({"versions": ["1.0.1", nativewin.SDK_VERSION]}).encode()
                return nupkg({nativewin.LOADER_IN_PACKAGE: dll})

            dest = nativewin.fetch(get=get, say=lambda m: None)
            check("fetch puts the loader under runtime/webview2, from nuget.org",
                  dest == Path(td) / "webview2" / "WebView2Loader.dll" and dest.read_bytes() == dll
                  and all(u.startswith("https://api.nuget.org/") for u in asked)
                  and asked[-1].endswith(f"{nativewin.SDK_VERSION}/microsoft.web.webview2.{nativewin.SDK_VERSION}.nupkg"))
            asked.clear()
            nativewin.fetch(get=get, say=lambda m: None)
            check("a second fetch downloads nothing", asked == [])
            check("on Windows without the loader the window is not offered, and says why",
                  nativewin.unavailable({}, "win32")[0] == "loader" if not nativewin.loader_path().exists() else True)
        finally:
            paths.RUNTIME = old

    check("WINLAB_BROWSER=edge or tab keeps the browser windows",
          not nativewin.env_allows({"WINLAB_BROWSER": "edge"}) and not nativewin.env_allows({"WINLAB_BROWSER": "Tab"})
          and nativewin.env_allows({}))
    cmd = nativewin.window_command("http://127.0.0.1:8780/")
    check("the window runs as `winlab window <url>`", cmd[-2:] == ["window", "http://127.0.0.1:8780/"])
    args = cli.build_parser().parse_args(["window", "http://127.0.0.1:8780/"])
    check("`winlab window` is a command", args.cmd == "window" and args.url == "http://127.0.0.1:8780/")
    check("Linux without a graphical session: no window, and the reason",
          nativewin.unavailable({}, "linux")[0] == "display")
    check("macOS has no native window", nativewin.unavailable({}, "darwin")[0] == "platform")
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        try:
            nativewin.run("http://127.0.0.1:8780/", Path("var/appwindow"))
            ok = False
        except nativewin.NativeWindowError as exc:
            ok = exc.code in nativewin.FALLBACK_CODES
        check("a window that cannot open refuses with a reason code (so the caller falls back)", ok)
    home = "http://127.0.0.1:8780/"
    check("winlab's own pop-outs stay winlab windows",
          nativewin.is_local("http://127.0.0.1:8780/?screen=dc01", home) and nativewin.is_local("about:blank", home))
    check("the outside world goes to the user's browser",
          not nativewin.is_local("https://www.microsoft.com/en-us/evalcenter/", home)
          and not nativewin.is_local("http://127.0.0.1:9999/", home))

    class Proc:
        def __init__(self, code):
            self.code = code

        def poll(self):
            return self.code

        def wait(self):
            return self.code

    started = []
    proc = appwindow.open_native("http://x/", wait=0.05, popen=lambda a, **k: started.append(a) or Proc(None))
    check("a native window that stays up counts as opened", proc is not None and started and started[0][-2] == "window")
    check("one that quits at once with an error does not",
          appwindow.open_native("http://x/", wait=0.3, popen=lambda a, **k: Proc(3)) is None)
    check("one that went to a browser tab by itself still counts",
          appwindow.open_native("http://x/", wait=0.3, popen=lambda a, **k: Proc(appwindow.UNTRACKED)) is not None)

    old_var = paths.VAR
    real_native, real_web, real_follow = appwindow.open_native, appwindow.webbrowser.open, appwindow._follow
    opened, followed = [], []
    with tempfile.TemporaryDirectory() as td:
        paths.VAR = Path(td)
        try:
            nativewin.note_fallback("webkit", "no WebKitGTK")
            got = nativewin.fallback()
            check("why the desktop is in a browser window is remembered for the page",
                  got.get("code") == "webkit" and got.get("detail") == "no WebKitGTK")
            nativewin.note_fallback("nonsense")
            check("an unknown reason is filed as failed", nativewin.fallback().get("code") == "failed")
            appwindow._follow = lambda target, *a: followed.append((target, a))
            appwindow.open_native = lambda url: Proc(None)
            how = appwindow.open_window("http://x/", Path(td) / "aw", env={}, native=True, on_closed=lambda: None)
            check("the native window comes first when it is there, and the desktop follows it",
                  how == "native" and followed and followed[0][0] is appwindow._follow_native
                  and nativewin.fallback() == {})
            appwindow.open_native = lambda url: None
            appwindow.webbrowser.open = lambda url: opened.append(url)
            how = appwindow.open_window("http://x/", Path(td) / "aw", env={"WINLAB_BROWSER": "tab"}, native=True)
            check("a native window that fails falls back to the browser and says why",
                  how == "tab" and opened == ["http://x/"] and nativewin.fallback().get("code") == "crashed")
            appwindow.open_native = lambda url: (_ for _ in ()).throw(AssertionError("not asked"))
            opened.clear()
            how = appwindow.open_window("http://x/", Path(td) / "aw", env={"WINLAB_BROWSER": "tab", "DISPLAY": ""},
                                        on_closed=lambda: None)
            check("WINLAB_BROWSER=tab is the user's choice: no native window, no complaint",
                  how == "tab" and opened == ["http://x/"])

            closed = []
            appwindow._follow_native(Proc(0), "http://x/", Path(td) / "aw", {}, lambda: closed.append(1))
            check("closing winlab's window stops the desktop", closed == [1])
            appwindow._follow_native(Proc(appwindow.UNTRACKED), "http://x/", Path(td) / "aw", {},
                                     lambda: closed.append(2))
            check("a browser tab cannot be followed, so the desktop keeps running", closed == [1])
            opened.clear()
            appwindow._follow_native(Proc(9), "http://x/", Path(td) / "aw", {"WINLAB_BROWSER": "tab"},
                                     lambda: closed.append(3))
            check("a window that crashes brings the desktop back in the browser, saying why",
                  opened == ["http://x/"] and nativewin.fallback().get("code") == "crashed" and closed == [1])

            real_bw, real_run = appwindow.open_browser_window, nativewin.run
            try:
                def fail(url, profile, title="winlab"):
                    raise nativewin.NativeWindowError("no runtime here", "runtime")
                nativewin.run = fail
                appwindow.open_browser_window = lambda url, profile, env=None: ("tab", None)
                code = cli.main(["window", "http://127.0.0.1:8780/"])
                check("`winlab window` that cannot start notes why, opens the browser window and exits untracked",
                      code == appwindow.UNTRACKED and nativewin.fallback().get("code") == "runtime")
                code = cli.main(["window", "--no-fallback", "http://127.0.0.1:8780/"])
                check("--no-fallback only fails", code == 3)
            finally:
                appwindow.open_browser_window, nativewin.run = real_bw, real_run
        finally:
            paths.VAR = old_var
            appwindow.open_native, appwindow.webbrowser.open, appwindow._follow = real_native, real_web, real_follow

    from winlab import quietstart
    check("double-clicked (only winlab on its console): run quietly",
          quietstart.owns_console_alone([10, 11], 11, 10))
    check("typed in a terminal (the shell shares the console): stay where it was typed",
          not quietstart.owns_console_alone([4, 10, 11], 11, 10) and not quietstart.owns_console_alone([], 11, 10))
    spawned = []
    check("off Windows nothing is relaunched",
          not quietstart.relaunch_hidden({}, "linux", pids=[os.getpid()], popen=lambda *a, **k: spawned.append(a)))
    hidden = quietstart.relaunch_hidden({}, "win32", pids=[os.getpid()],
                                        popen=lambda a, **k: spawned.append((a, k)))
    check("the quiet copy has no console window and knows it is the quiet one",
          hidden and spawned and spawned[0][1]["creationflags"] == quietstart.CREATE_NO_WINDOW
          and spawned[0][1]["env"].get(quietstart.ENV) == "1")
    spawned.clear()
    check("from a terminal nothing is relaunched",
          not quietstart.relaunch_hidden({}, "win32", pids=[1, 2, 3], popen=lambda *a, **k: spawned.append(a))
          and not spawned)

    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    web = Path("winlab/webui.py").read_text(encoding="utf-8")
    check("the desktop says why it is in a browser window, a sentence per reason",
          "function appWindowNotice(" in page and all(f"{c}:" in page for c in nativewin.FALLBACK_CODES)
          and '"/api/appwindow"' in web)
    check("the desktop stops when its window is closed",
          "on_closed=window_closed" in web and "httpd.shutdown" in web)
    iss = Path("packaging/winlab.iss").read_text(encoding="utf-8")
    ps = Path("packaging/build-exe.ps1").read_text(encoding="utf-8")
    check("the shortcuts start winlab without a console window (winlab-start.exe, built from our own C#)",
          'Filename: "{app}\\winlab-start.exe"; WorkingDir' in iss and "winlab-start.cs" in ps
          and "/target:winexe" in ps and Path("packaging/launcher/winlab-start.cs").is_file()
          and "WINLAB_QUIET" in Path("packaging/launcher/winlab-start.cs").read_text(encoding="utf-8"))

    lic = Path("LICENSING.md").read_text(encoding="utf-8")
    boot = Path("winlab/bootstrap.py").read_text(encoding="utf-8")
    check("the loader is fetched at setup and listed as fetched, never bundled",
          "WebView2Loader.dll" in lic and "nuget.org" in lic and "nativewin.fetch()" in boot)
    src = Path("winlab/nativewin.py").read_text(encoding="utf-8")
    check("the window follows the page's title and its full-screen machine screens",
          "on_title" in src and "on_fullscreen" in src and "WS_POPUP" in src and "rcMonitor" in src)


def test_native_feel():
    """The desktop as a program: its own app window (Edge or Chrome app mode,
    never a tab), windows that open centred, snap and animate, a Search panel
    of its own, desktop icons and taskbar pins arranged by dragging, commands
    dragged onto a machine, synthesised sounds with a switch, our own
    full-colour icons, and documents shown in a window of the desktop."""
    import os
    from pathlib import Path
    from winlab import appwindow

    env = {"PROGRAMFILES(X86)": r"C:\Program Files (x86)", "LOCALAPPDATA": r"C:\Users\s\AppData\Local"}
    edge = str(Path(r"C:\Program Files (x86)") / r"Microsoft\Edge\Application\msedge.exe")
    found = appwindow.find_browser(env, "win32", exists=lambda p: p == edge, which=lambda n: None)
    check("Edge, which every Windows PC has, is found first", found == edge, str(found))
    chrome = str(Path(r"C:\Users\s\AppData\Local") / r"Google\Chrome\Application\chrome.exe")
    check("Chrome is the fallback when Edge is missing",
          appwindow.find_browser(env, "win32", exists=lambda p: p == chrome, which=lambda n: None) == chrome)
    check("no app-mode browser: none found",
          appwindow.find_browser({}, "linux", exists=lambda p: False, which=lambda n: None) is None)
    args = appwindow.app_args("msedge.exe", "http://127.0.0.1:8780/", Path("var/appwindow"))
    check("one app window: no tabs or address bar, its own profile, no first-run pages",
          "--app=http://127.0.0.1:8780/" in args and any(a.startswith("--user-data-dir=") for a in args)
          and "--no-first-run" in args and not any(a.startswith("--kiosk") for a in args))
    opened = []
    real = appwindow.webbrowser.open
    try:
        appwindow.webbrowser.open = lambda url: opened.append(url)
        how = appwindow.open_window("http://127.0.0.1:8780/", Path("var/appwindow"), env={"WINLAB_BROWSER": "tab"})
    finally:
        appwindow.webbrowser.open = real
    check("WINLAB_BROWSER=tab keeps the old browser tab", how == "tab" and opened == ["http://127.0.0.1:8780/"])
    webui_src = Path("winlab/webui.py").read_text(encoding="utf-8")
    check("the GUI opens through the app window, never webbrowser directly",
          "appwindow.open_window(url" in webui_src and "webbrowser.open" not in webui_src)

    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    check("windows open in the middle of the screen", "Math.round((W-ww)/2)" in page and "function place(n)" in page)
    check("windows animate open, closed, minimised and maximised",
          "function animIn(" in page and "towardTaskbar(w,n)" in page and ".win.geom{transition" in page and "'closing'" in page)
    check("animations follow the setting and the system's reduced motion",
          "prefers-reduced-motion: reduce" in page and "body.nomotion *" in page and 'id="pref-motion"' in page)
    check("windows snap to the screen's halves and top", "function snapZone(" in page and 'id="snapzone"' in page)
    check("the taskbar search opens its own Search panel, not Start",
          'onclick="searchToggle(event)"' in page and 'id="search-q"' in page and "startToggle(event,true)" not in page)
    check("desktop icons and taskbar pins are arranged by dragging and remembered",
          "function appDragStart(" in page and "'winlabDesk'" in page and "'winlabPinned'" in page and 'id="marquee"' in page)
    check("right-click menus on the desktop, its icons and the taskbar",
          "function ctxMenu(" in page and "Pin to taskbar" in page and "Sort icons by name" in page)
    check("a dragged command is typed into a machine's window, Enter left to the user",
          'class="dragcmd"' in page and "conTypeText(c.rfb,text)" in page and "dropText(e)" in page)
    sounds = page.split("const SOUNDS={")[1].split("};")[0]
    check("sounds are synthesised in the page: no sound files at all",
          "createOscillator" in page and not re.search(r"\.(wav|mp3|ogg)\b", page) and "success:" in sounds and "fail:" in sounds)
    check("sounds have a switch in the tray and in Start", 'id="tray-sound"' in page and 'id="pref-sound"' in page)
    import re as _re
    symbols = set(_re.findall(r'<symbol id="ic-(\w+)"', page))
    check("every app has a full-colour icon of our own in the sprite",
          {"Machines", "Learn", "Topology", "Console", "Terminal", "winlab", "Viewer"} <= symbols
          and "<image" not in page.split('id="icon-sprite"')[1].split("</svg>")[0])
    check("transcript, certificate and printable map open inside the desktop",
          "openViewer('/transcript'" in page and "openViewer('/certificate" in page and "openViewer('/api/diagram'" in page
          and "window.open('/transcript" not in page)
    from winlab import drawio  # noqa: F401 - the diagram is diagrams.net's, served as a page and a file
    check("the printable map is a diagrams.net drawing with its .drawio download",
          'u.path == "/api/diagram.drawio"' in webui_src and "drawio.page(self.dash.plan)" in webui_src)
    os.environ.pop("WINLAB_BROWSER", None)


def test_workbench():
    """The network workbench: a network built from nothing (empty labs,
    empty ports, switches on or off the router, a canvas layout), Windows
    installed by hand from the evaluation DVD, and a running network changed
    live (livenet: pinned router ports, re-tagging, router interfaces, DHCP,
    ports hot-added in free slots, cables in and out over QMP)."""
    import json
    import os
    from winlab import editor, images, livenet, netplan, paths, schema, state, unattend, workbench
    from winlab.model import CUSTOM
    from winlab.providers.qemu import HOTPLUG_SLOTS, QemuProvider, check_isolation

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"))
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("My-Office")
            check("a new network is a lab file named in lower case", dest.name == "my-office.toml")
            lab = schema.load(dest)
            check("an empty workbench network is valid: no machines, no switches",
                  lab.workbench and lab.sandbox and not lab.nodes and not lab.networks)
            check("only the router is on its canvas", lab.layout == {"router": [440, 60]})
            try:
                editor.new_workbench("my-office")
                check("a second network of the same name is refused", False)
            except editor.EditError:
                check("a second network of the same name is refused", True)
            try:
                editor.new_workbench("9 bad name")
                check("a bad network name is refused", False)
            except editor.EditError:
                check("a bad network name is refused", True)

            # Windows installed by hand: the Setup DVD must be on this PC.
            try:
                images.hand_media("ws2025")
                check("no DVD imported: a hand install says what to import", False)
            except images.ImageError as exc:
                check("no DVD imported: a hand install says what to import", "Get Windows" in str(exc))
            paths.downloads_dir().mkdir(parents=True, exist_ok=True)
            for i in ("ws2025", "win11"):
                images.installer_path(i).write_bytes(b"\0" * 2048)
            check("Server Core is a Setup choice, not a separate hand install",
                  "ws2025" in images.HAND_INSTALL and "ws2025-core" not in images.HAND_INSTALL)

            editor.add_node(lab, "srv01", kind=CUSTOM, image="ws2025")
            editor.add_node(lab, "pc01", kind=CUSTOM, image="win11")
            srv = lab.nodes["srv01"]
            check("a machine arrives on the workbench with its port empty",
                  len(srv.nics) == 1 and not srv.nics[0].plugged and srv.nics[0].ip is None)
            check("a hand-installed server is a custom machine on the catalog DVD",
                  images.is_hand_install(srv) and not srv.roles and srv.memory_mb == 2048)
            editor.add_network(lab, "lan", cidr="192.168.10.0/24")
            editor.set_routed(lab, "lan", False)
            editor.cable(lab, "srv01", 0, "lan")
            check("a cable into an empty port of a hand-installed machine records DHCP",
                  srv.nics[0].network == "lan" and srv.nics[0].ip is None)
            editor.set_node(lab, "srv01", add_nic="-")
            check("a second network card arrives without a cable",
                  len(srv.nics) == 2 and not srv.nics[1].plugged)
            editor.set_layout(lab, {"srv01": [100, 300], "net:lan": [80, 200], "ghost": [1, 1]})
            editor.save(lab)
            text = dest.read_text(encoding="utf-8")
            check("the lab file keeps the workbench, the canvas and the empty ports",
                  "workbench = true" in text and "[layout]" in text and '"srv01" = [100, 300]' in text
                  and 'network = ""' in text and "routed = false" in text and "ghost" not in text)
            lab = schema.load(dest)
            check("it loads back the same", lab.layout["srv01"] == [100, 300]
                  and not lab.networks["lan"].routed and not lab.nodes["srv01"].nics[1].plugged)

            plan = netplan.compile_topology(lab, check_ports=False)
            check("every card is a router port, cabled or not", len(plan.ports) == 3 and len(plan.links) == 1)
            empty = [l for l in plan.ports if not l.plugged]
            check("an empty port sits alone in a VLAN of its own",
                  len({plan.vid_of(l) for l in empty}) == 2
                  and all(plan.vid_of(l) >= netplan.PARK_VID_BASE for l in empty))
            script = netplan.render_fabric_setup(plan)
            check("a switch off the router has no router interface and no DHCP",
                  "lan is not cabled to the router" in script and "192.168.10.1/24" not in script
                  and "dnsmasq" not in script)
            check("the empty ports are tagged on the router's switch too", "no cable" in script)

            prov = QemuProvider(plan, accel="tcg", display="none")
            rt = prov.build_node(lab.nodes["srv01"])
            check("a hand install boots the Setup DVD after its empty disk",
                  rt.install_iso == images.installer_path("ws2025")
                  and (rt.uefi_vars is not None or not paths.uefi_firmware()))
            check("both of its cards are in the machine, the empty one too",
                  sum(1 for a in rt.argv if a.startswith("e1000e,")) == 2)
            fab = prov.build_fabric()
            check("the router has free slots for ports added while it runs",
                  sum(1 for a in fab.argv if a.startswith("pcie-root-port")) == HOTPLUG_SLOTS)
            check("and stays isolated", not check_isolation(fab.argv) and not check_isolation(rt.argv))

            xml = unattend.setup_helper()
            check("the Windows 11 helper floppy only skips Setup's hardware checks",
                  "BypassTPMCheck" in xml and "LabConfig" in xml and "oobeSystem" not in xml
                  and "ProductKey" not in xml and "DiskConfiguration" not in xml)

            # ---- a running network, changed live
            fab_pid = os.getpid()
            st = state.new(lab.name, "tcg", "none", str(dest))
            st.nodes["fabric"] = state.NodeState(node_id="fabric", pid=fab_pid, qmp_port=4001)
            st.nodes["srv01"] = state.NodeState(node_id="srv01", pid=fab_pid, qmp_port=4002)
            state.save(st)
            check("no record: the router is not pinned", livenet.pinned_ports(lab.name) == {})
            boot = netplan.compile_topology(lab, check_ports=False)
            livenet.record(boot, fab_pid)
            check("the running router's ports are recorded", set(livenet.pinned_ports(lab.name)) ==
                  {"srv01:nic0", "srv01:nic1", "pc01:nic0"})

            calls, cmds = [], []

            class FakeQmp:
                def __init__(self, port, timeout=30):
                    self.port = port

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    pass

                def call(self, cmd, **kw):
                    calls.append((self.port, cmd, kw))

            def runner(cmd, timeout=60):
                cmds.append(cmd)
                return "eth9\n" if "/sys/class/net" in cmd else ""

            editor.set_routed(lab, "lan", True)
            lab.networks["lan"].dhcp = True
            editor.unplug(lab, "srv01", 0)
            editor.cable(lab, "srv01", 1, "lan")
            editor.add_node(lab, "pc02", kind=CUSTOM, image="win11")
            editor.cable(lab, "pc02", 0, "lan")
            editor.save(lab)
            lab = schema.load(dest)
            res = livenet.sync(lab, runner=runner, qmp=FakeQmp)
            script = "\n".join(cmds)
            check("the change goes into the running network", res["live"] and res["done"])
            check("the switch gets its router interface and DHCP live",
                  "ip addr replace 192.168.10.1/24" in script and "dhcp-range" in script)
            check("moved ports are re-tagged on the router's switch",
                  "bridge vlan add dev eth2 vid" in script and "pvid untagged" in script)
            hot = [c for c in calls if c[1] in ("netdev_add", "device_add")]
            nd = hot[0][2] if hot else {}
            # a socket or a stream port, by this PC's QEMU (test_cables_redial_and_router_restart)
            hp = nd.get("listen") or f"{nd.get('addr', {}).get('host')}:{nd.get('addr', {}).get('port')}"
            check("a new machine's port is added to the running router in a free slot",
                  [c[1] for c in hot] == ["netdev_add", "device_add"] and hp.startswith("127.0.0.1:")
                  and hot[1][2]["bus"] == "hp0" and hot[1][2]["mac"] == livenet.fabric_mac(int(hp.split(":")[1])))
            check("and is found on the router by its card's address", "eth9" in script and "/sys/class/net" in script)
            links = [c for c in calls if c[1] == "set_link"]
            check("the running machine's cables go out and in over QMP",
                  ("net0", False) in [(c[2]["name"], c[2]["up"]) for c in links]
                  and ("net1", True) in [(c[2]["name"], c[2]["up"]) for c in links])
            pins = livenet.pinned_ports(lab.name)
            check("the record follows the router", pins["pc02:nic0"]["iface"] == "eth9"
                  and not pins["srv01:nic0"]["plugged"])
            plan2 = netplan.compile_topology(lab, check_ports=False)
            check("later plans keep the running router's ports",
                  all(l.port == pins[l.label]["port"] and l.fabric_iface == pins[l.label]["iface"]
                      for l in plan2.ports))
            calls.clear(); cmds.clear()
            res = livenet.sync(lab, runner=runner, qmp=FakeQmp)
            check("nothing changed: nothing is sent", not res["done"] and not cmds and not calls)
            st = state.load(lab.name)
            st.nodes["fabric"].pid = 0
            state.save(st)
            check("a router that stopped pins nothing", livenet.pinned_ports(lab.name) == {}
                  and not livenet.sync(lab, runner=runner, qmp=FakeQmp)["live"])

            live = livenet.parse_live("#neigh\n192.168.10.57 dev lab0.100 lladdr 52:54:00:AA:BB:CC REACHABLE\n"
                                      "192.168.10.9 dev lab0.100  FAILED\n#leases\n1 52:54:00:11:22:33 192.168.10.60 pc *\n"
                                      "#fdb\n52:54:00:aa:bb:cc dev eth1 master lab0\n")
            check("the router's tables give addresses by card",
                  live["ips"] == {"52:54:00:aa:bb:cc": ["192.168.10.57"], "52:54:00:11:22:33": ["192.168.10.60"]}
                  and live["seen"] == ["52:54:00:aa:bb:cc"])

            # ---- the window's backend
            class Dash:
                def __init__(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)

                def reload(self):
                    self.__init__()

            d = Dash()
            v = workbench.view(d)
            check("the canvas lists every machine with its ports and every switch",
                  {m["id"] for m in v["machines"]} == {"srv01", "pc01", "pc02"}
                  and all(m["pos"] for m in v["machines"]) and v["switches"][0]["routed"])
            r = workbench.act(d, "wb-add", {"shelf": "switch", "x": 500, "y": 200})
            check("a switch from the shelf stands alone until cabled to the router",
                  r["ok"] and not d.lab.networks[r["id"]].routed and d.lab.layout["net:" + r["id"]] == [500, 200])
            r = workbench.act(d, "wb-add", {"shelf": "server", "how": "hand", "image": "ws2022"})
            check("a hand install without its DVD is refused at once", not r["ok"] and "DVD" in r["message"])
            r = workbench.act(d, "wb-add", {"shelf": "server", "how": "hand", "image": "ws2025", "x": 10, "y": 20})
            check("a server from the shelf is installed by hand by default",
                  r["ok"] and images.is_hand_install(d.lab.nodes[r["id"]]))
            sid = r["id"]
            r = workbench.act(d, "wb-cable", {"node": sid, "nic": 0, "network": "lan"})
            check("a cable from the canvas", r["ok"] and d.lab.nodes[sid].nics[0].network == "lan")
            r = workbench.act(d, "wb-parts", {"node": sid, "cpus": 4, "memory_mb": 6144, "add_disk_gb": 40,
                                              "add_nic": 1, "system_disk_gb": 128})
            n = d.lab.nodes[sid]
            check("parts fitted in the case reach the machine",
                  r["ok"] and n.cpus == 4 and n.memory_mb == 6144 and n.data_disks_gb == [40]
                  and len(n.nics) == 2 and n.vars.get("disk_gb") == 128)
            r = workbench.act(d, "wb-unplug", {"node": "router", "network": "lan"})
            check("the switch's uplink comes out of the router", r["ok"] and not d.lab.networks["lan"].routed
                  and not d.lab.networks["lan"].dhcp)
            r = workbench.act(d, "wb-rm", {"id": "net:lan"})
            check("a switch with cables in it is not removed", not r["ok"])
            folder = td / "apps"
            folder.mkdir()
            (folder / "setup.exe").write_bytes(b"MZ" + b"\0" * 100)
            r = workbench.act(d, "wb-burn", {"node": sid, "folder": str(folder)})
            check("a folder of the user's own apps is burned to a disc for the machine",
                  r["ok"] and workbench.disc_path(d.lab.name, sid).stat().st_size > 32768)
            r = workbench.act(d, "wb-new", {"name": "second"})
            check("a new network from the window", r["ok"] and r["lab"] == "second")
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]

    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    check("the workbench is the first app on the desktop and the taskbar",
          "const PINNED=['Workbench'" in page and "DESKTOP=['Workbench'" in page)
    check("the workbench draws its own devices", all(f'<symbol id="dv-{k}"' in page for k in
                                                     ("server", "pc", "switch", "router", "firewall")))
    check("cables, parts and power have their own sounds",
          all(f"{k}:[[" in page for k in ("plug", "unplug", "seat", "power")))
    check("the welcome card offers building a network from nothing", "welcomeWorkbench()" in page)


def test_hands_on_desktop():
    """Ron's rule: the app only connects things (power, cables, media, screens,
    grading); every setting is made by the student inside the machine. No
    button in the desktop configures a machine, and windows that repeated
    each other are merged."""
    import re
    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    check("no button applies roles to a machine",
          "applyRolesFor" not in page and "Apply roles" not in page and "Configure (apply roles)" not in page
          and "job:'roles'" not in page and 'data-win="Roles"' not in page)
    check("no command runs behind a machine's screen",
          "do:'exec'" not in page and "lesson-verify" not in page and 'id="exec-cmd"' not in page)
    check("a lesson's command is typed on the machine's own screen",
          "function typeInto(" in page and "Type it on" in page and "conTypeText(c.rfb,text)" in page)
    check("a problem is never fixed for you: Give up puts it back as given up",
          "Fix for me" not in page and ">Give up</button>" in page and "do:'guest-fault-hint',scenario:id}" in page)
    check("break a machine, break the network and the helpdesk shift share one window",
          all(f'data-tt="{t}"' in page for t in ("machine", "network", "shift"))
          and 'data-win="Faults"' not in page and 'data-win="OnCall"' not in page and 'data-win="Exercises"' not in page)
    desk = re.findall(r"DESKTOP=\[([^\]]*)\]", page)[0]
    check("nine windows or fewer on the desktop, the workbench first",
          desk.count("'") // 2 <= 9 and desk.startswith("'Workbench'"), desk)
    check("Settings holds start-up, memory profile, sounds and the license, without a server field",
          'data-win="Settings"' in page and 'id="autostart"' in page and 'id="lic-key"' in page and 'id="lic-server"' not in page)
    check("power lives behind the Start menu's power button", "function powerMenu(" in page and "Shut down the lab" in page)
    check("the tray shows no web-style chips", 'id="tray-lesson"' not in page and "no acceleration" not in page)
    check("the Lab guide opens on this lab's lessons", "localStorage.getItem('winlabLessonsHere')!=='0'" in page)
    help_txt = page.split('<h2>Quick start</h2>')[1].split('<h2>What each window does</h2>')[0]
    check("Help speaks to a buyer, not about plumbing",
          "QMP" not in help_txt and "serial agent" not in help_txt and "winlab never sets anything up for you" in help_txt)




def test_real_boot():
    """A machine's firmware, as on a PC: restarting it with Esc held opens
    its setup, and the router's DHCP pool tells a machine booting from the
    network where to fetch its boot file (next-server, bootfile)."""
    import time
    from winlab import orchestrator, qmp, netplan, schema
    calls = []

    class FakeQmp:
        def __init__(self, port, timeout=30.0):
            calls.append(("port", port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            calls.append(("closed",))

        def call(self, command, **args):
            calls.append((command, args))

    saved = qmp.Qmp
    qmp.Qmp = FakeQmp
    try:
        err = orchestrator.firmware_setup(5555, seconds=0.1, pause=0.01)
        for _ in range(500):
            if ("closed",) in calls:
                break
            time.sleep(0.005)
    finally:
        qmp.Qmp = saved
    names = [c[0] for c in calls]
    check("firmware setup restarts the machine, then holds Esc", not err and names[1] == "system_reset"
          and names.count("send-key") >= 3
          and calls[2][1] == {"keys": [{"type": "qcode", "data": "esc"}]}, str(calls[:4]))
    check("the monitor is let go when the key is up", names[-1] == "closed")

    lab = schema.load("ad-ds-basics")
    net = next(n for n in lab.networks.values() if n.routed)
    net.dhcp = True
    lab.devices["router"] = {f"next:{net.id}": "10.10.10.5", f"file:{net.id}": "boot\\x64\\wdsnbp.com"}
    text = "\n".join(netplan._render_dhcp(netplan.compile_topology(lab, check_ports=False)))
    check("the router's DHCP hands out the PXE server and boot file (siaddr, file, options 66/67)",
          "dhcp-boot=tag:" in text and ",boot\\x64\\wdsnbp.com,,10.10.10.5'" in text
          and ",66,10.10.10.5'" in text and ",67,boot\\x64\\wdsnbp.com'" in text, text[-500:])
    check("a backslash in the file name is not a printf escape", "printf '%s\\n' 'dhcp-boot" in text)

    # A machine's screen window: every toolbar button the code touches is in
    # its template (a missing one stopped the screen from connecting).
    page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    body = page[page.index("function conButtons("):]
    body = body[:body.index("\n}")]
    tpl = page[page.index('<template id="vmc-tpl">'):page.index("</template>", page.index('<template id="vmc-tpl">'))]
    used = set(re.findall(r"q\('\.(con-[a-z-]+)'\)", body))
    check("the screen window's buttons all exist", used and all(f'class="{c}"' in tpl for c in used),
          str(sorted(c for c in used if f'class="{c}"' not in tpl)))
    check("a machine's screen pops out into its own window for another monitor",
          "?screen='+encodeURIComponent(node)" in page and "body.solo .win.solo-win" in page
          and "const SOLO=" in page[:page.index("function conPopOut")])
    check("full screen is the monitor's, with the keys kept for the machine, on any monitor",
          "requestFullscreen(screen?{screen}:{})" in page and "navigator.keyboard.lock()" in page
          and "getScreenDetails()" in page)


def test_switch_trunks():
    """Several switches on one network: a switch's uplink cabled into another
    switch is a trunk, each VLAN number on both is one segment, the router
    reaches it through the switch at the top, and loops are refused."""
    import os
    from winlab import devcli, editor, images, livenet, netplan, paths, schema, workbench
    from winlab.model import CUSTOM

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("trunk-lab")
            lab = schema.load(dest)
            paths.downloads_dir().mkdir(parents=True, exist_ok=True)
            images.installer_path("win11").write_bytes(b"\0" * 2048)
            editor.add_network(lab, "core", cidr="192.168.10.0/24")
            editor.add_network(lab, "edge", cidr="192.168.20.0/24")
            editor.add_network(lab, "far", cidr="192.168.30.0/24")
            for sw in ("edge", "far"):
                editor.set_routed(lab, sw, False)
            for nid, net in (("pc01", "core"), ("pc02", "edge"), ("pc03", "far")):
                editor.add_node(lab, nid, kind=CUSTOM, image="win11")
                editor.cable(lab, nid, 0, net)
            editor.save(lab)

            class Dash:
                def __init__(self):
                    self.reload()

                def reload(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)

            workbench._running = lambda _name: {"fabric"}  # the router (and so the switches) on
            d = Dash()
            act = lambda a, **p: workbench.act(d, a, p)
            link = lambda node: d.plan.ports_for(node)[0]

            r = act("wb-cable", node="switch", network="edge", to="core")
            check("a switch's uplink goes into another switch", r["ok"] and "Gi0/2" in r["message"],
                  r["message"])
            check("the lab file says where the uplink goes", schema.load(dest).networks["edge"].upstream == "core")
            check("the switch below is part of the network above",
                  d.plan.joined == {"edge": "core"} and "edge" not in d.plan.segments
                  and d.plan.vid_of(link("pc02")) == d.plan.vid_of(link("pc01")))
            core = d.plan.segment_of("core")
            check("its machines are on the segment the router serves",
                  {l.node_id for l in core.members} == {"pc01", "pc02"} and core.network.routed)
            check("the routed one's address plan is the one they get",
                  d.plan.segment_of("edge").network.cidr == "192.168.10.0/24")
            r = act("wb-cable", node="switch", network="core", to="edge")
            check("a cable that makes a loop is refused", not r["ok"] and "loop" in r["message"], r["message"])
            r = act("wb-cable", node="switch", network="far", to="edge")
            check("switches chain: one below the one below",
                  r["ok"] and d.plan.joined.get("far") == "core"
                  and d.plan.vid_of(link("pc03")) == d.plan.vid_of(link("pc01")))
            check("a switch cannot hang below itself",
                  not act("wb-cable", node="switch", network="far", to="far")["ok"])

            sw = lambda dev: devcli.Console(d, dev, runner_factory=lambda: (lambda *a, **k: "", ""))
            core_c, edge_c = sw("sw:core"), sw("sw:edge")
            for c in (core_c, edge_c):
                c.run("en")
            out = core_c.run("show interfaces trunk")
            check("the switch above shows its trunks: to the router and down",
                  "Gi0/1" in out and "Gi0/2" in out and "trunking" in out, out)
            out = edge_c.run("show cdp neighbors")
            from winlab import lldp as _lldp
            gis = [p.name for p in _lldp.ports(d.lab, d.plan, "sw:edge") if p.name.startswith("Gig") and p.iface]
            check("CDP on the switch below runs on its cables up and down (lldpd's table, read on the router)",
                  "Device ID" in out and len(gis) >= 2, (out, gis))
            out = edge_c.run("show interfaces status")
            check("its gigabit ports say where they go", "Gi0/1" in out and "core" in out, out)
            run = edge_c.run("show running-config")
            check("its config shows the trunks", "uplink to core" in run and "description to far" in run, run)

            edge_c.run("conf t")
            edge_c.run("vlan 20")
            edge_c.run("exit")
            edge_c.run("int fa0/1")
            edge_c.run("switchport access vlan 20")
            d.reload()
            v20 = devcli.vlan_net(d.lab, "edge", 20)
            check("a VLAN only the switch below has stays its own",
                  v20 is not None and d.plan.segment_of(v20.id).network.id == v20.id)
            core_c.run("conf t")
            core_c.run("vlan 20")
            d.reload()
            c20 = devcli.vlan_net(d.lab, "core", 20)
            check("once the switch above has it too, it is one network over the trunk",
                  d.plan.joined.get(v20.id) == c20.id
                  and d.plan.vid_of(link("pc02")) == d.plan.segment_of(c20.id).vid)

            r = sw("router")
            r.run("en")
            r.run("conf t")
            check("a switch whose uplink is in another switch has no port on the router",
                  "edge" not in dict((s, n) for n, s in devcli.router_ports(d.lab)))
            r.run("ip dhcp pool LAN")
            r.run("network 192.168.10.0 255.255.255.0")
            r.run("next-server 192.168.10.5")
            r.run("bootfile boot\\x64\\wdsnbp.com")
            bad = r.run("bootfile it's")
            r.run("end")
            run = r.run("show running-config")
            check("PXE in the router's DHCP pool: next-server and bootfile",
                  " next-server 192.168.10.5" in run and " bootfile boot\\x64\\wdsnbp.com" in run
                  and schema.load(dest).devices["router"]["next:core"] == "192.168.10.5", run)
            check("a boot file name that is not a path is refused", "boot file" in bad, bad)
            check("show ip dhcp pool lists the pool as IOS does", "Pool LAN :" in r.run("show ip dhcp pool"))

            pins = {"routed": {"gone-lan": True}, "vids": {"gone-lan": 1777}}
            check("a routed segment that is gone is taken off the running router",
                  livenet.changes(d.plan, pins)["gone"] == [("gone-lan", 1777)])

            bad = schema.load(dest)
            bad.networks["core"].upstream = "far"
            bad.networks["core"].routed = False
            try:
                schema.validate(bad)
                looped = False
            except Exception as exc:
                looped = "loop" in str(exc)
            check("the lab file refuses switches cabled in a loop", looped)

            r = act("wb-unplug", node="switch", network="edge")
            check("pulling the trunk out leaves the switch on its own",
                  r["ok"] and "edge" in d.plan.segments
                  and d.plan.vid_of(link("pc02")) != d.plan.vid_of(link("pc01"))
                  and d.plan.joined.get("far") == "edge")
            r = act("wb-cable", node="switch", network="far", to="core")
            r = act("wb-rm", id="net:core")
            check("a switch with machines cannot go", not r["ok"])
            act("wb-unplug", node="pc01", nic=0)
            r = act("wb-rm", id="net:core")
            check("removing the switch above frees the switches below",
                  r["ok"] and not d.lab.networks["far"].upstream, r["message"])
            view = workbench.view(d)
            check("the canvas gets each switch's uplink and network",
                  all("upstream" in s and "segment" in s for s in view["switches"]))
        finally:
            (paths.VAR, paths.STATE, paths.LABS, img, workbench._running) = saved
            if img is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = img


def test_device_consoles():
    """The consoles of the router and the switches (devcli): IOS-style
    words that may be cut short, modes, help, and configuration that changes
    the real network; and the packets the router captured, played back on
    the canvas's cables."""
    import os
    from winlab import devcli, editor, images, livenet, netplan, paths, schema, workbench
    from winlab.model import CUSTOM

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("cli-lab")
            lab = schema.load(dest)
            paths.downloads_dir().mkdir(parents=True, exist_ok=True)
            images.installer_path("win11").write_bytes(b"\0" * 2048)
            editor.add_network(lab, "lan", cidr="192.168.10.0/24")
            editor.add_network(lab, "dmz", cidr="192.168.20.0/24")
            editor.set_routed(lab, "dmz", False)
            for nid, x in (("pc01", 300), ("pc02", 100)):
                editor.add_node(lab, nid, kind=CUSTOM, image="win11")
                editor.cable(lab, nid, 0, "lan")
                lab.layout[nid] = [x, 400]
            editor.save(lab)

            class Dash:
                def __init__(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
                    self.wb_live = workbench.Live()

                def reload(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)

            up = {"fabric", "pc01", "pc02"}
            workbench._running = lambda _name: set(up)
            ran = []

            def runner_factory():
                def run(cmd, timeout=60):
                    ran.append(cmd)
                    if cmd.startswith("ping"):
                        return ("64 bytes from 192.168.10.57: seq=0 ttl=128 time=0.8 ms\n"
                                "64 bytes from 192.168.10.57: seq=1 ttl=128 time=1.2 ms\n"
                                "64 bytes from 192.168.10.57: seq=3 ttl=128 time=2.0 ms\n")
                    if "dnsmasq.leases" in cmd:
                        return "1793135597 52:54:00:aa:bb:cc 192.168.10.57 pc01 *\n"
                    return ""
                return run, ""

            d = Dash()
            links = []
            con = devcli.Console(d, "router", runner_factory=runner_factory,
                                 link=lambda l, on: links.append((l.label, on)))
            say = con.run
            check("the router's console starts in user mode", con.prompt() == "Router>")
            say("en")
            check("enable, cut short, gives the privileged prompt", con.prompt() == "Router#")
            out = say("c")
            check("a word that fits two commands is ambiguous", "Ambiguous" in out)
            say("conf t")
            check("configure terminal, cut short", con.prompt() == "Router(config)#")
            out = say("sh ip int br")
            check("a show in configuration mode is refused with a marker under the word",
                  "Invalid input" in out and "^" in out)
            check("do runs it from there", "192.168.10.1" in say("do sh ip int br"))
            say("hostname R1")
            check("hostname renames the prompt and lands in the lab file",
                  con.prompt() == "R1(config)#" and schema.load(dest).devices["router"]["hostname"] == "R1")
            check("a bad hostname is refused", "illegal" in say("hostname 9bad"))
            ports = devcli.router_ports(d.lab)
            check("the router is an ISR's two onboard ports; a lab from before keeps its routed switch on one",
                  ports == [("GigabitEthernet0/0/0", "lan"), ("GigabitEthernet0/0/1", "")])
            say("int g0/0/0")
            check("interface, cut short", con.prompt() == "R1(config-if)#" and con.s.ctx == "GigabitEthernet0/0/0")
            say("ip address 10.1.1.254 255.255.255.0")
            net = d.lab.networks["lan"]
            check("an interface address is the router's address on that switch",
                  net.cidr == "10.1.1.0/24" and net.router_ip == "10.1.1.254")
            check("an address that overlaps another switch is refused",
                  "overlaps" in say("ip address 192.168.20.1 255.255.255.0"))
            say("description office floor")
            check("a description is kept with the router's port",
                  d.lab.devices["router"]["desc:GigabitEthernet0/0/0"] == "office floor")
            say("shut")
            check("shutdown takes the switch off the router", not d.lab.networks["lan"].routed)
            check("show ip interface brief tells it",
                  "administratively down" in say("do show ip interface brief").splitlines()[1])
            say("no shut")
            check("no shutdown routes it again", d.lab.networks["lan"].routed)
            say("exit")
            say("ip dhcp pool OFFICE")
            check("a DHCP pool has its own mode", con.prompt() == "R1(dhcp-config)#")
            say("network 172.16.0.0 255.255.0.0")
            check("a pool for a subnet the router is not on is kept and hands out nothing, as on IOS",
                  "pool:OFFICE" not in d.lab.devices["router"] and not d.lab.networks["lan"].dhcp)
            say("network 10.1.1.0 255.255.255.0")
            check("a pool's network makes the router hand out addresses there",
                  d.lab.networks["lan"].dhcp and d.lab.devices["router"]["pool:OFFICE"] == "lan")
            say("default-router 10.1.1.254")
            check("default-router is what the pool hands out as the gateway",
                  d.lab.devices["router"]["poolgw:OFFICE"] == "10.1.1.254")
            say("end")
            run_cfg = say("show run")
            check("show running-config is the device's configuration",
                  "hostname R1" in run_cfg and "ip dhcp pool OFFICE" in run_cfg
                  and " ip address 10.1.1.254 255.255.255.0" in run_cfg and "description office floor" in run_cfg)
            check("the help lists what may come next", "running-config" in say("show ?")
                  and "interface" in say("show ip ?"))
            check("Tab finishes a word", con.complete("sh") == "show " and con.complete("show run") == "show running-config ")
            out = say("ping 192.168.10.57")
            check("ping runs on the router and reads like a router's",
                  ran[-1].startswith("ping -c 5") and "!!.!." in out and "60 percent (3/5)" in out)
            check("ping wants an address", "Unrecognized host" in say("ping fileserver"))
            out = say("show ip dhcp binding")
            check("the DHCP bindings come from the router's leases", "192.168.10.57" in out and "5254.00aa.bbcc" in out)
            say("conf t")
            say("no ip dhcp pool OFFICE")
            check("no ip dhcp pool stops handing out addresses", not d.lab.networks["lan"].dhcp)
            say("end")
            check("an incomplete command says so", "Incomplete" in say("show ip"))

            # a switch
            sw = devcli.Console(d, "sw:lan", runner_factory=runner_factory,
                                link=lambda l, on: links.append((l.label, on)))
            check("a new switch's prompt is Switch, as out of the box", sw.prompt() == "Switch>")
            order = devcli.switch_ports(d.lab, d.plan)["lan"]
            check("switch ports follow the machines from left to right on the canvas",
                  [l.node_id for l in order] == ["pc02", "pc01"])
            status = sw.run("show interfaces status")
            check("show interfaces status lists each machine on its port",
                  "Fa0/1" in status and "pc02" in status.splitlines()[1].lower() and "connected" in status.splitlines()[1])
            sw.run("enable")
            sw.run("configure terminal")
            sw.run("interface fa0/2")
            out = sw.run("shutdown")
            check("shutting a switch port drops the link of the machine in it",
                  "administratively down" in out and links[-1] == ("pc01:nic0", False)
                  and devcli.held_down(schema.load(dest), d.plan.ports_for("pc01")[0]))
            sw.run("no shutdown")
            check("and no shutdown brings it back", links[-1] == ("pc01:nic0", True)
                  and not devcli.held_down(schema.load(dest), d.plan.ports_for("pc01")[0]))
            # VLANs made on the switch's own console, routed by sub-interfaces
            sw.run("exit")
            sw.run("vlan 20")
            sw.run("name accounting")
            v20 = d.lab.networks.get("lan-v20")
            check("vlan makes a VLAN on this switch, kept in the lab file",
                  v20 is not None and v20.switch == "lan" and v20.tag == 20 and not v20.routed
                  and schema.load(dest).networks["lan-v20"].description == "accounting"
                  and sw.prompt() == "Switch(config-vlan)#")
            sw.run("int fa0/2")
            sw.run("switchport mode access")
            sw.run("switchport access vlan 20")
            check("switchport access vlan moves the machine's port into that VLAN",
                  d.lab.nodes["pc01"].nics[0].network == "lan-v20")
            out = sw.run("switchport access vlan 30")
            check("an access VLAN that does not exist is made, as on a real switch",
                  "Creating vlan 30" in out and d.lab.nodes["pc01"].nics[0].network == "lan-v30")
            sw.run("switchport access vlan 20")
            sw.run("switchport mode trunk")
            nic = d.lab.nodes["pc01"].nics[0]
            check("a machine's port can be a trunk: its switch's other VLANs go to it tagged by their numbers",
                  sorted(nic.trunk) == ["lan", "lan-v30"] and d.lab.networks["lan-v30"].vlan == 30)
            sw.run("switchport mode access")
            check("and back to an access port", not d.lab.nodes["pc01"].nics[0].trunk)
            vb = sw.run("do show vlan brief")
            check("show vlan brief lists each VLAN with its ports",
                  "20   accounting" in vb and "Fa0/2" in vb.split("20   accounting")[1].splitlines()[0]
                  and vb.splitlines()[2].startswith("1    default"))
            check("show interfaces trunk shows the uplink carrying them",
                  "1,20,30" in sw.run("do show interfaces trunk"))
            check("a VLAN with ports in it is not deleted", "move" in sw.run("no vlan 20"))
            sw.run("no vlan 30")
            check("an empty VLAN is deleted", "lan-v30" not in d.lab.networks)
            sw.run("int fa0/2")
            sw.run("shutdown")
            check("a port in a VLAN is shut down like any other",
                  devcli.held_down(schema.load(dest), netplan.compile_topology(schema.load(dest), check_ports=False)
                                   .ports_for("pc01")[0]))
            sw.run("no shutdown")
            say("conf t")
            say("int g0/0/0.20")
            check("a sub-interface has its own mode", con.prompt() == "R1(config-subif)#")
            check("it needs its VLAN first", "encapsulation" in say("ip address 10.20.0.1 255.255.255.0"))
            say("encapsulation dot1Q 99")
            check("a VLAN the switch does not have yet: the sub-interface waits for it",
                  "not on the switch" in say("ip address 10.99.0.1 255.255.255.0"))
            say("encapsulation dot1Q 20")
            say("ip address 10.20.0.1 255.255.255.0")
            v20 = d.lab.networks["lan-v20"]
            check("the sub-interface routes the switch's VLAN",
                  v20.routed and v20.cidr == "10.20.0.0/24" and v20.router_ip == "10.20.0.1")
            brief = say("do show ip interface brief")
            check("show ip interface brief lists the sub-interface",
                  any(l.startswith("GigabitEthernet0/0/0.20") and "10.20.0.1" in l and l.endswith("up")
                      for l in brief.splitlines()))
            cfg = say("do show running-config")
            check("show running-config has it", "interface GigabitEthernet0/0/0.20\n encapsulation dot1Q 20\n"
                                                " ip address 10.20.0.1 255.255.255.0" in cfg)
            say("exit")
            say("int g0/0/0")
            say("shutdown")
            check("shutting the physical port takes every VLAN of the switch off the router",
                  not d.lab.networks["lan"].routed and not d.lab.networks["lan-v20"].routed)
            say("no shutdown")
            check("and no shutdown brings them back", d.lab.networks["lan"].routed and d.lab.networks["lan-v20"].routed)
            say("exit")
            say("no interface g0/0/0.20")
            check("no interface removes the sub-interface", not d.lab.networks["lan-v20"].routed)
            say("end")
            check("the canvas keeps one box per switch", [s["id"] for s in workbench.view(d)["switches"]
                                                          if not s["switch"]] == ["dmz", "lan"])
            check("a switch with no management address pings nothing", "0 percent" in sw.run("do ping 10.1.1.9"))
            check("vlan brief shows the switch's own VLAN", "1    default" in sw.run("do show vlan brief"))

            up.discard("fabric")
            check("a device that is off has a dark console", con.run("show version") == ""
                  and workbench.cli(d, "router")["off"])
            up.add("fabric")
            r = workbench.act(d, "wb-cli", {"device": "router", "line": "show ip route"})
            check("the desktop reaches the console as an action", r["ok"] and "C        10.1.1.0/24" in r["out"], r["out"])
            check("a device with no console is refused",
                  not workbench.act(d, "wb-cli", {"device": "sw:nope", "line": "en"})["ok"])

            v = workbench.view(d)
            check("the canvas has the device names and the router's ports",
                  v["router"]["name"] == "R1" and v["router"]["ports"][0] == {"name": "Gi0/0/0", "network": "lan", "up": True}
                  and {p["slot"] for m in v["machines"] for p in m["ports"]} == {0, 1})

            # packets
            plan = d.plan
            l1, l2 = plan.ports_for("pc01")[0], plan.ports_for("pc02")[0]
            l1.fabric_iface, l2.fabric_iface = "eth1", "eth2"
            svi = plan.segments["lan"].svi
            text = ("#pkts\n"
                    f"1793135597.500000 eth2  In  ARP, Request who-has 10.1.1.254 tell 10.1.1.7, length 28\n"
                    f"1793135597.500100 {svi}  In  ARP, Request who-has 10.1.1.254 tell 10.1.1.7, length 28\n"
                    f"1793135597.500200 eth1  Out IP 10.1.1.7.49720 > 10.1.1.8.445: Flags [P.], length 90\n"
                    f"1793135597.600000 eth0  In  IP 1.2.3.4 > 1.2.3.5: ICMP echo request\n"
                    "garbage line\n")
            pk = livenet.parse_packets(text, plan)
            check("captured frames become hops on the canvas's cables",
                  [(p["at"], p["id"], p["dir"], p["proto"]) for p in pk] ==
                  [("port", "pc02:nic0", "in", "ARP"), ("svi", "lan", "in", "ARP"),
                   ("port", "pc01:nic0", "out", "SMB")] and pk[2]["t"] == 0)
            check("the router's own management card is not part of the lab", len(pk) == 3)
            check("the capture is short and leaves the router's tables alone",
                  livenet.capture_cmd().count("timeout 2 tcpdump -i any") == 1)
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            workbench._running = saved[4]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]








def test_physical_faults():
    """Faults of the cables and cards of a running workbench network: broken
    on purpose from the canvas (a dead card over QMP, a bad cable, a flapping
    link, a 10 Mbit port, a duplex mismatch, a cable in the wrong VLAN's port
    on the router's switch, a full disk inside the machine), shown, listed and
    undone; and "Break something for me", which hides 1-3 of them, mended the
    way one mends a real network (the cable reseated or replaced, the port
    set back to auto), proved gone by "Check my fix" and revealed, with a
    hint ladder. Kept beside the machines, never in the lab file."""
    import contextlib
    import io
    import os
    import random
    import re
    from types import SimpleNamespace
    from winlab import cli, devcli, editor, livenet, netplan, paths, physfaults, schema, state, workbench

    saved = (paths.VAR, paths.STATE, paths.LABS, physfaults.fabric_runner, physfaults.qmp_class,
             physfaults.guest_channel)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        try:
            dest = editor.new_workbench("fault-bench")

            class _Dash:
                pass
            dash = _Dash()
            dash.reload = lambda: (setattr(dash, "lab", schema.load(dest)),
                                   setattr(dash, "plan", netplan.compile_topology(dash.lab, check_ports=False)))
            dash.reload()

            def act(what, **p):
                return workbench.act(dash, what, p)
            act("wb-add", shelf="switch", id="office", x=100, y=300)
            act("wb-add", shelf="switch", id="lab", x=600, y=300)
            for sw in ("office", "lab"):
                act("wb-cable", node="router", network=sw)
                _route_router(dash, sw)  # the student sets up the router's port
                act("wb-switch", network=sw, dhcp=True)
            for i, (nid, sw) in enumerate((("pc01", "office"), ("pc02", "office"), ("srv01", "lab"))):
                act("wb-add", shelf="server" if nid == "srv01" else "pc", how="ready",
                    image="ws2025" if nid == "srv01" else "win11", id=nid, x=60 + i * 150, y=500)
                act("wb-cable", node=nid, nic=0, network=sw)
            lab = dash.lab
            toml = dest.read_text(encoding="utf-8")
            check("a fault needs a running network", not act("wb-fault", op="add", kind="bad", node="pc01")["ok"])

            # A running network: the router and the machines are up.
            me = os.getpid()
            st = state.new(lab.name, "tcg", "none", str(dest))
            st.nodes["fabric"] = state.NodeState(node_id="fabric", pid=me, qmp_port=4001)
            for k, nid in enumerate(("pc01", "pc02", "srv01")):
                st.nodes[nid] = state.NodeState(node_id=nid, pid=me, qmp_port=4010 + k)
            state.save(st)
            plan = netplan.compile_topology(lab, check_ports=False)
            for n, link in enumerate(plan.ports, 1):
                link.fabric_iface = f"eth{n}"
            livenet.record(plan, me)
            iface = {link.label: f"eth{n}" for n, link in enumerate(plan.ports, 1)}
            vid = {link.label: plan.vid_of(link) for link in plan.ports}

            cmds, calls, guest = [], [], []
            router = {"tc": {}, "flap": set(), "vlan": {}}   # what the fake router's ports hold

            def run(cmd, timeout=60):
                cmds.append(cmd)
                for line in cmd.splitlines():
                    m = re.match(r"tc qdisc add dev (\S+) root (\w+)", line)
                    if m:
                        router["tc"][m.group(1)] = m.group(2)
                    m = re.match(r"tc qdisc del dev (\S+) root", line)
                    if m:
                        router["tc"].pop(m.group(1), None)
                    m = re.search(r"ip link set (\S+) down; sleep", line)
                    if m:
                        router["flap"].add(m.group(1))
                    m = re.match(r"rm -f /run/winlab-flap-(\S+)\.pid", line)
                    if m:
                        router["flap"].discard(m.group(1))
                    m = re.match(r"bridge vlan (add|del) dev (\S+) vid (\d+)", line)
                    if m:
                        have = router["vlan"].setdefault(m.group(2), {vid[k] for k, i in iface.items() if i == m.group(2)})
                        (have.add if m.group(1) == "add" else have.discard)(int(m.group(3)))
                out = []
                for m in re.finditer(r"echo '#(f\d+)'; echo '@tc'; tc qdisc show dev (\S+)", cmd):
                    fid, dev = m.groups()
                    vids = router["vlan"].get(dev, {vid[k] for k, i in iface.items() if i == dev})
                    out += [f"#{fid}", "@tc", f"qdisc {router['tc'][dev]} 8001: root" if dev in router["tc"]
                            else "qdisc noqueue 0: root", "@flap"] + (["FLAPPING"] if dev in router["flap"] else []) \
                        + ["@vlan", "port  vlan-id", f"{dev}  " + " ".join(str(v) for v in sorted(vids))]
                return "\n".join(out)

            class FakeQmp:
                def __init__(self, port, timeout=30):
                    self.port = port

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    pass

                def call(self, cmd, **kw):
                    calls.append((self.port, cmd, kw))

            class Chan:
                def run(self, cmd, shell="powershell", timeout=0):
                    guest.append((cmd, shell))
                    return SimpleNamespace(ok=True, out="", err="", rc=0)

                def close(self):
                    pass
            physfaults.fabric_runner = lambda name: (run, "")
            physfaults.qmp_class = FakeQmp
            physfaults.guest_channel = lambda name, node: Chan()

            # ---- broken on purpose, from the canvas
            r = act("wb-fault", op="add", kind="bad", node="pc01", nic=0)
            check("a bad cable: netem drops and corrupts towards the machine, a filter drops from it",
                  r["ok"] and f"tc qdisc add dev {iface['pc01:nic0']} root netem loss 8% 25% corrupt 2%" in cmds[-1]
                  and "action gact ok random netrand drop 12" in cmds[-1]
                  and f"tc qdisc add dev {iface['pc01:nic0']} handle ffff: ingress" in cmds[-1], r["message"])
            check("one fault per cable at a time", not act("wb-fault", op="add", kind="slow", node="pc01")["ok"])
            r = act("wb-fault", op="add", kind="nic", node="pc02", nic=0)
            check("a dead card: its link goes down over QMP",
                  r["ok"] and calls[-1] == (4011, "set_link", {"name": "net0", "up": False}), str(calls[-1:]))
            r = act("wb-fault", op="add", kind="flap", node="srv01")
            check("a flapping link: a loop on the router takes the port down and up, on its own fds",
                  r["ok"] and f"ip link set {iface['srv01:nic0']} down; sleep 4" in cmds[-1]
                  and "</dev/null >/dev/null 2>&1 &" in cmds[-1])
            r = act("wb-fault", op="add", kind="disk", node="srv01")
            check("a full disk is the guest scenario, inside the machine",
                  r["ok"] and "FULL_nightly_0300.bak" in guest[-1][0] and guest[-1][1] == "powershell", r["message"])
            v = workbench.view(dash)["faults"]
            check("the canvas lists every fault with its place",
                  [(f["kind"], f["link"] or f["node"]) for f in v["faults"]] ==
                  [("bad", "pc01:nic0"), ("nic", "pc02:nic0"), ("flap", "srv01:nic0"), ("disk", "srv01")]
                  and v["drill"] is None
                  and {k["id"] for k in v["kinds"]} >= {"nic", "bad", "flap", "slow", "duplex", "vlan", "disk"})
            check("nothing of it is in the lab file",
                  dest.read_text(encoding="utf-8") == toml and (paths.lab_dir(lab.name) / "faults.json").exists())
            con = devcli.Console(dash, "sw:office", runner_factory=lambda: (run, ""),
                                 link=lambda link, up: calls.append(("cli", link.label, up)))
            status = con._show_status([])
            check("the switch shows a dead card's port notconnect",
                  re.search(r"Fa0/2\s+pc02\s+notconnect", status, re.I), status)
            con._set_link(dash.plan.ports_for("pc02")[0], True)
            check("no shutdown on the switch does not bring a dead card back", ("cli", "pc02:nic0", True) not in calls)
            fid = {f["kind"]: f["id"] for f in v["faults"]}
            r = act("wb-fault", op="clear", id=fid["nic"])
            check("undo: the card comes back", r["ok"] and calls[-1] == (4011, "set_link", {"name": "net0", "up": True}))
            r = act("wb-fault", op="clear", id=fid["flap"])
            check("undo: the loop stops and the port is up",
                  r["ok"] and "kill $(cat /run/winlab-flap-" in cmds[-1] and f"ip link set {iface['srv01:nic0']} up" in cmds[-1])
            act("wb-fault", op="clear", id=fid["disk"])
            check("undo: the balloon file goes", "Remove-Item 'C:\\winlab\\balloon.bin'" in guest[-1][0])
            check("undo all", act("wb-fault", op="clear", id="all")["ok"] and not workbench.view(dash)["faults"]["faults"]
                  and f"tc qdisc del dev {iface['pc01:nic0']} root" in cmds[-1])
            r = act("wb-fault", op="add", kind="duplex", node="pc02")
            status = con._show_status([])
            check("a duplex mismatch: the port reads full / 100, hard-set",
                  r["ok"] and re.search(r"Fa0/2\s+pc02\s+connected\s+1\s+full\s+100 ", status, re.I), status)
            con.s.mode, con.s.ctx = "config-if", "FastEthernet0/2"
            out = con.run("duplex half")
            check("a duplex can be hard-set, as on a real port",
                  "changed state to up" in out and dash.lab.devices["sw:office"].get("duplex:pc02:nic0") == "half", out)
            out = con.run("duplex auto")
            check("duplex auto on the switch mends it", "changed state to up" in out
                  and not physfaults.active(lab.name, link="pc02:nic0"), out)
            r = act("wb-fault", op="add", kind="vlan", node="pc01")
            rec = physfaults.active(lab.name, link="pc01:nic0")[0]
            check("a cable in the wrong port: the router's port is moved to another switch's VLAN",
                  r["ok"] and rec["wrong"] == vid["srv01:nic0"]
                  and f"bridge vlan add dev {iface['pc01:nic0']} vid {vid['srv01:nic0']} pvid untagged" in cmds[-1])
            act("wb-fault", op="add", kind="slow", node="srv01")
            check("a 10 Mbit port: a token bucket and a policer", "tbf rate 10mbit" in cmds[-1] and "police rate 10mbit" in cmds[-1])
            check("the switch shows it at a-10", re.search(r"a-full a-10 ", devcli.Console(dash, "sw:lab")._show_status([])))
            # Pulling the cable out takes a cable fault with it (the user re-patches).
            act("wb-unplug", node="pc01", nic=0)
            check("pulling the cable out of the wrong port mends it",
                  not physfaults.active(lab.name, link="pc01:nic0")
                  and f"bridge vlan add dev {iface['pc01:nic0']} vid {vid['pc01:nic0']} pvid untagged" in "\n".join(cmds))
            act("wb-cable", node="pc01", nic=0, network="office")
            lab = dash.lab
            # A router restart takes its faults: lost, not fixed.
            st = state.load(lab.name)
            st.nodes["fabric"].pid = os.getppid()
            state.save(st)
            check("a fault the router took when it restarted is lost",
                  not physfaults.active(lab.name) and physfaults.load(lab.name)["faults"][-1]["state"] == "lost")
            st.nodes["fabric"].pid = me
            state.save(st)
            data = physfaults.load(lab.name)
            data["faults"] = []
            physfaults._write(lab.name, data)

            # ---- break something for me
            check("Check my fix with nothing hidden says so", not act("wb-drill", op="check")["ok"])
            r = physfaults.drill_start(lab, count=3, rng=random.Random(7))
            v = workbench.view(dash)["faults"]
            check("three faults hidden, none of them shown",
                  r["count"] == 3 and v["faults"] == [] and v["drill"]["total"] == 3 and v["drill"]["left"] == 3
                  and v["drill"]["revealed"] == [], r["message"])
            check("and not twice at once", not act("wb-drill", op="start")["ok"])
            check("nothing is broken on purpose while faults are hidden (it would give them away)",
                  not act("wb-fault", op="add", kind="bad", node="pc01")["ok"])
            hidden = physfaults._hidden(physfaults.load(lab.name))
            check("each on a different cable, of different kinds",
                  len({h["link"] for h in hidden}) == 3 and len({h["kind"] for h in hidden}) == 3,
                  str([(h["kind"], h["link"]) for h in hidden]))
            r = act("wb-drill", op="check")
            check("Check my fix before fixing anything: nothing fixed, nothing revealed",
                  r["ok"] and not r["fixed"] and r["left"] == 3 and r["revealed"] == [], r["message"])
            first = hidden[0]
            hints = [act("wb-drill", op="hint") for _ in range(4)]
            check("the hint ladder goes from where to look to the fix, for the first fault",
                  [h["n"] for h in hints] == [1, 2, 3, 3] and hints[0]["fault"] == 1
                  and "{" not in hints[1]["text"] + hints[2]["text"], hints[1]["text"])
            check("the later hints name the machine", first["node"] in hints[1]["text"].lower(), hints[1]["text"])
            # The user mends each the way it is mended.
            for h in hidden:
                net = lab.nodes[h["node"]].nics[0].network
                if physfaults.KINDS[h["kind"]].by == "console":
                    home = lab.networks[net].home
                    port = next(i for i, link in enumerate(devcli.switch_ports(lab, dash.plan)[home], 1)
                                if link.label == h["link"])
                    c = devcli.Console(dash, "sw:" + home, runner_factory=lambda: (run, ""), link=lambda link, up: None)
                    c.s.mode, c.s.ctx = "config-if", f"FastEthernet0/{port}"
                    c.run("duplex auto")
                else:
                    act("wb-unplug", node=h["node"], nic=0)
                    act("wb-cable", node=h["node"], nic=0, network=net)
                if h is hidden[0]:
                    r = act("wb-drill", op="check")
                    check("a check after one fix reveals that one only",
                          r["left"] == 2 and [x["id"] for x in r["revealed"]] == [h["id"]]
                          and r["revealed"][0]["title"] == physfaults.KINDS[h["kind"]].title, r["message"])
            lab = dash.lab
            check("the router's ports are clean again", not router["tc"] and not router["flap"], str(router))
            r = act("wb-drill", op="check")
            check("Check my fix: all three proved gone on the router, and each revealed",
                  r["fixed"] and r["left"] == 0 and len(r["revealed"]) == 3
                  and all(x["where"] and x["symptom"] for x in r["revealed"]), r["message"])
            v = workbench.view(dash)["faults"]["drill"]
            check("the drill's state is read back from the file (it survives the desktop restarting)",
                  v["done"] and v["checks"] == 3 and v["hints"] == 3 and v["touched"] >= 2, str(v))
            # A fault mended on the router some other way is caught.
            physfaults.drill_end(lab)
            physfaults.drill_start(lab, count=1, rng=random.Random(3))
            h = physfaults._hidden(physfaults.load(lab.name))[0]
            if physfaults.KINDS[h["kind"]].side == "router":
                router["tc"].clear()
                router["flap"].clear()
                router["vlan"].clear()
                r = physfaults.drill_check(lab)
                check("a fault gone from the router some other way counts as fixed", r["fixed"], r["message"])
            physfaults.drill_end(lab)
            physfaults.drill_start(lab, count=2, rng=random.Random(5))
            r = act("wb-drill", op="reveal")
            check("giving up shows what was broken and mends it",
                  r["ok"] and len(r["revealed"]) == 2 and not physfaults.active(lab.name))
            check("the drill hides only cabling faults", all(physfaults.KINDS[x["kind"]].drill for x in r["revealed"]))
            act("wb-drill", op="end")
            check("put away", workbench.view(dash)["faults"]["drill"] is None and not physfaults.load(lab.name)["faults"])
            seen = physfaults.parse_probe("#f9\n@tc\nqdisc noqueue 0: root\n@flap\n@vlan\nport vlan-id\n"
                                          "eth3 2001 PVID Egress Untagged\n")
            check("a probe of the router's port reads back",
                  not physfaults.still_there({"kind": "vlan", "wrong": 101}, seen["f9"])
                  and physfaults.still_there({"kind": "vlan", "wrong": 2001}, seen["f9"])
                  and not physfaults.still_there({"kind": "bad"}, seen["f9"]))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rcs = (cli.main(["fault", lab.name, "add", "bad", "pc01"]), cli.main(["fault", lab.name, "list"]),
                       cli.main(["fault", lab.name, "clear", "all"]))
            check("winlab fault add / list / clear", rcs == (0, 0, 0)
                  and "Bad cable" in buf.getvalue() and "1 undone" in buf.getvalue(), buf.getvalue())
        finally:
            (paths.VAR, paths.STATE, paths.LABS, physfaults.fabric_runner, physfaults.qmp_class,
             physfaults.guest_channel) = saved
    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    check("the canvas marks faults, the menus break things, the toolbar hides some",
          "function wbFaultLayer(" in page and "function wbFaultItems(" in page
          and "Break something for me" in page and "Check my fix" in page)






def test_media_shelf():
    """The media shelf: discs and USB sticks as things you hold. A disc goes
    into a drive and out with Eject (or Windows' own Eject), a stick into a
    USB port and back on the shelf with its files; live over QMP on a
    running machine, kept across a shutdown, and a disc in the drive boots
    when the DVD drive comes first in the boot order."""
    import contextlib
    import io
    import os
    from winlab import cli, editor, images, isowrite, mediashelf as ms, netplan, paths, schema, state, workbench
    from winlab.model import CUSTOM, WINDOWS_CLIENT
    from winlab.providers.qemu import QemuProvider, check_isolation

    calls: list[tuple[str, dict]] = []
    blocks: list[dict] = []

    class _FakeQmp:
        def __init__(self, port, timeout=30.0): self.port = port
        def __enter__(self): return self
        def __exit__(self, *a): return None
        def call(self, cmd, **args):
            calls.append((cmd, args))
            return blocks if cmd == "query-block" else {}

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"))
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("media-office")
            lab = schema.load(dest)
            editor.add_node(lab, "pc01", kind=CUSTOM, image="win11")
            editor.add_node(lab, "pc02", kind=WINDOWS_CLIENT, image="win11")
            editor.save(lab)
            lab = schema.load(dest)
            dl = paths.downloads_dir()
            dl.mkdir(parents=True)
            w = isowrite.IsoWriter("WS2025_EVAL")
            src = td / "src"
            src.mkdir()
            (src / "setup.exe").write_bytes(b"MZ" + b"\0" * 64)
            w.add_tree(src)
            w.write(images.installer_path("ws2025"))
            w.write(dl / "virtio-win.iso")
            discs = {d["ref"]: d for d in ms.discs(lab.name)}
            check("the shelf holds the Windows DVD and the driver ISO this PC has",
                  discs.get("image:ws2025", {}).get("kind") == "windows"
                  and any(d["kind"] == "drivers" and d["title"] == "WS2025_EVAL" for d in discs.values()), str(discs))
            r = ms.burn(lab.name, src, "my apps")
            check("a folder burned to a disc lands on the shelf, with its own label",
                  r["title"] == "MY_APPS" and r["ref"] in {d["ref"] for d in ms.discs(lab.name)}
                  and ms.volume_label(ms.resolve(r["ref"])) == "MY_APPS")
            try:
                ms.resolve(f"file:{td / 'elsewhere.iso'}")
                check("a disc outside winlab's folders is refused", False)
            except ms.ShelfError:
                check("a disc outside winlab's folders is refused", True)

            # Machine off: what goes in is there at power-on.
            node = lab.nodes["pc02"]
            r = ms.insert(lab, "pc02", "image:ws2025", qmp=_FakeQmp)
            c = ms.contents(lab.name, node)
            check("a disc in a stopped machine's drive waits for power-on",
                  not r["live"] and r["drive"] == 0 and c["drives"][0]["disc"]["ref"] == "image:ws2025" and not calls)
            plan = netplan.compile_topology(lab, check_ports=False)
            argv = QemuProvider(plan, accel="tcg").build_node(node).argv
            iso = images.installer_path("ws2025")
            check("the provider puts it in the drive", f"id=cdattach,file={iso},if=none,media=cdrom,readonly=on" in argv
                  and not any(a.endswith("drive=cdattach,bootindex=0") for a in argv))
            ms.set_boot(lab.name, node, ms.BOOT_DVD)
            argv = QemuProvider(plan, accel="tcg").build_node(node).argv
            check("DVD first in the boot order: the drive boots before the disk",
                  any(a.endswith("id=cdattach,drive=cdattach,bootindex=0") for a in argv)
                  and any("drive=sys,bootindex=1" in a for a in argv) and not check_isolation(argv))
            node.vars["iso"] = "ws2025"
            ms.eject(lab, "pc02", qmp=_FakeQmp)
            check("Eject empties the drive even when the definition keeps a disc in it",
                  ms.contents(lab.name, node)["drives"][0]["disc"] is None
                  and ms.provider_discs(lab.name, node, iso) == [None])
            node.vars["iso"] = "sql2022"
            check("a disc named anew in the definition wins again",
                  ms.contents(lab.name, node)["drives"][0]["disc"]["ref"] == "image:sql2022")
            node.vars.pop("iso")

            s1 = ms.new_blank(lab.name, 16)
            s2 = ms.new_from_folder(lab.name, src)
            check("new sticks lie on the shelf", {s["id"] for s in ms.sticks(lab.name)} == {s1["id"], s2["id"]}
                  and s2["files"] == 1)
            a = ms.plug(lab, "pc02", s1["id"], qmp=_FakeQmp)
            b = ms.plug(lab, "pc02", s2["id"], qmp=_FakeQmp)
            nd = paths.lab_dir(lab.name) / "pc02"
            check("sticks go into the first free USB ports and leave the shelf",
                  (a["port"], b["port"]) == (0, 1) and (nd / "stick.img").exists() and (nd / "stick1.img").exists()
                  and not ms.sticks(lab.name))
            argv = QemuProvider(plan, accel="tcg").build_node(node).argv
            check("both are in their ports at power-on", "usb-storage,bus=xhci.0,drive=wlstick,removable=on,id=wlstick" in argv
                  and f"id=wlstick1,file={nd / 'stick1.img'},if=none,format=raw" in argv)

            # Machine running: QMP.
            st = state.new(lab.name, "tcg", "none")
            st.nodes["pc02"] = state.NodeState("pc02", pid=os.getpid(), qmp_port=4444)
            state.save(st)
            (nd / "stick1.img").write_bytes((nd / "stick1.img").read_bytes()[:-5] + b"WROTE")
            r = ms.unplug(lab, "pc02", 1, qmp=_FakeQmp)
            back = ms.shelf_dir(lab.name, "sticks") / f"{r['id']}.img"
            check("a stick pulled out of a running machine comes out live and keeps what was written",
                  r["live"] and r["id"] == s2["id"] and [c[0] for c in calls] == ["device_del", "blockdev-del"]
                  and calls[0][1] == {"id": "wlstick1"} and back.read_bytes().endswith(b"WROTE"))
            calls.clear()
            r = ms.plug(lab, "pc02", s2["id"], 3, qmp=_FakeQmp)
            check("and goes into another port live",
                  r["live"] and r["port"] == 3 and calls[0][0] == "blockdev-add" and calls[1][0] == "device_add"
                  and calls[1][1]["id"] == "wlstick3" and calls[0][1]["file"]["filename"] == str(nd / "stick3.img"))
            calls.clear()
            r = ms.insert(lab, "pc02", "image:ws2025", qmp=_FakeQmp)
            check("a disc goes into the running machine's drive",
                  r["live"] and calls == [("blockdev-change-medium", {"id": "cdattach", "filename": str(iso), "format": "raw",
                                                                      "read-only-mode": "read-only"})])
            calls.clear()
            blocks[:] = [{"device": "cdattach", "tray_open": True, "inserted": {"file": str(iso)}}]
            check("Windows' own Eject is noticed: the disc is back on the shelf",
                  ms.sync(lab, node, qmp=_FakeQmp) and ms.contents(lab.name, node)["drives"][0]["disc"] is None
                  and ("blockdev-remove-medium", {"id": "cdattach"}) in calls)
            check("an empty drive stays as it is", not ms.sync(lab, node, qmp=_FakeQmp))
            st.nodes["pc02"].pid = 0
            state.save(st)

            # The workbench: the shelf, the machines' drives, the actions.
            class Dash:
                def __init__(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)

                def reload(self):
                    self.__init__()

            d = Dash()
            r = workbench.act(d, "wb-parts", {"node": "pc02", "dvd_drives": 2})
            check("a second DVD drive fitted in the case", r["ok"] and d.lab.nodes["pc02"].vars["dvd_drives"] == 2, r["message"])
            workbench.act(d, "wb-media", {"op": "insert", "node": "pc02", "disc": "image:ws2025"})
            r = workbench.act(d, "wb-media", {"op": "insert", "node": "pc02", "disc": ms.discs(lab.name)[-1]["ref"]})
            v = workbench.view(d)
            m = next(x for x in v["machines"] if x["id"] == "pc02")
            check("a disc dropped on a machine with a full drive goes into its empty one",
                  r["ok"] and [x["disc"]["ref"].split(":")[0] if x["disc"] else None for x in m["media"]["drives"]] == ["image", "file"])
            check("the canvas sees the drives, the ports and the shelf",
                  m["media"]["ports"][0]["stick"]["title"] == "16 GB stick" and m["media"]["boot"] == "dvd"
                  and "image:ws2025" in {x["ref"] for x in v["media_shelf"]["discs"]}
                  and next(x for x in v["media_shelf"]["discs"] if x["ref"] == "image:ws2025")["in"] == ["pc02"])
            argv = QemuProvider(d.plan, accel="tcg").build_node(d.lab.nodes["pc02"]).argv
            check("the second drive is on the SATA controller with its disc",
                  any(a.startswith("id=cdattach1,if=none,media=cdrom,file=") for a in argv)
                  and any(a.endswith("id=cdattach1,drive=cdattach1") for a in argv))
            r = workbench.act(d, "wb-media", {"op": "plug", "node": "pc01", "stick": "nope"})
            check("a stick that is not on the shelf is refused", not r["ok"])
            r = workbench.act(d, "wb-media", {"op": "state", "node": "pc02"})
            check("the screen window reads the machine's media", r["ok"] and len(r["drives"]) == 2 and len(r["ports"]) == 4)

            # The command line.
            p = cli.build_parser()
            a = p.parse_args(["media", lab.name, "pc02", "insert", "ws2025", "--drive", "2"])
            b = p.parse_args(["media", lab.name, "pc02", "boot", "disk"])
            check("winlab media insert --drive / boot", a.drive == 2 and a.image == "ws2025" and b.first == "disk")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rcs = (cli.main(["media", lab.name, "pc02", "eject", "--drive", "2"]),
                       cli.main(["media", lab.name, "pc02", "unplug", "--port", "1"]),
                       cli.main(["media", lab.name, "pc01", "plug", s1["id"]]),
                       cli.main(["media", lab.name, "pc02", "list"]))
            out = buf.getvalue()
            check("winlab media eject / unplug / plug / list", rcs == (0, 0, 0, 0) and "back on the shelf" in out
                  and "16 GB stick is in USB port 1" in out and "DVD drive 2: empty" in out
                  and "DVD drive 1: Windows Server 2025" in out, out)
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]
    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    check("the media drawer, its drag onto machines and the screen window's Media menu",
          all(f in page for f in ("function mdDrawer(", "function mdDown(", "function mdTarget(", "function conMedia(",
                                  "function conMediaMenu(", 'id="wb-md"', "out.push(mdBadges(m,b))")))












def test_perf_meters():
    """Live meters and alerts, measured from the host only (winlab/perfmon.py)."""
    import os
    from winlab import editor, netplan, paths, perfmon, physfaults, procstats, schema, state, workbench, webui

    text = ("#ifstat\neth1 1000 2000 0 0 0 0 up\neth2 50 60 1 0 0 2 down\nlab0.10 10 20 0 0 0 0 up\n"
            "#qdisc\nqdisc netem 8001: dev eth1 root refcnt 2 limit 1000 loss 8%\n"
            " Sent 2000 bytes 20 pkt (dropped 3, overlimits 0 requeues 0)\n"
            "qdisc ingress ffff: dev eth1 parent ffff:fff1 ----------------\n"
            " Sent 1000 bytes 10 pkt (dropped 4, overlimits 0 requeues 0)\n")
    c = perfmon.parse_counters(text)
    check("the router's port counters: bytes each way, errors, and drops with the qdiscs' (a bad cable's netem, its policer)",
          c["eth1"] == {"rx": 1000, "tx": 2000, "errors": 0, "drops": 7, "up": True}
          and c["eth2"]["errors"] == 1 and c["eth2"]["drops"] == 2 and not c["eth2"]["up"], str(c))
    check("the counters ride on the workbench's one live read of the router (no extra trip)",
          perfmon.COUNTERS_CMD in Path(workbench.__file__).read_text(encoding="utf-8")
          or "perfmon.COUNTERS_CMD" in Path(workbench.__file__).read_text(encoding="utf-8"))
    import time as _time
    live = workbench.Live()
    out = live.read(type("L", (), {"name": "x"})(),
                    runner_factory=lambda: ((lambda cmd, timeout=20: text if "#ifstat" in cmd else ""), ""))
    check("Live.read hands the counters on", out.get("counters", {}).get("eth1", {}).get("drops") == 7, str(out))

    saved = (paths.VAR, paths.STATE, paths.LABS, perfmon.qmp_class, perfmon.usage_reader)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        try:
            dest = editor.new_workbench("perf-bench")
            lab = schema.load(dest)
            editor.add_network(lab, "lan", cidr="192.168.10.0/24")
            editor.add_node(lab, "pc01", kind="windows-client", image="win11")
            editor.add_node(lab, "pc02", kind="windows-client", image="win11")
            editor.cable(lab, "pc01", 0, "lan")
            editor.cable(lab, "pc02", 0, "lan")
            editor.save(lab)
            counters = {}

            class FakeLive:
                def read(self, _lab):
                    return {"counters": {k: dict(v) for k, v in counters.items()}}

            class Dash:
                def __init__(self):
                    self.reload()
                    self.wb_live = FakeLive()

                def reload(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)

            d = Dash()
            workbench.act(d, "wb-cable", {"node": "router", "network": "lan"})
            _route_router(d, "lan")  # the student sets up the router's port
            d.reload()
            me = os.getpid()
            st = state.LabState(name="perf-bench", nodes={
                "fabric": state.NodeState("fabric", pid=me, phase="ready"),
                "pc01": state.NodeState("pc01", pid=me, qmp_port=1, phase="ready"),
                "pc02": state.NodeState("pc02", pid=me, qmp_port=2, phase="ready")})
            state.save(st)
            disk = {"n": 0}

            class FakeQmp:
                def __init__(self, port, timeout=0):
                    self.port = port

                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    pass

                def call(self, cmd, **kw):
                    # The guest's own memory, from the balloon driver's statistics.
                    if cmd == "qom-list":
                        return [{"name": "device[0]", "type": "child<virtio-balloon-pci>"}] \
                            if kw.get("path") == "/machine/peripheral-anon" else []
                    if cmd == "qom-set":
                        return {}
                    if cmd == "qom-get":
                        return {"last-update": 1, "stats": {"stat-total-memory": 2048 << 20,
                                                            "stat-available-memory": 512 << 20}}
                    assert cmd == "query-blockstats"
                    n = disk["n"]
                    return [{"device": "", "stats": {"rd_bytes": n * 4_000_000, "wr_bytes": n * 1_000_000,
                                                     "rd_operations": n * 100, "wr_operations": n * 100,
                                                     "rd_total_time_ns": n * 200 * 150_000_000, "wr_total_time_ns": 0}}]

            cpu = {"pc01": 95, "pc02": 10}
            perfmon.qmp_class = FakeQmp
            perfmon.usage_reader = lambda pid, vcpus: procstats.Usage(cpu_pct=cpu["pc01"], rss_mb=1024)
            p1 = next(l for l in d.plan.ports if l.label == "pc01:nic0")
            p2 = next(l for l in d.plan.ports if l.label == "pc02:nic0")
            svi = d.plan.segment_of("lan").svi

            def wire(t):
                counters.update({p1.fabric_iface: {"rx": t * 100_000, "tx": t * 400_000, "errors": 0, "drops": t * 5, "up": True},
                                 p2.fabric_iface: {"rx": 0, "tx": 0, "errors": 0, "drops": 0, "up": True},
                                 svi: {"rx": t * 1000, "tx": t * 2000, "errors": 0, "drops": 0, "up": True}})
            mon = perfmon.Monitor("perf-bench")
            d.perf_monitors = {"perf-bench": mon}  # the one the desktop's actions reach
            for t in (0, 4):
                wire(t)
                disk["n"] = t
                mon.sample(d, now=float(t))
            v = mon.view(d.lab)
            m = v["machines"]["pc01"]
            check("CPU from the QEMU process, memory as the guest's balloon driver reports it (not the process size)",
                  m["cpu_pct"] == 95 and m["rss_mb"] == 1024 and m["mem_pct"] == 75 and m["mem_used_mb"] == 1536
                  and m["mem_total_mb"] == 2048, str(m))
            check("disk I/O from QMP query-blockstats: bytes a second, operations a second, and latency",
                  m["disk"] == {"rd_bps": 4_000_000, "wr_bps": 1_000_000, "iops": 200, "lat_ms": 150.0}, str(m["disk"]))
            check("network from the router's port: what the port sends is what the machine receives",
                  m["net"] == {"rx_bps": 400_000, "tx_bps": 100_000}, str(m["net"]))
            cab = v["cables"]["pc01:nic0"]
            check("its cable carries the load and the errors and drops a minute",
                  cab["rx_bps"] == 100_000 and cab["tx_bps"] == 400_000 and cab["errors_min"] == 20 and cab["up"], str(cab))
            check("the switch's uplink to the router carries the router's interface on it",
                  v["uplinks"].get("lan") == {"rx_bps": 2000, "tx_bps": 1000}, str(v["uplinks"]))
            check("a few minutes of history per machine for the sparklines",
                  v["machines"]["pc01"]["hist"][0] == [95, 95] and len(v["machines"]["pc01"]["hist"]) == 4)
            check("the cable over its error limit raises an alert at once",
                  [a["rule"] for a in v["alerts"]["active"] if a["node"] == "pc01"] == ["errors"], str(v["alerts"]))
            for t in range(8, 130, 4):
                wire(t)
                disk["n"] = t
                mon.sample(d, now=float(t))
            act = {a["rule"]: a for a in mon.view(d.lab)["alerts"]["active"] if a["node"] == "pc01"}
            check("CPU above 90% for two minutes, and disk latency over 100 ms for one, alert",
                  {"cpu", "disk", "errors"} <= set(act) and act["cpu"]["value"] == "95%", str(list(act)))
            check("memory high is off until the user turns it on", "mem" not in act)
            data = perfmon.load("perf-bench")
            check("alerts are kept beside the lab's machines, not in the lab file",
                  (paths.lab_dir("perf-bench") / perfmon.FILE).exists() and "alert" not in dest.read_text())
            cpu["pc01"] = 20
            wire(134)
            mon.sample(d, now=134.0)
            v = mon.view(d.lab)
            check("an alert whose condition cleared moves to the history",
                  any(a["rule"] == "cpu" and a["how"] == "cleared" for a in v["alerts"]["history"]))
            r = perfmon.act(d, "perf-rule", {"node": "pc01", "rule": "cpu", "limit": 10, "for": 0})
            check("the user sets a machine's threshold", r["ok"] and perfmon.rules_of(perfmon.load("perf-bench"), "pc01")["cpu"]
                  == {"on": True, "limit": 10.0, "for": 0} and perfmon.rules_of(perfmon.load("perf-bench"), "pc02")["cpu"]["limit"] == 90)
            wire(138)
            mon.sample(d, now=138.0)
            a = next(a for a in mon.view(d.lab)["alerts"]["active"] if a["rule"] == "cpu")
            check("its own limit fires at once", "10%" in a["text"], a["text"])
            check("a dismissed alert ends and stays quiet while the condition holds",
                  perfmon.act(d, "perf-dismiss", {"id": a["id"]})["ok"])
            mon.sample(d, now=142.0)
            check("... it does not come straight back",
                  not any(x["rule"] == "cpu" for x in mon.view(d.lab)["alerts"]["active"]))
            check("a bad threshold is refused", not perfmon.act(d, "perf-rule", {"node": "pc01", "rule": "cpu", "limit": -1})["ok"])
            perfmon.act(d, "perf-rule", {"node": "*", "rule": "errors", "on": False})
            check("a rule turned off for every machine", not perfmon.rules_of(perfmon.load("perf-bench"), "pc02")["errors"]["on"])

            # A link that goes down, and a machine that goes off by itself.
            counters[p2.fabric_iface]["up"] = False
            FakeLive.read = lambda self, _lab: {"counters": {**{k: dict(v) for k, v in counters.items()},
                                                             p2.fabric_iface: {**counters[p2.fabric_iface], "up": False}}}
            for t in (150, 156, 162):
                mon.sample(d, now=float(t))
            act = {(a["node"], a["rule"]) for a in mon.view(d.lab)["alerts"]["active"]}
            check("a cabled port with no link while the machine runs: Link down after its 10 s", ("pc02", "link") in act, str(act))
            st = state.load("perf-bench")
            st.nodes["pc02"].pid = 0x7FFFFFF0
            state.save(st)
            mon.sample(d, now=170.0)
            check("a machine gone is not an alert at once (winlab may be stopping it)",
                  ("pc02", "stopped") not in {(a["node"], a["rule"]) for a in mon.view(d.lab)["alerts"]["active"]})
            mon.sample(d, now=180.0)
            act = {(a["node"], a["rule"]): a for a in mon.view(d.lab)["alerts"]["active"]}
            check("gone without winlab stopping it: Stopped unexpectedly, an error; its link alert clears",
                  ("pc02", "stopped") in act and act[("pc02", "stopped")]["level"] == "error"
                  and ("pc02", "link") not in act, str(list(act)))
            check("off, its meters read nothing", not mon.view(d.lab)["machines"]["pc02"]["running"])
            st.nodes["pc01"].pid, st.nodes["pc01"].phase = 0, "stopped"
            state.save(st)
            mon.sample(d, now=190.0)
            mon.sample(d, now=200.0)
            check("a machine winlab stopped raises nothing",
                  ("pc01", "stopped") not in {(a["node"], a["rule"]) for a in mon.view(d.lab)["alerts"]["active"]})
            st.nodes["pc02"].pid = me
            state.save(st)
            mon.sample(d, now=204.0)
            check("started again, the alert ends", any(a["rule"] == "stopped" and a["how"] == "started again"
                                                       for a in mon.view(d.lab)["alerts"]["history"]))
            check("the history is cleared on request, the open alerts stay",
                  perfmon.act(d, "perf-clear", {})["ok"] and not mon.view(d.lab)["alerts"]["history"])

            # While "Break something for me" runs, the cables' errors stay hidden.
            physfaults._write("perf-bench", {"faults": [], "seq": 0, "drill": {"checks": 0, "hints": {}, "touched": []}})
            mon.sample(d, now=210.0)
            check("a drill hides the cables' error counts (the student finds them with the lab's tools)",
                  mon.view(d.lab)["cables"]["pc02:nic0"]["errors_min"] is None and mon.view(d.lab)["errors_hidden"])
            physfaults._write("perf-bench", {"faults": [], "seq": 0, "drill": None})
            check("the rules list says what each one watches",
                  {k["id"] for k in perfmon.act(d, "perf-rules", {})["kinds"]} == set(perfmon.RULES))
            mon._thread = type("T", (), {"is_alive": lambda self: True})()
            v = perfmon.view(d)
            check("GET /api/perf is one batched answer: machines, cables, uplinks, alerts",
                  {"machines", "cables", "uplinks", "alerts", "router", "every"} <= set(v))
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            perfmon.qmp_class, perfmon.usage_reader = saved[3], saved[4]

    page = Path(webui.__file__).with_name("webui_page.html").read_text(encoding="utf-8")
    src = Path(webui.__file__).read_text(encoding="utf-8")
    check("the desktop serves /api/perf and the perf- actions", '"/api/perf"' in src and 'startswith("perf-")' in src)
    check("the canvas draws the meters and the cables' load, polls only while shown and visible",
          '<g id="wb-perf">' in page and "function pfLayer(" in page and "function pfCable(" in page
          and "document.hidden&&(isOpen('Workbench')||isOpen('Machines')||isOpen('Alerts')||isOpen('Performance')||isOpen('Building'))" in page)
    check("a Performance panel on the workbench and in Machines, a mini meter in the machines list",
          page.count("${pfSection(") == 2 and "${pfMini(n.id)}" in page)
    check("an Alerts window with active, history and rules, and a toast for a new alert",
          'data-win="Alerts"' in page and "function pfAlertsRender(" in page and "function pfNew(" in page)
    check("nothing on the performance side runs or changes anything inside a machine",
          "guestctl" not in Path(perfmon.__file__).read_text(encoding="utf-8")
          and "GuestChannel" not in Path(perfmon.__file__).read_text(encoding="utf-8"))








def test_history():
    """The bench's change history (winlab/history.py): every change made on
    the workbench recorded with its before and after, undo and redo of the
    layout and the cabling through the workbench's own save (and livenet),
    refusals a real bench would make, the CLI and the Activity trail."""
    import json
    import os
    from winlab import editor, history, labclock, livenet, netplan, paths, schema, workbench

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"))
    real_sync, real_running = livenet.sync, workbench._running
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        synced, running = [], set()
        livenet.sync = lambda lab, **k: synced.append(lab.name) or {"live": True, "done": ["x"], "note": ""}
        workbench._running = lambda name: set(running)
        try:
            editor.new_workbench("hist-lab")

            class _Dash:
                def reload(self):
                    self.lab = schema.load("hist-lab")
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
            d = _Dash()
            d.reload()

            def wb(action, **p):
                return workbench.act(d, action, p)
            wb("wb-add", shelf="switch", id="sw1", x=100, y=200)
            wb("wb-cable", node="router", network="sw1")
            _route_router(d, "sw1")  # the student sets up the router's port
            wb("wb-add", shelf="pc", how="ready", image="win11", id="pc01", x=300, y=400)
            wb("wb-cable", node="pc01", nic=0, network="sw1")
            wb("wb-move", positions={"pc01": [320, 420]})
            log = history.log_file("hist-lab")
            rows = [json.loads(x) for x in log.read_text().splitlines()]
            check("each bench change is a line in var/labs/<lab>/changes.jsonl",
                  log == paths.VAR / "labs" / "hist-lab" / "changes.jsonl" and len(rows) == 5
                  and [r["kind"] for r in rows] == ["add", "cable", "add", "cable", "move"])
            cab = rows[3]
            check("a line has the time, who, what and the settings before and after",
                  cab["t"] and cab["who"] and cab["what"].startswith("PC01 port 1 -> sw1")
                  and ["pc01 › nic 1 › network", "", "sw1"] in cab["changes"] and "pc01" in cab["devices"]
                  and cab["undo"] and (history._snap_dir("hist-lab") / f"{cab['before']}.toml").exists())
            check("a device that came is one line, not every one of its settings",
                  ["pc01", None, "present"] in rows[2]["changes"]
                  and not any(c[0] == "pc01 › cpus" for c in rows[2]["changes"]))
            check("a move is filed under the device that moved",
                  rows[4]["what"] == "moved pc01" and rows[4]["devices"] == ["pc01"])

            # undo and redo
            synced.clear()
            r = wb("wb-undo")
            check("undo takes the move back", r["ok"] and d.lab.layout["pc01"] == [300, 400] and "Undo: moved" in r["message"])
            r = wb("wb-undo")
            check("undo takes the cable out, through the workbench's save and the live network",
                  r["ok"] and not d.lab.nodes["pc01"].nics[0].plugged and synced == ["hist-lab", "hist-lab"]
                  and "(live)" in r["message"])
            v = history.view("hist-lab")
            check("the history marks what was undone and says what redo would put back",
                  set(v["undone"]) == {4, 5} and v["can_redo"].startswith("PC01 port 1")
                  and v["entries"][0]["kind"] == "undo")
            r = wb("wb-redo")
            check("redo puts the cable back", r["ok"] and d.lab.nodes["pc01"].nics[0].network == "sw1")
            wb("wb-add", shelf="pc", how="ready", image="win11", id="pc02", x=500, y=400)
            check("a new change clears what redo had", history.view("hist-lab")["can_redo"] == "")
            wb("wb-undo")
            check("undo of an added machine takes it off the bench", "pc02" not in d.lab.nodes)
            wb("wb-redo")

            # refusals
            running.add("pc02")
            r = wb("wb-undo")
            check("a running machine is not taken off the bench", not r["ok"] and "running" in r["message"]
                  and "pc02" in d.lab.nodes)
            running.discard("pc02")
            wb("wb-parts", node="pc01", add_disk_gb=10)
            disk = paths.VAR / "labs" / "hist-lab" / "pc01" / "data0.qcow2"
            disk.parent.mkdir(parents=True, exist_ok=True)
            disk.write_bytes(b"\0" * (history.DATA_BYTES + 1))
            r = wb("wb-undo")
            check("a disk with data on it is not pulled out by undo", not r["ok"] and "has data" in r["message"]
                  and d.lab.nodes["pc01"].data_disks_gb == [10])
            disk.unlink()
            wb("wb-parts", node="pc01", memory_mb=4096)
            running.add("pc01")
            r = wb("wb-undo")
            check("undo will not change the parts of a running machine", not r["ok"] and "shut it" in r["message"]
                  and d.lab.nodes["pc01"].memory_mb == 4096)
            wb("wb-move", positions={"pc01": [10, 10]})
            r = wb("wb-undo")
            check("but moves and cables of a running machine undo", r["ok"] and d.lab.layout["pc01"] == [300, 400])
            running.clear()
            wb("wb-undo")
            check("undoing parts with the machine off", d.lab.nodes["pc01"].memory_mb != 4096)

            # what undo stops at
            wb("wb-switch", network="sw1", dhcp=True)
            check("a switch setting is recorded but stops undo", history.view("hist-lab")["can_undo"] == ""
                  and history.entries("hist-lab")[-1]["kind"] == "switch")
            wb("wb-move", positions={"pc01": [50, 60]})
            src = Path(d.lab.source_path)
            src.write_text(src.read_text().replace('description = ""', 'description = "edited"', 1)
                           if 'description = ""' in src.read_text() else src.read_text() + "\n# edited\n")
            r = wb("wb-undo")
            check("a lab file changed outside the workbench stops undo", not r["ok"] and "outside" in r["message"])
            wb("wb-move", positions={"pc01": [70, 80]})
            undo, _ = history.stacks("hist-lab")
            check("and a change after it starts undo afresh", len(undo) == 1 and history.entries("hist-lab")[-1].get("gap"))
            n = len(history.entries("hist-lab"))
            try:
                wb("wb-fault", op="list")
            except Exception:  # noqa: BLE001 - only that it leaves no line
                pass
            wb("wb-history")
            check("faults and reads leave no line", len(history.entries("hist-lab")) == n)
            check("a device filter", all("pc02" in e["devices"] for e in history.view("hist-lab", "pc02")["entries"])
                  and history.view("hist-lab", "pc02")["entries"])
            k = "_".join(["admin", "password"])
            check("Wi-Fi keys and passwords never show in the history",
                  history.diff(f'[lab]\n{k} = "{"x" * 3}"\n', f'[lab]\n{k} = "{"y" * 3}"\n')
                  == [[f"lab › {k}", "••••", "••••"]])
            labclock.save("hist-lab", labclock.Clock(anchor_real=0, anchor_lab=86400.0, paused=True))
            wb("wb-move", positions={"pc01": [90, 90]})
            check("the lab clock's time is on each line once the lab has a clock",
                  history.entries("hist-lab")[-1]["lab_time"] == labclock.stamp(86400.0))
            check("the CLI's history", "moved pc01" in history.render("hist-lab") and "undo:" in history.render("hist-lab"))
            r = history.step(history.Bench(schema.load("hist-lab")))
            check("the CLI's undo", r["ok"] and schema.load("hist-lab").layout["pc01"] == [70, 80])
            history.recorded(d, "hw-pull", {"node": "pc01", "disk": 0},
                             lambda: {"ok": True, "message": "data disk 1 pulled out of pc01"})
            e = history.entries("hist-lab")[-1]
            check("a disk pulled or a disc put in is recorded though the lab file is unchanged",
                  e["kind"] == "disk" and "before" not in e and not e["undo"] and e["devices"] == ["pc01"]
                  and "hw-pull" in history.WATCHED)
            check("since(): who changed what, for the Activity window",
                  history.since("hist-lab", 0)[-1]["what"].startswith("data disk 1"))
        finally:
            livenet.sync, workbench._running = real_sync, real_running
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]


def test_console_cable():
    """The console cable (winlab/consolecable.py): a rollover from a router's or
    a switch's console port to a lab PC's USB-serial adapter, COM2 fitted at
    power-on on a loopback socket only, the desktop's bridge from it to the
    device's command line, and the serial terminal drawn on that PC."""
    import os
    import socket
    from winlab import commands, consolecable as cc, devcli, editor, lessons, netplan, paths, schema, state, workbench
    from winlab.providers.qemu import QemuProvider, check_isolation

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"))
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            editor.new_workbench("cc-lab")

            class _Dash:
                def reload(self):
                    self.lab = schema.load("cc-lab")
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
            d = _Dash()
            d.reload()

            def wb(action, **p):
                return workbench.act(d, action, p)
            wb("wb-add", shelf="switch", id="sw1")
            wb("wb-cable", node="router", network="sw1")
            _route_router(d, "sw1")  # the student sets up the router's port
            for n, shelf, img in (("pc01", "pc", "win11"), ("pc02", "pc", "win11"), ("lx01", "linux", "ubuntu")):
                wb("wb-add", shelf=shelf, how="ready", image=img, id=n)
                wb("wb-cable", node=n, nic=0, network="sw1")
            con = lambda action, **p: cc.act(d, action, p)
            r = con("con-plug", device="net:sw1", node="lx01")
            check("the adapter's USB end goes into a Windows machine only", not r["ok"] and "Windows" in r["message"])
            r = con("con-plug", device="net:sw1", node="pc01")
            check("a console cable from the switch to pc01: its adapter is COM2, 9600 8N1",
                  r["ok"] and cc.cables(d.lab) == {"sw:sw1": "pc01"} and "COM2" in r["message"]
                  and "9600 8N1" in r["message"] and cc.fitted(d.lab.nodes["pc01"]), r["message"])
            r = con("con-plug", device="router", node="pc01")
            check("one adapter, one cable: the router's needs the switch's out first",
                  not r["ok"] and "unplug that one first" in r["message"])
            check("it stays in the lab file", schema.load("cc-lab").devices["sw:sw1"][cc.VAR] == "pc01")
            v = workbench.view(d)["console"]
            check("the canvas gets the cable and the machines that take one",
                  v["cables"][0]["key"] == "net:sw1" and v["cables"][0]["node"] == "pc01"
                  and set(v["machines"]) == {"pc01", "pc02"} and v["line"]["speed"] == 9600)

            prov = QemuProvider(d.plan, accel="tcg")
            rt = prov.build_node(d.lab.nodes["pc01"])
            a = rt.argv
            sers = [a[i + 1] for i, x in enumerate(a) if x == "-serial"]
            check("pc01 powers on with COM2 after the agent's COM1, a loopback socket",
                  rt.com_port and sers == ["chardev:ser0", "chardev:com2"]
                  and f"socket,id=com2,host=127.0.0.1,port={rt.com_port},server=on,wait=off" in a
                  and not check_isolation(a), str(sers))
            rt2 = prov.build_node(d.lab.nodes["pc02"])
            check("a machine that never had the adapter is as before", not rt2.com_port and "chardev:com2" not in rt2.argv)

            # the bridge: QEMU's side of COM2 is a listening socket; Windows' terminal types into it
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            st = state.new("cc-lab", "tcg", "none", "")
            st.nodes["pc01"] = state.NodeState("pc01", pid=os.getpid(), com_port=port)
            state.save(st)
            made = []

            def factory(dash, device):
                c = devcli.Console(dash, device)
                c.powered = lambda: True
                made.append(c)
                return c
            br = cc.Bridge(lambda: d, factory)
            br.step(0.05)
            guest, _ = srv.accept()
            guest.settimeout(2)

            def read_until(word):
                got = b""
                for _ in range(40):
                    br.step(0.05)
                    try:
                        guest.settimeout(0.05)
                        got += guest.recv(4096)
                    except socket.timeout:
                        pass
                    if word.encode() in got:
                        break
                return got.decode("latin-1")
            out = read_until("RETURN")
            check("the switch's console greets the terminal on COM2", "Press RETURN to get started." in out, out)
            guest.sendall(b"\r")
            out = read_until("Switch>")
            check("Enter: its prompt", out.rstrip().endswith("Switch>"), out)
            guest.sendall(b"ena\t\r")
            out = read_until("Switch#")
            check("typed byte by byte, echoed, Tab completes: privileged mode", "Switch#" in out and "ena" in out, out)
            guest.sendall(b"conf t\rhostname CORE-SW1\r")
            out = read_until("CORE-SW1(config)#")
            check("configure terminal and hostname, as in PuTTY", "CORE-SW1(config)#" in out
                  and schema.load("cc-lab").devices["sw:sw1"]["hostname"] == "CORE-SW1", out)
            guest.sendall(b"\x1a")
            out = read_until("CORE-SW1#")
            check("Ctrl+Z leaves configuration", "^Z" in out and "CORE-SW1#" in out, out)
            guest.sendall(b"show vl?")
            out = read_until("vlan")
            check("'?' answers at once, the line kept", "?" in out and "vlan" in out, out)
            guest.sendall(b"\x7f\x7f\x7f\x7f\x7f\x7f\x7fsh\x08\x08show clock\r")
            out = read_until("CORE-SW1#")
            check("Backspace rubs out", "\b \b" in out and "% " not in out.split("show clock")[-1], out)
            # the cable out: the bridge lets go of COM2
            d.lab.devices["sw:sw1"].pop(cc.VAR)
            editor.save(d.lab)
            d.reload()
            br.step(0.05)
            guest.settimeout(1)
            check("unplugged: the line goes quiet", not br.wires and guest.recv(10) == b"")
            guest.close()
            srv.close()
            con("con-plug", device="net:sw1", node="pc01")

            # the serial terminal drawn on the PC: only from pc01, only on
            import winlab.workbench as wbm
            run0 = wbm._running
            wbm._running = lambda name: {"pc01", "fabric"}
            try:
                r = con("con-term", device="net:sw1", node="pc02")
                check("Connect from... a PC the cable does not run to is refused", not r["ok"] and "no console cable" in r["message"])
                good = {"port": "COM2", "speed": 9600, "data": 8, "parity": "none", "stop": 1}
                r = con("con-term", device="net:sw1", node="pc01", settings=good)
                check("opened at 9600 8N1 on COM2: Press RETURN", r["ok"] and "RETURN" in r["out"], str(r))
                r = con("con-term", device="net:sw1", node="pc01", settings=good, line="")
                check("Enter: the prompt", r["prompt"] == "CORE-SW1>", str(r))
                r = con("con-term", device="net:sw1", node="pc01", settings=good, line="enable")
                check("the student types the commands", r["prompt"] == "CORE-SW1#", str(r))
                r = con("con-term", device="net:sw1", node="pc01", settings={**good, "speed": 115200}, line="enable")
                check("a wrong speed reads as garbage", r["garbled"] and "CORE-SW1" not in r["out"], str(r))
                r = con("con-term", device="net:sw1", node="pc01", settings={**good, "port": "COM1"}, line="")
                check("the wrong serial line: silence", r.get("silent") and not r["out"])
            finally:
                wbm._running = run0
            state.save(state.new("cc-lab", "tcg", "none", ""))
            r = con("con-term", device="net:sw1", node="pc01")
            check("the terminal runs on the PC: off, it cannot open", not r["ok"] and "is off" in r["message"])
            from winlab import activity
            check("an instructor's network handed out without cables has no console cable either",
                  cc.cables(d.lab) and not cc.cables(activity._prune(d.lab, {"pc01", "net:sw1"}, False)))
            r = con("con-unplug", device="net:sw1")
            check("unplug: the adapter stays in the PC", r["ok"] and not cc.cables(d.lab) and cc.fitted(d.lab.nodes["pc01"]))
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]
    ls = {l.id: l for l in lessons.list_available()}
    les = ls.get("switch-console-first-setup")
    check("the lesson: first-time setup of a switch over the console cable",
          les is not None and les.module == "network" and any("9600" in s for s in les.steps)
          and not [x for x in lessons.validate_all() if "switch-console-first-setup" in x])
    cat = commands.load_catalog()
    check("the command reference has the serial-line commands", {"mode"} <= set(cat)
          and not [x for x in commands.undocumented() if x[1] == "switch-console-first-setup"])




def test_spanning_tree():
    """Spanning tree (winlab/stp.py): a spare cable between two switches is a
    loop; the 802.1D election (root by priority then address, root,
    designated and blocking ports) from the switches' consoles; a loop with
    it off is a storm; BPDU guard err-disables an uplink and cuts its switch
    off; the kernel bridges the router builds, capped; the graded drills."""
    import os
    from winlab import commands, devcli, editor, exercises, images, lessons, livenet, netplan, paths, schema, stp, workbench
    from winlab.model import CUSTOM

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("loop-lab")
            lab = schema.load(dest)
            paths.downloads_dir().mkdir(parents=True, exist_ok=True)
            images.installer_path("win11").write_bytes(b"\0" * 2048)
            for n, c in (("sw1", "192.168.10.0/24"), ("sw2", "192.168.20.0/24"), ("sw3", "192.168.30.0/24")):
                editor.add_network(lab, n, cidr=c)
            for s in ("sw2", "sw3"):
                editor.set_routed(lab, s, False)
            for nid, net in (("pc01", "sw1"), ("pc02", "sw2"), ("pc03", "sw3")):
                editor.add_node(lab, nid, kind=CUSTOM, image="win11")
                editor.cable(lab, nid, 0, net)
            editor.save(lab)

            class _Dash:
                def reload(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
            d = _Dash()
            d.reload()
            workbench._running = lambda _n: {"fabric"}

            def wb(action, **p):
                return workbench.act(d, action, p)
            check("switches not cabled to each other: no switch bridge to build", stp.render(d.plan) == [])
            wb("wb-cable", node="switch", network="sw2", to="sw1")
            wb("wb-cable", node="switch", network="sw3", to="sw1")
            r = wb("wb-stp-cable", a="sw2", b="sw2")
            check("a cable from a switch into itself is refused", not r["ok"])
            r = wb("wb-stp-cable", a="sw2", b="sw3")
            check("a spare cable between two switches below one is a loop, and is allowed", r["ok"], r.get("message", ""))
            res = stp.compute(d.lab)
            kinds = sorted(c.kind for c in res.cables)
            check("three cables in the ring: two uplinks and the spare", len(kinds) == 3 and kinds.count("extra") == 1, str(kinds))
            check("spanning tree on by default (PVST+, as a Cisco switch ships): one root, one blocking port, no loop",
                  len({b.root for b in res.bridges.values()}) == 1 and not res.loop
                  and sum(p.state == "BLK" for p in res.ports.values()) == 1)
            low = min(res.bridges, key=lambda s: res.bridges[s].bid)
            check("at equal priority the lowest address is root", all(b.root == low for b in res.bridges.values()))

            con = {s: devcli.Console(d, f"sw:{s}", runner_factory=lambda: (lambda *a, **k: "", "")) for s in ("sw1", "sw2", "sw3")}
            for c in con.values():
                c.run("enable")
                c.run("configure terminal")
            out = con["sw1"].run("spanning-tree vlan 1 root primary")
            res = stp.compute(d.lab)
            check("root primary makes the router's switch the root bridge",
                  all(b.root == "sw1" for b in res.bridges.values()) and res.bridges["sw1"].bid[0] < 32768, out)
            check("the root's ports are all designated", all(p.role == "desg" for e, p in res.ports.items() if e.sw == "sw1"))
            blk = [e for e, p in res.ports.items() if p.state == "BLK"]
            check("with sw1 root the spare cable is the one that blocks",
                  len(blk) == 1 and blk[0].port != stp.GI1, str(blk))
            show = con["sw2"].run("do show spanning-tree")
            check("show spanning-tree: root ID, this bridge, port roles", "Root ID" in show and "Bridge ID" in show
                  and "Root" in show and ("Desg" in show or "Altn" in show), show)
            con["sw2"].run("interface gi0/1")
            check("a port cost out of range is refused", con["sw2"].run("spanning-tree cost 0").startswith("%"))
            con["sw2"].run("exit")

            con["sw2"].run("no spanning-tree vlan 1")
            con["sw3"].run("no spanning-tree vlan 1")
            res = stp.compute(d.lab)
            check("two switches off, the root still blocks: a switch with STP off floods BPDUs, so no loop",
                  not res.loop and any(p.state == "BLK" for e, p in res.ports.items() if e.sw == "sw1"))
            out = con["sw1"].run("no spanning-tree vlan 1")
            res = stp.compute(d.lab)
            check("all three off: the ring forwards everywhere, a storm", len(res.loop) == 3 and set(res.storm) == {"sw1", "sw2", "sw3"}, str(res.loop))
            check("the switch logs MAC flapping when a loop forms", "MACFLAP" in out, out)
            v = stp.view(d.lab)
            check("the canvas gets the storm, its loop cables, and the cap said honestly",
                  v["storm"] and len(v["storm"]["cables"]) == 3 and "Mbit" in v["storm"]["cap"] and all(c["loop"] for c in v["cables"]))
            check("show processes cpu warns", "%" in con["sw2"].run("do show processes cpu"))
            con["sw3"].run("spanning-tree vlan 1")
            check("one command on one switch ends it", not stp.compute(d.lab).loop)
            con["sw1"].run("spanning-tree vlan 1")
            con["sw2"].run("spanning-tree vlan 1")

            d.reload()
            text = "\n".join(stp.render(d.plan))
            check("the router builds a kernel bridge per switch, STP on, with the switch's priority",
                  "stp_state 1" in text and "priority 24576" in text and "alias sw1" in text, text[:400])
            check("every cable is rate capped, so a storm cannot eat the PC",
                  text.count("tbf rate " + stp.STORM_RATE) >= 6 and stp.INTO_LAB_RATE in text)
            pins = livenet.snapshot(d.plan, 1)
            con["sw2"].run("spanning-tree vlan 1 priority 8192")
            d.reload()
            check("a spanning-tree change is something livenet pushes to the running router",
                  livenet.changes(d.plan, pins)["stp"] and not livenet.changes(d.plan, livenet.snapshot(d.plan, 1))["stp"])
            con["sw2"].run("no spanning-tree vlan 1 priority")

            joined = dict(d.plan.joined)
            con["sw2"].run("interface gi0/1")
            out = con["sw2"].run("spanning-tree bpduguard enable")
            check("BPDU guard on an uplink err-disables it at once", "ERR_DISABLE" in out and "sw2|" + stp.GI1 not in out
                  and stp.compute(d.lab).ports[stp.End("sw2", stp.GI1)].state == "err", out)
            check("err-disabled the uplink, sw2 still reaches sw1 the long way round (through sw3)",
                  not stp.cut_off(d.lab, "sw2"))
            spare = [c.id for c in stp.cables(d.lab) if c.kind == "extra"][0]
            r = wb("wb-stp-unplug", id=spare)
            d.reload()
            check("without the spare cable sw2 is cut off: its VLAN is a network of its own", r["ok"] and stp.cut_off(d.lab, "sw2")
                  and d.plan.joined != joined)
            con["sw2"].run("no spanning-tree bpduguard")
            check("no spanning-tree bpduguard alone does not bring it back", stp.cut_off(d.lab, "sw2"))
            con["sw2"].run("shutdown")
            con["sw2"].run("no shutdown")
            d.reload()
            check("shutdown, no shutdown does", not stp.cut_off(d.lab, "sw2") and d.plan.joined == joined)

            live = stp.parse_live("#stp\nB stp1 1 8000.0257 8000.0257\nP stp1 stp1g2 4\nT stp1g2 1234\nC cpu 10 0 5 100 0 0 0 0 0 0\n")
            check("the router's live read: bridges, port states, counters, CPU",
                  live["bridges"]["stp1"]["on"] and live["ports"]["stp1g2"] == "BLK"
                  and live["tx"]["stp1g2"] == 1234 and live["cpu"][:4] == [10, 0, 5, 100])

            r = wb("wb-stp-drill", op="start", id="loop")
            dv = stp.view(schema.load(dest))
            check("the loop drill hides a second cable with STP off at both ends", r["ok"] and dv["storm"] and dv["drill"]["id"] == "loop", r.get("message", ""))
            d.reload()
            check("a second drill cannot start over the first", not wb("wb-stp-drill", op="start", id="guard")["ok"])
            h = wb("wb-stp-drill", op="hint")
            check("hints come one at a time", h["ok"] and stp.drill_state("loop-lab")["hints"] == 1)
            check("Check my fix fails while it floods", not wb("wb-stp-drill", op="check")["passed"])
            flood = iter([f"T stp1g2 {n}" for n in (0, 999999)])
            d.reload()
            check("the kernel's counters say it floods even if the file says otherwise",
                  stp.storming(lambda *_a, **_k: next(flood), gap=0.01))
            d.reload()
            r = wb("wb-stp-drill", op="undo")
            d.reload()
            check("undo puts the network back", r["ok"] and not stp.compute(d.lab).loop and stp.drill_state("loop-lab") is None, r.get("message", ""))
            wb("wb-stp-drill", op="start", id="guard")
            d.reload()
            dd = stp.drill_state("loop-lab")
            c2 = devcli.Console(d, f"sw:{dd['a']}", runner_factory=lambda: (lambda *a, **k: "", ""))
            for line in ("enable", "configure terminal", "interface gi0/1", "no spanning-tree bpduguard", "shutdown", "no shutdown"):
                c2.run(line)
            d.reload()
            r = wb("wb-stp-drill", op="check")
            check("the BPDU guard drill passes once the uplink is fixed", r["passed"], r["message"])
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            workbench._running = saved[4]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]
    ls = {l.id: l for l in lessons.list_available()}
    ex = exercises.load("spanning-tree-root")
    check("the lesson and its exercise, graded on the router's kernel bridges",
          "spanning-tree-loops" in ls and all(c.node == "fabric" for c in ex.checks) and len(ex.checks) == 5)
    check("the switch commands are in the command reference",
          any(k == "switch" for k, _ in commands.KINDS)
          and {"show spanning-tree", "spanning-tree portfast", "spanning-tree bpduguard"}
          <= {e.name for e in commands.load_catalog().values() if e.kind == "switch"})
    page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    check("the canvas draws the cable-end marks and the storm", "function stpMarks" in page and "stpstorm" in page)




















# ===== rts-dist: activation, encrypted content packs, trial gating, updates, release upload =====

def _dist_server(routes):
    """A loopback HTTP server: routes maps (method, path) to a function
    (body bytes, query dict) -> (status, bytes or dict). Returns (base, seen, stop)."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlsplit

    seen = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _go(self, method):
            u = urlsplit(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            seen.append((method, u.path, u.query, body, dict(self.headers)))
            fn = routes.get((method, u.path))
            code, out = fn(body, parse_qs(u.query)) if fn else (404, {"error": "no route"})
            data = out if isinstance(out, bytes) else json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}", seen, srv.shutdown


def _dist_sign(obj, seed):
    import json
    from winlab.licensing import ed25519
    body = {k: v for k, v in obj.items() if k != "sig"}
    msg = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return {**body, "sig": ed25519.sign(msg, seed).hex()}
















def test_dist_seed_and_gui():
    """Upgrading from an exe that seeded the paid labs as plain files removes
    the untouched ones; the desktop has the Activate window, the key/trial
    choice at first run, locked labs in Start and the update settings."""
    from winlab import paths

    with tempfile.TemporaryDirectory() as td:
        bundle, dest = Path(td) / "b", Path(td) / "content"
        (bundle / "labs").mkdir(parents=True)
        (bundle / "labs" / "free.toml").write_text("f\n")
        (bundle / "labs" / "paid.toml").write_text("p\n")
        (bundle / "labs" / "edited.toml").write_text("e\n")
        paths.seed_content(bundle, dest)
        (dest / "labs" / "edited.toml").write_text("mine\n")
        (bundle / "labs" / "paid.toml").unlink()
        (bundle / "labs" / "edited.toml").unlink()
        (bundle / "packs").mkdir()
        (bundle / "packs" / "labs-full.wlpack").write_bytes(b"WLPACK")
        rep = paths.seed_content(bundle, dest)
        check("an upgrade removes plain paid files the user never touched, keeps edited ones, adds the pack",
              rep.removed == [dest / "labs" / "paid.toml"] and (dest / "labs" / "edited.toml").exists()
              and (dest / "packs" / "labs-full.wlpack").exists())
    page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    check("the Activate winlab window: state, key box, activate, move to another PC, where to buy",
          'data-win="Activation"' in page and 'id="lic-key"' in page and "keyFormat(this)" in page
          and "Move to another PC" in page and 'id="act-buy"' in page and "PCs used" in page and "Licensed to" in page)
    check("first run offers a product key or the free first lab",
          "Enter product key" in page and "Try the first lab free" in page and "welcomeTrial()" in page)
    check("locked labs in Start lead to the Activate window", "openActivation('${esc(l.name)}')" in page
          and "unlock with a license key" in page and "r.locked" in page)
    check("Help > About: automatic checks and install", 'id="upd-auto"' in page and "installUpdate()" in page
          and "'app-update'" in page)
    iss = (Path(__file__).resolve().parent.parent / "packaging" / "winlab.iss").read_text(encoding="utf-8")
    check("the installer can take a product key and relaunches after a silent update",
          "CreateInputQueryPage" in iss and "product-key.txt" in iss and "RELAUNCH" in iss)

# ===== graded checks (rts-graded) =====
# Lessons that stay ungraded on purpose, each with its reason. Everything else
# is checked in the guest: a graded exercise or a break-and-fix problem.
UNGRADED_LESSONS = {
    "cloud-address-plan": "planning on the Network map and on paper; nothing changes in a guest",
}
# Done in the student's own browser, on their own Azure tenant: the lab is
# isolated from the Internet, so nothing there can be checked from a guest.
BROWSER_LESSONS = {"azure-free-account", "entra-connect-sync", "conditional-access", "intune-enrol",
                   "azure-arc", "azure-monitor", "update-manager"}
# The Windows 11 track's cloud-only scenarios, done the same way on the
# student's own Microsoft 365 / Intune trial (test_w11_cloud).
BROWSER_LESSONS |= {"autopilot-register", "intune-win32-apps", "intune-assignment-filters",
                    "intune-update-rings", "co-management-tenant-attach",
                    "endpoint-analytics-remote-help", "defender-endpoint-onboard"}
# The AWS operations lessons whose services the lab's emulator cannot run
# (Lambda code, SSM agent features, AWS Backup jobs), done on a real account.
BROWSER_LESSONS |= {"aws-real-lambda-sqs", "aws-real-ssm-backup"}

GRADED_NEW = {
    # lesson: (exercise, guest fault that sets the scene or "")
    "helpdesk-unlock-and-reset": ("helpdesk-unlock-and-reset", "account-locked"),
    "offboard-a-leaver": ("offboard-a-leaver", "leaver-to-offboard"),
    "repurpose-a-computer-account": ("repurpose-a-computer-account", "prestaged-kiosk"),
    "stale-computer-accounts": ("stale-computer-cleanup", "stale-computers"),
    "gmsa-service-account": ("gmsa-for-a-task", ""),
    "workstation-baseline-gpo": ("workstation-baseline-gpo", ""),
    "privileged-group-review": ("domain-admins-review", "extra-domain-admins"),
    "scheduled-task-persistence": ("remove-task-persistence", "task-persistence"),
    "linux-install-by-hand": ("linux-servers-installed", ""),
    "switch-console-first-setup": ("switch-named-from-console", ""),
    "backup-to-the-cloud": ("dc-backup-in-the-cloud", ""),
}


def _ps51_problems(text: str) -> list[str]:
    """What Windows PowerShell 5.1 would refuse, as far as a scan can tell:
    unbalanced brackets or quotes, PowerShell 7 operators, and "$name:" in a
    double-quoted string (5.1 reads it as a drive-qualified variable)."""
    out = []
    err = _ps_balance_error(text)
    if err:
        out.append(err)
    if "??" in text or "?." in text or re.search(r"\s\?\s[^:]+\s:\s", text):
        out.append("a PowerShell 7 operator")
    if re.search(r'"[^"\n]*\$(?!env:|script:|global:|using:)[A-Za-z_]\w*:[^A-Za-z_\\]', text):
        out.append('"$name:" in a double-quoted string')
    if re.search(r"-Parallel\b|ForEach-Object\s+-Parallel|\bClean\s*\{", text):
        out.append("a PowerShell 7 parameter")
    return out











# ===== exam prep tracks and timed practice exams =====



# ===== teacher =====

# ===== help, support file and scenario days =====
def _hs_tmp_paths(td):
    """Points winlab's writable paths into td; returns what to restore."""
    from winlab import paths
    saved = (paths.ROOT, paths.VAR, paths.STATE, paths.LOGS)
    td = Path(td)
    paths.ROOT, paths.VAR, paths.STATE, paths.LOGS = td, td / "var", td / "var" / "state", td / "var" / "logs"
    return saved


def _hs_restore(saved):
    from winlab import paths
    paths.ROOT, paths.VAR, paths.STATE, paths.LOGS = saved








def _hs_runner(answers=None, log=None):
    """A fake guest: each call is logged; answers maps a substring of the
    command to (ok, stdout); default True."""
    def run(node, cmd, shell):
        if log is not None:
            log.append((node, cmd, shell))
        for k, v in (answers or {}).items():
            if k in cmd:
                return v
        return True, "True"
    return run








# ===== native-code protection of the licensing modules =====


# ===== each device's real management software (winlab/adminui.py) =====


# ===== real GUIs: printer (CUPS) and Admin workstation =====






# ===== real GUIs: NAS (OpenMediaVault) =====
def test_real_gui_nas_debian_appliance():
    """Debian's own cloud images as appliances: Debian 13 (the NAS's base)
    and Debian 12, from cloud.debian.org, verified against SHA512SUMS."""
    import hashlib
    import os
    from winlab import appliances, bootstrap, images, paths
    d13, d12 = appliances.get("debian13-cloud"), appliances.get("debian12")
    check("Debian 13 and 12 cloud images are appliances, beside the Debian 13 DVD id",
          d13 and d12 and d13.series == "trixie" and d12.series == "bookworm"
          and images.CATALOG["debian13"].kind != "linux" and images.CATALOG["debian13-cloud"].kind == "linux"
          and "debian13-cloud" in images.LINUX_IMAGES and "debian12" in images.LINUX_IMAGES)
    check("from the Debian cloud team's own directory, SHA512SUMS, its archive and security",
          d13.page == "https://cloud.debian.org/images/cloud/trixie/latest/"
          and d13.file == "debian-13-genericcloud-amd64.qcow2" and d13.sums == "SHA512SUMS"
          and d13.manifest == "debian-13-genericcloud-amd64.json" and d13.archive == "https://deb.debian.org/debian"
          and d13.security == "https://security.debian.org/debian-security" and d13.components == ("main",)
          and d12.file == "debian-12-genericcloud-amd64.qcow2")
    sha512 = "c" * 128
    sums = f"{sha512}  {d13.file}\n{'d' * 128}  debian-13-genericcloud-amd64.raw\n"
    check("a SHA-512 line is read by file name", appliances.parse_sums(sums, d13.file) == sha512)
    check("a JSON build manifest gives its package names",
          appliances._manifest_names('{"apiVersion": "v1", "items": [{"data": {"packages": '
                                     '[{"name": "libc6", "version": "2.41"}, {"name": "cloud-init"}]}}]}')
          == {"libc6", "cloud-init"} and appliances._manifest_names("{}") == set()
          and appliances._manifest_names("{broken") == set())
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "x.bin"
        f.write_bytes(b"winlab")
        want = hashlib.sha512(b"winlab").hexdigest()
        check("downloads are verified by SHA-512 when that is what the publisher gives",
              bootstrap._digest(f, want) == want and bootstrap._sha256(f) == hashlib.sha256(b"winlab").hexdigest())
        saved_runtime, saved_env = paths.RUNTIME, os.environ.get("WINLAB_IMAGES")
        os.environ["WINLAB_IMAGES"] = str(Path(td) / "images")
        paths.RUNTIME = Path(td) / "runtime"
        try:
            got = []

            def fake_download(url, dest, expect_sha="", label=""):
                got.append((url, expect_sha))
                dest.write_bytes(b"QFI\xfb" + b"\0" * 4000)
                return dest

            def no_manifest(url):
                if url.endswith("SHA512SUMS"):
                    return sums.encode()
                raise bootstrap.BootstrapError("404")

            appliances.fetch("debian13-cloud", get=no_manifest, download=fake_download)
            meta = images.base_meta("debian13-cloud")
            check("the image is fetched against its SHA-512; a missing build manifest is not fatal",
                  got == [(d13.page + d13.file, sha512)] and meta.get("sha512") == sha512
                  and not meta.get("sha256") and appliances.installed_packages("debian13-cloud") == set())
        finally:
            paths.RUNTIME = saved_runtime
            if saved_env is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved_env


def test_real_gui_nas_omv_pack():
    """OpenMediaVault as a pack: its own apt repository beside Debian's,
    each index checked against its Release file, pinned to 8.x."""
    import gzip
    import hashlib
    import lzma
    import os
    from winlab import appliances, debpacks, paths
    from winlab.bootstrap import BootstrapError
    pk = debpacks.PACKS["omv"]
    check("the omv pack: OpenMediaVault 8 (synchrony) for the Debian 13 image, for the nas role",
          pk.image == "debian13-cloud" and pk.packages == ("openmediavault-keyring", "openmediavault")
          and pk.roles == ("nas",) and pk.repos == (("https://packages.openmediavault.org/public", "synchrony", ("main",)),)
          and pk.verify_release and pk.pins == (("openmediavault", "8."),))
    app = appliances.get_or_raise("debian13-cloud")
    urls = [u for _, u in debpacks.index_urls(app, pk.repos)]
    check("indexes: trixie, trixie-updates, trixie-security, then OpenMediaVault's",
          urls == ["https://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.gz",
                   "https://deb.debian.org/debian/dists/trixie-updates/main/binary-amd64/Packages.gz",
                   "https://security.debian.org/debian-security/dists/trixie-security/main/binary-amd64/Packages.gz",
                   "https://packages.openmediavault.org/public/dists/synchrony/main/binary-amd64/Packages.gz"], str(urls))
    text = "Package: x\nVersion: 1\n"
    check("xz indexes are read too", debpacks._unpack_index(lzma.compress(text.encode())) == text
          and debpacks._unpack_index(gzip.compress(text.encode())) == text and debpacks._unpack_index(text.encode()) == text)
    sha = hashlib.sha256(text.encode()).hexdigest()
    release = (f"Origin: openmediavault\nSuite: synchrony\nMD5Sum:\n {'0' * 32} 20 main/binary-amd64/Packages\n"
               f"SHA256:\n {sha} {len(text)} main/binary-amd64/Packages\n {'e' * 64} 99 main/binary-arm64/Packages\n")
    url = "https://packages.openmediavault.org/public/dists/synchrony/main/binary-amd64/Packages.gz"
    check("Release's SHA256 section is read", debpacks.release_hashes(release)
          == {"main/binary-amd64/Packages": sha, "main/binary-arm64/Packages": "e" * 64})
    debpacks.check_release(release, url, gzip.compress(text.encode()))
    check("an index that matches its Release passes (its text against the plain entry)", True)
    try:
        debpacks.check_release(release, url, gzip.compress(b"Package: evil\n"))
        check("an index that does not match its Release is refused", False)
    except debpacks.PackError as exc:
        check("an index that does not match its Release is refused", "Release" in str(exc))

    def stanza(name, version, deps="", prio="optional", pool="pool/main"):
        return (f"Package: {name}\nVersion: {version}\nPriority: {prio}\n" + (f"Depends: {deps}\n" if deps else "")
                + f"Filename: {pool}/{name}_{version}_amd64.deb\nSize: 10\nSHA256: {'a' * 64}\n\n")
    debian = stanza("libc6", "2.41-12", prio="required") + stanza("samba", "4.22", "libc6") + stanza("nginx", "1.26")
    omv8 = stanza("openmediavault", "8.0.4-1", "samba, nginx, openmediavault-keyring") + stanza("openmediavault-keyring", "1.0")

    def make_get(omv_index):
        def body(u):
            return omv_index if "openmediavault" in u else debian if "/dists/trixie/" in u else ""

        def get(u):
            if u.endswith("/Release"):
                b = body(u)
                return f"SHA256:\n {hashlib.sha256(b.encode()).hexdigest()} {len(b)} main/binary-amd64/Packages\n".encode()
            if u.endswith("Packages.gz"):
                return gzip.compress(body(u).encode())
            raise BootstrapError("404 " + u)
        return get

    with tempfile.TemporaryDirectory() as td:
        saved_runtime, saved_env = paths.RUNTIME, os.environ.get("WINLAB_IMAGES")
        os.environ["WINLAB_IMAGES"] = str(Path(td) / "images")
        paths.RUNTIME = Path(td) / "runtime"
        try:
            img = appliances.image_path("debian13-cloud")
            img.parent.mkdir(parents=True, exist_ok=True)
            img.write_bytes(b"QFI\xfb")
            debs = []

            def dl(u, dest, expect_sha="", label=""):
                debs.append(u)
                dest.write_bytes(b"!<arch>\n")
                return dest
            man = debpacks.fetch("omv", get=make_get(omv8), download=dl)
            names = sorted(p["name"] for p in man["packages"])
            check("resolved across both archives; with no image manifest, Priority: required counts as there",
                  names == ["nginx", "openmediavault", "openmediavault-keyring", "samba"]
                  and any(u.startswith("https://packages.openmediavault.org/public/pool/") for u in debs)
                  and any(u.startswith("https://deb.debian.org/debian/pool/") for u in debs), str(names))
            shutil_rm = __import__("shutil").rmtree
            shutil_rm(paths.RUNTIME / "cache", ignore_errors=True)
            try:
                debpacks.fetch("omv", get=make_get(omv8.replace("8.0.4-1", "9.0.1-1")), download=dl)
                check("a repository that moved to another major version is refused (the pin)", False)
            except debpacks.PackError as exc:
                check("a repository that moved to another major version is refused (the pin)", "pinned" in str(exc))
        finally:
            paths.RUNTIME = saved_runtime
            if saved_env is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved_env







# ===== real GUIs: phone system (FreePBX) and IP phones (GNOME Calls) =====
def _voip_fake_key() -> tuple[str, bytes]:
    """An armoured OpenPGP public key block around one v4 key packet."""
    import base64
    from winlab import voip
    body = b"\x04" + (1700000000).to_bytes(4, "big") + b"\x01" + b"\x00\x08\xff" + b"\x00\x08\x03"
    packet = bytes([0xC6, len(body)]) + body
    crc = base64.b64encode(voip._crc24(packet).to_bytes(3, "big")).decode()
    armour = ("-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: test\n\n"
              + base64.b64encode(packet).decode() + "\n=" + crc + "\n-----END PGP PUBLIC KEY BLOCK-----\n")
    return armour, packet


def test_real_gui_voip_roles():
    """The phone system is FreePBX on Debian 12 from the freepbx pack, the
    phones GNOME Calls on Alpine; neither is told an extension, a server or
    a password, and the old panels are gone."""
    from winlab import alpineovl, debpacks, paths, roles
    man = roles.load_manifest()
    pbx, ph = man["pbx"], man["ipphone"]
    check("the phone system is a Debian 12 role with the freepbx pack",
          pbx.image == "debian12" and pbx.pack == "freepbx" and not pbx.apk
          and debpacks.PACKS["freepbx"].image == "debian12" and debpacks.PACKS["freepbx"].roles == ("pbx",))
    check("the phone is an Alpine role whose packages are on the package volume, Asterisk and pjsua gone",
          ph.image == "alpine" and "calls" in ph.apk and "cage" in ph.apk
          and set(ph.apk) <= set(alpineovl.APPLIANCE_PACKAGES)
          and "asterisk" not in alpineovl.APPLIANCE_PACKAGES and "pjsua" not in alpineovl.APPLIANCE_PACKAGES
          and len(alpineovl.APPLIANCE_PACKAGES) == len(set(alpineovl.APPLIANCE_PACKAGES))
          and {"pbx", "ipphone"} <= set(roles.SELF_STARTING))
    pbx_sh = (paths.ROLES / "pbx.sh").read_text(encoding="utf-8")
    ph_sh = (paths.ROLES / "ipphone.sh").read_text(encoding="utf-8")
    listed = pbx_sh.split('pkgs="', 1)[1].split('"', 1)[0].split()
    check("pbx.sh installs exactly the pack's packages", tuple(listed) == debpacks.PACKS["freepbx"].packages,
          str(set(listed) ^ set(debpacks.PACKS["freepbx"].packages)))
    sig, apt = pbx_sh.index("gpgv --keyring"), pbx_sh.index("install $pkgs")
    check("Sangoma's signature, its index and every Sangoma .deb are checked before apt installs",
          sig < apt and pbx_sh.index("sha256sum -c --quiet \"$work/sangoma.sha256\"") < apt
          and "--output \"$work/Release\"" in pbx_sh and "main/binary-amd64/Packages" in pbx_sh
          and pbx_sh.index("$tarball.sha256") < pbx_sh.index("tar -xzf"))
    check("FreePBX's own installer from the tarball, Asterisk as its own user, started at boot",
          "./install -n" in pbx_sh and "asterisk -U asterisk -G asterisk" in pbx_sh
          and "ExecStart=/usr/sbin/fwconsole start" in pbx_sh and "systemctl enable freepbx" in pbx_sh
          and "APACHE_RUN_USER=asterisk" in pbx_sh)
    check("factory state: no administrator, extension, trunk or lab password made by winlab",
          "WINLAB_ADMIN_PASSWORD" not in pbx_sh and "ampusers" not in pbx_sh and "INSERT" not in pbx_sh
          and "fwconsole extension" not in pbx_sh.lower() and "bulkimport" not in pbx_sh
          and "ma downloadinstall" not in pbx_sh and "upgradeall" not in pbx_sh)
    check("the phone: Calls with its SIP provider, full screen in cage, silent, nothing pre-set",
          "gnome-calls -p sip" in ph_sh and "cage -s" in ph_sh and "CALLS_AUDIOSINK=fakesink" in ph_sh
          and "WINLAB_EXT" not in ph_sh and "WINLAB_PBX" not in ph_sh and "WINLAB_ADMIN_PASSWORD" not in ph_sh
          and "sip-account.cfg" not in ph_sh and "pkill -f '[w]inlab-phone-ui'" in ph_sh
          and 'LABEL="phonedata"' in ph_sh)
    import re as _re
    check("no password-looking literal in the voice roles",
          not _re.search(r"(?i)(password|secret)\s*=\s*\S", pbx_sh + ph_sh))




def _voip_fake_publishers(tamper: bool = False):
    """get/download for the Debian archive, Sangoma's repository and the
    FreePBX mirror, all made up here."""
    import gzip
    import hashlib
    import io
    import tarfile
    from winlab import debpacks, voip
    from winlab.bootstrap import BootstrapError
    pack = debpacks.PACKS["freepbx"]
    deb_files: dict[str, bytes] = {}

    def stanzas(names, base):
        out = []
        for n in names:
            data = f"deb {n}".encode()
            fn = f"pool/main/{n}_1.0_amd64.deb"
            deb_files[f"{base}/{fn}"] = data
            out.append(f"Package: {n}\nVersion: 1.0\nPriority: optional\nFilename: {fn}\nSize: {len(data)}\n"
                       f"SHA256: {hashlib.sha256(data).hexdigest()}")
        return "\n\n".join(out) + "\n"
    ours = [p for p in pack.packages if p.startswith("asterisk")]
    debian = [p for p in pack.packages if p not in ours]
    sangoma_root = voip.FREEPBX_REPO
    files: dict[str, bytes] = {}

    def suite(root, s, text, signed=False, served_text=None):
        gz = gzip.compress(text.encode())
        files[f"{root}/dists/{s}/main/binary-amd64/Packages.gz"] = gzip.compress((served_text or text).encode())
        rel = (f"Suite: {s}\nSHA256:\n {hashlib.sha256(text.encode()).hexdigest()} 1 main/binary-amd64/Packages\n"
               f" {hashlib.sha256(gz).hexdigest()} 1 main/binary-amd64/Packages.gz\n")
        files[f"{root}/dists/{s}/Release"] = rel.encode()
        if signed:
            files[f"{root}/dists/{s}/InRelease"] = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + rel
                                                    + "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n").encode()
    suite("https://deb.debian.org/debian", "bookworm", stanzas(debian, "https://deb.debian.org/debian"))
    suite("https://deb.debian.org/debian", "bookworm-updates", "")
    suite("https://security.debian.org/debian-security", "bookworm-security", "")
    sangoma = stanzas(ours, sangoma_root)
    suite(sangoma_root, "bookworm", sangoma, signed=True)
    if tamper:
        # The unsigned Release agrees with what is served, but the signed
        # InRelease names another index: someone in between changed both.
        other = sangoma.replace(hashlib.sha256(b"deb asterisk22").hexdigest(), "f" * 64)
        rel = f"Suite: bookworm\nSHA256:\n {hashlib.sha256(other.encode()).hexdigest()} 1 main/binary-amd64/Packages\n"
        files[f"{sangoma_root}/dists/bookworm/InRelease"] = (
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + rel
            + "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n").encode()
    armour, _ = _voip_fake_key()
    files[voip.FREEPBX_KEY_URL] = armour.encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in (("freepbx/install", b"#!/usr/bin/env php\n"),
                           ("freepbx/module.xml", b"<module><version>17.0.33.5</version></module>")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    files[voip.FREEPBX_MIRROR + voip.FREEPBX_TARBALL] = buf.getvalue()
    files.update(deb_files)
    asked: list[str] = []

    def get(url, timeout=120):
        asked.append(url)
        if url not in files:
            raise BootstrapError(f"404 {url}")
        return files[url]

    def download(url, dest, expect_sha="", label=""):
        asked.append(url)
        data = files[url]
        if expect_sha and hashlib.sha256(data).hexdigest() != expect_sha:
            raise BootstrapError("checksum mismatch")
        dest.write_bytes(data)
        return dest
    return get, download, asked








# ===== real GUIs: Webmin, Roundcube, Grafana, Wireshark =====
def test_realgui_webmin_firmware():
    """Webmin on the Alpine appliances: the pinned release tarball fetched
    with its SHA-256 onto the repository volume, the webmin role that installs
    it onto the appliance's own disk with root on the lab's password, and the
    packages it needs."""
    import io
    import shutil
    import subprocess
    import tarfile
    from winlab import alpineovl, apkrepo, roles, paths, webmin

    check("Webmin is pinned to a release of its own GitHub, with a SHA-256",
          webmin.RELEASE.startswith("https://github.com/webmin/webmin/releases/download/")
          and re.fullmatch(r"[0-9a-f]{64}", webmin.TARBALL_SHA256) and re.fullmatch(r"[0-9a-f]{64}", webmin.DEB_SHA256)
          and webmin.TARBALL == f"webmin-{webmin.VERSION}.tar.gz" and webmin.LICENSE == "BSD-3-Clause")
    tmp = Path(tempfile.mkdtemp())
    real_store, real_size = webmin.store, webmin.TARBALL_SIZE
    try:
        webmin.store = lambda: tmp / "webmin"
        got = []

        def fake_download(url, dest, expect_sha="", label=""):
            got.append((url, expect_sha))
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"x" * 1000)
            return dest
        (tmp / "webmin").mkdir()
        (tmp / "webmin" / "webmin-1.0.tar.gz").write_bytes(b"old")
        webmin.fetch(download=fake_download)
        webmin.TARBALL_SIZE = 1000
        check("the fetch asks the release for the pinned tarball and checks its SHA-256; older ones go",
              got == [(f"{webmin.RELEASE}/{webmin.TARBALL}", webmin.TARBALL_SHA256)]
              and webmin.ready() and not (tmp / "webmin" / "webmin-1.0.tar.gz").exists())
        cache = tmp / "apk"
        for repo in apkrepo.REPOS:
            d = cache / repo / apkrepo.ARCH
            d.mkdir(parents=True)
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                data = b"P:alpine-base\nV:1\n\n"
                ti = tarfile.TarInfo("APKINDEX")
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
            (d / apkrepo.INDEX).write_bytes(buf.getvalue())
        img = apkrepo.build_image(cache, tmp / "repo.img")
        raw = img.read_bytes()
        check("the repository volume carries the tarball beside the packages, outside the boot repositories",
              webmin.volume_files() == [(f"webmin/{webmin.TARBALL}", tmp / "webmin" / webmin.TARBALL)]
              and webmin.TARBALL.upper()[:6].encode() in raw.upper() and b"x" * 1000 in raw)
    finally:
        webmin.store, webmin.TARBALL_SIZE = real_store, real_size
        shutil.rmtree(tmp, ignore_errors=True)
    check("not fetched: nothing extra on the volume", webmin.volume_files() == [] or webmin.ready())

    man = roles.load_manifest()
    sh = (paths.ROLES / "webmin.sh").read_text(encoding="utf-8")
    check("the webmin role: an Alpine role with Perl, Net::SSLeay, IO::Tty and openssl; the array and the "
          "NTP server need it",
          man["webmin"].image == "alpine" and set(man["webmin"].apk) >= {"perl", "perl-net-ssleay", "perl-io-tty", "openssl"}
          and set(man["webmin"].apk) <= set(alpineovl.APPLIANCE_PACKAGES)
          and "webmin" in man["san"].needs and "webmin" in man["ntp-server"].needs)
    from types import SimpleNamespace as NS
    check("an appliance's packages include what the roles it needs ask for",
          {"perl", "openssl", "scsi-tgt"} <= set(roles.apk_packages(NS(roles=["san"])))
          and "perl" in roles.apk_packages(NS(roles=["ntp-server"])))
    check("it installs from the volume with Webmin's own setup.sh: https 10000, root, the lab's password hashed",
          "./setup.sh" in sh and "port=10000" in sh and "login=root" in sh and "ssl=1" in sh
          and 'crypt="$hash"' in sh and "WINLAB_ADMIN_PASSWORD" in sh and "/media/*/webmin/webmin-*.tar.gz" in sh
          and "atboot=0" in sh and "/etc/webmin/start" in sh)
    check("it keeps its software and settings on the appliance's own disk, never formatting one in use",
          "WLFLASH" in sh and "mkfs.ext4" in sh and "SANBAY" in sh and "blkid -p" in sh
          and "winlab-keep /etc/webmin/ /var/webmin/" in sh)
    check("no password literal in the role", not re.search(r"password\s*=\s*['\"]", sh, re.I)
          and "password=" not in sh.replace("_", ""))
    if shutil.which("sh"):
        check("the webmin role parses as POSIX sh",
              subprocess.run(["sh", "-n"], input=sh, text=True, capture_output=True).returncode == 0)
    san_sh = (paths.ROLES / "san.sh").read_text(encoding="utf-8")
    check("the array sets Webmin's iSCSI TGTd module for Alpine's layout: targets.conf applied with tgt-admin",
          "/etc/webmin/iscsi-tgtd/config" in san_sh and "set_key config_file /etc/tgt/targets.conf" in san_sh
          and "set_key restart_cmd" in san_sh and "tgt-admin --update ALL" in san_sh)






def test_realgui_wireshark_stick():
    """The Wireshark stick: the Windows x64 installer from wireshark.org,
    checked against its release's SIGNATURES; Npcap never fetched."""
    import shutil
    from winlab import paths, webui, wireshark
    from winlab.bootstrap import BootstrapError
    sig = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nWireshark-4.6.9-x64.exe: 97931232 bytes\n"
           "SHA256(Wireshark-4.6.9-x64.exe)=" + "c" * 64 + "\nSHA1(Wireshark-4.6.9-x64.exe)=" + "d" * 40 + "\n"
           + "e" * 64 + "  Wireshark-4.6.9-arm64.exe\n")
    sums = wireshark.parse_signatures(sig)
    check("SIGNATURES files are read for their SHA-256 lines",
          sums["Wireshark-4.6.9-x64.exe"] == "c" * 64 and sums["Wireshark-4.6.9-arm64.exe"] == "e" * 64
          and len(sums) == 2)
    listing = ('<a href="Wireshark-4.6.9-x64.exe">x</a> <a href="Wireshark-4.4.19-x64.exe">x</a> '
               '<a href="Wireshark-4.7.1-x64.exe">dev</a> <a href="Wireshark-4.6.10-x64.exe">x</a>')
    check("the newest stable release from the directory: even minor versions only, 4.6.10 after 4.6.9",
          wireshark.newest_stable(listing) == "4.6.10" and wireshark.newest_stable("") == "")
    tmp = Path(tempfile.mkdtemp())
    real = wireshark.store
    try:
        wireshark.store = lambda: tmp / "ws"
        asked, got = [], []

        def fake_get(url, timeout=0):
            asked.append(url)
            if url.endswith("/win64/"):
                raise BootstrapError("offline")
            return sig.encode()

        def fake_download(url, dest, expect_sha="", label=""):
            got.append((url, expect_sha))
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"MZ installer")
            return dest
        m = wireshark.fetch(get=fake_get, download=fake_download)
        check("the pinned release when the directory cannot be read, its installer checked against SIGNATURES",
              m["version"] == wireshark.PINNED_VERSION and asked[-1].endswith(f"SIGNATURES-{wireshark.PINNED_VERSION}.txt")
              and got == [(f"{wireshark.WIN64}/Wireshark-4.6.9-x64.exe", "c" * 64)] and wireshark.ready())
        check("only the x64 installer is fetched: never Npcap",
              all("npcap" not in u.lower() for u, _ in got) and all("npcap" not in u.lower() for u in asked))
        files = wireshark.stick_files()
        rd = files["README.txt"].decode()
        check("the stick: the installer and a README that says plainly what Npcap is and what works without it",
              set(files) == {"Windows/Wireshark-4.6.9-x64.exe", "README.txt"} and "Npcap" in rd
              and "cannot capture from a network card" in rd and "capture probe" in rd and "never" in rd
              and "pcapng" in rd)
    finally:
        wireshark.store = real
        shutil.rmtree(tmp, ignore_errors=True)
    if not wireshark.ready():
        from types import SimpleNamespace as NS
        r = wireshark.act(NS(lab=NS(name="no-such-lab")), "wb-wireshark-stick", {})
        check("asked for a stick before the fetch: says so and offers the fetch", not r["ok"] and r["fetch"])
    check("Setup and the jobs know the fetch",
          "wireshark-fetch" in webui.JOB_INFO and "wireshark-fetch" in webui.AUTO_JOBS and "webmin-fetch" in webui.JOB_INFO)
    page = (paths.APP_DIR / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    check("the Images window and the media shelf offer it",
          "function wiresharkImgRow(" in page and "function wiresharkShelfBtn(" in page and "wb-wireshark-stick" in page)
    lic = (paths.APP_DIR / "LICENSING.md").read_text(encoding="utf-8")
    check("LICENSING lists Webmin, Roundcube, Wireshark, and that Npcap is never fetched or bundled",
          "| Webmin" in lic and "BSD-3-Clause" in lic and "| Roundcube" in lic and "GPL-3.0-or-later" in lic
          and "| Wireshark" in lic and "GPL-2.0-or-later" in lic and "| Npcap" in lic
          and "never fetched or bundled by winlab" in lic)


# ===== real GUIs: access point (OpenWrt), UPS card (NUT), server BMC =====
def _owrt_pkg(name, deps="", provides="", feed="base"):
    import hashlib
    data = f"ipk of {name}".encode()
    sha = hashlib.sha256(data).hexdigest()
    text = (f"Package: {name}\nVersion: 1.0-r1\nDepends: {deps}\n" + (f"Provides: {provides}\n" if provides else "")
            + f"Filename: {name}_1.0-r1_x86_64.ipk\nSize: {len(data)}\nSHA256sum: {sha}\n\n")
    return text, data


def test_real_guis_openwrt_fetch():
    """The OpenWrt image and the packages the APs and the UPS card need are
    fetched from downloads.openwrt.org at preparation: the image against the
    release's sha256sums, each package against its feed's index, the image's
    own packages left out, LuCI's add-on pages optional."""
    import gzip
    import hashlib
    import json
    import os
    from winlab import appliances, images, openwrt, paths

    text = "Package: a\nVersion: 1\nDepends: libc, b (>= 2), c | d\nFilename: x/a.ipk\nSHA256sum: " + "0" * 64 + "\n\n" \
           "Package: wpad-mbedtls\nProvides: wpad, hostapd\nFilename: w.ipk\n"
    idx = openwrt.parse_packages(text, "https://feed/")
    check("an opkg index: depends without versions and alternatives, provides, the file's URL",
          idx["a"].depends == ["libc", "b", "c"] and idx["wpad-mbedtls"].provides == ["wpad", "hostapd"]
          and idx["a"].url == "https://feed/x/a.ipk")

    feeds = {}
    blobs = {}
    def add(feed, name, deps="", provides=""):
        t, data = _owrt_pkg(name, deps, provides)
        feeds[feed] = feeds.get(feed, "") + t
        blobs[f"{name}_1.0-r1_x86_64.ipk"] = data
    kdir = "6.6.110-1-0123456789abcdef0123456789abcdef"
    add("kmods", "kmod-mac80211-hwsim", "kernel, kmod-mac80211")
    add("kmods", "kmod-mac80211", "kernel, kmod-cfg80211")
    add("kmods", "kmod-cfg80211", "kernel, wireless-regdb")
    add("base", "wireless-regdb")
    add("base", "wpad-mbedtls", "libc, hostapd-common, libmbedtls21", "wpad, hostapd")
    add("base", "hostapd-common")
    add("base", "libmbedtls21")
    add("base", "rpcd-mod-iwinfo", "libc, libiwinfo")
    add("packages", "nut-server", "nut-common")
    add("packages", "nut-common", "libc")
    add("packages", "nut-upsmon", "nut-common")
    add("packages", "nut-upsc", "nut-common")
    add("packages", "nut-web-cgi", "nut-common, libgd")
    add("packages", "libgd", "libc")
    add("packages", "nut-driver-dummy-ups", "nut-server")
    add("packages", "python3-light", "python3-base")
    add("packages", "python3-base", "libc")
    raw = b"\x00" * 4096 + b"OPENWRT" + b"\x00" * 4096
    img_gz = gzip.compress(raw) + b"\x00" * 300   # OpenWrt pads its gzip images
    sha = hashlib.sha256(img_gz).hexdigest()
    manifest = "libc - 1.2.5\nbusybox - 1.36\nlibiwinfo - 2024\nluci - 24.10\n"
    pages = {
        openwrt.TARGET + openwrt.SUMS: f"{'1' * 64} *other.img\n{sha} *{openwrt.IMAGE_FILE}\n".encode(),
        openwrt.TARGET + openwrt.MANIFEST_FILE: manifest.encode(),
        openwrt.KMODS_URL: f'<a href="{kdir}/">{kdir}/</a>'.encode(),
        openwrt.KMODS_URL + kdir + "/Packages": feeds["kmods"].encode(),
    }
    for f in openwrt.FEEDS:
        pages[openwrt.FEED_URL.format(feed=f) + "Packages"] = feeds.get(f, "").encode()
    asked, fetched = [], []

    def get(url):
        asked.append(url)
        if url not in pages:
            from winlab.bootstrap import BootstrapError
            raise BootstrapError(f"404 {url}")
        return pages[url]

    def download(url, dest, expect_sha="", label=""):
        name = url.rsplit("/", 1)[-1]
        data = img_gz if name == openwrt.IMAGE_FILE else blobs[name]
        if hashlib.sha256(data).hexdigest() != expect_sha:
            raise AssertionError(f"{name}: not the index's SHA-256")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        fetched.append(name)
        return dest

    def convert(src, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
        return dest

    saved = (paths.VAR, os.environ.get("WINLAB_IMAGES"))
    with tempfile.TemporaryDirectory() as td:
        paths.VAR = Path(td) / "var"
        os.environ["WINLAB_IMAGES"] = str(Path(td) / "images")
        try:
            said = []
            out = appliances.fetch("openwrt", progress=said.append, get=get, download=download, convert=convert)
            roles = openwrt.fetched_packages()["roles"]
            check("the image, verified against the release's sha256sums, unpacked past its padding",
                  out.exists() and out.read_bytes() == raw and openwrt.IMAGE_FILE in fetched)
            check("the AP's packages with their dependencies, dependencies first, the image's own left out",
                  roles["ap"][:4] == ["wireless-regdb_1.0-r1_x86_64.ipk", "kmod-cfg80211_1.0-r1_x86_64.ipk",
                                      "kmod-mac80211_1.0-r1_x86_64.ipk", "kmod-mac80211-hwsim_1.0-r1_x86_64.ipk"]
                  and any(r.startswith("wpad-mbedtls") for r in roles["ap"])
                  and not any(r.startswith("libiwinfo") for r in roles["ap"]), str(roles["ap"]))
            check("the card's NUT, with its CGI pages and the dummy-ups driver",
                  {r.split("_")[0] for r in roles["ups"]} >= {"nut-server", "nut-upsmon", "nut-web-cgi",
                                                             "nut-driver-dummy-ups", "nut-common", "libgd"})
            check("LuCI's NUT pages missing from the feed: said, and the card goes without them",
                  any("luci-app-nut" in s for s in said) and not any(r.startswith("luci-app-nut") for r in roles["ups"]))
            check("every package came from the release's feeds, each checked against its index",
                  all(u.startswith(openwrt.SITE) for u in asked) and "nut-server_1.0-r1_x86_64.ipk" in fetched
                  and (openwrt.packages_dir() / "nut-server_1.0-r1_x86_64.ipk").exists())
            meta = images.base_meta("openwrt")
            check("the base remembers its release and checksum", meta.get("version") == openwrt.RELEASE
                  and meta.get("sha256") == sha and meta.get("console") == "serial")
            pages[openwrt.FEED_URL.format(feed="packages") + "Packages"] = b""
            try:
                appliances.fetch("openwrt", get=get, download=download, convert=convert)
                check("a package the device cannot do without, missing: the fetch stops", False)
            except appliances.ApplianceError as exc:
                check("a package the device cannot do without, missing: the fetch stops", "nut-server" in str(exc), str(exc))
        finally:
            paths.VAR = saved[0]
            if saved[1] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[1]
    app = appliances.OPENWRT
    check("an appliance driven over its serial console, pinned to one release",
          appliances.console_driven("openwrt") and openwrt.RELEASE in app.file and app.page == openwrt.TARGET
          and images.CATALOG["openwrt"].kind == "linux")




def test_real_guis_openwrt_console():
    """OpenWrt's console has no base64 and no stty: commands go in as printf
    octal escapes, output comes back as hexdump, and the markers are typed in
    halves so the tty's echo never reads as one (a fake console that echoes
    every line and runs the command it rebuilt)."""
    import re as _re
    import socket
    import threading
    from winlab import consoleagent

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    seen = {"cmd": b""}

    def serve():
        conn, _ = srv.accept()
        conn.sendall(b"\r\nPlease press Enter to activate this console.")
        buf = b""
        while True:
            try:
                chunk = conn.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            while b"\r" in buf:
                line, buf = buf.split(b"\r", 1)
                conn.sendall(line + b"\r\n")                      # the tty echoes everything
                text = line.decode()
                if not text or text.startswith("PS1="):
                    conn.sendall(b"root@OpenWrt:~# " if not text else b"WLSH>>> ")
                    continue
                m = _re.match(r"printf '(.*)' >> /tmp/wl.cmd$", text)
                if m:
                    seen["cmd"] += bytes(int(o, 8) for o in _re.findall(r"\\([0-7]{3})", m.group(1)))
                elif text.startswith("sh /tmp/wl.cmd"):
                    out = ("ran: " + seen["cmd"].decode()).encode()
                    conn.sendall(b"@@RC=3@@\r\n" + out.hex().encode() + b"\r\n@@OUT@@\r\n" + b"oops".hex().encode()
                                 + b"\r\n@@END@@\r\nWLSH>>> ")
                    seen["cmd"] = b""
                conn.sendall(b"WLSH>>> ")
    threading.Thread(target=serve, daemon=True).start()
    con = consoleagent.OpenWrtConsole(port, "root", "")
    con.connect(retries=3, delay=0.2)
    try:
        cmd = "echo 'it''s' \"%d\" $HOME; printf '@@END@@'\nuci show wireless | grep -c ssid"
        rc, out, err = con.run(cmd, timeout=20)
        check("a command with quotes, a % and the marker itself comes through whole, and its answer back",
              rc == 3 and out == "ran: " + cmd and err == "oops", repr((rc, out, err)))
    finally:
        con.close()
        srv.close()
    check("the agent knows both consoles", consoleagent.CONSOLES["openwrt"] is consoleagent.OpenWrtConsole
          and consoleagent.OpenWrtConsole.OS == "OpenWrt")
    check("no marker is ever typed whole", "@@END@@" not in consoleagent.OpenWrtConsole.SHELL_SETUP
          and "WLSH>>>" not in consoleagent.OpenWrtConsole.SHELL_SETUP)






# ===== containers: Docker, a registry of your own, Windows containers, k3s air-gapped =====



# ===== kubeadm and the CKA: a cluster built by hand, etcd, upgrades, RBAC to Helm =====


# ===== databases: PostgreSQL and MariaDB beside SQL Server =====


# ===== dynamic routing: OSPF and BGP on routers the student builds =====


# ===== web filtering: the web-proxy lab (winlab/webproxy.py) =====


# ===== IPv6: addressing, RAs, DHCPv6, DNS and dual stack (winlab/ipv6.py) =====


# ===== intrusion detection: the intrusion-detection lab (winlab/ids.py) =====


# ===== remote access: working from home (winlab/remoteaccess.py) =====


# ===== automation at scale: Ansible and PowerShell DSC (winlab/automation.py) =====




# ===== Red Hat Enterprise Linux by hand, and Cockpit =====
def test_rhel_by_hand():
    """RHEL 9 and 10 are installed by hand from the user's own DVD (Red Hat
    hands it out only behind an account, so winlab never fetches it), told by
    its label or .treeinfo; RHEL and Rocky show Cockpit as their web console."""
    import os
    import tempfile
    from types import SimpleNamespace as NS
    from winlab import adminui, images, isowrite, linuxiso, paths, workbench
    for rid in ("rhel9", "rhel10"):
        d = linuxiso.DISTROS[rid]
        check(f"{rid} is import only, with how to get it", not d.folder and "developers.redhat.com" in d.page
              and "Developer Subscription" in d.get and images.CATALOG[rid].mode == images.IMPORT and d.repo)
        try:
            linuxiso.resolve(rid, get=lambda u: b"")
            check(f"{rid} is never fetched", False)
        except linuxiso.LinuxIsoError as exc:
            check(f"{rid} is never fetched", "cannot fetch" in str(exc) and f"images import {rid}" in str(exc))
        check(f"{rid}'s missing text says to import it", "images import " + rid in linuxiso.missing_text(rid))
    check("the shelf's Linux server offers RHEL 9 and 10",
          {"rhel9", "rhel10"} <= set(next(s for s in workbench.SHELF if s["id"] == "linux")["images"]))
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        def disc(name, label, tree):
            src = td / ("t-" + name)
            src.write_text(tree)
            w = isowrite.IsoWriter("x")
            w.volume_id = label
            w.add_file(src, ".treeinfo")
            return w.write(td / name)
        r9 = disc("rhel-9.6-x86_64-dvd.iso", "RHEL-9-6-0-BaseOS-x86_64",
                  "[general]\nfamily = Red Hat Enterprise Linux\nversion = 9.6\n")
        r10 = disc("odd-name.iso", "SOMETHING", "[general]\nfamily = Red Hat Enterprise Linux\nversion = 10.0\n")
        check("a RHEL 9 DVD is told by its label, RHEL 10 by its .treeinfo",
              linuxiso.detect(r9) == "rhel9" and linuxiso.detect(r10) == "rhel10")
        try:
            linuxiso.check_import("rocky9", r9)
            check("a RHEL DVD is refused as Rocky", False)
        except linuxiso.LinuxIsoError as exc:
            check("a RHEL DVD is refused as Rocky", "RHEL 9" in str(exc))
    lab = NS(node_list=lambda: [])
    for image in ("rhel9", "rhel10", "rocky9"):
        g = adminui.gui_of(lab, NS(id="lx1", kind="custom", image=image, roles=[], is_windows=False))
        check(f"{image} shows Cockpit on https 9090, off until the student turns it on",
              g is not None and g.software.startswith("Cockpit") and g.url("lx1") == "https://lx1:9090/"
              and "systemctl enable --now cockpit.socket" in g.note, str(g))
    check("no Cockpit on Ubuntu", adminui.gui_of(lab, NS(id="u", kind="custom", image="ubuntu24", roles=[],
                                                       is_windows=False)) is None)
    lic = (paths.APP_DIR / "LICENSING.md").read_text(encoding="utf-8")
    check("LICENSING: RHEL never fetched, the customer's own subscription, Cockpit's licence",
          "Red Hat Enterprise Linux 9 and 10" in lic and "never fetched or bundled" in lic
          and "LGPL-2.1-or-later" in lic)


# ===== real GUIs: server BMC (OpenBMC web UI) =====
def _sh_env(**extra):
    """The environment for running one of the router's scripts with this PC's
    sh: on Windows, Git's POSIX tools first on PATH, so find, sort and date
    are the ones busybox has on the router, not Windows' own commands of the
    same name."""
    import os
    import shutil
    env = {**os.environ, **extra}
    sh = shutil.which("sh")
    if os.name == "nt" and sh:
        here = Path(sh).resolve().parent
        tools = [str(d) for d in (here, here.parent / "usr" / "bin") if (d / "find.exe").exists()]
        env["PATH"] = os.pathsep.join(tools + [env.get("PATH", "")])
    return env


def _bmc_http(folder, method, path, body=b"", headers=None, peer="10.10.10.50"):
    """One request to content/agent/bmc.sh, the way tcpsvd runs it: (status
    line, headers as a list of (name, value), body bytes)."""
    import os
    import shutil
    import subprocess
    from winlab import paths
    h = f"{method} {path} HTTP/1.1\r\nHost: bmc\r\n"
    for k, v in (headers or {}).items():
        h += f"{k}: {v}\r\n"
    if body:
        h += f"Content-Length: {len(body)}\r\n"
    # the folder as the router names it: forward slashes (bmc.sh finds webui beside it with ${D%/*})
    res = subprocess.run([shutil.which("sh"), str(paths.CONTENT / "agent" / "bmc.sh"), Path(folder).as_posix()],
                         input=h.encode() + b"\r\n" + body, capture_output=True,
                         env=_sh_env(TCPREMOTEIP=peer))
    if not res.stdout.startswith(b"HTTP/"):
        print("    bmc.sh answered", res.stdout[:200], res.stderr.decode("utf-8", "replace")[:400])
    head, _, data = res.stdout.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", "replace").split("\r\n")
    hdrs = [tuple(x.split(": ", 1)) for x in lines[1:] if ": " in x]
    return lines[0], hdrs, data


def _bmc_folder(td):
    """A BMC's folder as power.render writes it, the toe tag made up now."""
    import base64
    import secrets
    folder = td / "bmc" / "SRV01"
    folder.mkdir(parents=True)
    tag = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
    facts = {"name": "SRV01", "user": "Administrator", "auth": base64.b64encode(f"Administrator:{tag}".encode()).decode(),
             "ip": "10.10.10.200", "mac": "02:54:00:12:34:56", "mask": "255.255.255.0", "gateway": "10.10.10.1",
             "cpus": "4", "memory": "6144", "power": "On", "health": "OK"}
    for k, v in facts.items():   # the router's files: LF line ends, whatever this PC writes
        (folder / k).write_text(v + "\n", newline="\n")
    (folder / "events").write_text("2026-10-29 10:00:00|Info|Server powered on\n"
                                   "2026-10-29 10:05:00|Critical|The operating system stopped responding (no heartbeat)\n",
                                   newline="\n")
    return folder, tag


def test_real_guis_bmc_redfish():
    """The BMC's Redfish API as OpenBMC's web UI uses it: the session (its
    token, its cookies and XSRF), the system and its power actions, the event
    log, the BMC and its port, the account; Redfish errors for the rest."""
    import json
    import shutil
    if not shutil.which("sh"):
        check("the BMC's Redfish API (no sh here: skipped)", True)
        return
    # Git's sh on Windows is bash outside POSIX mode (a bare "bash" there may
    # be WSL's launcher instead), so on Windows that sh is the bash to try
    import os
    bash = shutil.which("sh") if os.name == "nt" else shutil.which("bash")
    if bash:
        import subprocess
        from winlab import paths
        r = subprocess.run([bash, "-n", str(paths.CONTENT / "agent" / "bmc.sh")], capture_output=True, text=True)
        check("the BMC's script parses as bash too, not only as busybox sh", r.returncode == 0, r.stderr[:300])
    with tempfile.TemporaryDirectory() as td:
        folder, tag = _bmc_folder(Path(td))

        def call(method, path, body=None, headers=None):
            raw = json.dumps(body).encode() if isinstance(body, dict) else (body or b"")
            status, hdrs, data = _bmc_http(folder, method, path, raw, headers)
            try:
                doc = json.loads(data) if data else {}
            except ValueError:
                doc = {}
            return status, hdrs, doc
        st, _, root = call("GET", "/redfish/v1")
        check("the service root answers without a sign-in, OpenBMC's way",
              st.endswith("200 OK") and root["SessionService"]["@odata.id"] == "/redfish/v1/SessionService"
              and root["ManagerProvidingService"]["@odata.id"] == "/redfish/v1/Managers/bmc")
        st, hd, err = call("GET", "/redfish/v1/Systems/system")
        st2, hd2, _ = call("GET", "/redfish/v1/Systems/system", headers={"X-Requested-With": "XMLHttpRequest"})
        check("everything else asks for a sign-in: a Redfish error, and a Basic challenge only for scripts",
              st.endswith("401 Unauthorized") and err["error"]["code"].endswith("NoValidSession")
              and any(k == "WWW-Authenticate" for k, _ in hd) and not any(k == "WWW-Authenticate" for k, _ in hd2))
        st, _, _ = call("POST", "/redfish/v1/SessionService/Sessions", {"UserName": "Administrator", "Password": tag[::-1] + "x"})
        check("a wrong sign-in is refused and logged with who tried",
              st.endswith("401 Unauthorized") and "Login failure from 10.10.10.50" in (folder / "events").read_text())
        st, hd, sess = call("POST", "/redfish/v1/SessionService/Sessions", {"UserName": "Administrator", "Password": tag})
        hdr = {}
        cookies = {}
        for k, v in hd:
            hdr[k] = v
            if k == "Set-Cookie":
                cookies[v.split("=", 1)[0]] = v
        token = hdr.get("X-Auth-Token", "")
        xsrf = cookies.get("XSRF-TOKEN", "=;").split("=", 1)[1].split(";")[0]
        sess_cookie = cookies.get("SESSION", "=;").split("=", 1)[1].split(";")[0]
        check("the toe tag's sign-in makes a session: its Location, X-Auth-Token, an HttpOnly SESSION cookie and XSRF-TOKEN",
              st.endswith("201 Created") and hdr.get("Location", "").startswith("/redfish/v1/SessionService/Sessions/")
              and len(token) == 32 and "HttpOnly" in cookies.get("SESSION", "") and "HttpOnly" not in cookies.get("XSRF-TOKEN", "x")
              and sess["Roles"] == ["Administrator"] and sess["UserName"] == "Administrator"
              and "Login: Administrator signed in from 10.10.10.50" in (folder / "events").read_text())
        tok = {"X-Auth-Token": token}
        st, _, sysj = call("GET", "/redfish/v1/Systems/system", headers=tok)
        _, _, old = call("GET", "/redfish/v1/Systems/1", headers=tok)
        check("the system: power state, health, model, processors and memory, the reset types OpenBMC's pages send",
              st.endswith("200 OK") and sysj["PowerState"] == "On" and sysj["Status"]["Health"] == "OK"
              and sysj["ProcessorSummary"]["Count"] == 4 and sysj["MemorySummary"]["TotalSystemMemoryGiB"] == 6
              and {"On", "ForceOff", "GracefulShutdown", "GracefulRestart", "ForceRestart"}
              <= set(sysj["Actions"]["#ComputerSystem.Reset"]["ResetType@Redfish.AllowableValues"])
              and old["Id"] == "system")
        ck = {"Cookie": f"SESSION={sess_cookie}; XSRF-TOKEN={xsrf}; IsAuthenticated=true"}
        reset = "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset"
        st_get, _, _ = call("GET", "/redfish/v1/Managers/bmc", headers=ck)
        st_bad, _, _ = call("POST", reset, {"ResetType": "GracefulShutdown"}, headers=ck)
        check("the SESSION cookie reads; a change with it alone is refused (cross-site request forgery)",
              st_get.endswith("200 OK") and st_bad.endswith("401 Unauthorized") and not (folder / "queue").exists())
        st, _, _ = call("POST", reset, {"ResetType": "GracefulShutdown"}, headers={**ck, "X-XSRF-TOKEN": xsrf})
        check("with the X-XSRF-TOKEN the pages send, the graceful shutdown is queued for winlab and logged with who asked",
              st.endswith("200 OK") and (folder / "queue").read_text().split() == ["GracefulShutdown", "10.10.10.50"]
              and "Power: GracefulShutdown requested by Administrator from 10.10.10.50" in (folder / "events").read_text()
              and call("GET", "/redfish/v1/Systems/system", headers=tok)[2].get("LastResetTime", "").endswith("+00:00"))
        st, _, _ = call("POST", reset, {"ResetType": "Explode"}, headers=tok)
        check("a reset type Redfish does not list is refused", st.endswith("400 Bad Request"))
        st, _, _ = call("POST", reset, {"ResetType": "ForceRestart"}, headers={"Authorization": "Basic " + (folder / "auth").read_text().strip()})
        check("scripts sign in with HTTP Basic (Invoke-RestMethod -Credential), as before",
              st.endswith("200 OK") and "ForceRestart" in (folder / "queue").read_text())

        logs = "/redfish/v1/Systems/system/LogServices/EventLog/Entries"
        _, _, ent = call("GET", logs, headers=tok)
        crit = [m for m in ent["Members"] if m["Severity"] == "Critical"]
        check("the event log as LogEntry resources: Info is OK, the hang Critical, unresolved",
              ent["Members@odata.count"] >= 5 and ent["Members"][0]["Severity"] == "OK" and len(crit) == 1
              and crit[0]["Resolved"] is False and crit[0]["@odata.id"] == f"{logs}/2"
              and call("GET", "/redfish/v1/Managers/1/LogServices/IEL/Entries", headers=tok)[2]["Members@odata.count"]
              == ent["Members@odata.count"])
        st, _, _ = call("PATCH", f"{logs}/2", {"Resolved": True}, headers=tok)
        check("an entry marked resolved stays so", st.endswith("200 OK")
              and call("GET", f"{logs}/2", headers=tok)[2]["Resolved"] is True)
        before = (folder / "events").read_text()
        st1, _, _ = call("DELETE", f"{logs}/2", headers=tok)
        st2, _, e2 = call("POST", "/redfish/v1/Systems/system/LogServices/EventLog/Actions/LogService.ClearLog", headers=tok)
        check("the event log is the record: deleting or clearing it is refused, with a Redfish error",
              st1.startswith("HTTP/1.0 405") and st2.startswith("HTTP/1.0 405")
              and e2["error"]["code"].endswith("OperationNotAllowed") and (folder / "events").read_text() == before)

        _, _, eth = call("GET", "/redfish/v1/Managers/bmc/EthernetInterfaces/eth0", headers=tok)
        _, _, mgr = call("GET", "/redfish/v1/Managers/bmc", headers=tok)
        check("the BMC and its port: the toe tag's address, mask, gateway and MAC; its clock",
              eth["IPv4Addresses"][0] == {"Address": "10.10.10.200", "SubnetMask": "255.255.255.0", "Gateway": "10.10.10.1",
                                         "AddressOrigin": "Static"} and eth["MACAddress"] == "02:54:00:12:34:56"
              and mgr["ManagerType"] == "BMC" and mgr["DateTime"].endswith("+00:00"))
        st, _, _ = call("PATCH", "/redfish/v1/Systems/system", {"AssetTag": "RACK-7 U12", "LocationIndicatorActive": True}, headers=tok)
        _, _, sysj = call("GET", "/redfish/v1/Systems/system", headers=tok)
        check("the asset tag and the identify LED are set from the pages", st.endswith("200 OK")
              and sysj["AssetTag"] == "RACK-7 U12" and sysj["LocationIndicatorActive"] is True)
        _, _, acc = call("GET", "/redfish/v1/AccountService/Accounts", headers=tok)
        st, _, _ = call("POST", "/redfish/v1/AccountService/Accounts", {"UserName": "x", "RoleId": "Operator"}, headers=tok)
        check("the toe tag's account first; a user with no password of 8 to 20 characters is refused",
              [m["@odata.id"] for m in acc["Members"]] == ["/redfish/v1/AccountService/Accounts/Administrator"]
              and st.startswith("HTTP/1.0 400"))
        st, hd, e = call("GET", "/redfish/v1/CertificateService/CertificateLocations", headers=tok)
        st2, hd2, _ = call("PUT", "/redfish/v1/Managers/bmc", {"x": 1}, headers=tok)
        check("what this BMC does not have answers ResourceNotFound; a method it does not take, 405 with Allow",
              st.endswith("404 Not Found") and e["error"]["code"].endswith("ResourceNotFound")
              and st2.startswith("HTTP/1.0 405") and ("Allow", "GET,PATCH") in hd2)
        sid = hdr["Location"].rsplit("/", 1)[1]
        _, _, coll = call("GET", "/redfish/v1/SessionService/Sessions", headers=tok)
        st, _, _ = call("DELETE", hdr["Location"], headers=tok)
        check("the sessions page lists it; signing out deletes it and its token stops working",
              any(m["@odata.id"].endswith(sid) for m in coll["Members"]) and st.endswith("200 OK")
              and call("GET", "/redfish/v1/Systems/system", headers=tok)[0].endswith("401 Unauthorized"))


def test_real_guis_bmc_webui_files():
    """OpenBMC's web UI files served as built (gzipped ones with
    Content-Encoding), no sign-in for the app itself; winlab's own pages when
    it was not fetched."""
    import gzip
    import shutil
    if not shutil.which("sh"):
        check("the BMC's web files (no sh here: skipped)", True)
        return
    with tempfile.TemporaryDirectory() as td:
        folder, tag = _bmc_folder(Path(td))
        st, _, page = _bmc_http(folder, "GET", "/")
        check("without OpenBMC's UI the BMC keeps winlab's own pages, behind the toe tag",
              st.endswith("401 Unauthorized")
              and b"value=ForceRestart" in _bmc_http(folder, "GET", "/", headers={
                  "Authorization": "Basic " + (folder / "auth").read_text().strip()})[2])
        web = Path(td) / "bmc" / "webui"
        (web / "js").mkdir(parents=True)
        (web / "index.html").write_text("<!doctype html><title>OpenBMC</title><div id=app></div>")
        (web / "js" / "app.abc.js.gz").write_bytes(gzip.compress(b"console.log(1)", mtime=0))
        (web / ".version").write_text("openbmc-webui-x\n")
        st, hd, page = _bmc_http(folder, "GET", "/")
        check("with it, the app's page is served to anyone (the sign-in is the app's own page)",
              st.endswith("200 OK") and b"<div id=app>" in page and ("Cache-Control", "no-store") in hd)
        st, hd, js = _bmc_http(folder, "GET", "/js/app.abc.js")
        check("its gzipped files go as they are, with Content-Encoding, as bmcweb does",
              st.endswith("200 OK") and ("Content-Encoding", "gzip") in hd and gzip.decompress(js) == b"console.log(1)"
              and ("Content-Type", "text/javascript") in hd)
        check("nothing outside the app's files: no climbing out, no hidden files, no old pages",
              _bmc_http(folder, "GET", "/js/../../SRV01/auth")[0].endswith("404 Not Found")
              and _bmc_http(folder, "GET", "/.version")[0].endswith("404 Not Found")
              and _bmc_http(folder, "GET", "/log")[0].endswith("404 Not Found"))




# ===== VM host and ISOs by hand =====


# ===== the job: the lab's staff directory and the helpdesk store (winlab/people.py, helpdesk.py) =====



# ===== the job: the helpdesk queue (winlab/helpdesk.py) =====

# ===== the job: the staff's working day (winlab/workday.py, the Office window, the onboarding lesson) =====



# ===== the job: on-call alerting, the pager and the rota (winlab/alerts.py) =====


# ===== the admin's documentation tools: GLPI, DokuWiki, Vaultwarden (winlab/doctools.py) =====


# ===== the job: the rack (winlab/rack.py) and the admin toolkit stick (winlab/toolkit.py) =====


# ===== the job: the rack as a physical view (drawings, live lights, racking, cabling, sounds, the lesson) =====


# ===== the rack: a cable stays in the switch port it was plugged into (devcli.pin_port) =====


# ===== the inherited company (pre-built scenario) and the locked server room =====


# ===== real servers: more scenario days, and an engine that branches =====


# ===== real servers: wear on the lab clock, the start of shift, the company run =====


# ===== real servers: the load engine (winlab/traffic.py, workday's further actions, the Load tab) =====


# ===== file and print operations: migrations, audits, DFS-R, profiles, housekeeping, drills, runbooks (winlab/fileops.py) =====


# ===== real servers: identity (winlab/identityops.py, winlab/dcrollback.py) =====


# ===== security operations: WEF, Wazuh, Greenbone, baselines, software, certificates, reports (winlab/secops.py) =====


# ===== free play under load: Start-OfficeLoad inside a guest (winlab/freeload.py) =====


def _srv_freeload_checks(root):
    import base64
    import json
    from winlab import cli, freeload, helptopics, paths, schema, traffic, workday
    from winlab.model import Nic, Node
    lab = schema.load(root / "content" / "labs" / "sandbox.toml")
    lab.name = "fl-sandbox"
    for nid, kind in (("fs01", "windows-server"), ("web01", "windows-server"), ("pc02", "windows-client"),
                      ("mail01", "linux")):
        lab.nodes[nid] = Node(id=nid, image="ws2025" if kind != "linux" else "ubuntu", kind=kind, nics=[Nic("corp")])
    plan = workday.lab_facts(lab)
    check("before Start-OfficeLoad the sandbox has the plan's facts: no roles, nothing to load",
          "source" not in plan and plan["dc_node"] == "" and plan["files_node"] == ""
          and workday.plan_facts(lab) == plan and freeload.discovered_facts(lab.name) is None
          and workday.everyone(lab) == workday.directory.load(lab))

    # ---- the request the module leaves in the guest
    key = "Spring" + "Start-1"     # a lab-only first password, as typed at Read-Host
    req_text = "﻿" + json.dumps({"action": "start", "id": "abc-123", "level": "busy", "profile": "flat",
                                      "pace": "busyday", "group": "G-Staff", "shifts": False, "server_jobs": False,
                                      "computer": "PC01", "user": "CORP\\ron",
                                      "signin": base64.b64encode(key.encode()).decode()})
    r = freeload.parse_request(req_text)
    check("the request is read (a BOM from Windows PowerShell is fine), the secret kept apart",
          r["action"] == "start" and r["level"] == "busy" and r["profile"] == "flat" and r["pace"] == "busyday"
          and r["group"] == "G-Staff" and r["server_jobs"] is False and r["secret"] == key and r["user"] == "CORP\\ron")
    bad = []
    for raw in ('{"action": "format-c"}', '{"action": "start", "level": "insane"}', "[1]", "not json",
                json.dumps({"action": "start", "group": "G\nStaff"}), json.dumps({"action": "start", "signin": "%%%"})):
        try:
            freeload.parse_request(raw)
            bad.append(raw)
        except freeload.FreeloadError:
            pass
    check("a request with an unknown action, level, a control character or an unreadable secret is refused", not bad, str(bad))

    # ---- the poll: status in, request out, nothing made on a machine without the folder
    pc = freeload.poll_command({"ack": "", "state": "stopped", "message": "off"})
    host, text = freeload.parse_poll(True, f"{freeload.HOST_MARK} PC01\n{freeload.REQ_MARK} "
                                     + base64.b64encode(req_text.encode()).decode() + "\n")
    check("the poll writes status.json and takes request.json away, only where the module made the folder",
          "Test-Path -LiteralPath $d" in pc and "status.json" in pc and "Remove-Item -LiteralPath $r" in pc
          and freeload.GUEST_DIR.replace("\\", "\\") in pc and "New-Item" not in pc and host == "PC01" and text == req_text
          and freeload.parse_poll(True, "") == ("", None) and freeload.parse_poll(False, "x") == ("", None))
    disc_cmd = freeload.discover_command("G-Staff*", "O'Brien")
    inv_cmd = freeload.inventory_command()
    scripts = {"poll": pc, "discover": disc_cmd, "inventory": inv_cmd}
    probs = {k: _ps51_problems(v) for k, v in scripts.items() if _ps51_problems(v)}
    check("the commands sent over the agent parse under Windows PowerShell 5.1, no top-level return or exit",
          not probs and not [k for k, v in scripts.items() if re.search(r"(?m)^\s*(return|exit)\b", v)], str(probs))
    check("discovery only reads: no Set-, New-AD, Add-, Remove-, Install- or Enable- in it",
          not re.search(r"\b(Set-\w+|New-AD\w+|Add-\w+|Remove-\w+|Install-\w+|Enable-\w+|New-SmbShare)\b",
                        disc_cmd + inv_cmd))
    check("the group and OU names from the guest are escaped for LDAP and for PowerShell",
          "G-Staff\\2a" in disc_cmd and "'O''Brien'" in disc_cmd)
    check("discovery asks the domain, nltest, the SRV records, the directory, MX, DNS names and the WSUS policy",
          all(x in disc_cmd for x in ("GetComputerDomain", "nltest.exe", "_ldap._tcp.dc._msdcs.", "objectCategory=computer",
                                      "objectCategory=printQueue", "MSSQLSvc", "-Type MX", "WUServer", "1.2.840.113556.1.4.1941"))
          and all(x in inv_cmd for x in ("Get-SmbShare", "Get-Printer", "Get-WebBinding", "MSSQL", "RDS-RD-Server", "WsusService")))

    # ---- discovery: the network the student built, under names they chose
    disc = {"computer": "PC01", "domain": "corp.lab", "netbios": "CORP", "dcs": ["dc01.corp.lab"], "pdc": "dc01.corp.lab",
            "nltest": "dc01.corp.lab", "srv": "dc01.corp.lab", "errors": None,
            "computers": [{"name": "dc01"}, {"name": "files"}, {"name": "intra"}, {"name": "pc01"}, {"name": "pc02"},
                          {"name": "oldbox"}],
            "staff": [{"account": "ron", "first": "Ron", "last": "Admin"},
                      {"account": "AGreen", "first": "Alice", "last": "Green", "name": "Alice Green", "department": "Finance",
                       "title": "Accountant", "mail": "alice@corp.lab", "phone": "+1 555 0142"},
                      {"account": "bwhite", "name": "Bob White"}, {"account": "PC01$"}],
            "staff_from": "group CN=G-Staff,OU=Staff,DC=corp,DC=lab",
            "printers": {"name": "Floor1", "server": "files.corp.lab"},
            "mx": "mail01.corp.lab", "names": [{"name": "intranet", "cname": "intra.corp.lab", "ips": None}],
            "sqlspn": ["mssqlsvc/files.corp.lab:1433"], "wsus": "http://files.corp.lab:8530"}
    invs = {
        "srv01": {"computer": "DC01", "domain": "corp.lab", "member": True, "type": 2, "ips": "10.20.0.11",
                  "shares": ["NETLOGON", "SYSVOL"], "printers": None, "web": None, "sql": None},
        "fs01": {"computer": "FILES", "domain": "corp.lab", "member": True, "type": 3, "ips": ["10.20.0.12"],
                 "shares": ["Company", "Home$", "print$"], "printers": "Floor1", "sql": "MSSQLSERVER", "rds": True, "wsus": True},
        "web01": {"computer": "INTRA", "domain": "corp.lab", "member": True, "type": 3, "ips": ["10.20.0.13"],
                  "shares": [], "web": ["http *:80:"]},
        "pc01": {"computer": "PC01", "domain": "corp.lab", "member": True, "type": 1, "shares": []},
        "pc02": {"computer": "PC02", "domain": "workgroup", "member": False, "type": 1},
    }
    hm = freeload.host_map(lab, invs)
    check("computer names map back to the lab's machines, the name given inside Windows first",
          hm["dc01"] == "srv01" and hm["files"] == "fs01" and hm["intra"] == "web01" and hm["srv01"] == "srv01"
          and hm["mail01"] == "mail01")
    f = freeload.build_facts(lab, disc, invs)
    check("the facts the engine uses, marked discovered: DC, file server and its company share, printing, mail by MX",
          f["source"] == "discovered" and f["domain"] == "corp.lab" and f["netbios"] == "CORP"
          and f["dc"] == "dc01" and f["dc_node"] == "srv01" and f["dc_addr"] == "dc01.corp.lab" and f["dc_nodes"] == ["srv01"]
          and f["files"] == "files" and f["files_node"] == "fs01" and f["company"] == "Company" and f["shares"] == ["Company"]
          and f["printserver"] == "files" and f["printserver_node"] == "fs01"
          and f["mail"] == "mail01.corp.lab" and f["mail_node"] == "mail01", str(f))
    check("the intranet by the DNS name the student made, SQL, the session host and WSUS where they run",
          f["intranet"] == "intranet.corp.lab" and f["intranet_node"] == "web01" and f["sites"] == []
          and f["sql"] == "files.corp.lab" and f["sql_node"] == "fs01" and f["rds_node"] == "fs01" and f["wsus_node"] == "fs01"
          and f["wsus"] == "files", str(f))
    check("the PCs are the domain's running workstations (a PC still in a workgroup is not), unknown computers listed",
          f["pcs"] == ["pc01"] and set(f["windows"]) == {"srv01", "fs01", "web01", "pc01"} and f["unmatched"] == ["oldbox"]
          and set(workday.plan_facts(lab)) == set(f) - {"shares", "unmatched", "source", "hosts"}
          and f["hosts"]["srv01"] == "dc01", str(set(f) ^ set(plan)))
    staff = freeload.build_staff(disc, f, "CORP\\ron")
    check("the staff are the group's people: not the admin who typed the command, not a computer account",
          [p["id"] for p in staff] == ["agreen", "bwhite"] and staff[0]["department"] == "Finance" and staff[0]["ext"] == 142
          and staff[1]["department"] == "Company" and staff[1]["first"] == "Bob" and staff[1]["mail"] == "bwhite@corp.lab"
          and all(not p["admin"] and p["source"] == "discovered" for p in staff), str(staff))
    run_all = {"srv01", "fs01", "web01", "pc01", "pc02", "mail01"}
    check("with those facts the staff save, print, mail, browse, run reports and reach the session host",
          set(workday.available(f, run_all)) == {"share", "home", "print", "mail", "intranet"}
          and set(workday.available_more(f, run_all)) == {"lookup", "document", "bigcopy", "sql", "rdp"})
    bg_nodes = {bg.id: traffic.targets(bg, f, run_all) for bg in traffic.BACKGROUND.values()}
    check("the servers' own work only where a server for it was found",
          all(set(v) <= set(f["windows"]) for v in bg_nodes.values()) and any(v == ["fs01"] for v in bg_nodes.values()),
          str(bg_nodes))
    found, missing = freeload.found_lines(lab, f, staff, disc)
    check("what was found, in words", any("domain corp.lab (CORP), domain controller DC01 (srv01)" in x for x in found)
          and any("file server FILES (fs01): shares Company" in x for x in found) and any(x.startswith("staff: 2 from group") for x in found)
          and missing == [], str((found, missing)))
    f0 = freeload.build_facts(lab, {**disc, "domain": ""}, invs)
    probs = {
        "no domain": freeload.problem(f0, staff, {**disc, "domain": ""}, "PC01"),
        "silent": freeload.problem(f, staff, {"silent": True}, "PC01"),
        "no dc": freeload.problem(freeload.build_facts(lab, {**disc, "dcs": [], "pdc": "", "nltest": "", "srv": []},
                                                       {k: v for k, v in invs.items() if k != "srv01"}), staff, disc, "PC01"),
        "dc off": freeload.problem(freeload.build_facts(lab, disc, {k: v for k, v in invs.items() if k != "srv01"}), staff, disc, "PC01"),
        "no group": freeload.problem(f, [], {**disc, "errors": ["nogroup G-Nope"]}, "PC01"),
        "no staff": freeload.problem(f, [], disc, "PC01"),
        "no pcs": freeload.problem({**f, "pcs": []}, staff, disc, "PC01"),
    }
    check("clear reasons when there is nothing to load",
          "PC01 is not in a domain" in probs["no domain"] and "did not answer" in probs["silent"]
          and probs["no dc"] == "Nothing to load: no domain controller answered for corp.lab."
          and "DC01 is not a running machine" in probs["dc off"] and "no group of that name" in probs["no group"]
          and probs["no staff"].startswith("Nothing to load: no staff found") and "no running Windows PC" in probs["no pcs"]
          and freeload.problem(f, staff, disc, "PC01") == "", str(probs))

    # ---- the whole round trip with a fake runner: the request, discovery, the engine, the answer
    sent: list[tuple[str, str]] = []
    pending = {"pc01": req_text}
    answers = {"disc": disc}

    def runner(node, cmd, shell):
        sent.append((node, cmd))
        if freeload.HOST_MARK in cmd:
            if node not in invs:
                return True, ""
            out = f"{freeload.HOST_MARK} {invs[node]['computer']}\n"
            if node in pending:
                out += f"{freeload.REQ_MARK} " + base64.b64encode(pending.pop(node).encode()).decode() + "\n"
            return True, out
        if "GetComputerDomain" in cmd:
            return True, f"noise\n{freeload.BEGIN}\n{json.dumps(answers['disc'])}\n{freeload.END}\n"
        if "Win32_ComputerSystem" in cmd:
            return (True, f"{freeload.BEGIN}\n{json.dumps(invs[node])}\n{freeload.END}") if node in invs else (False, "no agent")
        return False, "unexpected"

    def statuses(node):
        out = []
        for n, c in sent:
            m = re.search(r"FromBase64String\('([^']+)'\)", c)
            if n == node and freeload.HOST_MARK in c and m:
                out.append(json.loads(base64.b64decode(m.group(1))))
        return out

    check("no polling in a lab that never had the stick or a start from inside", not freeload.wants_poll(lab))
    every0 = schema.load(root / "content" / "labs" / "every-role.toml")
    first = freeload.offer_stick(lab)
    sticks0 = sorted((paths.lab_dir(lab.name) / "media" / "sticks").glob("*.img"))
    check("a free-play lab gets the Load engine stick on its shelf the first time it opens, once, plugged into nothing",
          first and freeload.load(lab.name)["stick"] == first and len(sticks0) == 1 and freeload.wants_poll(lab)
          and freeload.offer_stick(lab) == "" and not freeload.offer_stick(every0)
          and not freeload.load(every0.name).get("stick")
          and not (paths.lab_dir(lab.name) / "nodes").exists(), str(sticks0))
    stick = freeload.to_stick(lab.name)
    shelf = paths.lab_dir(lab.name) / "media" / "sticks"
    mf = freeload.module_files()
    check("the Load engine stick: the module, an installer and a README on the media shelf; polling from now on",
          (shelf / f"{stick['id']}.img").is_file() and freeload.wants_poll(lab)
          and set(mf) == {"OfficeLoad/OfficeLoad.psm1", "OfficeLoad/OfficeLoad.psd1", "Install.ps1", "README.txt"}
          and json.loads((shelf / f"{stick['id']}.json").read_text())["title"] == freeload.STICK_TITLE)
    done = freeload.poll(lab, runner, run_all)
    wd = workday.load(lab.name)
    ts = traffic.load(lab.name)
    st = freeload.load(lab.name)
    found_disk = json.loads(freeload.found_file(lab.name).read_text())
    check("the request starts the engine on what was found: workday at its level, the profile, a busy day, no server jobs",
          len(done) == 1 and done[0]["state"] == "running" and wd["on"] and wd["level"] == "busy" and wd["sheet"] == "free play"
          and ts["profile"] == "flat" and ts["busy"].get("day") and ts["background"] is False, str(done))
    check("discovered facts and staff stored in the lab's folder; lab_facts and the staff list use them",
          workday.lab_facts(lab)["source"] == "discovered" and workday.lab_facts(lab)["files_node"] == "fs01"
          and [p["id"] for p in workday.everyone(lab)] == ["agreen", "bwhite"]
          and [r["account"] for r in workday.staff_rows(lab)] == ["AGreen", "bwhite"] and found_disk["origin"] == "pc01")
    check("the typed password went only into the lab's staff secrets, for each person who had none",
          workday.load_secrets(lab.name) == {"agreen": key, "bwhite": key}
          and key not in freeload.state_file(lab.name).read_text() and key not in freeload.found_file(lab.name).read_text()
          and not [c for _, c in sent if key in c])
    sts = statuses("pc01")
    check("the answer goes back into the guest: discovering first, then running with what was found",
          [s["state"] for s in sts][-2:] == ["discovering", "running"] and sts[-1]["ack"] == "abc-123"
          and sts[-1]["from"] == "PC01" and sts[-1]["by"] == "CORP\\ron" and sts[-1]["staff"] == 2 and sts[-1]["started"]
          and any("file server FILES" in x for x in sts[-1]["found"])
          and set(sts[-1]) >= {"ack", "state", "message", "from", "by", "started", "level", "profile", "staff", "in_now",
                               "tickets", "found", "missing", "updated"}, str(sts[-1:]))
    check("the inventory ran only on running Windows machines (never the Linux mail server)",
          not [n for n, c in sent if "Win32_ComputerSystem" in c and n == "mail01"] and st["seen"] == ["fs01", "pc01", "pc02", "srv01", "web01"]
          and st["origin"] == "pc01" and st["origin_name"] == "PC01", str(st))
    v = traffic.view(lab)
    check("the Load tab knows who started it, from where, when, and what was found",
          v["free"]["origin_name"] == "PC01" and v["free"]["by"] == "CORP\\ron" and v["free"]["started"] > 0
          and v["free"]["state"] == "running" and v["free"]["found"] and v["free"]["staff"] == 2)
    check("the status lines for the command line", "Started from PC01 by CORP\\ron" in freeload.render(freeload.view(lab)))

    # A Windows machine discovery has not seen starts: it looks again by itself.
    invs["pc03"] = {"computer": "PC03", "domain": "corp.lab", "member": True, "type": 1}
    lab.nodes["pc03"] = Node(id="pc03", image="win11", kind="windows-client", nics=[Nic("corp")])
    with freeload._lock:
        s2 = freeload.load(lab.name)
        s2["discovered_at"] = 0
        freeload.save(lab.name, s2)
    again = freeload.poll(lab, runner, run_all | {"pc03"})
    check("a new Windows machine running: winlab looks again and puts it to work",
          len(again) == 1 and "pc03" in workday.lab_facts(lab)["pcs"] and "pc03" in freeload.load(lab.name)["seen"])

    # Stop-OfficeLoad: everyone goes home.
    pending["pc01"] = json.dumps({"action": "stop", "id": "stop-1"})
    freeload.poll(lab, runner, run_all | {"pc03"})
    check("Stop-OfficeLoad sends the staff home and says so in the guest",
          not workday.load(lab.name)["on"] and statuses("pc01")[-1]["state"] == "stopped"
          and statuses("pc01")[-1]["ack"] == "stop-1")

    # Nothing to load: the group is empty. Nothing starts, the reason goes back.
    answers["disc"] = {**disc, "staff": []}
    pending["pc01"] = json.dumps({"action": "start", "id": "e-1", "group": "G-Empty"})
    res = freeload.poll(lab, runner, run_all | {"pc03"})
    check("an empty group: nothing starts, and Start-OfficeLoad hears why",
          res and res[0]["state"] == "error" and res[0]["message"].startswith("Nothing to load: no staff found")
          and not workday.load(lab.name)["on"] and statuses("pc01")[-1]["ack"] == "e-1", str(res))
    pending["pc02"] = "garbage"
    freeload.poll(lab, runner, run_all | {"pc03"})
    check("an unreadable request is answered with the reason, never run",
          "could not read the request" in statuses("pc02")[-1]["message"])

    # The poll never runs beside the working day's own tick, and forget goes back to the plan.
    with workday._lock:
        workday._running.add(lab.name)
    try:
        check("no look into the guests while the working day's tick talks to them", freeload.kick(lab) is False)
    finally:
        with workday._lock:
            workday._running.discard(lab.name)
    freeload.forget(lab.name)
    check("Forget: back to the lab plan's facts and directory",
          workday.lab_facts(lab) == workday.plan_facts(lab) and workday.everyone(lab) == workday.directory.load(lab))
    every = schema.load(root / "content" / "labs" / "every-role.toml")
    check("a normal lab keeps its plan's facts", workday.lab_facts(every)["dc_node"] == "dc01"
          and "source" not in workday.lab_facts(every))

    # ---- the module the student types, the CLI, the window, the help
    psm = (root / "content" / "officeload" / "OfficeLoad.psm1").read_text(encoding="utf-8")
    psd = (root / "content" / "officeload" / "OfficeLoad.psd1").read_text(encoding="utf-8")
    check("the module: three commands, the password asked with Read-Host -AsSecureString, never a parameter",
          all(f"function {c}" in psm for c in ("Start-OfficeLoad", "Stop-OfficeLoad", "Get-OfficeLoad"))
          and "Read-Host -AsSecureString" in psm and "ZeroFreeBSTR" in psm and "SetAccessRuleProtection" in psm
          and not re.search(r"\[(?:string|securestring)\]\$\w*(?:Password|Secret|Key)\b", psm, re.I)
          and "'Start-OfficeLoad', 'Stop-OfficeLoad', 'Get-OfficeLoad'" in psd and "-StaffGroup" in freeload.readme()
          and not _ps51_problems(psm) and not _ps51_problems(freeload.install_script()), str(_ps51_problems(psm)))
    check("the module only writes into its own folder: no web requests, no sockets, no remoting",
          not re.search(r"Invoke-WebRequest|Net\.Sockets|Enter-PSSession|Invoke-Command|New-PSSession", psm))
    a = cli.build_parser().parse_args(["load", "discover", "sandbox", "--from", "pc01"])
    check("winlab load discover <lab> --from <machine>, and stick, free, poll, forget",
          a.what == "discover" and a.arg == "sandbox" and a.origin == "pc01"
          and all(cli.build_parser().parse_args(["load", w, "sandbox"]).what == w for w in ("stick", "free", "poll", "forget")))
    page = (root / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    web = (root / "winlab" / "webui.py").read_text(encoding="utf-8")
    check("the Office window's Load tab draws the free-play banner; the desktop's poll reads the guests",
          "function ldFree(" in page and "Started from ${esc(f.origin_name)}" in page and "load-free-stick" in page
          and "load-free-rediscover" in page and "freeload.kick(self.dash.lab)" in web)
    dash = type("D", (), {"lab": lab})()
    check("the free-play actions are answered", freeload.act(dash, "load-free-nope", {})["ok"] is False
          and traffic.act(dash, "load-free-forget", {})["ok"])
    topic = next((t for t in helptopics.load_all() if t.id == "free-play-load"), None)
    check("a help topic: Put your network under load", topic is not None and "Start-OfficeLoad" in topic.body
          and "winlab load discover" in topic.body and not helptopics.validate())
    texts = [psm, (root / "winlab" / "freeload.py").read_text(encoding="utf-8"),
             (root / "content" / "help" / "free-play-load.toml").read_text(encoding="utf-8"), freeload.readme()]
    leak = [t[:40] for t in texts if re.search(r"(?i)password\s*[:=]\s*\S|-(?:Account)?Password\s+[\"'$\w]|-SharedSecret\s", t)]
    check("no password-looking literal in the module, the code or the help", not leak, str(leak))


# ===== real servers: Ron's decisions on PR #70 (server jobs, copies, overnight SLAs, gentle wear, company record, walks, BMCs) =====


# ===== refinement pass: machines (Settings dialog, Hyper-V verbs, checkpoints, real Save, shell) =====
def test_ref_machines():
    """The machines area made real: one Settings dialog whose pages change
    real things, Hyper-V Manager's verbs on QEMU (pause, reset, shut down,
    the lab's ordered shutdown, Save with memory where QEMU can), named
    checkpoints in a tree that keep the TPM, and the shell's Windows parts."""
    import os
    import re
    import shutil
    import socket
    import subprocess
    import tempfile
    import time
    from winlab import (dropin, editor, labclock, naming, orchestrator, paths, schema, snapshots,
                        state, vmctl, webui)
    from winlab.images import ImageError
    from winlab.providers.qemu import check_isolation

    root = Path(__file__).resolve().parents[1]
    page = (root / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    qemu_src = (root / "winlab" / "providers" / "qemu.py").read_text(encoding="utf-8")

    # ---- the display adapter QEMU refused, and the saved-state flag.
    check("no GL display adapter without gl=on", "virtio-vga-gl" not in qemu_src)
    check("a saved state comes back from a file only",
          not check_isolation(["-incoming", "file:/x/saved.vmstate"])
          and check_isolation(["-incoming", "tcp:0.0.0.0:4444"]))

    # ---- vmctl's pure parts.
    lab = schema.load("ad-ds-basics")
    dc, fs, pc = lab.nodes["dc01"], lab.nodes["fs01"], lab.nodes["pc01"]
    check("every integration service is on by default", vmctl.services(dc) == {"shutdown": True, "time": True, "files": True})
    vmctl.set_services(fs, {"time": False})
    check("a service switched off is kept by name, the rest stay on",
          fs.vars[vmctl.SERVICES_OFF] == ["time"] and vmctl.service_on(fs, "files") and not vmctl.service_on(fs, "time"))
    vmctl.set_services(fs, {"time": True})
    check("all on again leaves nothing in the lab file", vmctl.SERVICES_OFF not in fs.vars)
    check("the automatic stop action is Save unless set", vmctl.stop_action(dc) == "save")
    order = vmctl.shutdown_order(lab, {"dc01": 1, "fs01": 1, "pc01": 1})
    check("the lab shuts down in reverse boot order, the DC last", order[-1] == "dc01" and order[0] == "pc01", str(order))
    pc.vars["stop_action"] = "off"
    plan = vmctl.exit_plan(lab, {"dc01": 1, "pc01": 1})
    check("the desktop's exit groups machines by their stop action",
          plan == {"save": ["dc01"], "off": ["pc01"], "shutdown": []}, str(plan))
    check("a MAC address is taken as Hyper-V writes it", vmctl.check_mac("00-15-5D-0A-01-02") == "00:15:5d:0a:01:02"
          and vmctl.check_mac("00155d0a0103") == "00:15:5d:0a:01:03")
    for bad in ("01:00:5e:00:00:01", "00:00:00:00:00:00", "nope"):
        try:
            vmctl.check_mac(bad)
            check(f"MAC {bad} refused", False)
        except vmctl.VmError:
            check(f"MAC {bad} refused", True)

    # ---- Apply sends only what changed (a description edit on a saved machine is fine).
    dc2 = schema.load("ad-ds-basics").nodes["dc01"]
    every = dict(cpus=dc2.cpus, memory_mb=dc2.memory_mb, boot_order=dc2.boot_order, start_delay=dc2.start_delay,
                 wait_ready=dc2.wait_ready, iso="none", usb_storage_gb=0, gpu=False, hardware="pc",
                 lean=dc2.lean, description="new notes")
    left = editor.drop_unchanged(dc2, every)
    check("untouched fields are not changes", left == {"description": "new notes"}, str(left))
    check("so a description edit is no hardware change", editor.hardware_changes(left) == [])

    saved = (paths.LABS, paths.VAR, paths.STATE, paths.qemu_img)
    qimg = shutil.which("qemu-img")
    qsys = shutil.which("qemu-system-x86_64")
    with tempfile.TemporaryDirectory() as td:
        paths.LABS = Path(td) / "labs"
        paths.VAR = Path(td) / "var"
        paths.STATE = paths.VAR / "state"
        shutil.copytree(saved[0], paths.LABS)
        if qimg:
            paths.qemu_img = lambda: Path(qimg)
        try:
            d = webui.Dashboard(schema.load("ad-ds-basics"), accel="tcg")
            st = state.new("ad-ds-basics", "tcg", "none")
            st.nodes["dc01"] = state.NodeState(node_id="dc01", phase=state.SUSPENDED)
            state.save(st)
            r = d._act("node-set", {"node": "dc01", "cpus": str(dc2.cpus), "memory_mb": str(dc2.memory_mb),
                                    "iso": "none", "gpu": "0", "description": "the first DC"})
            check("a saved machine takes a description edit sent with every field", r["ok"]
                  and d.lab.nodes["dc01"].description == "the first DC", str(r))
            r = d._act("node-set", {"node": "dc01", "memory_mb": "4096"})
            check("but not new memory", not r["ok"] and "suspended" in r["message"], str(r))
            state.clear("ad-ds-basics")
            r = d._act("node-set", {"node": "fs01", "cpus": str(d.lab.nodes["fs01"].cpus)})
            check("nothing changed is said so", r["ok"] and r["message"] == "nothing to change", str(r))

            # The management pages, kept in the lab file.
            r = d._act("vm-settings", {"node": "fs01", "svc_files": "0", "svc_time": "0", "stop_action": "shutdown",
                                       "checkpoints": "0", "mac0": "00-15-5D-0A-0B-0C"})
            fsn = schema.load("ad-ds-basics").nodes["fs01"]
            check("Settings' management pages are saved", r["ok"] and vmctl.stop_action(fsn) == "shutdown"
                  and not vmctl.service_on(fsn, "files") and not vmctl.checkpoints_on(fsn)
                  and fsn.nics[0].mac == "00:15:5d:0a:0b:0c", str(r))
            r = d._act("vm-settings", {"node": "fs01", "mac0": "01:00:5e:00:00:01"})
            check("a multicast MAC is refused", not r["ok"] and "multicast" in r["message"], str(r))
            r = d._act("vm-settings", {"node": "pc01", "nested": "1"})
            check("virtualization extensions only where they are fitted", not r["ok"], str(r))
            r = d._act("vm-settings", {"node": "fs01", "boot": "dvd"})
            check("the firmware boots the DVD drive first", r["ok"]
                  and d.snapshot()["nodes"][2]["vm"]["boot"] == "dvd", str(r))
            r = d._act("snap-save", {"node": "fs01", "tag": "x"})
            check("checkpoints off: none is taken", not r["ok"] and "checkpoints are off" in r["message"], str(r))
            # Guest services and time synchronization really gate what they name.
            try:
                dropin.check(d.lab.nodes["fs01"], 10)
                check("a file drop is refused with Guest services off", False)
            except dropin.DropError as exc:
                check("a file drop is refused with Guest services off", "Guest services" in str(exc))
            asked = []
            done = labclock.apply(d.lab, labclock.Clock(), {"dc01": "ready", "fs01": "ready"},
                                  lambda nid, cmd, sh: (asked.append(nid), (True, "ok"))[1])
            check("the lab clock leaves a machine with time synchronization off alone",
                  asked == ["dc01"] and "time synchronization is off" in done["fs01"], str(done))

            # Rename is a label once Windows is installed: nothing typed into the guest.
            disk = paths.lab_dir("ad-ds-basics") / "pc01" / "system.qcow2"
            disk.parent.mkdir(parents=True, exist_ok=True)
            disk.write_bytes(b"")
            live = naming.rename_live
            naming.rename_live = lambda *a, **k: (_ for _ in ()).throw(AssertionError("typed into the guest"))
            try:
                r = d._act("node-set", {"node": "pc01", "hostname": "Desk-7"})
            finally:
                naming.rename_live = live
            check("renaming an installed Windows machine relabels it only", r["ok"] and "in winlab" in r["message"]
                  and naming.hostname_of(d.lab.nodes["pc01"]) == "Desk-7", str(r))
            disk.unlink()

            # The lab's Shut Down: power buttons in reverse boot order, each waited for.
            st = state.new("ad-ds-basics", "tcg", "none")
            for i, nid in enumerate(("dc01", "fs01", "pc01")):
                st.nodes[nid] = state.NodeState(node_id=nid, pid=os.getpid(), qmp_port=9000 + i)
            state.save(st)
            lab3 = schema.load("ad-ds-basics")
            vmctl.set_services(lab3.nodes["fs01"], {"shutdown": False})
            pressed, gone = [], set()
            left = vmctl.shut_down_lab(lab3, wait=1, press=lambda ns: (pressed.append(ns.node_id), gone.add(ns.node_id), "")[2],
                                       alive=lambda ns: ns.node_id not in gone, sleep=lambda s: None)
            check("each machine's power button, members first, the DC last; one without the service is left",
                  pressed == ["pc01", "dc01"] and left == ["fs01"], f"{pressed} {left}")
            state.clear("ad-ds-basics")

            # Delete Saved State: the memory file goes, the next start is cold.
            st = state.new("ad-ds-basics", "tcg", "none")
            st.nodes["fs01"] = state.NodeState(node_id="fs01", phase=state.SUSPENDED)
            state.save(st)
            sv = paths.lab_dir("ad-ds-basics") / "fs01" / orchestrator.SAVED_STATE
            sv.parent.mkdir(parents=True, exist_ok=True)
            sv.write_bytes(b"state")
            r = d._act("vm-discard", {"node": "fs01"})
            check("Delete Saved State removes the memory and the Saved mark", r["ok"] and not sv.exists()
                  and state.suspended("ad-ds-basics") == set(), str(r))
            state.clear("ad-ds-basics")

            # ---- checkpoints: names with spaces, a tree, rename, the TPM, one machine's delete.
            if qimg:
                for nid in ("dc01", "fs01"):
                    nd = paths.lab_dir("ad-ds-basics") / nid
                    nd.mkdir(parents=True, exist_ok=True)
                    subprocess.run([qimg, "create", "-f", "qcow2", str(nd / "system.qcow2"), "32M"],
                                   check=True, capture_output=True)
                tpm = paths.lab_dir("ad-ds-basics") / "dc01" / "tpm"
                tpm.mkdir()
                (tpm / "tpm2-00.permall").write_bytes(b"keys-1")
                (tpm / "swtpm.log").write_text("log")
                check("a checkpoint name may have spaces",
                      snapshots.save("ad-ds-basics", "Before the GPO", only=["dc01"]) == ["dc01"]
                      and snapshots.listing("ad-ds-basics")["dc01"] == ["Before_the_GPO"])
                check("the TPM's state is kept with it, not its log",
                      (tpm.parent / "tpm.Before_the_GPO" / "tpm2-00.permall").read_bytes() == b"keys-1"
                      and not (tpm.parent / "tpm.Before_the_GPO" / "swtpm.log").exists())
                (tpm / "tpm2-00.permall").write_bytes(b"keys-2")
                snapshots.save("ad-ds-basics", "after", only=["dc01"])
                tree = snapshots.details("ad-ds-basics")["dc01"]
                names = [c["name"] for c in tree["checkpoints"]]
                check("the tree: the second hangs from the first, the machine is at the second",
                      names == ["Before the GPO", "after"] and tree["checkpoints"][1]["parent"] == "Before_the_GPO"
                      and tree["current"] == "after" and all(c["created"] > 0 for c in tree["checkpoints"]), str(tree))
                snapshots.restore("ad-ds-basics", "Before the GPO", only=["dc01"])
                check("applying one by its name brings the TPM back and moves Now",
                      (tpm / "tpm2-00.permall").read_bytes() == b"keys-1"
                      and snapshots.details("ad-ds-basics")["dc01"]["current"] == "Before_the_GPO")
                r = d._act("snap-rename", {"node": "dc01", "tag": "after", "name": "After the GPO"})
                check("a checkpoint is renamed, its tag stays", r["ok"]
                      and [c["name"] for c in snapshots.details("ad-ds-basics")["dc01"]["checkpoints"]][1] == "After the GPO"
                      and "after" in snapshots.listing("ad-ds-basics")["dc01"], str(r))
                snapshots.save("ad-ds-basics", "Before the GPO", only=["fs01"])
                r = d._act("snap-rm", {"node": "dc01", "tag": "Before the GPO"})
                check("deleting from one machine's list leaves the other machine's",
                      r["ok"] and snapshots.listing("ad-ds-basics")["fs01"] == ["Before_the_GPO"]
                      and snapshots.listing("ad-ds-basics")["dc01"] == ["after"], str(r))
                check("its child hangs from the root now",
                      snapshots.details("ad-ds-basics")["dc01"]["checkpoints"][0]["parent"] == "")
                try:
                    snapshots.save("ad-ds-basics", 'say "hi"', only=["dc01"])
                    check("a name with quotes is refused", False)
                except ImageError:
                    check("a name with quotes is refused", True)

            # ---- real Save, pause and reset on a real (tiny) QEMU.
            if qsys and qimg:
                nd = paths.lab_dir("ad-ds-basics") / "dc01"
                with socket.socket() as so:
                    so.bind(("127.0.0.1", 0))
                    port = so.getsockname()[1]
                argv = [qsys, "-accel", "tcg", "-machine", "q35", "-m", "64", "-nodefaults", "-display", "none",
                        "-device", "ich9-ahci,id=ahci",
                        "-drive", f"id=sys,file={nd / 'system.qcow2'},if=none,format=qcow2",
                        "-device", "ide-hd,bus=ahci.0,drive=sys",
                        "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off"]

                def up(extra=()):
                    p = subprocess.Popen(argv + list(extra), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        try:
                            socket.create_connection(("127.0.0.1", port), timeout=1).close()
                            break
                        except OSError:
                            time.sleep(0.05)
                    return p
                proc = up()
                try:
                    st = state.new("ad-ds-basics", "tcg", "none")
                    st.nodes["dc01"] = state.NodeState(node_id="dc01", pid=proc.pid, qmp_port=port)
                    state.save(st)
                    from winlab.qmp import Qmp
                    r = d._act("vm-pause", {"node": "dc01"})
                    with Qmp(port) as mon:
                        paused = mon.call("query-status")["running"] is False
                    check("Pause stops the processors and the desktop says Paused", r["ok"] and paused
                          and next(n for n in d.snapshot()["nodes"] if n["id"] == "dc01")["vm"]["paused"], str(r))
                    r = d._act("vm-resume", {"node": "dc01"})
                    with Qmp(port) as mon:
                        check("Resume runs it again", r["ok"] and mon.call("query-status")["running"] is True)
                    r = d._act("vm-reset", {"node": "dc01"})
                    check("Reset is the reset button", r["ok"] and proc.poll() is None, str(r))
                    sv = nd / orchestrator.SAVED_STATE
                    err = orchestrator._save_state(port, sv)
                    proc.wait(timeout=20)
                    check("Save writes the memory to a file and the machine stops", err == "" and sv.stat().st_size > 0
                          and proc.returncode is not None, err)
                    proc = up(["-incoming", f"file:{sv}"])
                    ok = orchestrator._wait_restored(port, proc, timeout=60)
                    with Qmp(port) as mon:
                        running = mon.call("query-status")["running"]
                    check("the next start carries on from the saved state", ok and running is True)
                finally:
                    proc.kill()
                    proc.wait(timeout=10)
                    state.clear("ad-ds-basics")
        finally:
            paths.LABS, paths.VAR, paths.STATE, paths.qemu_img = saved

    # ---- the desktop: one Settings dialog, Hyper-V's verbs, the shell's Windows parts.
    check("one Settings dialog with its tree, OK, Cancel and Apply",
          "function vsOpen(" in page and "Settings for ${nm(id)} on winlab" in page and "vsApply(true)\">OK<" in page
          and "vsApply(false)\">Apply<" in page and "Integration Services" in page and "Automatic Stop Action" in page)
    check("the Machines, map and workbench forms are gone for a Settings button",
          'id="mh-cpus"' not in page and "function mapApply" not in page and "function applySettings" not in page
          and page.count("vsOpen('${esc(m.id)}'") >= 2)
    check("Apply sends only what changed", "function vsChanges(" in page and "if(d[k]!==o[k])ns[k]" in page)
    check("the Action menu and right-click carry Hyper-V's verbs",
          all(v in page for v in ("'Turn Off…'", "'Shut Down…'", "['Save',", "'Pause'", "'Reset…'", "'Revert…'", "'Rename…'")))
    check("Ctrl+Alt+End sends Ctrl+Alt+Delete", "e.ctrlKey&&e.altKey&&e.key==='End'" in page)
    check("Virtual Machine Connection: File > Settings, the verbs, View > Zoom",
          "onclick=\"vsOpen(conNode(this))\">Settings…" in page and "function conActionMenu(" in page
          and "[75,100,125,150,200]" in page)
    check("the lab shuts down machine by machine; Turn off asks first",
          "do:'vm-lab-shutdown'" in page.replace("act('vm-lab-shutdown'", "do:'vm-lab-shutdown'")
          and "function turnOffLab(" in page and "act('lab-down',{},'stopping the network')" not in page)
    check("checkpoints: a tree with Now, rename and delete from one machine",
          "function cpTree(" in page and ">Now<" in page.replace("<i></i>Now", ">Now") and "do:'snap-rename'" in page.replace("act('snap-rename'", "do:'snap-rename'"))
    check("Start: Pinned and All apps; the taskbar's own menu; resizing from every edge",
          "function startAll(" in page and "All apps" in page and "function tbMenu(" in page and "function edgeOf(" in page)
    check("Setup's developer panels sit under Advanced; folders have Browse",
          'class="panel setup-adv"><summary>Advanced</summary>' in page and "pickFolderInto('#xp-folder')" in page
          and "pickFolderInto('#im-folder')" in page)
    check("Notes has Notepad's menus", "function notesFind(" in page and "function notesWrap(" in page and "Time/Date" in page)
    mine = ["function vsApply", "function cpDelete", "function vmTurnOff", "function checkpointNode", "function revertTo",
            "function rmTemplate", "function dkAct", "function sysAct", "function blAct", "function installUpdate",
            "function deactivate", "function pcFix", "function roomWalk", "function suspendLab"]
    leftover = []
    for name in mine:
        i = page.index(name)
        body = page[i:page.index("\n}", i) if "\n}" in page[i:i + 4000] else i + 1500]
        if re.search(r"(?<![\w.])(confirm|prompt)\(", body):
            leftover.append(name)
    check("no browser confirm() or prompt() left in these", not leftover, str(leftover))


# ===== refine: learning (problems, hints, answers, alerts, pager, helpdesk, shift, classwork, rack, guide, map) =====


# ===== refinement: the devices' front panels, the BMC's services, the UPS and printer =====


# ===== refinement: the network (router and switch consoles, real settings) =====
def _route_router(dash, sw: str) -> None:
    """What a student types on the router's console for a switch just cabled
    to it (cabling is only the link): an address on its port, no shutdown."""
    from winlab import devcli
    net = dash.lab.networks[sw]
    port = devcli.cabled_ports(dash.lab)[sw]
    con = devcli.Console(dash, devcli.ROUTER, runner_factory=lambda: ((lambda *a, **k: ""), ""))
    con.powered = lambda: True
    for line in ("enable", "configure terminal", f"interface {port}",
                 f"ip address {net.router_ip} {net.netmask}", "no shutdown", "end"):
        con.run(line)


def test_ref_network():
    """The router and switch consoles refined to the real thing: the ISR's
    ports keep their names, cabling is only the link, NVRAM is real, routes,
    access lists and NAT are applied on the router, passwords and the
    console login work, a switch has a management address of its own,
    trunks filter VLANs, DHCP pools hand out what they say, and the output
    reads as IOS's. The router never boots here: what it is told is checked
    as the script it runs."""
    import os
    from winlab import (devcli, editor, iosl2, iosl3, iosnv, livenet, netplan, paths, schema,
                        workbench)
    from winlab.model import CUSTOM

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    word = "".join(["c", "l", "a", "s", "s"])   # a password, built at run time
    other = "".join(["c", "i", "s", "c", "o"])
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("ref-net")

            class Dash:
                def __init__(self):
                    self.reload()

                def reload(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
                    self.wb_live = workbench.Live()

            d = Dash()
            up = {"fabric", "pc01", "pc02"}
            workbench._running = lambda _name: set(up)
            ran: list[str] = []

            def runner_factory():
                def run(cmd, timeout=60):
                    ran.append(cmd)
                    if "ping" in cmd:
                        return "64 bytes from 10.1.1.20: seq=0 ttl=64 time=0.5 ms\n"
                    if "ip -s -s link" in cmd:
                        return ("5: lab0.100@lab0: <UP> mtu 1500\n    link/ether 52:54:00:aa:bb:01 brd ff:ff:ff:ff:ff:ff\n"
                                "    RX:  bytes packets errors dropped  missed   mcast\n         9000      70      0       0       0       4\n"
                                "    TX:  bytes packets errors dropped carrier collsns\n         4000      30      0       0       0       0\n")
                    if iosl3.TABLE_ACL in cmd:
                        return 'ip saddr 10.1.1.0/24 counter packets 12 bytes 900 accept comment "WEB 10"\n'
                    if "conntrack" in cmd:
                        return ("tcp 6 117 ESTABLISHED src=10.1.1.20 dst=10.2.2.9 sport=50000 dport=80 "
                                "src=10.2.2.9 dst=10.2.2.1 sport=80 dport=50000 [ASSURED] mark=0 use=1\n"
                                "udp 17 20 src=10.1.1.30 dst=10.1.1.31 sport=1 dport=2 src=10.1.1.31 dst=10.1.1.30 sport=2 dport=1\n")
                    return ""
                return run, ""

            act = lambda what, **p: workbench.act(d, what, p)  # noqa: E731
            for sw, x in (("lan", 200), ("dmz", 700)):
                act("wb-add", shelf="switch", id=sw, x=x, y=240)
            for nid, x, sw in (("pc01", 100, "lan"), ("pc02", 300, "lan")):
                editor.add_node(d.lab, nid, kind=CUSTOM, image="win11")
                editor.cable(d.lab, nid, 0, sw)
                d.lab.layout[nid] = [x, 400]
            editor.save(d.lab)
            d.reload()

            # P1: stable router ports; cabling is only the link
            r = act("wb-cable", node="router", network="dmz", port="Gi0/0/1")
            check("a cable into a chosen router port: only the link", r["ok"] and not d.lab.networks["dmz"].routed
                  and devcli.cabled_ports(d.lab) == {"dmz": "GigabitEthernet0/0/1"}, r["message"])
            act("wb-cable", node="router", network="lan")
            check("the next cable takes the first free port", devcli.cabled_ports(d.lab)["lan"] == "GigabitEthernet0/0/0")
            act("wb-add", shelf="switch", id="aaa", x=500, y=240)
            check("a switch added later renames no port",
                  devcli.cabled_ports(d.lab) == {"dmz": "GigabitEthernet0/0/1", "lan": "GigabitEthernet0/0/0"})
            check("a third switch on the canvas fits the NIM's ports", len(devcli.router_ports(d.lab)) == 10
                  and devcli.router_ports(d.lab)[2][0] == "GigabitEthernet0/1/0")
            check("a taken port is refused", not act("wb-cable", node="router", network="aaa", port="Gi0/0/0")["ok"])
            check("a new router's ports come shut down",
                  devcli.router_shut(d.lab, "GigabitEthernet0/0/0") and devcli.router_shut(d.lab, "GigabitEthernet0/1/3"))
            old = editor.new_workbench("old-net")
            ol = schema.load(old)
            editor.add_network(ol, "b", cidr="10.8.0.0/24")
            editor.add_network(ol, "a", cidr="10.9.0.0/24")
            ol.networks["a"].routed = False
            ol.devices["router"] = {"desc:GigabitEthernet0/1": "old b", "shut:GigabitEthernet0/0": "yes"}
            devcli.pin_router_ports(ol)
            own = ol.devices["router"]
            check("a lab from before: its ports by the old order, settings moved to the new names",
                  devcli.cabled_ports(ol) == {"a": "GigabitEthernet0/0/0", "b": "GigabitEthernet0/0/1"}
                  and own["desc:GigabitEthernet0/0/1"] == "old b" and own["shut:GigabitEthernet0/0/0"] == "yes"
                  and own["ip:GigabitEthernet0/0/1"] == "b", str(own))

            con = devcli.Console(d, "router", runner_factory=runner_factory)
            say = con.run
            for line in ("en", "conf t", "int g0/0/0", "ip address 10.1.1.1 255.255.255.0"):
                say(line)
            check("an address on a shut port does not route yet", not d.lab.networks["lan"].routed)
            out = say("no shut")
            check("no shutdown brings it up: the switch is routed",
                  d.lab.networks["lan"].routed and "changed state to up" in out, out)
            for line in ("int g0/0/1", "ip address 10.2.2.1 255.255.255.0", "no shutdown", "end"):
                say(line)
            brief = say("show ip interface brief")
            check("show ip interface brief: both ports up with their addresses",
                  "GigabitEthernet0/0/0   10.1.1.1        YES manual up" in brief
                  and "GigabitEthernet0/0/1   10.2.2.1" in brief, brief)

            # IOS manners: help, errors, pipes, version
            check("? describes each word", "running-config  Current operating configuration" in say("show ?")
                  and "ip  " in say("show ?"))
            check("an ambiguous word is IOS's message", say("c").startswith('% Ambiguous command:  "c"'))
            check("a bad word gets the marker", "% Invalid input detected at '^' marker." in say("show bogus"))
            check("| include filters the output", say("show run | include hostname") == "hostname Router")
            check("| section keeps a block", say("show run | section GigabitEthernet0/0/1").startswith(
                  "interface GigabitEthernet0/0/1\n ip address 10.2.2.1"))
            ver = say("show version")
            check("show version: the ISR's block in winlab's own words",
                  "ISR4321/K9" in ver and "Configuration register is 0x2102" in ver and "uptime is" in ver)
            iface = say("show interfaces g0/0/0")
            check("show interfaces: the router's own counters", "70 packets input, 9000 bytes" in iface
                  and "5254.00aa.bb01" in iface, iface)

            # P1: static routes, access lists, NAT, applied on the router
            say("conf t")
            for line in ("ip route 10.9.0.0 255.255.0.0 10.1.1.254", "ip route 0.0.0.0 0.0.0.0 10.2.2.254 5",
                         "access-list 1 permit 10.1.1.0 0.0.0.255", "ip access-list extended WEB",
                         "permit tcp 10.1.1.0 0.0.0.255 host 10.2.2.9 eq www", "15 permit icmp any any echo",
                         "deny ip any any", "int g0/0/0", "ip access-group WEB in", "ip nat inside",
                         "int g0/0/1", "ip nat outside", "exit",
                         "ip nat inside source list 1 interface g0/0/1 overload",
                         "ip nat inside source static 10.1.1.5 10.2.2.50", "end"):
                say(line)
            route = say("show ip route")
            check("show ip route: connected, local, static, and the default",
                  "S        10.9.0.0/16 [1/0] via 10.1.1.254" in route and "S*       0.0.0.0/0 [5/0] via 10.2.2.254" in route
                  and "Gateway of last resort is 10.2.2.254 to network 0.0.0.0" in route
                  and "L        10.1.1.1/32 is directly connected, GigabitEthernet0/0/0" in route, route)
            acl = say("show access-lists")
            check("show access-lists: sequences, port names, the router's own match counts",
                  "Extended IP access list WEB\n    10 permit tcp 10.1.1.0 0.0.0.255 host 10.2.2.9 eq www (12 matches)\n"
                  "    15 permit icmp any any echo\n    25 deny ip any any" in acl
                  and "Standard IP access list 1\n    10 permit 10.1.1.0, wildcard bits 0.0.0.255" in acl, acl)
            script = "\n".join(iosl3.render(d.plan))
            svi = {n: d.plan.segment_of(n).svi for n in ("lan", "dmz")}
            check("the routes are the router's own (proto 120)",
                  "ip route replace 10.9.0.0/16 via 10.1.1.254 proto 120 metric 1" in script
                  and "ip route replace 0.0.0.0/0 via 10.2.2.254 proto 120 metric 5" in script
                  and "ip route flush proto 120" in script, script)
            check("an access list in on an interface: an nftables chain with counters and the implicit deny",
                  f'iifname "{svi["lan"]}" jump acl_WEB' in script
                  and 'meta l4proto tcp ip saddr 10.1.1.0/24 ip daddr 10.2.2.9 tcp dport 80 counter accept comment "WEB 10"' in script
                  and 'meta l4proto icmp icmp type echo-request counter accept comment "WEB 15"' in script
                  and 'counter drop comment "WEB implicit deny"' in script, script)
            check("NAT overload: masquerade from inside out of the outside interface, for what list 1 permits",
                  f'iifname {{ "{svi["lan"]}" }} oifname "{svi["dmz"]}" jump nat_1' in script
                  and 'ip saddr 10.1.1.0/24 counter masquerade comment "1 10"' in script, script)
            check("static NAT: both ways, and the global address answered for on the outside",
                  f'iifname "{svi["dmz"]}" ip daddr 10.2.2.50 counter dnat to 10.1.1.5' in script
                  and f'oifname "{svi["dmz"]}" ip saddr 10.1.1.5 counter snat to 10.2.2.50' in script
                  and f"ip addr add 10.2.2.50/32 dev {svi['dmz']}" in script, script)
            check("NAT stays between the lab's own networks: every NAT rule names a lab SVI",
                  all("lab0." in line for line in script.splitlines()
                      if "jump nat_" in line or "dnat to" in line or "snat to" in line))
            check("it is in the router's start script", "table ip wlacl" in netplan.render_fabric_setup(d.plan))
            pins = livenet.snapshot(d.plan, 1)
            say("conf t")
            say("no ip route 10.9.0.0 255.255.0.0 10.1.1.254")
            say("end")
            check("a running router is told when they change", livenet.changes(d.plan, pins)["l3"])
            own = d.lab.devices["router"]
            check("an access list decides as the router does",
                  iosl3.decide(own, "WEB", "10.1.1.7", "10.2.2.9", "tcp", 50000, 80) == ("permit", 10)
                  and iosl3.decide(own, "WEB", "10.1.1.7", "10.2.2.9", "tcp", 50000, 443) == ("deny", 25)
                  and iosl3.decide(own, "1", "10.3.0.1") == ("deny", 0))
            nat = say("show ip nat translations")
            check("show ip nat translations from the router's conntrack, statics first",
                  "--- 10.2.2.50" in nat and "tcp 10.2.2.1:50000" in nat and "10.1.1.20:50000" in nat
                  and "10.1.1.30" not in nat, nat)
            check("a non-contiguous wildcard becomes a mask match",
                  iosl3._nft_addr("saddr", ("10.0.1.0", "0.255.0.255")) == "ip saddr & 255.0.255.0 == 10.0.1.0 ")

            # DHCP: what the pool says, real ranges
            say("conf t")
            for line in ("ip dhcp excluded-address 10.1.1.1 10.1.1.49", "ip dhcp pool OFFICE",
                         "network 10.1.1.0 255.255.255.0", "default-router 10.1.1.1", "dns-server 10.1.1.10",
                         "domain-name corp.lab", "lease 0 8", "end"):
                say(line)
            net = d.lab.networks["lan"]
            check("excluded addresses and the router's own are kept out of the pool",
                  netplan.pool_ranges(d.lab, net) == [("10.1.1.50", "10.1.1.254")])
            dh = "\n".join(netplan._render_dhcp(netplan.compile_topology(d.lab, check_ports=False)))
            seg = netplan.compile_topology(d.lab, check_ports=False).segment_of("lan").svi
            check("dnsmasq hands out the pool's range, gateway, DNS, domain and lease",
                  f"dhcp-range={seg},10.1.1.50,10.1.1.254,255.255.255.0,28800" in dh
                  and f"dhcp-option={seg},3,10.1.1.1" in dh and f"dhcp-option={seg},6,10.1.1.10" in dh
                  and f"dhcp-option={seg},15,corp.lab" in dh, dh)
            say("conf t")
            say("ip dhcp pool OFFICE")
            say("no dns-server")
            say("no domain-name")
            say("end")
            dh = "\n".join(netplan._render_dhcp(netplan.compile_topology(d.lab, check_ports=False)))
            check("in a workbench lab nothing is handed out that was not typed",
                  f"dhcp-option={seg},6" not in dh and f"dhcp-option={seg},15" not in dh)

            # P1: NVRAM
            check("before write: startup-config is not present", say("show startup-config") == "startup-config is not present")
            out = say("write")
            check("write alone is write memory", out == "Building configuration...\n[OK]")
            check("show startup-config prints what was written",
                  "hostname Router" in say("show startup-config") and say("show startup-config").startswith("Using "))
            say("conf t")
            say("hostname EDGE")
            say("int g0/0/1")
            say("shutdown")
            say("end")
            check("the change is in the running config", con.prompt() == "EDGE#" and not d.lab.networks["dmz"].routed)
            out = say("reload")
            check("reload asks to save what changed", "Save? [yes/no]" in con.prompt())
            say("no")
            check("then to proceed", "Proceed with reload" in con.prompt())
            out = say("")
            check("reload: back to the startup configuration, the session starts again",
                  "Press RETURN to get started." in out and d.lab.devices["router"].get("hostname") is None
                  and d.lab.networks["dmz"].routed and con.prompt() == "", out)
            say("")
            say("en")
            say("conf t")
            say("hostname LOST")
            say("end")
            d.reload()
            check("a power cycle loses what was never written",
                  iosnv.power_on(d.lab) and "hostname" not in d.lab.devices["router"])
            say("copy running-config startup-config")
            check("copy run start asks for the file name", con.prompt().startswith("Destination filename"))
            check("and writes it", "[OK]" in say(""))
            say("erase startup-config")
            say("")
            check("erase startup-config: not present", say("show startup-config") == "startup-config is not present")

            # P1: passwords and the console line
            check("type 7 is reversible, as IOS's", iosnv.untype7(iosnv.type7(word, 5)) == word
                  and iosnv.type7(word, 5).startswith("05"))
            h = iosnv.type9(word)
            check("type 9 is scrypt, checked again from its salt",
                  h.startswith("$9$") and len(h.split("$")[2]) == 14 and iosnv.check9(word, h) and not iosnv.check9(other, h))
            say("conf t")
            say("enable secret " + word)
            say("line con 0")
            say("password " + other)
            say("login")
            say("end")
            run = say("show run")
            check("show run: the secret as type 9, the line's password in clear until service password-encryption",
                  "enable secret 9 $9$" in run and f"line con 0\n password {other}\n login" in run, run)
            say("conf t")
            say("service password-encryption")
            say("end")
            check("with it, the line's password is type 7", " password 7 " in say("show run"))
            out = say("exit")
            check("exit in user or enable mode logs out", "Press RETURN to get started." in out)
            out = con.banner()
            check("the console line asks for its password", "User Access Verification" in out and con.secret()
                  and con.prompt() == "Password: ")
            check("a wrong one asks again", say(word) == "" and con.prompt() == "Password: ")
            say(other)
            check("the right one lets in", con.prompt() == "Router>")
            say("enable")
            check("enable asks for the secret, without echo", con.prompt() == "Password: " and con.secret())
            say(other)
            say(other)
            check("three wrong ones: % Bad secrets", say(other).startswith("% Bad secrets") and con.prompt() == "Router>")
            say("enable")
            say(word)
            check("the secret gives enable mode", con.prompt() == "Router#")
            say("conf t")
            say("username admin privilege 15 secret " + word)
            say("line con 0")
            say("login local")
            say("end")
            check("a local user's secret is type 9 too", "username admin privilege 15 secret 9 $9$" in say("show run"))
            say("exit")
            con.banner()
            check("login local asks for a user name", con.prompt() == "Username: ")
            say("admin")
            say(word)
            check("and its password", con.prompt() == "Router>")
            check("no password is in the lab file in clear",
                  word not in dest.read_text(encoding="utf-8") and other not in dest.read_text(encoding="utf-8"))
            d.lab.devices["router"] = {k: v for k, v in d.lab.devices["router"].items()
                                       if not k.startswith(("line-con", "enable-", "user:"))}
            editor.save(d.lab)
            d.reload()

            # P1: a switch's management address
            sw = devcli.Console(d, "sw:lan", runner_factory=runner_factory)
            sw.run("")
            sw.run("en")
            check("a new switch is Switch, as out of the box", sw.prompt() == "Switch#")
            for line in ("conf t", "interface vlan 1", "ip address 10.1.1.2 255.255.255.0", "no shutdown", "exit",
                         "ip default-gateway 10.1.1.1", "end"):
                sw.run(line)
            ns = iosl2.netns(d.lab, "lan")
            l2 = "\n".join(iosl2.render(d.plan))
            vid = d.plan.segment_of("lan").vid
            check("the switch is a host of its own on the router: a namespace, a port in its VLAN, its address and gateway",
                  ns and f"ip netns add {ns}" in l2 and f"bridge vlan add dev {ns}h0 vid {vid} pvid untagged" in l2
                  and f"ip -n {ns} addr replace 10.1.1.2/24 dev {ns}n0" in l2
                  and f"ip -n {ns} route replace default via 10.1.1.1" in l2, l2)
            out = sw.run("ping 10.1.1.20")
            check("ping on the switch runs from its own address", ran[-1].startswith(f"ip netns exec {ns} ping") and "!" in out, out)
            check("show ip interface brief on the switch", "Vlan1                  10.1.1.2        YES manual up" in sw.run("show ip interface brief"))
            check("show run has it", "interface Vlan1\n ip address 10.1.1.2 255.255.255.0\n!" in sw.run("show run")
                  and "ip default-gateway 10.1.1.1" in sw.run("show run"))

            # trunks, speed and duplex, interface range
            sw.run("conf t")
            sw.run("vlan 20")
            sw.run("exit")
            sw.run("interface range fa0/1 - 2")
            check("interface range has its own mode", sw.prompt() == "Switch(config-if-range)#")
            sw.run("description desk")
            check("a command under range runs on each port",
                  d.lab.devices["sw:lan"].get("desc:pc01:nic0") == "desk" and d.lab.devices["sw:lan"].get("desc:pc02:nic0") == "desk")
            sw.run("interface fa0/1")
            sw.run("speed 10")
            l2 = "\n".join(iosl2.render(d.plan))
            first = devcli.switch_ports(d.lab, d.plan)["lan"][0]
            check("speed 10 is the port's rate on the router",
                  f"tc qdisc add dev {first.fabric_iface} root tbf rate 10mbit" in l2, l2)
            sw.run("duplex full")
            check("duplex full against a negotiating card: a mismatch, with its losses",
                  "netem rate 10mbit loss 3%" in "\n".join(iosl2.render(d.plan))
                  and "late collision" in sw.run("do show interfaces fa0/1"))
            sw.run("duplex auto")
            sw.run("speed auto")
            check("auto again: nothing on the port", "tbf" not in "\n".join(iosl2.render(d.plan)))
            sw.run("interface g0/1")
            sw.run("switchport trunk allowed vlan 1")
            sw.run("end")
            check("the uplink allows VLAN 1 only", "Gi0/1       1" in sw.run("show interfaces trunk"))
            r = devcli.Console(d, "router", runner_factory=runner_factory)
            for line in ("en", "conf t", "int g0/0/0.20", "encapsulation dot1q 20", "ip address 10.20.0.1 255.255.255.0", "end"):
                r.run(line)
            v20 = devcli.vlan_net(d.lab, "lan", 20)
            check("a VLAN the uplink does not carry leaves the router's bridge",
                  v20.routed and f"bridge vlan del dev lab0 vid {d.plan.segment_of(v20.id).vid} self" in "\n".join(iosl2.render(d.plan)))
            # between switches: allowed lists and native VLANs decide which VLANs are one network
            act("wb-add", shelf="switch", id="acc", x=200, y=500)
            act("wb-cable", node="switch", network="acc", to="lan")
            ac = devcli.Console(d, "sw:acc", runner_factory=runner_factory)
            for line in ("", "en", "conf t", "vlan 20", "int g0/1", "switchport trunk allowed vlan 1", "end"):
                ac.run(line)
            d.reload()
            a20 = devcli.vlan_net(d.lab, "acc", 20)
            check("VLAN 20 is not allowed up the trunk: two networks", d.lab.segment_id(a20.id) == a20.id)
            for line in ("conf t", "int g0/1", "switchport trunk allowed vlan all", "end"):
                ac.run(line)
            check("allowed: one network over the trunk", d.lab.segment_id(a20.id) == v20.id)
            for line in ("conf t", "int g0/1", "switchport trunk native vlan 20", "end"):
                ac.run(line)
            check("a native VLAN mismatch joins the two native VLANs, as on real switches",
                  d.lab.segment_id(a20.id) == "lan" and d.lab.segment_id("acc") == "lan")
            check("show interfaces trunk says the native VLAN", "Gi0/1       on           802.1q         trunking      20"
                  in ac.run("show interfaces trunk"))
            check("vlan lists edit as IOS's", devcli.edit_vlans({1, 10}, "add 20-22") == {1, 10, 20, 21, 22}
                  and devcli.edit_vlans(None, "remove 1") == set(range(2, 4095))
                  and devcli.vlan_text({1, 10, 20, 21, 22}) == "1,10,20-22" and devcli.edit_vlans({5}, "all") is None)

            # the switch's power
            from winlab import livenet as _ln, netplan as _np
            lan_svi = d.plan.segment_of("lan").svi
            before = _ln.snapshot(d.plan, 1)
            check("a switch on: the router's interface toward it is up, the switch below joined to it",
                  not _np.dark_svis(d.plan) and d.lab.segment_id("acc") == "lan" and before["dark"] == {})
            r2 = act("wb-swpower", network="lan", on=False)
            check("a switch powered off: dark console, every machine's link down",
                  r2["ok"] and not devcli.Console(d, "sw:lan").powered()
                  and devcli.held_down(d.lab, d.plan.ports_for("pc01")[0]))
            lan_svi = d.plan.segment_of("lan").svi  # (no router running here to keep the VLAN ids)
            script = _np.render_fabric_setup(d.plan)
            check("... the router's interface toward it loses its link, so its connected route goes",
                  _np.dark_svis(d.plan).get(lan_svi) == "lan" and f"ip link set {lan_svi} down" in script
                  and script.index(f"ip link set {lan_svi} down") > script.index(f"ip link set {lan_svi} up"),
                  str(_np.dark_svis(d.plan)))
            check("... and the switch cabled below it is cut off from the router, as on real gear",
                  d.lab.segment_id("acc") == "acc" and "acc" in d.plan.segments)
            ch = _ln.changes(d.plan, before)
            check("the running router is told: the interface goes down, last in the script",
                  ch["dark"] and f"ip link set {lan_svi} down" in "\n".join(_np.dark_lines(d.plan, before["dark"]))
                  and _np.dark_lines(d.plan, before["dark"])[-1] == "")
            off = _ln.snapshot(d.plan, 1)
            act("wb-swpower", network="lan", on=True)
            check("on again: links back", not devcli.held_down(d.lab, d.plan.ports_for("pc01")[0]))
            check("on again: the router's interface comes back up and the switch below rejoins",
                  not _np.dark_svis(d.plan) and d.lab.segment_id("acc") == "lan"
                  and f"ip link set {lan_svi} up" in "\n".join(_np.dark_lines(d.plan, off["dark"]))
                  and _ln.changes(d.plan, off)["dark"])

            # the canvas and its port choice
            v = workbench.view(d)
            lan = next(s for s in v["switches"] if s["id"] == "lan")
            check("the canvas has the router's port names, their state, and where each uplink is",
                  v["router"]["ports"][0]["name"] == "Gi0/0/0" and v["router"]["ports"][0]["up"] and lan["rport"] == "Gi0/0/0")
            check("a cable dropped on a chosen switch port goes into it",
                  act("wb-cable", node="pc02", nic=0, network="lan", port=7)["ok"]
                  and devcli.port_no(d.lab, d.plan, "pc02:nic0") == ("lan", 7))
            page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
            check("the canvas picks the port under the pointer, or asks like Packet Tracer, and lights LEDs",
                  "function wbSockAt(" in page and "function wbPickSwPort(" in page and "function wbPickRouterPort(" in page
                  and "function wbPortLed(" in page and "Cable to the router" not in page)
            check("the switch's MODE button cycles its LEDs", "function swModeNext(" in page)
            check("helpers parse the router's tables",
                  iosl3.parse_counters('x counter packets 3 bytes 9 drop comment "A 30"') == {("A", 30): 3}
                  and devcli.parse_link_stats("    RX:  bytes packets errors dropped  missed   mcast\n 1 2 3 4 5 6")["rx_errors"] == 3)
            check("unplugging a switch from the router takes it off, and back to its port's settings on the cable",
                  act("wb-unplug", node="router", network="dmz")["ok"] and not d.lab.networks["dmz"].routed
                  and act("wb-cable", node="router", network="dmz", port="Gi0/0/1")["ok"] and d.lab.networks["dmz"].routed)
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            workbench._running = saved[4]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]
    # No literal that a secret scanner would take for a password.
    import re
    looks = re.compile(r"""\b(password|secret)\s*[:=]\s*["'][^"'{ ]+["']|-Password\s+["']?\w"""
                       r"""|\b(enable|username \w+(?: privilege \d+)?) (secret|password) (?=\S*[\d@!#$%])\S{4,}""")
    files = ["winlab/iosl2.py", "winlab/iosl3.py", "winlab/iosnv.py", "winlab/devcli.py"]
    hits = [(f, m.group(0)) for f in files for m in looks.finditer(Path(f).read_text(encoding="utf-8"))
            if m.group(0) != "enable password parameters"]   # IOS's own help text for enable
    check("the network's files hold no password-looking literal", not hits, str(hits[:3]))



# ===== refine: one message box for the whole desktop =====
def test_ref_message_box():
    """The browser's own confirm()/prompt()/alert() look like a web page and
    block the page; every question the desktop asks goes through ask() or
    askText(), the Windows-style message box."""
    import re
    page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    code = "\n".join(l for l in page.splitlines() if not l.lstrip().startswith("//"))
    left = re.findall(r"(?<![\w.])(?:confirm|prompt|alert)\(", code)
    check("no browser confirm(), prompt() or alert() left on the desktop", not left, str(len(left)))
    check("the message box is there", "function ask(" in page and "function askText(" in page and 'id="wdlg"' in page)

# ===== Windows 11 desktops: Microsoft 365 Apps and USMT media =====


# ===== Windows 11 track: Configuration Manager beyond the install =====


# ===== Windows 11 track: servicing policy and Microsoft Edge =====



# ===== Windows 11 security: App Control, Credential Guard, exploit protection, Hello =====


# ===== Windows 11 track: the cloud-only desktop scenarios =====



# ===== the lab router as a router: OSPF, BGP, VRFs, VRRP (winlab/iosrouting.py) =====
def test_w11_routing():
    """The lab router's console speaks OSPF and BGP (FRRouting on the
    router, peering with the Ubuntu routers of winlab/routing.py), keeps a
    network apart in a VRF (a Linux VRF device), and shares a gateway with
    VRRP (EIGRP and HSRP have tests of their own below). The router never
    boots here: what it is told is checked as the script and the FRRouting
    configuration it is given, and what it says is parsed from FRRouting's
    own output."""
    import json
    import tomllib
    from winlab import (alpineovl, devcli, iosl3, iosnv, iosrouting, livenet, netplan, paths, schema,
                        workbench)

    root = Path(__file__).resolve().parent.parent
    saved = (paths.VAR, paths.STATE, paths.LABS, workbench._running)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        paths.LABS.mkdir(parents=True)
        (paths.LABS / "router-protocols.toml").write_text(
            (root / "content" / "labs" / "router-protocols.toml").read_text(encoding="utf-8"), encoding="utf-8")
        try:
            class Dash:
                def __init__(self):
                    self.reload()

                def reload(self):
                    self.lab = schema.load("router-protocols")
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
                    self.wb_live = workbench.Live()

            d = Dash()
            workbench._running = lambda _name: {"fabric"}
            ran: list[str] = []
            vid = lambda n: d.plan.segment_of(n).svi  # noqa: E731

            def runner_factory():
                def run(cmd, timeout=60):
                    ran.append(cmd)
                    if "show ip route json" in cmd:
                        return json.dumps({
                            "10.81.0.0/24": [{"prefix": "10.81.0.0/24", "protocol": "ospf", "selected": True,
                                              "distance": 110, "metric": 20, "uptime": "00:01:02",
                                              "nexthops": [{"ip": "10.80.0.3", "interfaceName": vid("office"),
                                                            "active": True}]}],
                            "10.80.0.0/24": [{"prefix": "10.80.0.0/24", "protocol": "ospf", "selected": False,
                                              "distance": 110, "metric": 10, "nexthops": []}],
                            "203.0.113.0/24": [{"prefix": "203.0.113.0/24", "protocol": "bgp", "selected": True,
                                                "distance": 20, "metric": 0, "uptime": "00:00:30",
                                                "nexthops": [{"ip": "198.51.100.2", "interfaceName": vid("isp-link"),
                                                              "active": True}]}]})
                    if "show ip ospf neighbor" in cmd:
                        return ("\nNeighbor ID     Pri State           Up Time         Dead Time Address         "
                                "Interface                        RXmtL RqstL DBsmL\n"
                                f"3.3.3.3           1 Full/Backup     1m02s             36.712s 10.80.0.3       "
                                f"{vid('office')}:10.80.0.2                    0     0     0\n")
                    if "show ip bgp summary" in cmd:
                        return f"Neighbor        V   AS   MsgRcvd\n198.51.100.2    4 65100  12 on {vid('isp-link')}\n"
                    return ""
                return run, ""

            con = devcli.Console(d, "router", runner_factory=runner_factory)
            say = con.run
            ports = dict((n, sw) for n, sw in devcli.router_ports(d.lab) if sw)
            check("the lab's interfaces: guest Gi0/0/0, the ISP Gi0/0/1, the office Gi0/1/0 (as the lessons say)",
                  ports == {"GigabitEthernet0/0/0": "guest", "GigabitEthernet0/0/1": "isp-link",
                            "GigabitEthernet0/1/0": "office"}, str(ports))

            # OSPF
            for line in ("en", "conf t", "router ospf 1"):
                say(line)
            check("router ospf enters IOS's router mode", con.prompt() == "Router(config-router)#", con.prompt())
            helpt = say("?")
            check("? in router mode lists its commands with their help",
                  "network" in helpt and "passive-interface      Suppress routing updates on an interface" in helpt, helpt)
            for line in ("router-id 2.2.2.2", "net 10.80.0.0 0.0.0.255 ar 0", "passive-interface default",
                         "no passive-interface g0/1/0", "default-information originate always", "exit",
                         "int g0/1/0", "ip ospf priority 200", "ip ospf cost 10", "end"):
                say(line)
            check("a wildcard with holes is refused", "contiguous wildcard" in
                  (say("conf t"), say("router ospf 1"), say("network 10.80.0.0 0.255.0.255 area 0"))[2])
            check("a second OSPF process in the same table is refused with the reason",
                  "one OSPF process per VRF" in say("router ospf 2"))
            check("a new router-id says it needs clear ip ospf process",
                  "clear ip ospf process" in (say("router ospf 1"), say("router-id 2.2.2.3"))[1])
            say("router-id 2.2.2.2")
            check("named-mode EIGRP is refused, saying why (FRRouting's eigrpd takes the classic mode)",
                  "Named-mode EIGRP" in say("router eigrp CORP") and con.prompt() == "Router(config-router)#")
            check("another protocol is named in the refusal", "RIP is not in it" in say("router rip"))
            run = say("do show running-config")
            check("show running-config: router ospf as IOS prints it, interface lines under the interface",
                  "router ospf 1\n router-id 2.2.2.2\n passive-interface default\n no passive-interface "
                  "GigabitEthernet0/1/0\n network 10.80.0.0 0.0.0.255 area 0\n default-information originate always"
                  in run and " ip ospf cost 10\n ip ospf priority 200" in run, run)
            conf = iosrouting.frr_conf(d.plan)
            check("FRRouting's configuration: one ospfd instance, a prefix for the wildcard, passive by interface",
                  "router ospf\n ospf router-id 2.2.2.2\n passive-interface default\n network 10.80.0.0/24 area 0\n"
                  " default-information originate always" in conf
                  and f"interface {vid('office')}\n ip ospf cost 10\n ip ospf priority 200\n no ip ospf passive" in conf,
                  conf)

            # BGP
            for line in ("router bgp 65000", "neighbor 198.51.100.2 description ISP"):
                out = say(line)
            check("a neighbour option before remote-as is refused as on IOS",
                  "Specify remote-as or peer-group commands first" in out, out)
            for line in ("neighbor 198.51.100.2 remote-as 65100", "neighbor 198.51.100.2 description ISP",
                         "address-family ipv4"):
                say(line)
            check("address-family ipv4 enters config-router-af", con.prompt() == "Router(config-router-af)#")
            for line in ("network 10.80.0.0 mask 255.255.255.0", "network 10.81.0.0 mask 255.255.255.0",
                         "exit-address-family", "exit"):
                say(line)
            check("a second AS is refused", "BGP is already running; AS is 65000" in say("router bgp 65001"))
            say("end")
            run = say("show running-config")
            check("router bgp in IOS-XE's form, with the address family",
                  "router bgp 65000\n bgp log-neighbor-changes\n neighbor 198.51.100.2 remote-as 65100\n neighbor "
                  "198.51.100.2 description ISP\n !\n address-family ipv4\n  network 10.80.0.0 mask 255.255.255.0\n"
                  "  network 10.81.0.0 mask 255.255.255.0\n  neighbor 198.51.100.2 activate\n exit-address-family"
                  in run, run)
            conf = iosrouting.frr_conf(d.plan)
            check("FRRouting's bgpd behaves as IOS: no RFC 8212 policy needed, import check on",
                  "router bgp 65000\n" in conf and " no bgp ebgp-requires-policy" in conf
                  and " bgp network import-check" in conf and "  network 10.81.0.0/24" in conf
                  and " neighbor 198.51.100.2 remote-as 65100" in conf, conf)
            daemons = iosrouting.daemons_file(d.lab.devices["router"])
            check("the daemons file runs ospfd and bgpd, not eigrpd", "ospfd=yes" in daemons and "bgpd=yes" in daemons
                  and "eigrpd=no" in daemons and "vrrpd=no" in daemons)

            # what the router says
            route = say("show ip route")
            check("show ip route: O and B routes from zebra beside the connected ones, interfaces by IOS name",
                  "O        10.81.0.0/24 [110/20] via 10.80.0.3, 00:01:02, GigabitEthernet0/1/0" in route
                  and "B        203.0.113.0/24 [20/0] via 198.51.100.2, 00:00:30" in route
                  and "C        10.80.0.0/24 is directly connected, GigabitEthernet0/1/0" in route
                  and "[110/10]" not in route, route)
            check("show ip route ospf: only the OSPF lines", say("show ip route ospf").startswith("O        10.81.0.0/24"))
            nbr = say("sh ip os nei")
            check("show ip ospf neighbor: FRRouting's table told the IOS way",
                  "3.3.3.3           1   FULL/BDR        00:00:36    10.80.0.3       GigabitEthernet0/1/0" in nbr, nbr)
            check("FRRouting's output names the console's interfaces, not the router's Linux devices",
                  "GigabitEthernet0/0/1" in say("show ip bgp summary") and vid("isp-link") not in say("show ip bgp summary"))
            prot = say("show ip protocols")
            check("show ip protocols: both processes, their networks, the passive interfaces, the neighbour",
                  'Routing Protocol is "ospf 1"' in prot and "    10.80.0.0 0.0.0.255 area 0" in prot
                  and "Passive Interface(s):\n    GigabitEthernet0/0/0" in prot and 'Routing Protocol is "bgp 65000"' in prot
                  and "    198.51.100.2" in prot, prot)
            check("FRRouting missing on an old package volume is said plainly",
                  "winlab images prepare fabric" in iosrouting._frr_note("%nofrr"))

            # VRFs
            for line in ("conf t", "vrf definition GUEST", "rd 65000:20", "address-family ipv4"):
                say(line)
            check("vrf definition and its address family: IOS's prompts", con.prompt() == "Router(config-vrf-af)#")
            for line in ("exit-address-family", "exit", "int g0/0/0"):
                say(line)
            out = say("vrf forwarding GUEST")
            check("vrf forwarding removes the interface's address, as IOS says",
                  "% Interface GigabitEthernet0/0/0 IP address 10.80.20.1 removed due to enabling VRF GUEST" in out
                  and not d.lab.networks["guest"].routed, out)
            check("ip vrf forwarding on a vrf definition is refused with the right command",
                  "Use 'vrf forwarding' command for VRF 'GUEST'" in say("ip vrf forwarding GUEST"))
            say("ip address 10.80.20.1 255.255.255.0")
            say("end")
            check("the address back, in the VRF", d.lab.networks["guest"].routed)
            main, guest = say("show ip route"), say("show ip route vrf GUEST")
            check("show ip route vrf GUEST holds the guest network, the global table does not",
                  "C        10.80.20.0/24 is directly connected, GigabitEthernet0/0/0" in guest
                  and "Routing Table: GUEST" in guest and "10.80.20.0/24" not in main, guest)
            check("show ip vrf lists it with its interface", "GUEST" in say("show ip vrf") and "Gi0/0/0" in say("show vrf"))
            run = say("show running-config")
            check("show running-config: the VRF before the interfaces, vrf forwarding before the address",
                  run.index("vrf definition GUEST\n rd 65000:20\n !\n address-family ipv4\n exit-address-family")
                  < run.index("interface GigabitEthernet0/0/0\n vrf forwarding GUEST\n ip address 10.80.20.1"), run)
            script = "\n".join(iosrouting.render(d.plan))
            check("a VRF is a Linux VRF device with a table, the SVI its slave, and no fall-through to main",
                  "ip link add GUEST type vrf table 1001" in script and f"ip link set {vid('guest')} master GUEST" in script
                  and "ip route replace unreachable default metric 4278198272 table 1001" in script
                  and "_l3mdev_accept" in script, script)
            check("a VRF's name must make a Linux device name", "15 letters" in
                  (say("conf t"), say("vrf definition lab0x"))[1])
            say("end")

            # VRRP and HSRP
            for line in ("conf t", "int g0/1/0"):
                say(line)
            check("standby with object tracking takes the object, saying while it does not exist yet",
                  "Track object 7 does not exist yet" in say("standby 1 track 7 decrement 10")
                  and d.lab.devices["router"].get("hsrp-trackobj:GigabitEthernet0/1/0:1:7") == "10")
            say("no standby 1")
            check("no standby <group> takes the tracked object away with the group",
                  not any(k.startswith("hsrp") for k in d.lab.devices["router"]))
            check("the interface's own address cannot be the virtual one", "own address" in say("vrrp 1 ip 10.80.0.2"))
            check("an address outside the subnet is refused", "not in GigabitEthernet0/1/0's subnet" in say("vrrp 1 ip 10.9.9.1"))
            check("a priority before the address is refused", "vrrp 1 ip <address> first" in say("vrrp 1 priority 110"))
            for line in ("vrrp 1 ip 10.80.0.1", "vrrp 1 pri 110", "end"):
                say(line)
            conf = iosrouting.frr_conf(d.plan)
            script = "\n".join(iosrouting.render(d.plan))
            mv = iosrouting._macvlan(vid("office"), 1)
            check("VRRP: vrrpd speaks version 2 (IOS's) on the office SVI, with the console's priority",
                  f"interface {vid('office')}\n ip ospf cost 10\n ip ospf priority 200\n no ip ospf passive\n vrrp 1 version 2\n"
                  " vrrp 1 priority 110\n vrrp 1 ip 10.80.0.1" in conf
                  and "vrrpd=yes" in iosrouting.daemons_file(d.lab.devices["router"]), conf)
            check("the virtual address lives on a macvlan with the group's virtual MAC",
                  f"ip link add {mv} link {vid('office')} addrgenmode random type macvlan mode bridge" in script
                  and f"ip link set dev {mv} address 00:00:5e:00:01:01" in script
                  and f"ip addr replace 10.80.0.1/24 dev {mv}" in script
                  and f"/proc/sys/net/ipv4/conf/{vid('office')}/arp_ignore" in script, script)
            check("show running-config: the vrrp lines under the interface",
                  " vrrp 1 ip 10.80.0.1\n vrrp 1 priority 110" in say("show running-config"))
            check("show vrrp brief: the group, its priority, its address", "Gi0/1/0       1    110" in say("show vrrp brief")
                  and "10.80.0.1" in say("show vrrp brief"))
            check("master or backup is read from the kernel: vrrpd holds a backup's interface in protodown",
                  iosrouting.vrrp_states("9: vr104x1@lab0.104: <BROADCAST,UP,LOWER_UP> mtu 1500 protodown on\n"
                                         "10: vr105x1@lab0.105: <BROADCAST,UP,LOWER_UP> mtu 1500")
                  == {"vr104x1": "Backup", "vr105x1": "Master"})

            # NVRAM and the start script
            say("write memory")
            startup = iosnv.startup_text(d.lab, "router")
            check("write memory keeps it all for the next start", "router ospf 1" in startup and "router bgp 65000" in startup
                  and "vrf definition GUEST" in startup and "vrrp 1 ip 10.80.0.1" in startup)
            setup = netplan.render_fabric_setup(d.plan)
            check("the router's start script installs FRRouting offline and starts it on the console's configuration",
                  "apk add --no-network frr" in setup and "cat > /etc/frr/frr.conf <<'WLFRR'" in setup
                  and "/usr/lib/frr/frrinit.sh restart" in setup)
            check("the console's static routes are not FRRouting's own protocol numbers (zebra would sweep them)",
                  iosl3.ROUTE_PROTO not in (11, *range(186, 199)) and iosrouting.VROUTE_PROTO not in (11, *range(186, 199)))

            # a running router: FRRouting's own commands for what changed
            old = iosrouting.frr_conf(d.plan)
            say("conf t")
            say("router bgp 65000")
            say("address-family ipv4")
            say("no network 10.81.0.0 mask 255.255.255.0")
            say("end")
            new = iosrouting.frr_conf(d.plan)
            cmds = iosrouting.delta(old, new)
            check("a removed line is taken away with no, in its block, with no restart",
                  cmds == [["configure terminal", "router bgp 65000", "address-family ipv4 unicast",
                            "no network 10.81.0.0/24", "end"]], str(cmds))
            check("a removed process goes whole", iosrouting.delta(old, new.split("router bgp")[0])
                  [-1] == ["configure terminal", "no router bgp 65000", "end"])
            daemons = iosrouting.daemons_file(d.lab.devices["router"])
            live = "\n".join(iosrouting.live_script(d.plan, lambda c, timeout=0: f"{old}#winlab-daemons\n{daemons}#winlab-up\nup\n"))
            check("a running router gets the change without restarting FRRouting",
                  "vtysh -c 'configure terminal' -c 'router bgp 65000' -c 'address-family ipv4 unicast' "
                  "-c 'no network 10.81.0.0/24' -c end" in live and "frrinit.sh restart" not in live
                  and "vtysh -f /run/winlab-frr-apply.conf" in live, live)
            live = "\n".join(iosrouting.live_script(d.plan, lambda c, timeout=0: f"{old}#winlab-daemons\nbgpd=no\n#winlab-up\n"))
            check("a new daemon, or FRRouting not running, starts it again", "frrinit.sh restart" in live)
            pins = livenet.snapshot(d.plan, 1)
            check("livenet follows the routing settings like the other router settings",
                  "rt" in pins and not livenet.changes(d.plan, pins)["rt"])
            say("conf t")
            say("no router ospf 1")
            say("end")
            check("a change to them is one the running router must take", livenet.changes(d.plan, pins)["rt"]
                  and "router ospf" not in iosrouting.frr_conf(d.plan))
        finally:
            paths.VAR, paths.STATE, paths.LABS, workbench._running = saved

    # the package, the docs, the lessons
    check("FRRouting is on the Alpine package volume, installed on the router on demand",
          "frr" in alpineovl.APPLIANCE_PACKAGES and "frr" not in alpineovl.FABRIC_PACKAGES)
    lic = (root / "LICENSING.md").read_text(encoding="utf-8")
    check("LICENSING lists Alpine's FRRouting package, fetched and never bundled",
          "FRRouting (Alpine's `frr` package" in lic)
    doc = iosrouting.__doc__ or ""
    check("the module says what it leaves out and why", "EIGRP" in doc and "alpha" in doc and "HSRP" in doc
          and "VRRP" in doc and "instance per VRF" in doc)
    lab = schema.load(root / "content" / "labs" / "router-protocols.toml")
    mine = ["router-console-ospf", "router-console-bgp", "router-console-vrf", "router-console-vrrp"]
    rows = [tomllib.loads((root / "content" / "lessons" / f"{m}.toml").read_text(encoding="utf-8"))["lesson"] for m in mine]
    check("four network lessons in order 300 to 303, each with its exercise in the lab",
          [r["order"] for r in rows] == [300, 301, 302, 303] and all(r["module"] == "network" for r in rows)
          and [r["exercise"] for r in rows] == lab.exercises[:4], str(lab.exercises))
    exs = [(root / "content" / "exercises" / f"{e}.toml").read_text(encoding="utf-8") for e in lab.exercises[:4]]
    check("the exercises grade the router itself (node fabric) and the machines around it",
          all('node = "fabric"' in e for e in exs) and sum(e.count("[[check]]") for e in exs) >= 20)
    import re as _re
    looks = _re.compile(r"""\b(password|secret)\s*[:=]\s*["'][^"'{ ]+["']|-Password\s+["']?\w"""
                        r"""|\b(enable|username \w+) (secret|password) [A-Za-z][\w]{3,}""")
    files = [root / "winlab" / "iosrouting.py"] + [root / "content" / "lessons" / f"{m}.toml" for m in mine]
    hits = [m.group(0) for f in files for m in looks.finditer(f.read_text(encoding="utf-8"))]
    check("no password-looking literal in the routing files", not hits, str(hits[:3]))



# ===== the lab router: zone-based firewall, IKEv2/IPsec tunnels, QoS =====
def test_w11_router_policy():
    """The router's console takes IOS's zone-based firewall (zones,
    class-map/policy-map type inspect, zone-pairs), IKEv2 and IPsec with a
    static VTI (crypto ikev2 ..., crypto ipsec ..., interface Tunnel0) and
    MQC QoS (class-map, policy-map, service-policy), keeps them in the lab
    file and NVRAM, and makes them real on the router as nftables with
    conntrack, an XFRM interface with strongSwan, and tc HTB. The router never
    boots here: what it is told is checked as the script it runs."""
    import os
    import shutil
    import subprocess
    from winlab import (debpacks, devcli, editor, iosnv, livenet, lessons, mqc, netplan, paths, qos,
                        routerpolicy, schema, vti, workbench, zbf)
    from winlab.exercises import load as load_ex

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    key = "".join(["l", "a", "b", "-", "k", "e", "y", "7"])   # a pre-shared key, built at run time
    sas = ("Tunnel0: #3, ESTABLISHED, IKEv2, 6b5c1a2b3c4d5e6f_i* 9d8e7f6a5b4c3d2e_r\n"
           "  local  '203.0.113.1' @ 203.0.113.1[500]\n  remote '203.0.113.2' @ 203.0.113.2[500]\n"
           "  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048\n"
           "  established 52s ago, rekeying in 84017s\n"
           "  Tunnel0: #4, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128\n"
           "    installed 52s ago, rekeying in 3166s, expires in 3908s\n"
           "    in  c5a2a1b5,    840 bytes,    10 packets,     1s ago\n"
           "    out c6f1c2e7,    924 bytes,    11 packets,     1s ago\n"
           "    local  0.0.0.0/0\n    remote 0.0.0.0/0\n")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("w11-pol")

            class Dash:
                def __init__(self):
                    self.reload()

                def reload(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
                    self.wb_live = workbench.Live()

            d = Dash()
            workbench._running = lambda _name: {"fabric"}

            def runner_factory():
                def run(cmd, timeout=60):
                    if "swanctl --list-sas" in cmd:
                        return sas
                    if zbf.TABLE in cmd:
                        return ('counter packets 12 bytes 900 ct mark set 0x5a100101 accept comment "zbf U2S DOMAIN inspect"\n'
                                'counter packets 3 bytes 180 drop comment "zbf U2S class-default drop"\n')
                    if "conntrack" in cmd:
                        return ("tcp 6 117 ESTABLISHED src=10.2.2.20 dst=10.1.1.10 sport=50000 dport=445 "
                                f"src=10.1.1.10 dst=10.2.2.20 sport=445 dport=50000 [ASSURED] mark={0x5A100101} use=1\n")
                    if qos.TABLE in cmd:
                        return ('counter packets 40 bytes 60000 comment "qos GigabitEthernet0/0/1 out SHAPE-USERS FILES"\n'
                                f'#dev {d.plan.segment_of("users").svi}\nclass htb 1:12 parent 1:10 rate 5Mbit\n'
                                ' Sent 60000 bytes 40 pkt (dropped 2, overlimits 0 requeues 0)\n')
                    return ""
                return run, ""

            act = lambda what, **p: workbench.act(d, what, p)  # noqa: E731
            for sw, x in (("servers", 200), ("users", 500), ("isp", 800)):
                act("wb-add", shelf="switch", id=sw, x=x, y=240)
                act("wb-cable", node="router", network=sw)
            con = devcli.Console(d, "router", runner_factory=runner_factory)
            prompts = {}
            script = """en|conf t|int g0/0/0|ip address 10.1.1.1 255.255.255.0|no shut|int g0/0/1
ip address 10.2.2.1 255.255.255.0|no shut|int g0/1/0|ip address 203.0.113.1 255.255.255.0|no shut|exit
ip access-list extended DOMAIN-SVCS|permit tcp any host 10.1.1.10 eq 445|deny tcp any any eq 445
permit udp any host 10.1.1.10 eq domain
class-map type inspect match-any DOMAIN|match access-group name DOMAIN-SVCS|match protocol icmp|exit
policy-map type inspect U2S-POL|class type inspect DOMAIN|inspect|class class-default|drop log|exit|exit
zone security SERVERS|description dc01 and fs01|zone security USERS|exit
zone-pair security U2S source USERS destination SERVERS|service-policy type inspect U2S-POL|exit
int g0/0/0|zone-member security SERVERS|int g0/0/1|zone-member security USERS|exit
ip access-list extended SMB|permit tcp any eq 445 any|exit
class-map match-any VOICE|match dscp ef|class-map match-any FILES|match access-group name SMB|exit
policy-map USERS|class VOICE|priority 1000|class FILES|bandwidth 5000|set dscp af11
police 8000000 conform-action transmit exceed-action drop|class class-default|fair-queue
policy-map SHAPE|class class-default|shape average 20000000|service-policy USERS|exit|exit
int g0/0/1|service-policy output SHAPE|exit
crypto ikev2 proposal PROP|encryption aes-cbc-256|integrity sha256|group 14
crypto ikev2 policy POL|proposal PROP
crypto ikev2 keyring KR|peer BR01|address 203.0.113.2|pre-shared-key KEY|exit|exit
crypto ikev2 profile PROF|match identity remote address 203.0.113.2 255.255.255.255
authentication remote pre-share|authentication local pre-share|keyring local KR
crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac|mode tunnel
crypto ipsec profile VTI|set transform-set TS|set ikev2-profile PROF
interface Tunnel0|ip address 10.255.0.1 255.255.255.252|tunnel source g0/1/0|tunnel mode ipsec ipv4
tunnel destination 203.0.113.2|tunnel protection ipsec profile VTI|exit
ip route 10.50.0.0 255.255.255.0 Tunnel0|end""".replace("KEY", key)
            errors = []
            for line in script.replace("\n", "|").split("|"):
                out = con.run(line)
                prompts[line.split()[0] if line.split()[0] in ("crypto", "class-map", "policy-map", "interface")
                        else line] = con.prompt()
                if out.startswith("% ") or "Invalid input" in out:
                    errors.append(f"{line}: {out}")
            check("every line of the build is taken", not errors, str(errors[:3]))

            # IOS manners: prompts, help, abbreviations, exit, the firewall's and QoS's maps kept apart
            con.run("conf t")
            check("a class-map type inspect and a QoS class-map both prompt (config-cmap)",
                  con.run("class-map type inspect match-any X") == "" and con.prompt() == "Router(config-cmap)#"
                  and "Invalid input" in con.run("match dscp ef"), con.prompt())
            con.run("exit")
            con.run("no class-map type inspect X")
            con.run("class-map match-any Y")
            check("a QoS class-map takes match dscp; its policy-map class prompts (config-pmap-c)",
                  con.run("match dscp af41") == "" and con.run("policy-map P2") == "" and con.run("class Y") == ""
                  and con.prompt() == "Router(config-pmap-c)#")
            check("exit from a class goes back to its policy-map", con.run("exit") == "" and con.prompt() == "Router(config-pmap)#")
            con.run("exit")
            con.run("no policy-map P2")
            con.run("no class-map Y")
            con.run("crypto ipsec transform-set T2 esp-gcm 256")
            check("a transform set and an IPsec profile prompt as IOS's do",
                  con.prompt() == "Router(cfg-crypto-trans)#" and con.run("crypto ipsec profile IP2") == ""
                  and con.prompt() == "Router(ipsec-profile)#")
            check("a global command in a sub-mode leaves it and runs", con.run("hostname R1") == ""
                  and con.prompt() == "R1(config)#")
            con.run("no crypto ipsec profile IP2")
            con.run("no crypto ipsec transform-set T2")
            con.run("int tu0")
            check("interface Tunnel0 prompts (config-if) and ? lists the tunnel's words",
                  con.prompt() == "R1(config-if)#" and "protection" in con.run("tunnel ?")
                  and "zone-member" in con.run("?"))
            check("GCM takes no HMAC; AH is said to be absent", "authenticated cipher" in con.run(
                "crypto ipsec transform-set BAD esp-gcm 256 esp-sha-hmac") and "AH" in con.run(
                "crypto ipsec transform-set BAD ah-sha-hmac"))
            check("certificates are said to be out of the lab, not silently taken",
                  con.run("crypto ikev2 profile PROF") == "" and "only pre-share" in con.run("authentication remote rsa-sig"))
            check("do runs an exec command in a sub-mode", "Zone-pair name U2S" in con.run("do show zone-pair security"))
            con.run("end")
            check("abbreviations work: sh zone sec", "Member Interfaces:\n    GigabitEthernet0/0/0" in con.run("sh zone sec"))

            # show running-config and NVRAM
            run = con.run("show running-config")
            for want in ("class-map type inspect match-any DOMAIN\n match access-group name DOMAIN-SVCS\n match protocol icmp",
                         "policy-map type inspect U2S-POL\n class type inspect DOMAIN\n  inspect\n class class-default\n  drop log",
                         "zone security SERVERS\n description dc01 and fs01\nzone security USERS",
                         "zone-pair security U2S source USERS destination SERVERS\n service-policy type inspect U2S-POL",
                         "class-map match-any VOICE\n match dscp ef",
                         "policy-map SHAPE\n class class-default\n  shape average 20000000\n  service-policy USERS",
                         "  priority 1000", "  bandwidth 5000", "  set dscp af11",
                         "crypto ikev2 proposal PROP \n encryption aes-cbc-256\n integrity sha256\n group 14",
                         "crypto ikev2 keyring KR\n peer BR01\n  address 203.0.113.2 255.255.255.255\n  pre-shared-key " + key,
                         "crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac \n mode tunnel",
                         "crypto ipsec profile VTI\n set transform-set TS \n set ikev2-profile PROF",
                         "interface GigabitEthernet0/0/1\n ip address 10.2.2.1 255.255.255.0\n zone-member security USERS\n"
                         " service-policy output SHAPE",
                         "interface Tunnel0\n ip address 10.255.0.1 255.255.255.252\n tunnel source GigabitEthernet0/1/0\n"
                         " tunnel mode ipsec ipv4\n tunnel destination 203.0.113.2\n tunnel protection ipsec profile VTI",
                         "ip route 10.50.0.0 255.255.255.0 Tunnel0"):
                check(f"show running-config: {want.splitlines()[0].strip()}", want in run, run[-1500:] if want not in run else "")
            own = d.lab.devices["router"]
            kept = editor.emit(d.lab)
            check("the pre-shared key is kept scrambled (type 7) in the lab file, never in clear",
                  key not in kept and vti.psk_clear(vti._j(own, "ikev2-keyring:KR")["BR01"]["psk"]) == key)
            con.run("conf t")
            con.run("service password-encryption")
            con.run("end")
            check("service password-encryption hides it in show running-config too",
                  key not in con.run("show running-config") and "pre-shared-key 7 " in con.run("show running-config"))
            con.run("write memory")
            check("write memory keeps it all in NVRAM", "crypto ikev2 profile PROF" in con.run("show startup-config")
                  and "zone-member security SERVERS" in con.run("show startup-config") and not iosnv.unsaved(con))
            check("show running-config interface Tunnel0 is the tunnel's block",
                  con.run("show running-config interface Tunnel0").startswith("Building configuration")
                  and "tunnel protection ipsec profile VTI" in con.run("show running-config interface Tunnel0"))
            check("show ip interface brief and show ip route know the tunnel",
                  "Tunnel0                10.255.0.1      YES manual up" in con.run("show ip interface brief")
                  and "S        10.50.0.0/24 is directly connected, Tunnel0" in con.run("show ip route"))

            # the router's script
            d.reload()
            script = "\n".join(routerpolicy.render(d.plan))
            svi = {n: d.plan.segment_of(n).svi for n in ("servers", "users", "isp")}
            check("Tunnel0 is an XFRM interface on the outside SVI, addressed, and the branch routed into it",
                  f"ip link add wltun0 type xfrm dev {svi['isp']} if_id 0x100" in script
                  and "ip addr replace 10.255.0.1/30 dev wltun0" in script
                  and "ip route replace 10.50.0.0/24 dev wltun0 proto 120" in script, script[:800])
            check("strongSwan is told IKEv2 with the typed proposal, PSK both ways, any-to-any on the interface's if_id",
                  "proposals = aes256-sha256-modp2048" in script and "esp_proposals = aes256-sha256" in script
                  and "remote_addrs = 203.0.113.2" in script and "local_ts = 0.0.0.0/0" in script
                  and "if_id_in = 0x100" in script and "auth = psk" in script and "install_routes = no" in script
                  and "swanctl --load-all" in script and "chmod 600" not in script and "umask 077" in script)
            check("the zones: users to servers jump to the pair's policy, servers to users is dropped, same zone passes",
                  f'iifname {{ "{svi["users"]}" }} oifname {{ "{svi["servers"]}" }} jump zp_U2S' in script
                  and f'iifname {{ "{svi["servers"]}" }} oifname {{ "{svi["users"]}" }} counter drop comment '
                      '"zbf no-zone-pair SERVERS USERS"' in script
                  and f'iifname {{ "{svi["servers"]}" }} oifname {{ "{svi["servers"]}" }} accept' in script, script)
            check("inspect is stateful: it marks the connection, and marked return traffic comes back",
                  "ct mark set 0x5a100101 accept" in script
                  and "ct state established,related ct mark & 0xfff00000 == 0x5a100000 accept" in script)
            check("an access list in a class: a deny entry ends the list, a permit takes the action",
                  "meta l4proto tcp tcp dport 445 return" in script
                  and "meta l4proto tcp ip daddr 10.1.1.10 tcp dport 445 counter ct mark set" in script
                  and "meta l4proto icmp counter ct mark set" in script, script)
            check("class-default drop log logs and drops",
                  'counter log prefix "%FW-6-DROP_PKT: U2S class-default: " drop' in script)
            check("QoS: an HTB tree, the shaper over a child policy, priority, bandwidth and fq_codel",
                  f"tc qdisc add dev {svi['users']} root handle 1: htb default 10" in script
                  and "classid 1:10 htb rate 20000kbit ceil 20000kbit" in script
                  and "classid 1:11 htb rate 1000kbit ceil 1000kbit prio 0" in script
                  and "classid 1:12 htb rate 5000kbit ceil 20000kbit prio 1" in script
                  and "parent 1:13 handle 13: fq_codel" in script, script)
            check("QoS: classification marks, polices and queues in nftables",
                  "ip dscp 46 jump qc_" in script and "ip dscp set 10 meta priority set 1:12 counter accept" in script
                  and "limit rate over 1000000 bytes/second burst 25000 bytes counter drop" in script
                  and "meta priority set 1:10 counter jump qp_" in script)
            full = netplan.render_fabric_setup(d.plan)
            check("all of it is in the router's start script, after its routes and lists",
                  "table ip wlzbf" in full and "table ip wlqos" in full and "type xfrm" in full
                  and full.index("table ip wlzbf") > full.index("ip route flush proto 120"))
            if shutil.which("nft"):
                bodies = re.findall(r"nft -f - <<'EOF' \|\| true\n(.*?)\nEOF", script, re.S)
                bad = []
                for b in bodies:
                    r = subprocess.run(["nft", "-c", "-f", "-"], input=b, text=True, capture_output=True)
                    if r.returncode != 0 and "Operation not permitted" not in r.stderr:
                        bad.append(r.stderr[:300])
                check("nft -c takes every table the router is given", bodies and not bad, str(bad))
            pins = livenet.snapshot(d.plan, 1)
            con.run("conf t")
            con.run("policy-map USERS")
            con.run("class FILES")
            con.run("no police")
            con.run("end")
            d.reload()
            check("a running router is told when they change", livenet.changes(d.plan, pins)["pol"])

            # reading the router
            parsed = vti.parse_sas(sas)
            check("swanctl --list-sas is read: the IKE SA, its child and its counters",
                  parsed[0]["state"] == "ESTABLISHED" and parsed[0]["children"][0]["pkts_out"] == 11
                  and parsed[0]["children"][0]["spi_in"] == "c5a2a1b5")
            ike = con.run("show crypto ikev2 sa")
            check("show crypto ikev2 sa: READY, AES-CBC 256, SHA256, group 14, PSK",
                  "203.0.113.1/500       203.0.113.2/500       none/none            READY" in ike
                  and "Encr: AES-CBC, keysize: 256, PRF: SHA256, Hash: SHA256, DH Grp:14, Auth sign: PSK" in ike, ike)
            ips = con.run("show crypto ipsec sa")
            check("show crypto ipsec sa: encaps and decaps from the SA's counters, the SPIs",
                  "#pkts encaps: 11" in ips and "#pkts decaps: 10" in ips and "spi: 0xC5A2A1B5" in ips
                  and "transform: esp-256-aes esp-sha256-hmac" in ips, ips)
            sess = con.run("show policy-map type inspect zone-pair sessions")
            check("show policy-map type inspect zone-pair sessions: counters and the inspected connection",
                  "Packets matched: 12" in sess and "Session 1 (10.2.2.20:50000)=>(10.1.1.10:445) tcp SIS_OPEN" in sess
                  and "3 packets, 180 bytes" in sess, sess)
            pol = con.run("show policy-map interface g0/0/1")
            check("show policy-map interface: the shaper, its child classes, what was marked",
                  "Service-policy output: SHAPE" in pol and "shape (average) cir 20000000" in pol
                  and "Service-policy : USERS" in pol and "Class-map: FILES (match-any)" in pol
                  and "Packets marked 40" in pol and "(queue depth/total drops/no-buffer drops) 0/2/0" in pol, pol)

            # refusals IOS makes
            con.run("conf t")
            con.run("int g0/0/0")
            check("queueing is refused on input", "only be attached in the output direction"
                  in con.run("service-policy input SHAPE"))
            con.run("policy-map USERS")
            con.run("class FILES")
            check("a guarantee bigger than the shaper is refused while attached",
                  "exceeds available bandwidth 20000" in con.run("bandwidth 30000")
                  and '"kbps 5000"' in d.lab.devices["router"]["pmap:USERS"])
            check("a policy in use cannot be removed", "in use" in con.run("no policy-map SHAPE")
                  and "child" in con.run("no policy-map USERS"))
            check("a zone with members cannot be removed", "member interfaces" in con.run("no zone security USERS"))
            check("self cannot be configured or joined", "system defined" in con.run("zone security self"))
            con.run("interface Tunnel1")
            con.run("ip address 10.255.1.1 255.255.255.252")
            con.run("tunnel source g0/1/0")
            con.run("tunnel destination 203.0.113.9")
            con.run("end")
            d.reload()
            check("a tunnel left in GRE mode is a plain GRE tunnel",
                  "ip link add wltun1 type gre local 203.0.113.1 remote 203.0.113.9 ttl 255" in
                  "\n".join(routerpolicy.render(d.plan)))
            con.run("conf t")
            con.run("no interface Tunnel1")
            con.run("end")
            check("no interface Tunnel1 removes it", "Tunnel1" not in con.run("show running-config"))
            check("mqc keeps DSCP names", mqc.dscp_value("af11") == 10 and mqc.dscp_show(46) == "ef")
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            workbench._running = saved[4]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]

    # the far end, the lessons and their grading
    sw = debpacks.PACKS["strongswan"]
    check("the strongswan pack: charon-systemd and swanctl from the Ubuntu archive, installed by hand",
          sw.image == "ubuntu" and not sw.roles and "strongswan-swanctl" in sw.packages and "charon-systemd" in sw.packages)
    check("strongSwan is on the router already (the Alpine fabric package)", "strongswan" in
          __import__("winlab.alpineovl", fromlist=["x"]).FABRIC_PACKAGES)
    lic = Path("LICENSING.md").read_text(encoding="utf-8")
    check("LICENSING lists the strongswan pack, fetched and never bundled", "the `strongswan` pack" in lic)
    by = {l.id: l for l in lessons.list_available()}
    for lid, module in (("router-zone-firewall", "security"), ("router-ipsec-vti", "security"),
                        ("router-qos-mqc", "network")):
        l = by.get(lid)
        check(f"lesson {lid}: in {module}, order 360-399, graded by its exercise on the router",
              l is not None and l.module == module and 360 <= l.order <= 399 and l.exercise == lid
              and any(c.node == "fabric" for c in load_ex(Path(f"content/exercises/{lid}.toml")).checks))
    looks = re.compile(r"""\b(password|secret|psk|pre-shared-key)\s*[:=]?\s*["'][^"'{ $<]+["']""", re.I)
    files = ["winlab/zbf.py", "winlab/vti.py", "winlab/qos.py", "winlab/mqc.py", "winlab/routerpolicy.py",
             "content/lessons/router-ipsec-vti.toml", "content/exercises/router-ipsec-vti.toml"]
    hits = [(f, m.group(0)) for f in files for m in looks.finditer(Path(f).read_text(encoding="utf-8"))]
    check("no key-looking literal in the new router files", not hits, str(hits[:3]))



# ===== network: EtherChannel, SPAN, SSH to the devices =====
def test_w11_etherchannel_span_ssh():
    """EtherChannel (winlab/etherchannel.py): channel-group modes, IOS's
    rules for what bundles, Linux bonds on the router for a channel that
    forms, spanning tree seeing one port, the on-against-LACP misconfiguration
    err-disabled; SPAN (winlab/span.py) as tc mirred on the router's ports;
    SSH (winlab/iosssh.py): real RSA keys, Dropbear on the lab addresses
    only, and an SSH session that is the device's own console."""
    import base64
    import os
    import shutil
    from winlab import (alpineovl, commands, devcli, editor, etherchannel, exercises, images, iosl2, iosnv,
                        iosssh, lessons, netplan, paths, schema, span, stp, workbench)
    from winlab.model import CUSTOM
    from winlab.providers.qemu import check_isolation

    word = "".join(["c", "l", "a", "s", "s"])   # a password, built at run time
    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("ec-lab")
            lab = schema.load(dest)
            paths.downloads_dir().mkdir(parents=True, exist_ok=True)
            images.installer_path("win11").write_bytes(b"\0" * 2048)
            for n, c in (("sw1", "192.168.10.0/24"), ("sw2", "192.168.20.0/24")):
                editor.add_network(lab, n, cidr=c)
            editor.set_routed(lab, "sw2", False)
            for nid, net in (("pc01", "sw1"), ("pc02", "sw2"), ("pc03", "sw1")):
                editor.add_node(lab, nid, kind=CUSTOM, image="win11")
                editor.cable(lab, nid, 0, net)
            editor.save(lab)

            class _Dash:
                def reload(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
            d = _Dash()
            d.reload()
            workbench._running = lambda _n: {"fabric"}
            workbench.act(d, "wb-cable", {"node": "switch", "network": "sw2", "to": "sw1"})
            r = workbench.act(d, "wb-stp-cable", {"a": "sw1", "b": "sw2"})
            check("two parallel cables between two switches: the uplink and a spare, and spanning tree blocks one",
                  r["ok"] and "blocks" in r["message"], r.get("message", ""))
            con = {s: devcli.Console(d, f"sw:{s}", runner_factory=lambda: (lambda *a, **k: "", "")) for s in ("sw1", "sw2")}
            for c in con.values():
                c.run("enable")
                c.run("configure terminal")
            s1, s2 = con["sw1"], con["sw2"]

            # --- EtherChannel ---------------------------------------------------
            s1.run("interface range gi0/2 - 3")
            out = s1.run("channel-group 1 mode active")
            check("channel-group makes the port-channel, once", out.count("Creating a port-channel interface Port-channel 1") == 1, out)
            summ = s1.run("do show etherchannel summary")
            check("the far end speaks no LACP yet: Po1(SD), members stand-alone (I)",
                  "Po1(SD)" in summ and "Gi0/2(I)" in summ and "LACP" in summ, summ)
            s2.run("interface range gi0/1 - 2")
            out = s2.run("channel-group 1 mode passive")
            check("passive answers active: the port-channel comes up", "Port-channel1, changed state to up" in out, out)
            summ = s1.run("do show etherchannel summary")
            check("show etherchannel summary: Po1(SU), both members bundled (P)",
                  "Po1(SU)" in summ and "Gi0/2(P)" in summ and "Gi0/3(P)" in summ, summ)
            res = stp.compute(d.lab)
            check("spanning tree sees one port: nothing blocks, no loop, a 2 Gbit cost",
                  not any(p.state == "BLK" for p in res.ports.values()) and not res.loop
                  and all(p.po == "Po1" and p.cost == etherchannel.PO_COST for p in res.ports.values()))
            show = s2.run("do show spanning-tree")
            check("show spanning-tree lists Po1, not its members", "Po1 " in show and "Gi0/2 " not in show, show)
            d.reload()
            text = "\n".join(stp.render(d.plan))
            check("the router bonds each end: 802.3ad, the members' veths its slaves, the bond the bridge port",
                  "stp1po1 type bond mode 802.3ad" in text and "ip link set stp1g2 master stp1po1" in text
                  and "ip link set stp1g3 master stp1po1" in text and "ip link set stp1po1 master stp1" in text
                  and "ip link set stp1g2 master stp1\n" not in text, text[-1500:])
            check("passive is lacp_active off, and the LACP system id is the switch's address",
                  "stp2po1 type bond mode 802.3ad" in text and "lacp_active off" in text.split("stp2po1 type bond")[1].split("\n")[0]
                  and f"ad_actor_system {stp.bridge_mac(d.lab, 'sw1')}" in text)
            s1.run("exit")
            s1.run("port-channel load-balance src-dst-ip")
            d.reload()
            check("port-channel load-balance src-dst-ip is the bond's layer2+3 hash",
                  "xmit_hash_policy layer2+3" in "\n".join(stp.render(d.plan))
                  and "src-dst-ip" in s1.run("do show etherchannel load-balance"))
            iface = s1.run("do show interfaces port-channel 1")
            check("show interfaces port-channel: up, two gigabits, its members",
                  "Port-channel1 is up" in iface and "BW 2000000 Kbit/sec" in iface and "Members in this channel: Gi0/2 Gi0/3" in iface, iface)
            check("sh int po1 is the same", s1.run("do sh int po1") == iface)
            check("show lacp neighbor names the partner and that it is passive",
                  "FP" in s1.run("do show lacp neighbor") and devcli.dotted_mac(stp.bridge_mac(d.lab, "sw2")) in s1.run("do show lacp neighbor"))
            s1.run("interface port-channel 1")
            check("interface port-channel 1: the (config-if) prompt", s1.prompt() == "Switch(config-if)#" and s1.s.ctx == "Port-channel1")
            s1.run("description to sw2")
            s1.run("switchport trunk allowed vlan 1,10")
            s1.run("end")
            run = s1.run("show running-config")
            check("show running-config: the global hash, Port-channel1 first, channel-group under each member, "
                  "the trunk setting handed down to them",
                  "port-channel load-balance src-dst-ip" in run and "interface Port-channel1\n description to sw2" in run
                  and run.index("interface Port-channel1") < run.index("interface FastEthernet0/1")
                  and " switchport trunk allowed vlan 1,10\n switchport mode trunk\n channel-group 1 mode active" in run, run)
            s1.run("write memory")
            s1.run("configure terminal")
            s1.run("interface range gi0/2 - 3")
            s1.run("no channel-group")
            s1.run("end")
            check("no channel-group takes the ports out", "channel-group" not in s1.run("show running-config interface gi0/2"))
            s1.run("reload")
            s1.run("no")
            s1.run("")
            check("reload: the channel comes back from NVRAM", etherchannel.member_of(d.lab, "sw1", "GigabitEthernet0/2") == (1, "active"))
            s1.run("")
            s1.run("enable")
            s1.run("configure terminal")

            # the classic mistake: on against LACP
            s2.run("interface range gi0/1 - 2")
            s2.run("no channel-group")
            out = s2.run("channel-group 1 mode on")
            check("on against active: the on side's port-channel is err-disabled (channel-misconfig)",
                  "%PM-4-ERR_DISABLE: channel-misconfig (STP) error detected on Po1" in out
                  and d.lab.devices["sw:sw2"].get("ec-err:1") == "yes", out)
            summ = s2.run("do show etherchannel summary")
            check("its summary: Po1(SD), members down (D)", "Po1(SD)" in summ and "Gi0/1(D)" in summ, summ)
            res = stp.compute(d.lab)
            ends = {(e.sw, e.port): p.state for e, p in res.ports.items()}
            check("spanning tree: err-disabled on the on side, down at the far end, and the floor switch cut off",
                  ends[("sw2", "GigabitEthernet0/1")] == "err" and ends[("sw1", "GigabitEthernet0/2")] == "down"
                  and stp.cut_off(d.lab, "sw2"), str(ends))
            check("show spanning-tree says why", "CHANNEL_MISCONFIG (err-disabled)" in s2.run("do show spanning-tree"))
            d.reload()
            text = "\n".join(stp.render(d.plan))
            check("the router takes those cables' links down", "ip link set stp2g1 down   # err" in text, text[-800:])
            check("ec-err is the device's state, not configuration (NVRAM leaves it out)", iosnv.physical("ec-err:1"))
            r = s2.run("channel-group 1 mode active")
            check("an on group takes no LACP port while it has on members: Invalid etherchnl mode",
                  "Command rejected (Port-channel1, Gi0/1): Invalid etherchnl mode" in r, r)
            s2.run("no channel-group")
            s2.run("channel-group 1 mode active")
            check("fixing the modes alone leaves it err-disabled", "Po1(SD)" in s2.run("do show etherchannel summary"))
            s2.run("interface port-channel 1")
            s2.run("shutdown")
            out = s2.run("no shutdown")
            summ = s2.run("do show etherchannel summary")
            check("shutdown / no shutdown on the port-channel brings it back", "Port-channel1, changed state to up" in out
                  and "Po1(SU)" in summ, out + summ)
            s2.run("interface range gi0/1 - 2")
            s2.run("no channel-group")
            s2.run("channel-group 1 mode passive")
            s1.run("interface range gi0/2 - 3")
            s1.run("no channel-group")
            s1.run("channel-group 1 mode passive")
            res = stp.compute(d.lab)
            summ = s1.run("do show etherchannel summary")
            check("passive with passive never forms: stand-alone, and spanning tree blocks a cable again",
                  "Gi0/2(I)" in summ and any(p.state == "BLK" for p in res.ports.values()), summ)
            s1.run("no channel-group")
            out = s1.run("channel-group 2 mode desirable")
            check("PAgP is accepted, and the console says honestly that Linux has none", etherchannel.PAGP_NOTE in out, out)
            summ = s1.run("do show etherchannel summary")
            check("desirable against LACP passive: stand-alone", "Gi0/2(I)" in summ, summ)
            s2.run("no channel-group")
            s2.run("channel-group 2 mode auto")
            check("desirable with auto bundles", "Po2(SU)" in s1.run("do show etherchannel summary"))
            d.reload()
            text = "\n".join(stp.render(d.plan))
            check("a PAgP channel is winlab-pagpd's: an empty non-LACP bond, the members bridge ports until "
                  "PAgP agrees, the speaker started on its file",
                  "stp1po2 type bond mode balance-xor" in text and "ip link set stp1g2 master stp1\n" in text
                  and "ip link set stp1g2 master stp1po2" not in text and "802.3ad" not in text
                  and etherchannel.SPEAKER_CONF in text and "setsid python3 /usr/local/sbin/winlab-pagpd" in text,
                  text[-1500:])
            s2.run("no channel-group")
            s2.run("channel-group 2 mode auto")
            sample = ("#bond stp1po2\nBonding Mode: IEEE 802.3ad Dynamic link aggregation\n802.3ad info\n"
                      "Active Aggregator Info:\n\tAggregator ID: 1\n\tNumber of ports: 2\n"
                      "Slave Interface: stp1g2\nMII Status: up\nAggregator ID: 1\ndetails partner lacp pdu:\n"
                      "    system mac address: 02:57:4c:00:00:02\n"
                      "Slave Interface: stp1g3\nMII Status: up\nAggregator ID: 2\ndetails partner lacp pdu:\n"
                      "    system mac address: 00:00:00:00:00:00\n")
            live = etherchannel.live_flags(d.lab, etherchannel.parse_live(sample))
            check("the kernel's own view: a member outside the active aggregator, no partner, is suspended",
                  live.get(("sw1", "GigabitEthernet0/2")) == "P" and live.get(("sw1", "GigabitEthernet0/3")) == "s", str(live))
            check("the channel group range is the 2960's, 1 to 6", s1.run("channel-group 7 mode active").startswith("%"))
            s1.run("end")
            s2.run("end")

            # --- SPAN ------------------------------------------------------------
            s1.run("configure terminal")
            s1.run("monitor session 1 source interface fa0/1 both")
            s1.run("monitor session 1 source interface gi0/2 rx")
            r = s1.run("monitor session 1 destination interface fa0/1")
            check("a source cannot be the destination", "already configured as monitor sources" in r, r)
            s1.run("monitor session 1 destination interface fa0/2")
            r = s1.run("monitor session 1 source vlan 1")
            check("interfaces and VLANs do not mix in one session", r.startswith("%"), r)
            mon = s1.run("do show monitor")
            check("show monitor: sources by direction, the destination, ingress disabled",
                  "Both                 : Fa0/1" in mon and "RX Only              : Gi0/2" in mon
                  and "Destination Ports        : Fa0/2" in mon and "Ingress        : Disabled" in mon, mon)
            d.reload()
            links = devcli.switch_ports(d.lab, d.plan)["sw1"]
            src, dst = links[0].fabric_iface, links[1].fabric_iface
            text = "\n".join(span.render(d.plan, reset=True))
            check("the router mirrors with tc: the source's ingress and egress copied to the destination",
                  f"tc filter add dev {src} ingress pref 11 matchall action mirred egress mirror dev {dst}" in text
                  and f"tc filter add dev {src} egress pref 11 matchall action mirred egress mirror dev {dst}" in text, text)
            check("rx alone mirrors only the ingress of the switch-to-switch cable",
                  "tc filter add dev stp1g2 ingress pref 11" in text and "dev stp1g2 egress pref 11" not in text)
            check("the destination leaves its VLAN and drops what comes in",
                  f"bridge vlan add dev {dst} vid {netplan.park_vid(links[1].port)} pvid untagged" in text
                  and f"tc filter add dev {dst} ingress pref 11 matchall action drop" in text)
            check("a reset puts a destination port back in its VLAN as the plan has it",
                  f"grep -q '^dst {dst} ' {span.STATE}" in text and f"bridge vlan add dev {dst} vid {d.plan.vid_of(links[1])} pvid untagged" in text)
            check("the mirrors ride on the switches' own settings, so a change re-runs them",
                  "action mirred" in "\n".join(iosl2.render(d.plan)))
            run = s1.run("do show running-config")
            check("show running-config: the monitor session lines",
                  "monitor session 1 source interface Fa0/1\n" in run and "monitor session 1 source interface Gi0/2 rx" in run
                  and "monitor session 1 destination interface Fa0/2" in run, run)
            s1.run("no monitor session all")
            check("no monitor session all: none left", s1.run("do show monitor") == "No SPAN configured.")

            # --- SSH -------------------------------------------------------------
            key = iosssh.generate(1024)
            check("an RSA key pair of exactly the size asked, that works: (m^e)^d = m",
                  key["n"].bit_length() == 1024 and key["p"] * key["q"] == key["n"] and pow(pow(42, key["e"], key["n"]), key["d"], key["n"]) == 42)
            blob = iosssh.dropbear_key(key)
            check("Dropbear's key file: the ssh-rsa public blob, then d, p, q", blob.startswith(iosssh.public_blob(key))
                  and blob[4:11] == b"ssh-rsa" and iosssh.fingerprint(key).startswith("SHA256:"))
            der = iosssh.spki(key)
            check("show crypto key's DER is a SubjectPublicKeyInfo with rsaEncryption",
                  der[0] == 0x30 and bytes.fromhex("2A864886F70D010101") in der)
            r = s1.run("crypto key generate rsa modulus 2048")
            check("no key without a hostname", r == "% Please define a hostname other than Switch.", r)
            s1.run("hostname SW1")
            r = s1.run("crypto key generate rsa modulus 2048")
            check("nor without a domain name", r == "% Please define a domain-name first.", r)
            s1.run("ip domain-name corp.lab")
            r = s1.run("crypto key generate rsa")
            check("without a size it asks, as IOS does", "The name for the keys will be: SW1.corp.lab" in r
                  and s1.prompt() == "How many bits in the modulus [512]: ", r)
            r = s1.run("2048")
            check("2048 bits: SSH enabled", "% Generating 2048 bit RSA keys" in r and "%SSH-5-ENABLED: SSH 1.99 has been enabled" in r, r)
            k = iosssh.key_of(d.lab, "sw:sw1")
            check("the key is kept beside the lab, the configuration names it", k and k["bits"] == 2048
                  and k["label"] == "SW1.corp.lab" and (paths.lab_dir("ec-lab") / iosssh.STORE).exists())
            s1.run("ip ssh version 2")
            ssh = s1.run("do show ip ssh")
            check("show ip ssh: version 2.0, the key and its fingerprint", "SSH Enabled - version 2.0" in ssh
                  and iosssh.fingerprint(k) in ssh and "ssh-rsa AAAA" in ssh, ssh)
            check("show crypto key mypubkey rsa: the key's name and data", "Key name: SW1.corp.lab" in s1.run("do show crypto key mypubkey rsa"))
            s1.run("username admin privilege 15 secret " + word)
            s1.run("username guest secret " + word)
            s1.run("interface vlan 1")
            s1.run("ip address 192.168.10.2 255.255.255.0")
            s1.run("no shutdown")
            s1.run("line vty 0 4")
            s1.run("login local")
            s1.run("transport input ssh")
            s1.run("end")
            run = s1.run("show running-config")
            check("show running-config: the switch's users (type 9), the domain, ip ssh version 2, the vty lines",
                  "username admin privilege 15 secret 9 $9$" in run and "ip domain-name corp.lab" in run
                  and "ip ssh version 2" in run and "line vty 0 4\n login local\n transport input ssh" in run, run)
            check("no secret in clear anywhere in it", word not in run)
            d.reload()
            text = "\n".join(iosl2.render(d.plan, reset=True))
            ns = iosl2.netns(d.lab, "sw1")
            line = next((l for l in text.splitlines() if f"{iosssh.SSHD} " in l and " -r " in l), "")
            check("Dropbear runs in the switch's management namespace, on its address only, no forwarding, no root",
                  line.startswith(f"ip netns exec {ns} {iosssh.SSHD} /etc/winlab-ssh/sw-sw1.shadow -r ") and "-p 192.168.10.2:22" in line and " -j -k" in line
                  and " -w" in line and "-c '/usr/local/bin/winlab-vty sw:sw1'" in line
                  and "0.0.0.0" not in line and " -p 22" not in line, line)
            check("each login runs the console over ttyS2; the IOS users are accounts it lets in",
                  "winlab-vtyd" in text and "/dev/ttyS2" in text and "adduser -D -H -h /var/empty -s /bin/sh -g 'IOS user' admin" in text)
            check("the vty lines as SSH meets them are on the router for the grader",
                  "login=local transport=ssh version=2.0 bits=2048" in text)
            check("an unchanged management namespace is kept on a re-run, with its SSH sessions",
                  f'"{ns} ' in text and "ip netns del $n" in text.split(f'"{ns} ')[1].split("\n")[0])
            check("no SSH server for a device without a key", "router" not in "".join(f"{dev}" for dev, _, _ in iosssh.servers(d.plan)))

            # a session, as the router's ttyS2 brings it
            v = iosssh.VtyConsole(d, "sw:sw1", "admin", "192.168.10.50")
            v.powered = lambda: True
            check("an SSH login with login local: the SSH client asked the password (Dropbear checked it), "
                  "privilege 15: straight to SW1#", v.open() == "" and v.prompt() == "SW1#" and v.logged)
            check("the same switch: its running configuration", "hostname SW1" in v.run("show running-config"))
            v.run("exit")
            check("exit ends the session (no con0 banner)", v.s.mode == "idle")
            g = iosssh.VtyConsole(d, "sw:sw1", "guest", "192.168.10.50")
            g.powered = lambda: True
            g.open()
            check("a level 1 user lands at SW1>, and enable with no enable secret: % No password set",
                  g.prompt() == "SW1>" and g.run("enable") == "% No password set")
            d.lab.devices["sw:sw1"]["line-vty:transport"] = "telnet"
            check("transport input telnet: SSH is refused", iosssh.VtyConsole(d, "sw:sw1", "admin", "x").open() is None)
            d.lab.devices["sw:sw1"]["line-vty:transport"] = "ssh"
            d.lab.devices["sw:sw1"]["line-vty:login"] = "yes"
            t = iosssh.VtyConsole(d, "sw:sw1", "admin", "x")
            t.powered = lambda: True
            check("login with no line password: Password required, but none set", "Password required, but none set" in t.open()
                  and t.s.mode == "idle")
            d.lab.devices["sw:sw1"]["line-vty:login"] = "local"

            sent: list[str] = []
            br = iosssh.Bridge(lambda: d, console_factory=lambda dash, dev, user, peer: _vty(dash, dev, user, peer))

            def _vty(dash, dev, user, peer):
                c = iosssh.VtyConsole(dash, dev, user, peer)
                c.powered = lambda: True
                return c
            br.send = sent.append
            br.lab = "ec-lab"
            b64 = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731
            br.handle(f"N 4242 {b64('sw:sw1 admin 192.168.10.50')}".encode())
            check("the bridge opens a session on ttyS2's word: the prompt goes back",
                  "4242" in br.sessions and any(s.startswith("O 4242 ") and b"SW1#" in base64.b64decode(s.split()[2]) for s in sent))
            check("a login that passes is logged on the router", any(s.startswith("L 4242 ") for s in sent))
            br.handle(f"I 4242 {b64('exit' + chr(13))}".encode())
            check("exit closes the connection", sent[-1] == "X 4242" and "4242" not in br.sessions)
            br.handle(f"N 4243 {b64('sw:nosuch admin x')}".encode())
            check("a device that is not there: closed at once", sent[-1] == "X 4243")

            s1.run("configure terminal")
            s1.run("crypto key zeroize rsa")
            r = s1.run("yes")
            check("crypto key zeroize rsa: SSH off", "%SSH-5-DISABLED" in r and iosssh.key_of(d.lab, "sw:sw1") is None, r)
            s1.run("end")

            # the session line's two shell programs, run for real over two ptys
            if os.name == "posix" and all(shutil.which(x) for x in ("sh", "flock", "base64", "mkfifo", "dd")):
                check("the router's session programs carry a login both ways", _vty_scripts_roundtrip(td))

            # the router's QEMU, the package, the paperwork, the lessons
            from winlab.providers.qemu import QemuProvider
            rt = QemuProvider(d.plan, accel="tcg").build_fabric()
            check("the router gets a third serial line for the sessions, on loopback, and stays isolated",
                  rt.com_port and f"socket,id=vty,host=127.0.0.1,port={rt.com_port},server=on,wait=off" in rt.argv
                  and not check_isolation(rt.argv))
            check("Dropbear is a fabric package, named in LICENSING", "dropbear" in alpineovl.FABRIC_PACKAGES
                  and "Dropbear (MIT" in Path("LICENSING.md").read_text(encoding="utf-8"))
            for lid, exid in (("etherchannel-lacp", "etherchannel-lacp-bundle"), ("span-port-mirroring", "span-mirror-capture"),
                              ("ssh-to-switches", "ssh-to-the-switch")):
                les = lessons.load(lid)
                check(f"lesson {lid}: network module, 330-359, graded by {exid}",
                      les.module == "network" and 330 <= les.order <= 359 and les.exercise == exid
                      and len(exercises.load(exid).checks) >= 3)
            names = {e.name for e in commands.load_catalog().values() if e.kind == "switch"}
            check("the command reference knows the new commands",
                  {"channel-group", "show etherchannel summary", "monitor session", "show monitor",
                   "crypto key generate rsa", "ip ssh version", "transport input"} <= names)
            looks = re.compile(r"""\b(password|secret)\s*[:=]\s*["'][^"'{ ]+["']|-Password\s+["']?\w"""
                               r"""|\b(enable|username \w+(?: privilege \d+)?) (secret|password) (?=\S*[\d@!#$%])\S{4,}""")
            files = ["winlab/etherchannel.py", "winlab/span.py", "winlab/iosssh.py", "content/lessons/ssh-to-switches.toml",
                     "content/exercises/ssh-to-the-switch.toml"]
            hits = [(f, m.group(0)) for f in files for m in looks.finditer(Path(f).read_text(encoding="utf-8"))]
            check("no password-looking literal in the new files", not hits, str(hits[:3]))
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            workbench._running = saved[4]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]


def _vty_scripts_roundtrip(td: Path) -> bool:
    """winlab-vtyd and winlab-vty (iosssh.VTYD_SCRIPT, VTY_SCRIPT) under sh,
    one pty standing for the router's ttyS2 and one for the SSH client's:
    the session announces itself, what the client types reaches the
    desktop, what the desktop prints reaches the client, and X ends it."""
    import base64
    import os
    import pty
    import select
    import subprocess
    import time
    import tty
    from winlab import iosssh
    work = td / "vtyrun"
    work.mkdir()
    lm, ls_ = pty.openpty()
    tty.setraw(lm)
    lpath = os.ttyname(ls_)
    rundir = str(work / "run")

    def fix(s: str) -> str:
        return (s.replace("/dev/ttyS2", lpath).replace("/run/winlab-vty", rundir)
                .replace("/var/log/winlab-vty.log", str(work / "log")).replace("[ -c $P ]", "[ -e $P ]"))
    (work / "vtyd").write_text(fix(iosssh.VTYD_SCRIPT))
    (work / "vty").write_text(fix(iosssh.VTY_SCRIPT))
    daemon = subprocess.Popen(["sh", str(work / "vtyd")], stdin=subprocess.DEVNULL)
    cm, cs = pty.openpty()
    sess = None
    try:
        time.sleep(0.5)
        env = dict(os.environ, USER="admin", SSH_CLIENT="10.70.10.50 50000 22")
        sess = subprocess.Popen(["sh", str(work / "vty"), "sw:sw1"], stdin=cs, stdout=cs, stderr=cs, env=env,
                                start_new_session=True)
        got: list[bytes] = []

        def lines(t: float) -> None:
            end, buf = time.time() + t, b""
            while time.time() < end:
                r, _, _ = select.select([lm], [], [], 0.1)
                if r:
                    buf += os.read(lm, 4096)
            got.extend(buf.split(b"\n"))

        def client(t: float) -> bytes:
            end, out = time.time() + t, b""
            while time.time() < end:
                r, _, _ = select.select([cm], [], [], 0.1)
                if r:
                    try:
                        out += os.read(cm, 4096)
                    except OSError:
                        break
            return out
        lines(1.5)
        opened = [g for g in got if g.startswith(b"N ")]
        if not opened:
            return False
        sid = opened[0].split()[1].decode()
        head = base64.b64decode(opened[0].split()[2]).decode()
        os.write(lm, f"O {sid} {base64.b64encode(b'Password: ').decode()}\n".encode())
        seen = client(1.0)
        os.write(cm, b"show version\r")
        lines(1.0)
        typed = b"".join(base64.b64decode(g.split()[2]) for g in got if g.startswith(b"I "))
        os.write(lm, f"X {sid}\n".encode())
        end = time.time() + 4
        while time.time() < end and sess.poll() is None:
            time.sleep(0.1)
        return (head == "sw:sw1 admin 10.70.10.50" and b"Password: " in seen and typed == b"show version\r"
                and sess.poll() is not None)
    finally:
        daemon.kill()
        if sess is not None and sess.poll() is None:
            sess.kill()
        for fd in (lm, ls_, cm, cs):
            try:
                os.close(fd)
            except OSError:
                pass


# ===== wire a site: a client's buildings, cabled and set up by the student =====



def _cs_solve(dash, job):
    """Play a client job from an empty site to everything the work order
    asks, the way a student would: panels, switches, cables, tests, devices,
    patches, fibre, VLANs on the consoles, the router, the APs, the cameras."""
    import ipaddress, math
    from winlab import campus, devcli, openwrt, wifi, workbench
    def a(action, **p):
        r = campus.act(dash, action, p)
        if not r.get("ok"):
            raise AssertionError(f"{action} {p}: {r.get('message')}")
        return r
    pts = {b["id"]: list(b["points"].values()) for b in job["buildings"].values()}
    # each point to the nearest closet in its building (a data hall has several)
    near = {p["id"]: min(job["buildings"][bid]["closets"],
                         key=lambda c: campus.route(job["buildings"][bid], p, job["closets"][c])["length"])
            for bid, ps in pts.items() for p in ps}
    # panels, switches, cables, test
    for cid in job["closets"]:
        mine = [p for p in near if near[p] == cid]
        a("campus-panel", closet=cid, count=math.ceil((len(mine) + 1) / 24))
        a("campus-switch", closet=cid, model="poe", id=f"sw-{cid}")
    for ps in pts.values():
        for p in ps:
            a("campus-pull", point=p["id"], closet=near[p["id"]])
    a("campus-test")
    # the devices the work order names, in its rooms; an AP on every ceiling, a camera outside
    want = {}
    needs = campus.needs_of(dash.lab, job)  # the change orders have come by now
    for n in needs:
        if n["kind"] == "devices":
            for i in n.get("ids") or []:
                want[i] = (n["device"], n.get("rooms") or [n.get("room")])
    names = next((n["ids"] for n in needs if n["kind"] == "names"), [])
    used = set()
    for nid, (kind, rooms) in want.items():
        p = next(p for ps in pts.values() for p in ps if p["kind"] == "jack" and p["room"] in rooms and p["id"] not in used)
        used.add(p["id"])
        a("campus-install", point=p["id"], kind=kind, id=nid, how="ready", image="win11" if kind == "pc" else "")
    # a ceiling in a room the Wi-Fi need leaves out, near a spot to watch, takes a dome camera
    wifi_rooms = next((n.get("rooms") for n in needs if n["kind"] == "wifi"), "all")
    spots = [campus.site_xy(job, tg["building"], tg["x"], tg["y"]) for tg in job["targets"].values()]
    n_ap = n_cam = 0
    for ps in pts.values():
        for p in ps:
            xy = campus.site_xy(job, p["building"], p["x"], p["y"])
            dome = (p["kind"] == "ceiling" and wifi_rooms != "all" and p["room"] not in wifi_rooms
                    and any(math.dist(xy, s) <= campus.CAM_RANGE_M["ceiling"] for s in spots))
            if p["kind"] == "ceiling" and not dome:
                n_ap += 1
                a("campus-install", point=p["id"], kind="ap", id=f"ap{n_ap:02d}")
            elif p["kind"] == "outdoor" or dome:
                n_cam += 1
                a("campus-install", point=p["id"], kind="camera", id=f"cam{n_cam:02d}")
    # servers: in the closets the spec names (the first that has the power), else the main one
    place = {}
    for n in needs:
        if n["kind"] == "servers":
            for i in n["ids"]:
                place[i] = n.get("closets") or [n["closet"]]
    servers = [i for i in names if i not in want] + [i for i in place if i not in names and i not in want]
    what = {m["id"]: m.get("what", "") for m in job.get("machines", [])}
    for nid in servers:
        kind = "nas" if what.get(nid, "").startswith("NAS") else "linux" if what.get(nid, "").startswith("Linux") else "server"
        for cid in place.get(nid, [job["mdf"]]):
            a("campus-server", closet=cid, kind=kind, id=nid, how="ready")
            a("campus-psu", node=nid, psu="1", feed="A")
            a("campus-psu", node=nid, psu="2", feed="B")
            if not campus.rack_power(dash.lab, job)[cid]["over"]:
                break
            a("campus-unserver", node=nid)
    for cid, c in job["closets"].items():
        if c["cold"]:
            a("campus-face", closet=cid, side=c["cold"])
    # patch: every point, every server, the backbone, the router
    t = campus.table(dash.lab)
    port = {}
    nxt = {cid: 1 for cid in job["closets"]}
    for bid, ps in pts.items():
        for p in ps:
            cid = near[p["id"]]
            pp = "P" + t["cables"][p["id"]].split("|")[1]
            a("campus-patch", closet=cid, front=pp, switch=f"sw-{cid}", port=f"Fa0/{nxt[cid]}")
            key = campus.table(dash.lab)["devices"].get(p["id"], "")
            if key:
                port[key] = (cid, nxt[cid])
            nxt[cid] += 1
    for nid in servers:
        cid = campus.table(dash.lab)["servers"][nid]
        a("campus-patch", closet=cid, front=f"SRV:{nid}", switch=f"sw-{cid}", port=f"Fa0/{nxt[cid]}")
        port[nid] = (cid, nxt[cid])
        nxt[cid] += 1
    gi = 2
    for cid, c in job["conduits"].items():
        a("campus-backbone", conduit=cid, media="om4" if c["length"] <= campus.OM4_MAX_M else "os2")
        a("campus-patch", closet=c["from"], front=f"F:{cid}", switch=f"sw-{c['from']}", port=f"Gi0/{gi}")
        a("campus-patch", closet=c["to"], front=f"F:{cid}", switch=f"sw-{c['to']}", port="Gi0/1")
        gi += 1
    a("campus-patch", closet=job["mdf"], front="RTR", switch=f"sw-{job['mdf']}", port="Gi0/1")
    # VLANs on every switch, each device's port in its VLAN
    vlans = [n for n in needs if n["kind"] == "vlan"]
    lk = campus.links(dash.lab, job)
    if job["job"].get("label_scheme"):
        for pid, l in lk.items():
            if l["closet"]:
                a("campus-label", point=pid, text=campus.label_for(job, l))
    tag_of = {}
    t = campus.table(dash.lab)
    kinds = {key: campus._device_kind(dash.lab, key) for key in port}
    for n in vlans:
        for key in port:
            if kinds[key] in (n.get("devices") or []) or key in (n.get("ids") or []):
                tag_of[key] = int(n["tag"])
    for cid in job["closets"]:
        con = workbench.console(dash, f"sw:sw-{cid}")
        con.powered = lambda: True
        lines = ["enable", "configure terminal"]
        for n in vlans:
            lines += [f"vlan {n['tag']}", f"name {n['name']}", "exit"]
        _cs_run_lines(con, lines + ["end"], f"sw-{cid}")
    _cs_router(dash, job, servers)
    for cid in job["closets"]:
        con = workbench.console(dash, f"sw:sw-{cid}")
        lines = ["configure terminal"]
        for key, (c, i) in port.items():
            if c == cid and key in tag_of:
                lines += [f"interface FastEthernet0/{i}", f"switchport access vlan {tag_of[key]}", "exit"]
        _cs_run_lines(con, lines + ["end"], f"sw-{cid}")
    _cs_wifi_setup(dash, job)
    _cs_aim_cameras(dash, job, a)
    _cs_edge(dash, job, a)
    _cs_v6(dash, job)


def _cs_v6(dash, job):
    import ipaddress
    from winlab import devcli, workbench
    v6 = job.get("ipv6")
    if not v6:
        return
    con = workbench.console(dash, devcli.ROUTER)
    con.powered = lambda: True
    lines = ["configure terminal", "ipv6 unicast-routing"]
    for tag, net in v6["nets"].items():
        gw = next(iter(ipaddress.IPv6Network(net).hosts()))
        lines += [f"interface GigabitEthernet0/0/1.{tag}", f"ipv6 address {gw}/64",
                  f"ipv6 nd ra dns server {v6['dns']}", "exit"]
    _cs_run_lines(con, lines + ["end"], "router")


def _cs_edge(dash, job, a):
    """The way out, as a student types it: the ISP's line patched, the WAN
    address, a default route, PAT, an inbound list, and the cloud's VPN."""
    import ipaddress
    from winlab import campus, devcli, workbench
    inet, cloud = job.get("internet"), job.get("cloud")
    if not inet:
        return
    a("campus-patch", closet=job["mdf"], front=campus.FRONT_ISP, switch="router", port="Gi0/0/0")
    con = workbench.console(dash, devcli.ROUTER)
    con.powered = lambda: True
    wan = ipaddress.IPv4Network(inet["wan"])
    gws = [ipaddress.ip_interface(n["gateway"]) for n in job["needs"] if n["kind"] == "routed"]
    lines = ["configure terminal", "interface GigabitEthernet0/0/0", f"ip address {inet['address']} {wan.netmask}",
             "ip nat outside", "ip access-group FROM-ISP in", "no shutdown", "exit"]
    for n in job["needs"]:
        if n["kind"] == "routed":
            lines += [f"interface GigabitEthernet0/0/1.{n['tag']}", "ip nat inside", "exit"]
    lines += ["ip access-list standard INSIDE"] + [f"permit {g.network.network_address} {g.network.hostmask}"
                                                    for g in gws] + ["exit"]
    lines += ["ip nat inside source list INSIDE interface GigabitEthernet0/0/0 overload",
              f"ip route 0.0.0.0 0.0.0.0 {inet['gateway']}",
              "ip access-list extended FROM-ISP", "permit tcp any any established", "permit udp any eq domain any",
              "permit icmp any any echo-reply"]
    if cloud:
        lines += [f"permit udp host {cloud['public']} any eq isakmp", f"permit udp host {cloud['public']} any eq 4500",
                  f"permit esp host {cloud['public']} any"]
    lines += ["deny ip any any", "exit"]
    if cloud:
        node = dash.lab.nodes[campus.CLOUD_NODE]
        lines += ["crypto ikev2 proposal PROP", "encryption aes-cbc-256", "integrity sha256", "group 14", "exit",
                  "crypto ikev2 policy POL", "proposal PROP", "exit",
                  "crypto ikev2 keyring KR", "peer CLOUD", f"address {cloud['public']}",
                  f"pre-shared-key {node.vars['cloud_psk']}", "exit", "exit",
                  "crypto ikev2 profile PROF", f"match identity remote address {cloud['public']} 255.255.255.255",
                  "authentication remote pre-share", "authentication local pre-share", "keyring local KR", "exit",
                  "crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac", "mode tunnel", "exit",
                  "crypto ipsec profile VTI", "set transform-set TS", "set ikev2-profile PROF", "exit",
                  "interface Tunnel0", "ip address 172.31.255.1 255.255.255.252", "tunnel source GigabitEthernet0/0/0",
                  "tunnel mode ipsec ipv4", f"tunnel destination {cloud['public']}", "tunnel protection ipsec profile VTI",
                  "exit", f"ip route {cloud['prefix'].split('/')[0]} 255.255.255.0 Tunnel0"]
    _cs_run_lines(con, lines + ["end"], "router")


def _cs_aim_cameras(dash, job, a):
    from winlab import campus
    """Turn each outdoor camera to the spot it covers best, as an installer would."""
    t = campus.table(dash.lab)
    spots = [campus.site_xy(job, tg["building"], tg["x"], tg["y"]) for tg in job["targets"].values()]
    for b in job["buildings"].values():
        for pid, p in b["points"].items():
            if p["kind"] != "outdoor" or not t["devices"].get(pid):
                continue
            c = campus.site_xy(job, b["id"], p["x"], p["y"])
            best = (0, campus.default_aim(job, p))
            for deg in range(0, 360, 5):
                n = sum(campus.camera_sees(job, c, "outdoor", deg, xy)[0] for xy in spots)
                if n > best[0]:
                    best = (n, deg)
            a("campus-aim", point=pid, deg=best[1])


def _cs_run_lines(con, lines, who):
    for line in lines:
        out = con.run(line)
        if any(x.startswith("% ") and "Creating vlan" not in x for x in str(out).splitlines()):
            raise AssertionError(f"{who}: {line}: {out}")


def _cs_router(dash, job, servers):
    import ipaddress
    from winlab import devcli, workbench
    # the router: a sub-interface per VLAN, DHCP pools, helpers to the DC
    con = workbench.console(dash, devcli.ROUTER)
    con.powered = lambda: True
    lines = ["enable", "configure terminal", "interface GigabitEthernet0/0/1", "no shutdown", "exit"]
    gws = {int(n["tag"]): ipaddress.ip_interface(n["gateway"]) for n in job["needs"] if n["kind"] == "routed"}
    for tag, gw in gws.items():
        lines += [f"interface GigabitEthernet0/0/1.{tag}", f"encapsulation dot1Q {tag}",
                  f"ip address {gw.ip} {gw.network.netmask}"]
        for n in job["needs"]:
            if n["kind"] == "helper" and int(n["tag"]) == tag:
                for ip in n.get("servers") or [gws[min(gws)].network.network_address + 10]:
                    lines.append(f"ip helper-address {ip}")
        lines.append("exit")
    for n in job["needs"]:
        if n["kind"] == "dhcp-pool":
            gw = gws[int(n["tag"])]
            lines += [f"ip dhcp pool V{n['tag']}", f"network {gw.network.network_address} {gw.network.netmask}",
                      f"default-router {gw.ip}", "exit"]
    _cs_run_lines(con, lines + ["end"], "router")


def _cs_wifi_setup(dash, job):
    from winlab import campus, openwrt, wifi
    # the APs' Wi-Fi, as their own pages would write it
    ssid = next((n for n in job["needs"] if n["kind"] == "ssid"), None)
    if ssid:
        dash.reload()
        for ap in wifi.aps(dash.lab):
            wifi.apply_wireless(dash.lab, ap, openwrt.uci_wireless(ssid["ssid"], "psk2+ccmp", "-".join(["a", "long", "phrase"]),
                                                                    disabled=False))
        campus._save(dash)
    dash.reload()




def test_campus_playthrough():
    """Every client job can be finished: played from an empty site to a full
    hand-over score through the same actions and consoles a student uses
    (the machines' own checks stand in as passed: they need real Windows)."""
    import shutil
    from winlab import campus, netplan, paths, schema
    for jid in campus.job_ids():
        name = f"play-{jid}"[:30]
        (paths.LABS / f"{name}.toml").unlink(missing_ok=True)

        class _Dash:
            pass
        dash = _Dash()
        try:
            campus.act(dash, "campus-start", {"job": jid, "name": name})
            dash.reload = lambda: (setattr(dash, "lab", schema.load(name)),
                                   setattr(dash, "plan", netplan.compile_topology(dash.lab, check_ports=False)))
            dash.reload()
            job = campus.job_of(dash.lab)
            try:
                _cs_solve(dash, job)
                err = ""
            except AssertionError as exc:
                err = str(exc)
            g = campus.handover(dash.lab, job, runner=lambda c: (True, "ok"))
            check(f"{jid}: played through to a full hand-over", not err and g["passed"],
                  err or "; ".join(f"{i['text'][:50]}: {i['found']}" for i in g["items"] if not i["ok"]))
        finally:
            for f in (paths.LABS / f"{name}.toml", paths.LABS / f"{name}.toml.bak"):
                f.unlink(missing_ok=True)
            shutil.rmtree(paths.lab_dir(name), ignore_errors=True)





# ===== open source in the interface: Cytoscape.js, Termshark, vwifi =====
def test_open_source_parts():
    """Three open-source parts, each fetched onto the customer's PC and
    pinned, never shipped: Cytoscape.js lays out the Network map, Termshark
    is the capture probe's packet view, vwifi (being built) will carry real
    Wi-Fi between Linux machines."""
    import gzip
    import hashlib
    import io
    import subprocess
    import tarfile
    import tempfile
    from types import SimpleNamespace
    from winlab import mapview, termshark, termview, vwifi

    root = Path(__file__).resolve().parent.parent
    page = (root / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    licensing = (root / "LICENSING.md").read_text(encoding="utf-8")

    def tgz(members: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data in members.items():
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
        return buf.getvalue()

    # --- Cytoscape.js --------------------------------------------------------
    check("Cytoscape.js is pinned from the npm registry with its licence",
          all(len(d) == 64 for d, _ in mapview.PACKAGES.values())
          and set(mapview.FILES) == {"cytoscape.min.js", "LICENSE-cytoscape.txt"}
          and mapview.REGISTRY == termview.REGISTRY)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        saved, saved_pk = mapview.paths.RUNTIME, dict(mapview.PACKAGES)
        mapview.paths.RUNTIME = d / "runtime"
        try:
            pkgs = {rel: tgz({m: m.encode() for m in members}) for rel, (_, members) in mapview.PACKAGES.items()}
            for rel, (_, members) in list(mapview.PACKAGES.items()):
                mapview.PACKAGES[rel] = (hashlib.sha256(pkgs[rel]).hexdigest(), members)
            urls = []
            mapview.fetch(progress=lambda _l: None, get=lambda u: urls.append(u) or pkgs[u[len(mapview.REGISTRY):]])
            check("winlab viewer fetch puts Cytoscape.js in runtime/cytoscape",
                  mapview.ready() and urls == [mapview.REGISTRY + r for r in pkgs]
                  and (mapview.map_dir() / "LICENSE-cytoscape.txt").exists())
            mapview.PACKAGES.update({r: ("0" * 64, m) for r, (_, m) in saved_pk.items()})
            try:
                mapview.fetch(refresh=True, progress=lambda _l: None, get=lambda u: pkgs[u[len(mapview.REGISTRY):]])
                refused = False
            except mapview.MapViewError:
                refused = True
            check("a tarball that is not the pinned one is refused", refused and not mapview.ready())
        finally:
            mapview.PACKAGES.clear()
            mapview.PACKAGES.update(saved_pk)
            mapview.paths.RUNTIME = saved
    webui_src = (root / "winlab" / "webui.py").read_text(encoding="utf-8")
    check("the desktop serves it from the fetched folder only, and says whether it is there",
          'u.path.startswith("/cytoscape/")' in webui_src and '"map_ready": mapview.ready()' in webui_src)
    check("the Network map has a By VLAN and a Laid out view, the second drawn by Cytoscape.js",
          "mapSetMode('graph')" in page and "mapSetMode('vlan')" in page
          and "/cytoscape/cytoscape.min.js" in page and "function renderMapGraph(" in page
          and "if(mapMode==='graph'){renderMapGraph();return;}" in page)
    check("the laid-out view draws winlab's own glyphs, opens screens and shares the sheet",
          "cyIcon(" in page and "DEV_GLYPH[core?'core':kind]" in page
          and "mapCy.on('dbltap'" in page and "mapSelect(type,id)" in page)
    check("without it the view offers to fetch it and the VLAN view stays",
          "The laid-out view is not on this PC yet" in page and "mapCyFetch(this)" in page)

    # --- Termshark -----------------------------------------------------------
    check("Termshark is pinned to its release and licence",
          len(termshark.TARBALL_SHA256) == 64 and len(termshark.LICENSE_SHA256) == 64
          and termshark.RELEASE.startswith("https://github.com/gcla/termshark/releases/download/")
          and termshark.LICENSE == "MIT")
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        good = d / "good.tgz"
        good.write_bytes(tgz({termshark.MEMBER: b"\x7fELF fake", "other/file": b"x"}))
        termshark.extract(good, d / "termshark")
        check("only the binary comes out of the tarball", (d / "termshark").read_bytes() == b"\x7fELF fake"
              and not (d / "other").exists())
        bad = d / "bad.tgz"
        bad.write_bytes(tgz({termshark.MEMBER: b"#!/bin/sh"}))
        try:
            termshark.extract(bad, d / "x")
            refused = False
        except termshark.TermsharkError:
            refused = True
        check("a tarball without a Linux program is refused", refused)
        saved = termshark.paths.downloads_dir
        termshark.paths.downloads_dir = lambda: d / "dl"
        try:
            got = []

            def fake(url, dest, expect_sha="", label=""):
                got.append((url, expect_sha))
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(good.read_bytes() if dest.name.endswith(".tar.gz") else b"MIT")
                return dest

            termshark.fetch(progress=lambda _m: None, download=fake)
            check("fetch checks both downloads against their pins and keeps the binary and licence",
                  got == [(f"{termshark.RELEASE}/{termshark.TARBALL}", termshark.TARBALL_SHA256),
                          (termshark.LICENSE_URL, termshark.LICENSE_SHA256)]
                  and termshark.ready() and not (d / "dl" / "termshark" / termshark.TARBALL).exists())
            check("the repository volume carries it for the probe",
                  [n for n, _ in termshark.volume_files()] == ["termshark/termshark", "termshark/LICENSE"])
        finally:
            termshark.paths.downloads_dir = saved
    lab = SimpleNamespace(node_list=lambda: [SimpleNamespace(id="probe01", roles=["capture"]),
                                             SimpleNamespace(id="dc01", roles=["ad-ds"])])
    steps = termshark.setup_steps(lab)
    check("a lab with a capture probe gets a Setup step for it",
          len(steps) == 1 and steps[0]["job"] == "termshark-fetch" and "probe01" in steps[0]["hint"]
          and termshark.setup_steps(lab, {"termshark"}) == [])
    cap = (root / "content" / "roles" / "capture.sh").read_text(encoding="utf-8")
    check("the capture role installs it from the volume, with a colour terminal",
          "/media/*/termshark/termshark" in cap and "TERM=xterm-256color" in cap and "blkid -L WLAPK" in cap)
    r = subprocess.run(["sh", "-n", str(root / "content" / "roles" / "capture.sh")], capture_output=True, text=True)
    check("capture.sh is valid shell", r.returncode == 0, r.stderr)
    apkrepo_src = (root / "winlab" / "apkrepo.py").read_text(encoding="utf-8")
    prepare_src = (root / "winlab" / "prepare.py").read_text(encoding="utf-8")
    check("preparing the fabric fetches it onto the volume, and a failure is not fatal",
          "files += termshark.volume_files()" in apkrepo_src and "termshark.fetch(" in prepare_src
          and "except termshark.TermsharkError" in prepare_src)

    # --- vwifi ---------------------------------------------------------------
    check("vwifi is pinned to a commit with libnl's release and nothing is fetched before a build is pinned",
          len(vwifi.COMMIT) == 40 and len(vwifi.LIBNL_SHA256) == 64
          and (vwifi.published() or vwifi.fetch(progress=lambda _m: None) is None))
    wf = (root / ".github" / "workflows" / "vwifi.yml").read_text(encoding="utf-8")
    check("the workflow builds it from the pinned commit, by hand only, and refuses a different digest",
          "workflow_dispatch" in wf and "import winlab.vwifi as v" in wf and "-DCMAKE_EXE_LINKER_FLAGS=-static" in wf
          and "sha256sum -c -" in wf and "not published." in wf and "tools/pack_vwifi.py" in wf)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "bin").mkdir()
        for prog in vwifi.PROGRAMS:
            (d / "bin" / prog).write_bytes(b"\x7fELF " + prog.encode())
        (d / "v.tar.gz").write_bytes(b"vsrc")
        (d / "nl.tar.gz").write_bytes(b"nlsrc")
        (d / "LICENSE.md").write_bytes(b"LGPL")
        import importlib.util
        spec = importlib.util.spec_from_file_location("pack_vwifi", root / "tools" / "pack_vwifi.py")
        pv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pv)
        a = pv.pack(d / "bin", d / "v.tar.gz", d / "nl.tar.gz", d / "LICENSE.md")
        b = pv.pack(d / "bin", d / "v.tar.gz", d / "nl.tar.gz", d / "LICENSE.md")
        with tarfile.open(fileobj=io.BytesIO(a), mode="r:gz") as tar:
            names = tar.getnames()
        check("the pack is reproducible and carries the programs, licence, notice and full source",
              a == b and gzip.decompress(a)[:5] == b"vwifi"
              and set(names) == {"vwifi/LICENSE.md", "vwifi/NOTICE", "vwifi/source/v.tar.gz", "vwifi/source/nl.tar.gz"}
              | {f"vwifi/bin/{p}" for p in vwifi.PROGRAMS}, str(names))

    # --- licences ------------------------------------------------------------
    check("LICENSING.md lists all three as fetched, never bundled",
          "| Cytoscape.js (the Network map's Laid out view) | MIT" in licensing
          and "| Termshark (the capture probe's packet view" in licensing
          and "| vwifi (real 802.11 between the lab's Linux machines" in licensing)



# ===== network operations: LibreNMS, Oxidized, Uptime Kuma (winlab/netops.py) =====


def _raises(fn, exc) -> bool:
    try:
        fn()
    except exc:
        return True
    return False



# ===== the network written down: phpIPAM and NetBox on the IPAM server (winlab/netdocs.py) =====



# ===== open source, batch 2: a real helpdesk (osTicket) and Wazuh on the Linux servers =====




# ===== VM-level backup: Hyper-V's own tools, Veeam, Proxmox Backup Server =====

# ===== Command Prompt and PowerShell windows on Windows machines =====
class _FakeConsoleHost:
    """The guest end of COM3 as winlab-term.cs speaks it, for the tests: a
    session echoes what is typed, `exit` ends it with code 0."""

    def __init__(self, build: str) -> None:
        import socket as _s
        import threading as _t
        self.build = build
        self.srv = _s.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.got: list[str] = []
        self.conn = None
        _t.Thread(target=self._serve, daemon=True).start()

    def say(self, text: str) -> None:
        if self.conn:
            self.conn.sendall((text + "\n").encode())

    def _serve(self) -> None:
        import base64 as b
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            self.conn = c
            buf = b""
            while True:
                try:
                    chunk = c.recv(65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    msg = raw.decode().strip()
                    self.got.append(msg)
                    f = msg.split(" ")
                    if f[0] == "HELLO" and self.build:
                        self.say(f"HELLO {self.build} {b.b64encode(b'Windows Server 2022').decode()} {b.b64encode(b'DC01').decode()}")
                    elif f[0] == "OPEN":
                        self.say(f"OUT {f[1]} " + b.b64encode(b"Microsoft Windows [Version 10.0.20348]\r\n\r\nC:\\Users\\alice>").decode())
                    elif f[0] == "IN":
                        data = b.b64decode(f[2])
                        if data == b"exit\r":
                            self.say(f"EXIT {f[1]} 0")
                        else:
                            self.say(f"OUT {f[1]} " + b.b64encode(data).decode())

    def close(self) -> None:
        self.srv.close()
        if self.conn:
            self.conn.close()


def test_windows_consoles():
    """Command Prompt and PowerShell windows for every Windows machine: a
    third serial port (COM3) on a loopback socket, the console host in the
    machine (ConPTY, signed in with the account typed), installed or updated
    over the agent, one session per window over the desktop's WebSocket."""
    import re
    import socket
    import struct
    import time as _time
    from winlab import netplan, schema, state, winterm, wsbridge
    from winlab.providers.qemu import QemuProvider, check_isolation

    # --- the hardware: COM3 on every Windows machine, nowhere else ---
    lab = schema.load("ad-ds-basics")
    plan = netplan.compile_topology(lab, check_ports=False)
    prov = QemuProvider(plan, accel="tcg")
    win = next(n for n in lab.node_list() if n.is_windows)
    rt = prov.build_node(win)
    argv = rt.argv
    dev = [argv[i + 1] for i, a in enumerate(argv) if a == "-device" and "isa-serial" in argv[i + 1]]
    check("a Windows machine gets COM3 (index 2) on its own IRQ, wired to a loopback socket",
          rt.wterm_port and dev == ["isa-serial,chardev=wterm,index=2,irq=5"]
          and f"socket,id=wterm,host=127.0.0.1,port={rt.wterm_port},server=on,wait=off" in argv, str(dev))
    check("COM1 stays the agent's: the first -serial is still the agent chardev",
          [argv[i + 1] for i, a in enumerate(argv) if a == "-serial"][0] == "chardev:ser0")
    check("the machine with COM3 is still isolated", not check_isolation(argv), str(check_isolation(argv)))
    fab = prov.build_fabric()
    check("the router (fabric) has no console port of this kind", "wterm" not in " ".join(fab.argv))
    st = state.LabState(name="t")
    st.nodes["dc01"] = state.NodeState("dc01", wterm_port=31055)
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        saved = state.paths.STATE
        state.paths.STATE = Path(td)
        try:
            state.save(st)
            check("the console port is kept in the lab state", state.load("t").nodes["dc01"].wterm_port == 31055)
        finally:
            state.paths.STATE = saved

    # --- the guest files ---
    agent = Path("content") / "agent"
    cs = (agent / "winlab-term.cs").read_text(encoding="utf-8")
    code = "\n".join(l for l in cs.splitlines() if not l.lstrip().startswith("//"))
    check("the console host is C# 5 (Windows PowerShell 5.1's Add-Type): no $\"\" strings, no => members",
          '$"' not in code and not re.search(r"\)\s*=>", code))
    check("the console host uses Windows' pseudoconsole and signs the account in",
          all(x in cs for x in ("CreatePseudoConsole", "ResizePseudoConsole", "ClosePseudoConsole", "LogonUser",
                                "CreateProcessAsUserW", "LoadUserProfile", "CreateEnvironmentBlock", "Elevated(")))
    check("the build is the start of the SHA-256 of the C# file",
          re.fullmatch(r"[0-9a-f]{16}", winterm.build_id()) and "[Security.Cryptography.SHA256]::Create()" in (agent / "winlab-term.ps1").read_text(encoding="utf-8"))
    check("a new machine copies the C# file and installs the console host at first logon",
          '*.cs"' in (agent / "winlab-stage0.cmd").read_text(encoding="utf-8")
          and "setup-term.ps1" in (agent / "setup-agent.ps1").read_text(encoding="utf-8"))
    setup = (agent / "setup-term.ps1").read_text(encoding="utf-8")
    check("the console host runs as a SYSTEM startup task that restarts",
          "-UserId 'SYSTEM'" in setup and "-AtStartup" in setup and "RestartCount" in setup)

    # --- the line: hello, sessions, output, exit ---
    guest = _FakeConsoleHost(winterm.build_id())
    try:
        line = winterm.Line(guest.port)
        info = line.hello(3.0)
        check("the host in the machine answers HELLO with its build, Windows edition and name",
              info and info["build"] == winterm.build_id() and info["os"] == "Windows Server 2022" and info["computer"] == "DC01", str(info))
        check("a new line first ends sessions an earlier desktop left open", guest.got and guest.got[0] == "RESET", str(guest.got[:2]))
        out, ended = [], []
        sid = line.open("cmd", 100, 30, False, out.append, lambda c, w: ended.append((c, w)))
        line.write(sid, b"dir\r")
        line.resize(sid, 132, 40)
        line.write(sid, b"x" * 7000)
        for _ in range(100):
            if len(out) >= 5:
                break
            _time.sleep(0.02)
        check("output comes back per session", out and b"C:\\Users\\alice>" in out[0] and b"dir\r" in b"".join(out))
        check("long input goes in pieces, a resize as SIZE",
              any(m == f"SIZE {sid} 132 40" for m in guest.got)
              and len([m for m in guest.got if m.startswith(f"IN {sid} ")]) == 4)
        line.write(sid, b"exit\r")
        for _ in range(100):
            if ended:
                break
            _time.sleep(0.02)
        check("exit in the console ends the session with its code", ended == [(0, "")], str(ended))
        sid2 = line.open("powershell", 80, 25, True, out.append, lambda c, w: ended.append((c, w)))
        for _ in range(100):
            if f"OPEN {sid2} powershell 80 25 1" in guest.got:
                break
            _time.sleep(0.02)
        check("Run as administrator asks for the account's full token", f"OPEN {sid2} powershell 80 25 1" in guest.got)
        guest.say(f"READY {winterm.build_id()} eA== eA==")
        for _ in range(100):
            if len(ended) == 2:
                break
            _time.sleep(0.02)
        check("a restarted console service ends the sessions it had", len(ended) == 2 and ended[1][0] is None and "restarted" in ended[1][1], str(ended))
        try:
            line.open("bash", 80, 25, False, out.append, lambda c, w: None); refused = False
        except winterm.TermError:
            refused = True
        check("only cmd and powershell", refused)
        line.close_line()
    finally:
        guest.close()

    # --- ensure: a machine without the console host gets it over the agent ---
    guest = _FakeConsoleHost("")       # nothing answers HELLO yet
    calls = []

    class FakeAgent:
        def put_file(self, path, data):
            calls.append(("put", path, len(data)))

        def run(self, command, timeout=0):
            calls.append(("run", command[:40]))
            guest.build = winterm.build_id()
            from winlab.guestctl import Result
            return Result(0, "setup-term: winlab-terminal started", "")

        def close(self):
            calls.append(("close",))
    try:
        ns = state.NodeState("dc01", serial_port=1, wterm_port=guest.port)
        said = []
        winterm._lines.pop(guest.port, None)
        saved_hello = winterm.Line.hello
        winterm.Line.hello = lambda self, timeout=4.0: saved_hello(self, min(timeout, 0.6))
        try:
            info = winterm.ensure(ns, said.append, connect=lambda: FakeAgent(), timeout=10)
        finally:
            winterm.Line.hello = saved_hello
        check("a machine with no console host gets the three files and its task over the agent",
              [c[1] for c in calls if c[0] == "put"] == [f"C:\\winlab\\{f}" for f in winterm.FILES]
              and any(c[0] == "run" for c in calls) and calls[-1] == ("close",) and info["build"] == winterm.build_id(), str(calls))
        check("and the window says so while it happens", said and "console service" in said[0], str(said))
        calls.clear()
        info = winterm.ensure(ns, said.append, connect=lambda: FakeAgent())
        check("a current console host is used as it is", not calls)
        try:
            winterm.ensure(state.NodeState("dc01"), connect=lambda: FakeAgent()); refused = ""
        except winterm.TermError as exc:
            refused = str(exc)
        check("a machine started before COM3 existed is told to restart once", "start it" in refused, refused)

        # --- one window over a WebSocket ---
        a, b = socket.socketpair()
        rf = a.makefile("rb")
        th = __import__("threading").Thread(target=winterm.serve_ws, daemon=True,
                                            args=(a, rf.read1, a.sendall, ns, "cmd", False, 90, 28))
        th.start()
        b.sendall(wsbridge.encode_frame(b'{"size": [120, 33]}', wsbridge.OP_TEXT, mask=True))
        b.sendall(wsbridge.encode_frame(b"ver\r", wsbridge.OP_BINARY, mask=True))
        reader = wsbridge.FrameReader(b.recv)
        got_open = got_echo = False
        deadline = _time.monotonic() + 5
        while _time.monotonic() < deadline and not (got_open and got_echo):
            op, payload = reader.next_message()
            if op == wsbridge.OP_TEXT and b'"open"' in payload:
                got_open = True
            if op == wsbridge.OP_BINARY and b"ver\r" in payload:
                got_echo = True
        check("a console window opens a session and carries keystrokes both ways", got_open and got_echo)
        check("the window's size reaches the console", any(m.startswith("SIZE ") and m.endswith(" 120 33") for m in guest.got))
        check("the session opened at the window's size", any(m.startswith("OPEN ") and m.endswith(" cmd 90 28 0") for m in guest.got))
        b.sendall(wsbridge.encode_frame(b"exit\r", wsbridge.OP_BINARY, mask=True))
        exit_seen = closed = False
        while _time.monotonic() < deadline + 5:
            msg = reader.next_message()
            if msg is None:
                break
            op, payload = msg
            if op == wsbridge.OP_TEXT and b'"exit": 0' in payload:
                exit_seen = True
            if op == wsbridge.OP_CLOSE:
                closed = True
                try:   # answer the close as a browser does (Windows' recv does not wake on SHUT_RD alone)
                    b.sendall(wsbridge.encode_frame(payload, wsbridge.OP_CLOSE, mask=True))
                except OSError:
                    pass
                break
        th.join(3)
        check("exit closes the window's connection after telling it the code", exit_seen and closed and not th.is_alive())
        b.close(); a.close()
    finally:
        guest.close()

    # --- the desktop ---
    page = (Path("winlab") / "webui_page.html").read_text(encoding="utf-8")
    check("the desktop opens Command Prompt and PowerShell windows over /ws/winterm",
          "function openWinTerm(" in page and "/ws/winterm?" in page and "Windows PowerShell (Administrator)" in page)
    check("they look like Windows' console: Campbell colours, PowerShell blue, Consolas, underline cursor",
          "#0c0c0c" in page and "#012456" in page and "Consolas" in page and "cursorStyle:'underline'" in page)
    check("they are on the machine window, the Machines list and the right-click menus",
          'class="con-wterm"' in page and "...wtItems(id)" in page and "...wtItems(key)" in page)
    check("conhost's copy and paste: right-click copies a selection or pastes", "addEventListener('contextmenu'" in page and "wtPaste(key)" in page)
    web = Path("winlab/webui.py").read_text(encoding="utf-8")
    check("the desktop serves /ws/winterm and tells the page which machines have COM3",
          '"/ws/winterm"' in web and '"wterm":' in web)


# ===== the hardware view: parts dragged in and out of a machine =====
def page_text() -> str:
    return (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")


def test_pc_hardware_view():
    """A PC, a server and a laptop open on the bench (winlab/pcparts.py):
    every part fitted lands in the lab file and the QEMU command line; the
    machine must be off, except a server's hot-swap drive bays."""
    import os
    from winlab import editor, hardware, media, netplan, paths, pcparts, schema, workbench
    from winlab.providers.qemu import QemuProvider
    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"))
    real = (workbench._running, pcparts._running, hardware._qmp_port, pcparts._qmp, pcparts._host)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        running = set()
        workbench._running = lambda name: set(running)
        pcparts._running = lambda lab, nid: nid in running
        hardware._qmp_port = lambda lab, nid: 4444 if nid in running else 0
        calls = []

        class FakeQmp:
            def __init__(self, port): pass
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def call(self, cmd, **kw):
                calls.append((cmd, kw))
                if cmd == "query-named-block-nodes":
                    return [{"node-name": n} for n in ("data0-fmt", "data0-file", "data0-gone")]
                return {}
        pcparts._qmp = FakeQmp
        pcparts._host = lambda: {"cores": 64, "ram_mb": 262144, "free_gb": 4000}
        try:
            editor.new_workbench("hw-lab")

            class _Dash:
                def reload(self):
                    self.lab = schema.load("hw-lab")
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
            d = _Dash()
            d.reload()

            def hw(**p):
                return workbench.act(d, "wb-hw", p)
            workbench.act(d, "wb-add", {"shelf": "pc", "how": "ready", "image": "win11", "id": "pc01", "x": 10, "y": 10})
            workbench.act(d, "wb-add", {"shelf": "server", "how": "ready", "image": "ws2022", "id": "srv01", "x": 90, "y": 10})
            b = hw(node="pc01")["board"]
            s = b["slots"]
            check("a PC opens as a tower: socket, four memory slots, six PCIe slots, two M.2, a drive cage",
                  b["form"] == "tower" and s["cpu"]["part"]["cores"] == d.lab.nodes["pc01"].cpus
                  and sum(1 for k in s if k.startswith("dimm-")) == 4 and sum(1 for k in s if k.startswith("pcie-")) == 6
                  and s["m2-0"]["part"] is None and s["bay35-0"]["part"]["system"]
                  and sum(x["mb"] for x in [s[f"dimm-{k}"]["part"] for k in range(4)] if x) == d.lab.nodes["pc01"].memory_mb)
            check("its network card sits in a PCIe slot", any((v["part"] or {}).get("kind") == "nic"
                                                             for k, v in s.items() if k.startswith("pcie-")))
            check("the tray offers processors, sticks, drives, cards, a DVD drive and a TPM",
                  {p["kind"] for p in b["tray"]} >= {"cpu", "dimm", "disk", "nic", "gpu", "hba", "dvd", "tpm"})
            r = hw(node="pc01", op="fit", part="cpu:8", slot="cpu")
            check("a processor dropped on the socket swaps it", r["ok"] and d.lab.nodes["pc01"].cpus == 8, r["message"])
            free = next(k for k, v in hw(node="pc01")["board"]["slots"].items() if k.startswith("dimm-") and not v["part"])
            mem = d.lab.nodes["pc01"].memory_mb
            r = hw(node="pc01", op="fit", part="dimm:8192", slot=free)
            n = d.lab.nodes["pc01"]
            check("a stick in a free slot adds its memory and stays in that slot",
                  r["ok"] and n.memory_mb == mem + 8192 and n.vars["dimms"].split()[int(free[-1])] == "8192", r["message"])
            r = hw(node="pc01", op="out", slot="dimm-0")
            check("a stick comes out", r["ok"] and d.lab.nodes["pc01"].memory_mb < mem + 8192, r["message"])
            r = hw(node="pc01", op="fit", part="gpu", slot="pcie-3")
            check("a graphics card does not go in an x1 slot", not r["ok"] and "x16" in r["message"])
            empty16 = next(k for k, v in hw(node="pc01")["board"]["slots"].items()
                           if k.startswith("pcie-") and not v["part"] and v["lanes"] == "x16")
            r = hw(node="pc01", op="fit", part="gpu", slot=empty16)
            check("it goes in a free x16 slot", r["ok"] and d.lab.nodes["pc01"].vars.get("gpu"), r["message"])
            r = hw(node="pc01", op="fit", part="nic", slot="pcie-5")
            n = d.lab.nodes["pc01"]
            check("a network card goes in the slot it was dropped on",
                  r["ok"] and len(n.nics) == 2 and n.vars["pcie"].split()[5] == "nic1", r["message"])
            nic0 = next(k for k, v in hw(node="pc01")["board"]["slots"].items() if (v["part"] or {}).get("nic") == 0)
            r = hw(node="pc01", op="out", slot=nic0)
            n = d.lab.nodes["pc01"]
            check("taking the first card out renumbers the other, which stays in its slot",
                  r["ok"] and len(n.nics) == 1 and n.vars["pcie"].split()[5] == "nic0", r["message"])
            b = hw(node="pc01")["board"]
            check("a SAS drive needs the adapter",
                  not hw(node="pc01", op="fit", part="disk:sas:40", slot=b["lands"]["sas"])["ok"])
            hba = next(k for k, v in b["slots"].items() if k.startswith("pcie-") and not v["part"])
            check("the adapter goes in a free slot", hw(node="pc01", op="fit", part="hba", slot=hba)["ok"])
            b = hw(node="pc01")["board"]
            r = hw(node="pc01", op="fit", part="disk:sas:40", slot=b["lands"]["sas"])
            r2 = hw(node="pc01", op="fit", part="disk:nvme:64", slot=b["lands"]["nvme"])
            r3 = hw(node="pc01", op="fit", part="disk:sata:20", slot="bay35-3")
            n = d.lab.nodes["pc01"]
            check("drives land in their bays: SAS on the adapter, NVMe in an M.2 socket",
                  r["ok"] and r2["ok"] and n.data_disks_gb == [40, 64] and n.vars["disk_bus"] == "sas nvme"
                  and b["lands"]["nvme"] == "m2-0" and b["lands"]["sas"] == "bay25-0", r["message"] + r2["message"])
            check("a drive dropped past the next free bay is told where it goes", not r3["ok"] and "bay35-1" not in r3["message"]
                  and "3.5-inch bay 2" in r3["message"], r3["message"])
            check("the adapter stays while SAS drives hang on it",
                  not hw(node="pc01", op="out", slot=hba)["ok"])
            argv = " ".join(QemuProvider(d.plan, accel="tcg").build_node(d.lab.nodes["pc01"]).argv)
            check("the parts are the QEMU machine's", "-smp 8" in argv and "virtio-vga" in argv and "mptsas1068" in argv
                  and "nvme," in argv and argv.count("e1000e") == 1 and f"-m {d.lab.nodes['pc01'].memory_mb}" in argv)

            running.add("pc01")
            r = hw(node="pc01", op="fit", part="nic", slot="pcie-4")
            check("nothing is fitted while it runs", not r["ok"] and "shut" in r["message"])
            r = hw(node="pc01", op="out", slot="m2-0")
            check("an M.2 drive does not come out while it runs", not r["ok"] and "hot-swap" in r["message"])
            running.discard("pc01")
            r = hw(node="pc01", op="out", slot="m2-0")
            check("off, a drive comes out onto the bench with its data",
                  r["ok"] and hw(node="pc01")["board"]["bench"][0]["index"] == 1, r["message"])
            r = hw(node="pc01", op="trash", disk=1)
            check("a drive on the bench thrown away is gone", r["ok"] and d.lab.nodes["pc01"].data_disks_gb == [40])

            r = hw(node="srv01", op="fit", part="disk:sata:40", slot=hw(node="srv01")["board"]["lands"]["sata"])
            b = hw(node="srv01")["board"]
            check("a server has hot-swap bays at the front, eight memory slots and a management module slot",
                  r["ok"] and b["form"] == "server" and b["slots"]["hs-0"]["part"]["system"]
                  and b["slots"]["hs-1"]["part"]["index"] == 0 and b["slots"]["hs-1"]["hot"]
                  and sum(1 for k in b["slots"] if k.startswith("dimm-")) == 8 and "bmc" in b["slots"])
            check("the management module goes in", hw(node="srv01", op="fit", part="bmc", slot="bmc")["ok"]
                  and "bmc" in d.lab.nodes["srv01"].vars and hw(node="srv01")["board"]["slots"]["bmc"]["part"])
            running.add("srv01")
            r = hw(node="srv01", op="out", slot="hs-1")
            check("a hot-swap drive comes out live: it stops answering", r["ok"] and "stops answering" in r["message"]
                  and [c for c, _ in calls] == ["blockdev-add", "blockdev-reopen"], str(calls))
            calls.clear()
            r = hw(node="srv01", op="back", disk=0)
            check("and goes back live, with its data", r["ok"] and hardware.pulled("hw-lab", "srv01") == set()
                  and [c for c, _ in calls] == ["query-named-block-nodes", "blockdev-reopen", "blockdev-del"]
                  and calls[1][1]["options"][0]["file"] == "data0-file", str(calls))
            running.discard("srv01")

            workbench.act(d, "wb-add", {"shelf": "laptop", "how": "ready", "image": "win11", "id": "lap01", "x": 200, "y": 10})
            b = hw(node="lap01")["board"]
            check("a laptop: soldered processor, two SO-DIMM slots, no PCIe slots",
                  b["form"] == "laptop" and b["slots"]["cpu"]["fixed"] and not any(k.startswith("pcie-") for k in b["slots"])
                  and sum(1 for k in b["slots"] if k.startswith("dimm-")) == 2
                  and not hw(node="lap01", op="fit", part="cpu:4", slot="cpu")["ok"])
            # a machine stronger than this PC: fitted, with a warning
            pcparts._host = lambda: {"cores": 4, "ram_mb": 8192, "free_gb": 100}
            n = d.lab.nodes["pc01"]
            r = hw(node="pc01", op="fit", part="cpu:16", slot="cpu")
            check("more cores than this PC has: fitted, and told", r["ok"] and n.cpus == 16
                  and "16 cores on a PC with 4" in r["message"], r["message"])
            free = next(k for k, v in hw(node="pc01")["board"]["slots"].items() if k.startswith("dimm-") and not v["part"])
            r = hw(node="pc01", op="fit", part="dimm:32768", slot=free)
            w = hw(node="pc01")["board"]["warnings"]
            check("more memory than this PC has: it will not start at this size",
                  r["ok"] and "will not start at this size" in r["message"]
                  and {x["part"] for x in w} == {"cpu", "dimm"}, r["message"])
            pcparts._host = lambda: {"cores": 4, "ram_mb": 8192, "free_gb": 30}
            b = hw(node="pc01")["board"]
            check("drives that can grow past the free disk are flagged",
                  any(x["part"] == "disk" and "30 GB free" in x["text"] for x in b["warnings"]) and b["host"]["free_gb"] == 30)
            pcparts._host = lambda: {"cores": 64, "ram_mb": 262144, "free_gb": 4000}
            check("a PC with room: no warning", hw(node="pc01")["board"]["warnings"] == [])
            check("this PC is read for real", pcparts.host()["cores"] >= 1 and pcparts.host()["ram_mb"] > 0)
            # each machine's label: its own serial, asset tag and UUID, in its firmware (winlab/identity.py)
            from winlab import identity
            b = hw(node="pc01")["board"]
            i = b["identity"]
            argv = QemuProvider(d.plan, accel="tcg").build_node(d.lab.nodes["pc01"]).argv
            check("a PC has its own label: maker, model, serial, asset tag, UUID",
                  i["maker"] == "winlab" and "Tower" in i["model"] and i["serial"].startswith("WL")
                  and i["asset"].startswith("IT-") and len(i["uuid"]) == 36, i)
            check("the label is in its firmware (SMBIOS types 1, 2, 3 and -uuid)",
                  argv[argv.index("-uuid") + 1] == i["uuid"]
                  and sum(1 for a in argv if a.startswith("type=")) == 3
                  and any(a.startswith("type=1,") and f"serial={i['serial']}" in a for a in argv)
                  and any(a.startswith("type=3,") and f"asset={i['asset']}" in a for a in argv))
            j = hw(node="srv01")["board"]["identity"]
            check("every machine its own serial and UUID; a server is a rack server",
                  j["serial"] != i["serial"] and j["uuid"] != i["uuid"] and "Rack" in j["model"]
                  and identity.of("other-lab", d.lab.nodes["pc01"])["serial"] != i["serial"])
            d.lab.nodes["pc01"].vars["asset_tag"] = "CORP,0042"
            check("a machine's asset_tag sets its tag (no comma reaches QEMU)",
                  identity.of("hw-lab", d.lab.nodes["pc01"])["asset"] == "CORP0042")
            d.lab.nodes["pc01"].vars.pop("asset_tag")
            ser = [s["part"]["serial"] for s in b["slots"].values() if (s.get("part") or {}).get("serial")]
            check("a new drive shows the serial on its label that QEMU gives it",
                  ser and all(f"serial={x}" in " ".join(argv) for x in ser), ser)
            check("the hardware view draws the label", "function hwTag(" in page_text() and "hwTag(b.identity)" in page_text())
            page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
            check("the device window has the hardware view", "function hwView(" in page and "'hw','Hardware'" in page)
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            workbench._running, pcparts._running, hardware._qmp_port, pcparts._qmp, pcparts._host = real
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]


# ===== Windows 11 track: firmware per machine, Secure Boot and legacy BIOS =====





# ===== IPv6 on the lab router's console and the switches (winlab/iosv6.py) =====


def _re_line(text: str, pattern: str) -> bool:
    import re as _re
    return any(_re.match(pattern, l) for l in text.splitlines())


def _raised(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - the test looks at what was raised
        return exc
    return None


# ---- DHCP snooping, Dynamic ARP Inspection and AAA logins (winlab/snooping.py, winlab/aaa.py) ----
def _l2sec_dhcp_ack(yi: str, mac: str, lease: int, kind: int = 5) -> bytes:
    """An IPv4 packet carrying a DHCP reply (ACK by default) as a server sends it."""
    import struct
    bo = bytearray(240)
    bo[0], bo[1], bo[2] = 2, 1, 6
    bo[16:20] = bytes(int(x) for x in yi.split("."))
    bo[28:34] = bytes.fromhex(mac.replace(":", ""))
    bo[236:240] = bytes.fromhex("63825363")
    opts = bytes([53, 1, kind, 54, 4, 10, 10, 10, 1, 51, 4]) + struct.pack(">I", lease) + bytes([0, 255])
    payload = bytes(bo) + opts
    udp = struct.pack(">HHHH", 67, 68, 8 + len(payload), 0) + payload
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, bytes(4), bytes(4)) + udp


def _l2sec_tcpdump(ts: int, ifc: str, way: str, pkt: bytes) -> str:
    """The packet as tcpdump -i any -tt -x prints it."""
    hx = pkt.hex()
    lines = [f"{ts}.123456 {ifc}  {way} IP 10.10.10.1.67 > 255.255.255.255.68: BOOTP/DHCP, Reply, length 300"]
    for off in range(0, len(pkt), 16):
        chunk = hx[off * 2:(off + 16) * 2]
        lines.append(f"\t0x{off:04x}:  " + " ".join(chunk[i:i + 4] for i in range(0, len(chunk), 4)))
    return "\n".join(lines)


class _L2secWire:
    """The router's nc, answered by a RADIUS and a TACACS+ server written
    here: what a student's FreeRADIUS or a TACACS+ daemon would say."""

    def __init__(self, key: str, users: dict):
        self.rkey = self.tkey = key
        self.users = users
        self.cmds: list[str] = []
        self.down = False
        self.priv = 15

    def _radius(self, pkt: bytes) -> bytes:
        import hashlib
        import hmac
        import struct
        from winlab import aaa
        s = self.rkey.encode()
        auth = pkt[4:20]
        attrs = dict(aaa._attrs(pkt[20:]))
        ma = attrs.get(80)
        if ma is None:
            return b""
        i = pkt.index(bytes([80, 18]) + ma)
        if hmac.new(s, pkt[:i + 2] + b"\0" * 16 + pkt[i + 18:], hashlib.md5).digest() != ma:
            return b""   # FreeRADIUS: invalid Message-Authenticator, dropped
        hidden, pw, last = attrs[2], b"", auth
        for k in range(0, len(hidden), 16):
            pw += bytes(x ^ y for x, y in zip(hidden[k:k + 16], hashlib.md5(s + last).digest()))
            last = hidden[k:k + 16]
        ok = self.users.get(attrs[1].decode()) == pw.rstrip(b"\0").decode("latin-1")
        out = aaa._attr(26, struct.pack(">I", 9) + aaa._attr(1, f"shell:priv-lvl={self.priv}".encode())) if ok else b""
        hdr = bytes([2 if ok else 3, pkt[1]]) + struct.pack(">H", 20 + len(out))
        return hdr + hashlib.md5(hdr + auth + out + s).digest() + out

    def _tacacs(self, data: bytes) -> bytes:
        import struct
        from winlab import aaa
        pk = aaa.tac_split(data, self.tkey)
        session = data[4:8]
        if not pk:
            return b""
        kind, _, body = pk[0]
        if kind == 1:
            if len(pk) < 2 or len(body) < 8 or 8 + body[4] > len(body):
                return b""   # cannot decode: the server closes the connection
            user = body[8:8 + body[4]].decode("latin-1")
            n = struct.unpack(">H", pk[1][2][:2])[0]
            pw = pk[1][2][5:5 + n].decode("latin-1")
            ask = bytes([5, 1]) + struct.pack(">HH", 9, 0) + b"Password:"
            fin = bytes([1 if self.users.get(user) == pw else 2, 0]) + struct.pack(">HH", 0, 0)
            return aaa.tac_packet(1, 2, session, ask, self.tkey) + aaa.tac_packet(1, 4, session, fin, self.tkey)
        arg = f"priv-lvl={self.priv}".encode()
        return aaa.tac_packet(2, 2, session, bytes([1, 1]) + struct.pack(">HH", 0, 0) + bytes([len(arg)]) + arg, self.tkey)

    def __call__(self, cmd: str, timeout: float = 0) -> str:
        import base64
        self.cmds.append(cmd)
        m = re.search(r"printf '%s' '?([A-Za-z0-9+/=]+)'? \| base64 -d \| (?:ip netns exec \S+ )?nc (-u )?-w \d+ (\S+) (\d+)",
                      cmd)
        if not m or self.down:
            return "\n"
        data = base64.b64decode(m.group(1))
        return base64.b64encode(self._radius(data) if m.group(2) else self._tacacs(data)).decode() + "\n"











def test_browse_dialog_in_front():
    """Browse... opens the Windows Open dialog in front of the app window:
    its owner is a shown, topmost window (a hidden one left the dialog behind
    the app with no taskbar button), PowerShell is found by its full path,
    a dialog that cannot open says so instead of doing nothing, and a
    cancel is an empty answer."""
    from types import SimpleNamespace
    from winlab import readiness
    script = readiness.dialog_script("file", "Choose the ISO you downloaded", "Disk images (*.iso)|*.iso",
                                     "C:\\Users\\o'brien\\Downloads")
    show, dialog = script.find("$owner.Show()"), script.find("ShowDialog($owner)")
    check("the dialog's owner is shown, topmost and on the taskbar before the dialog opens",
          0 < show < dialog and "$owner.TopMost = $true" in script and "$owner.ShowInTaskbar = $true" in script
          and "$owner.Activate()" in script and "$owner.Close()" in script)
    check("quotes in the start folder are PowerShell-escaped", "'C:\\Users\\o''brien\\Downloads'" in script)
    folder = readiness.dialog_script("folder", "Choose the folder to put on the disc")
    check("the folder dialog has the same owner", "FolderBrowserDialog" in folder and "$owner.Show()" in folder
          and "$d.SelectedPath" in folder)
    seen = []

    def fake(answer, code=0, err=b""):
        def run(argv, **kw):
            seen.append((argv, kw))
            return SimpleNamespace(stdout=answer, stderr=err, returncode=code)
        return run
    got = readiness.pick_file(run=fake("D:\\isos\\server.iso\r\n".encode()), windows=True)
    argv = seen[-1][0]
    check("the chosen file comes back as its path", got == "D:\\isos\\server.iso", got)
    check("PowerShell runs single-threaded-apartment, non-interactive",
          argv[0].lower().endswith("powershell.exe") and "-STA" in argv and "-NonInteractive" in argv)
    check("a cancel is an empty answer", readiness.pick_folder(run=fake(b""), windows=True) == "")
    try:
        readiness.pick_file(run=fake(b"", 1, b"Add-Type : cannot load\r\n"), windows=True)
        check("a dialog that fails to open raises", False)
    except RuntimeError as exc:
        check("a dialog that fails to open says so, so the page asks for the path", "type the path" in str(exc), str(exc))
    argvs = []
    def rec(argv, **kw):
        argvs.append(argv)
        return SimpleNamespace(returncode=0, stdout=b"/home/u/x.iso\n", stderr=b"")
    try:
        got = readiness.pick_file(run=rec, windows=False)
        why = ""
    except RuntimeError as exc:
        got, why = "", str(exc)
    if sys.platform.startswith("linux"):
        check("on Linux the desktop's own dialog opens (or the page asks for the path)",
              (got == "/home/u/x.iso" and argvs and argvs[0][0] in ("zenity", "kdialog", "yad")
               and "powershell" not in " ".join(argvs[0]).lower()) or ("type the path" in why and not argvs),
              f"{argvs} {why}")
    else:
        check("off Windows and Linux the picker refuses", bool(why) and not argvs)
    check("PowerShell by its full path under SystemRoot when it is there",
          readiness.powershell_exe({"SystemRoot": "/nonexistent"}) == "powershell.exe")
    check("the timeout and the hidden console stay", seen[0][1]["timeout"] == 3600 and "creationflags" in seen[0][1])
    page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    check("Browse... falls back to typing the path when the dialog cannot open",
          "do:'pick-iso'" in page and "Full path to the ISO you downloaded" in page)


def test_any_iso_goes_in():
    """Use any ISO: winlab reads the disc and files it where it fits instead
    of refusing "the wrong ISO". A Windows it installs goes in as that
    Windows (even picked under another one), an unknown or unsupported disc
    as the user's own ISO a machine boots for a hand install."""
    import os
    import tempfile
    from winlab import bsdfw, images, linuxiso, wim

    saved = (wim.images_in_iso, images.import_media, linuxiso.detect, bsdfw.detect, os.environ.get("WINLAB_IMAGES"))
    win11 = [{"name": "Windows 11 Pro", "edition": "Professional", "build": 26100, "type": "client", "index": 6}]
    win7 = [{"name": "Windows 7 Ultimate", "edition": "Ultimate", "build": 7601, "type": "client", "index": 1}]
    media: dict = {}
    calls = []

    def fake_wim(path):
        got = media.get(Path(path).name)
        if got is None:
            raise wim.WimError("no install.wim")
        return "sources/install.wim", got

    def fake_import(image_id, src, progress=None):
        calls.append(image_id)
        return Path(src)

    with tempfile.TemporaryDirectory() as td:
        os.environ["WINLAB_IMAGES"] = td
        wim.images_in_iso, images.import_media = fake_wim, fake_import
        linuxiso.detect = lambda p: "ubuntu24" if "ubuntu" in Path(p).name else ""
        bsdfw.detect = lambda p: ""
        try:
            def iso(name):
                f = Path(td) / name
                f.write_bytes(b"\0" * 4096)
                return f
            media["Win11_24H2_English_x64.iso"] = win11
            got, _, note = images.import_any(iso("Win11_24H2_English_x64.iso"), wanted="ws2022")
            check("a Windows 11 ISO picked under Server 2022 goes in as Windows 11, with a note",
                  got == "win11" and calls[-1] == "win11" and "went in as that" in note, f"{got} {note}")
            got, _, note = images.import_any(iso("Win11_24H2_English_x64.iso"), wanted="win11")
            check("the ISO asked for goes in quietly", got == "win11" and note == "")
            got, _, note = images.import_any(iso("ubuntu-24.04-live-server-amd64.iso"))
            check("a Linux installer goes in as that distribution", got == "ubuntu24" and calls[-1] == "ubuntu24")
            got, _, note = images.import_any(iso("unreadable.iso"), wanted="ws2025")
            check("an unreadable Windows disc under a Windows slot goes in as asked", got == "ws2025")
            media["en_windows_7_ultimate.iso"] = win7
            got, dest, note = images.import_any(iso("en_windows_7_ultimate.iso"), wanted="win10")
            check("a Windows winlab cannot set up goes in as the user's own ISO",
                  got == "en-windows-7-ultimate" and got in images.custom_images() and dest.exists()
                  and "install it yourself" in note and "Windows 7" in note, f"{got} {note}")
            got, _, note = images.import_any(iso("hirens-boot.iso"))
            check("any other disc goes in as the user's own ISO", got == "hirens-boot" and "does not know" in note)
            got2, _, _ = images.import_any(iso("hirens-boot.iso"))
            check("a second disc of the same name gets its own id", got2 == "hirens-boot-2", got2)
            check("ids from odd names stay valid", images.CUSTOM_ID.match(images.custom_id_for(Path("123 ##.iso"))) is not None
                  and images.custom_id_for(Path("ws2022.iso")) != "ws2022")
            try:
                images.import_any(Path(td) / "notes.txt")
                check("a missing file is refused", False)
            except images.ImageError:
                check("a missing file is refused", True)
        finally:
            wim.images_in_iso, images.import_media, linuxiso.detect, bsdfw.detect = saved[:4]
            if saved[4] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[4]
    page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    check("Setup offers Use any ISO", "browseIso('')" in page and "Use any ISO" in page)


def test_parallel_fetch_progress():
    """Several fetches at once (pressing Fetch on more than one item): each
    job's downloads report to that job's own bar, and the console gets
    whole, named lines instead of \\r redraws that overwrote each other."""
    import contextlib
    import io
    import tempfile
    import threading
    from winlab import bootstrap, webui

    with tempfile.TemporaryDirectory() as td:
        srcs = []
        for name in ("alpha", "beta"):
            f = Path(td) / f"{name}.bin"
            f.write_bytes(bytes(range(256)) * 12288)  # 3 MB: a dozen reads
            srcs.append(f)
        err = io.StringIO()
        jobs = webui.Jobs()
        with contextlib.redirect_stderr(err):
            ids = [jobs.start("iso-import", lambda emit, f=f: bootstrap._download_to(
                f.as_uri(), Path(td) / "out" / f.name, label=f"{f.stem} disc")) for f in srcs]
            for _ in range(200):
                if all(r["done"] for r in jobs.list()):
                    break
                threading.Event().wait(0.05)
        out = err.getvalue()
        recs = {r["id"]: r for r in jobs.list()}
        check("both fetches finish", all(recs[i]["ok"] for i in ids), str(recs))
        check("inside a job the console gets whole lines, no \\r redraws", "\r" not in out, repr(out[:200]))
        check("each download's lines are named", "alpha disc" in out and "beta disc" in out
              and out.count("done") >= 2 and " 50%" in out)
        check("each job's bar gets its own download's progress",
              all(recs[i]["last"].endswith("done") for i in ids))
        with contextlib.redirect_stderr(io.StringIO()) as solo:
            bootstrap._download_to(srcs[0].as_uri(), Path(td) / "solo.bin", label="solo")
        check("on its own (the command line) the download still redraws one line", "\r    solo" in solo.getvalue())


def test_get_ready_follows_own_fetches():
    """Fetch pressed on single items, then Get everything ready: the run
    follows the fetches already going (no second download of the same file),
    shows their progress as its own steps, and Setup marks those steps as
    running instead of offering their buttons again."""
    import threading
    import time
    from winlab import schema, webui

    class Dash(webui.Dashboard):
        def __init__(self, lab):
            super().__init__(lab, accel="tcg")
            self.done: set[str] = set()
            self.ran: list[str] = []

        def _setup_state(self, quick=False):
            def st(i, job, **kw):
                return {"id": i, "label": f"step {i}", "job": job, "done": i in self.done, "blocked": False, **kw}
            return {"steps": [st("bootstrap", "bootstrap"), st("virtio", "virtio-fetch"),
                              st("ubuntu", "appliance-fetch", image="ubuntu"),
                              {"id": "up", "label": "Start the lab", "done": False}], "media": []}

        def _run(self, name):
            def run(emit):
                self.ran.append(name)
                emit(f"{name} 100%")
                self.done.add(name)
            return run

        def stream_bootstrap(self, emit):
            self._run("bootstrap")(emit)

        @property
        def stream_virtio(self):
            return self._run("virtio")

        def stream_appliance(self, image_id):
            return self._run(image_id)

    d = Dash(schema.load("ad-ds-basics"))
    release = threading.Event()

    def own_virtio(emit):  # the user pressed Fetch drivers by itself
        emit("virtio-win.iso 40%")
        release.wait(10)
        d.done.add("virtio")
    jid = d.jobs.start("virtio-fetch", own_virtio)
    d.jobs.tag(jid, {"job": "virtio-fetch"})
    end = time.monotonic() + 5
    while d.jobs.record(jid)["percent"] != 40 and time.monotonic() < end:
        time.sleep(0.01)
    steps = {st["id"]: st for st in d.setup_state(quick=True)["steps"]}
    check("Setup shows the fetch running with its percent", steps["virtio"].get("running") == 40
          and "running" not in steps["bootstrap"], str(steps["virtio"]))
    check("pressing the same Fetch again follows the running job", d.same_job("virtio-fetch", {}) == jid)
    check("a different image is a different job", d.same_job("appliance-fetch", {"image": "ubuntu"}) == "")
    out: list[str] = []
    t = threading.Thread(target=d.stream_get_ready, args=(out.append,))
    t.start()
    end = time.monotonic() + 5
    while not any("following it" in x for x in out) and time.monotonic() < end:
        time.sleep(0.01)
    check("Get everything ready reaches the running fetch and follows it", any("following it" in x for x in out), str(out))
    check("while it follows, Get everything ready's step is that fetch",
          d.same_job("virtio-fetch", {}) == jid and d.ready["steps"][d.ready["current"]]["label"] == "step virtio")
    release.set()
    t.join(10)
    check("the fetch is not run a second time; the rest of the steps run",
          d.ran == ["bootstrap", "ubuntu"], str(d.ran))
    check("the run ends with every step done", "everything is ready" in out[-1], out[-1])
    page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    check("Setup shows fetches pressed one by one next to Get everything ready",
          "Fetching now: " in page and "working on it… ${st.running}%" in page)



def test_download_resume_and_leftovers():
    """Closing winlab mid-download: the .part is resumed on the next fetch
    with a Range request (a server that sends the whole file starts it
    over), bad bytes are never resumed, and half files nothing touches any
    more are removed when winlab starts."""
    import contextlib
    import hashlib
    import io
    import os
    import tempfile
    import threading
    import time as _time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from winlab import bootstrap

    body = bytes(range(256)) * 4096  # 1 MB
    seen: list[str] = []

    class H(BaseHTTPRequestHandler):
        ranges = True

        def do_GET(self):
            rng = self.headers.get("Range", "")
            seen.append(rng)
            if rng and H.ranges:
                start = int(rng.split("=")[1].rstrip("-"))
                if start >= len(body):
                    self.send_response(416)
                    self.end_headers()
                    return
                self.send_response(206)
                self.send_header("Content-Length", str(len(body) - start))
                self.end_headers()
                self.wfile.write(body[start:])
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/disc.iso"
    sha = hashlib.sha256(body).hexdigest()
    try:
        with tempfile.TemporaryDirectory() as td, contextlib.redirect_stderr(io.StringIO()) as err:
            dest = Path(td) / "disc.iso"
            part = dest.with_name("disc.iso.part")
            part.write_bytes(body[:300000])  # what a closed winlab left
            bootstrap._download_to(url, dest, sha, label="disc")
            check("a half download is resumed where it stopped", seen[-1] == "bytes=300000-"
                  and dest.read_bytes() == body and not part.exists() and "resuming at" in err.getvalue(), str(seen))
            dest.unlink()
            H.ranges = False
            part.write_bytes(body[:300000])
            bootstrap._download_to(url, dest, sha, label="disc")
            check("a server that sends the whole file starts it over, still correct", dest.read_bytes() == body)
            dest.unlink()
            H.ranges = True
            part.write_bytes(body)  # complete already: the server answers 416
            bootstrap._download_to(url, dest, sha, label="disc")
            check("a .part the server cannot continue is fetched again", dest.read_bytes() == body)
            dest.unlink()
            part.write_bytes(b"\xff" * 300000)  # not this file's bytes
            sleep, bootstrap.time.sleep = bootstrap.time.sleep, lambda s: None
            try:
                bootstrap._download_to(url, dest, sha, label="disc")
                check("bad bytes are thrown away, then the download is done again", dest.read_bytes() == body)
            except bootstrap.BootstrapError as exc:
                check("bad bytes are thrown away, then the download is done again", False, str(exc))
            finally:
                bootstrap.time.sleep = sleep
            # leftovers at start
            root = Path(td) / "store"
            (root / "downloads").mkdir(parents=True)
            old_part = root / "downloads" / "old.iso.part"
            new_part = root / "downloads" / "new.iso.part"
            old_copy = root / "downloads" / "win.iso.copying"
            live_copy = root / "downloads" / "live.iso.copying"
            for f in (old_part, new_part, old_copy, live_copy):
                f.write_bytes(b"x")
            now = _time.time()
            os.utime(old_part, (now - 8 * 86400, now - 8 * 86400))
            os.utime(new_part, (now - 2 * 86400, now - 2 * 86400))
            os.utime(old_copy, (now - 3600, now - 3600))
            gone = bootstrap.clean_leftovers([root], now=now)
            check("a .part untouched for a week and a cut-off import copy are removed",
                  set(gone) == {old_part, old_copy} and not old_part.exists() and not old_copy.exists())
            check("a recent .part stays to be resumed; a copy still running stays",
                  new_part.exists() and live_copy.exists())
    finally:
        srv.shutdown()
    import winlab.webui as _w
    check("the desktop cleans leftovers when it starts", "threading.Thread(target=_clean_leftovers" in
          Path(_w.__file__).read_text(encoding="utf-8"))

# ===== the helpdesk ticket game (winlab/ticketgame.py) =====














def json_dump(v) -> str:
    import json
    return json.dumps(v)


# ===== the Linux track: Samba, BIND and a Linux client in the Windows domain =====


# ===== EIGRP (FRRouting's eigrpd) and HSRP (winlab's own speaker) on the router (winlab/ioseigrp.py, ioshsrp.py, hsrpd.py) =====
# eigrpd's own output, captured from FRRouting 8.4.4 in network namespaces:
# the lab router (2.2.2.2) with rtr-edge (10.80.0.3) and rtr-isp
# (198.51.100.2) both announcing 10.90.0.0/24, delay 200 on the office link.
_EIGRP_NBR = """
EIGRP neighbors for AS(100)

H   Address           Interface            Hold   Uptime   SRTT   RTO   Q     Seq
                                           (sec)           (ms)        Cnt    Num
0   10.80.0.3         {office}              11     0        0      2    0      2
0   198.51.100.2      {isp}              14     0        0      2    0      2
"""
_EIGRP_TOPO = """
EIGRP Topology Table for AS(100)/ID(2.2.2.2)

Codes: P - Passive, A - Active, U - Update, Q - Query, R - Reply
       r - reply Status, s - sia Status

P  10.80.0.0/24, 3 successors, FD is 28160, serno: 0
       via Connected, {office}
       via Connected, {office}
       via Connected, {office}
P  10.81.0.0/24, 1 successors, FD is 79360, serno: 0
       via 10.80.0.3 (79360/28160), {office}
P  10.90.0.0/24, 1 successors, FD is 30720, serno: 0
       via 198.51.100.2 (30720/28160), {isp}
       via 10.80.0.3 (79360/28160), {office}
P  198.51.100.0/30, 1 successors, FD is 28160, serno: 0
       via Connected, {isp}
"""
_EIGRP_IFS = """
EIGRP interfaces for AS(100)

Interface        Bandwidth  Delay      Peers  Xmit Queue   Mean    Pacing Time    Multicast    Pending  Hello    Holdtime
                                              Un/Reliable  SRTT    Un/Reliable    Flow Timer   Routes
{office}         100000     200        1      0 / 0         0       0              0            0       5        15
{isp}         100000     10         1      0 / 0         0       0              0            0       5        15
"""


def _router_console_dash(root, td):
    """A router-protocols lab in a temp dir and a console on its router."""
    from winlab import netplan, paths, schema, workbench
    paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
    paths.LABS.mkdir(parents=True)
    (paths.LABS / "router-protocols.toml").write_text(
        (root / "content" / "labs" / "router-protocols.toml").read_text(encoding="utf-8"), encoding="utf-8")

    class Dash:
        def __init__(self):
            self.reload()

        def reload(self):
            self.lab = schema.load("router-protocols")
            self.plan = netplan.compile_topology(self.lab, check_ports=False)
            self.wb_live = workbench.Live()
    workbench._running = lambda _name: {"fabric"}
    return Dash()




def test_w11_hsrp_speaker():
    """winlab-hsrpd, winlab's own HSRP speaker: its packets byte for byte
    against RFC 2281 (version 1) and the version 2 TLV layout, the frames it
    puts on the wire, its configuration file, and its state machine with
    two speakers in one process over a fake wire."""
    import socket
    import struct
    from winlab import hsrpd

    dflt = "".join(map(chr, (99, 105, 115, 99, 111))).encode()   # the protocol's default text
    check("with no authentication configured, the protocol's default text is sent",
          hsrpd.auth_bytes(None) == dflt + b"\0\0\0")
    text = "lab" + "1"
    v1 = hsrpd.encode_v1(hsrpd.OP_HELLO, "Active", 3, 10, 110, 1, hsrpd.auth_bytes(text), "10.80.0.1")
    check("version 1, RFC 2281 5.1: version 0, op hello, state 16 (Active), 3 s, 10 s, priority 110, group 1, "
          "8 octets of text, the virtual IP: 20 octets",
          v1 == bytes.fromhex("00 00 10 03 0a 6e 01 00") + text.encode() + b"\0" * 4 + bytes.fromhex("0a500001"),
          v1.hex())
    check("the version 1 state octets are RFC 2281's",
          [hsrpd.V1_CODE[s] for s in hsrpd.STATES] == [0, 1, 2, 4, 8, 16])
    coup = hsrpd.encode_v1(hsrpd.OP_COUP, "Speak", 3, 10, 120, 7, hsrpd.auth_bytes(None), "10.80.0.1")
    check("coup is op 1 and resign op 2", coup[1] == 1 and coup[2] == 4
          and hsrpd.encode_v1(hsrpd.OP_RESIGN, "Active", 3, 10, 1, 1, dflt, "")[1:3] == b"\x02\x10")
    m = hsrpd.decode(v1)
    check("a version 1 packet decodes back", m["version"] == 1 and m["state"] == "Active" and m["prio"] == 110
          and m["group"] == 1 and m["vip"] == "10.80.0.1" and m["hold"] == 10.0)
    ident = bytes.fromhex("525400123456")
    v2 = hsrpd.encode_v2(hsrpd.OP_HELLO, "Standby", 4095, ident, 100, 3, 10, "10.80.0.1", hsrpd.auth_bytes(None))
    want = (bytes([1, 40, 2, 0, 5, 4]) + struct.pack("!H", 4095) + ident + struct.pack("!III", 100, 3000, 10000)
            + bytes.fromhex("0a500001") + b"\0" * 12 + bytes([3, 8]) + dflt + b"\0\0\0")
    check("version 2: group state TLV (type 1, length 40: version 2, op, state 5 Standby, IPv4, group in two "
          "octets, the sender's MAC, priority, hello and hold in ms, the address in 16 octets), then text auth TLV",
          v2 == want and len(v2) == 52, v2.hex())
    m2 = hsrpd.decode(v2 + bytes([2, 4, 0, 1, 0, 0]))
    check("a version 2 packet decodes back, an unknown TLV after it skipped",
          m2["version"] == 2 and m2["group"] == 4095 and m2["state"] == "Standby" and m2["hello"] == 3.0
          and m2["ident"] == ident and m2["auth"] == hsrpd.auth_bytes(None))
    check("garbage and wrong versions decode to nothing", hsrpd.decode(b"\x01\x05xx") is None
          and hsrpd.decode_v1(b"\x00" * 10) is None and hsrpd.decode(b"\x01\x28" + b"\x03" + b"\0" * 39) is None)
    check("virtual MACs: 0000.0c07.acXX for version 1, 0000.0c9f.fXXX for version 2",
          hsrpd.vmac(1, 1) == "00:00:0c:07:ac:01" and hsrpd.vmac(2, 1) == "00:00:0c:9f:f0:01"
          and hsrpd.vmac(2, 4095) == "00:00:0c:9f:ff:ff" and hsrpd.cisco_mac(hsrpd.vmac(2, 1)) == "0000.0c9f.f001")
    fr = hsrpd.udp_frame("00:00:0c:9f:f0:01", "10.80.0.2", hsrpd.V2_GROUP, v2, 7)
    ip, udp = fr[14:34], fr[34:]
    pseudo = socket.inet_aton("10.80.0.2") + socket.inet_aton("224.0.0.102") + struct.pack("!BBH", 0, 17, len(udp))
    check("the frame: to 01:00:5e:00:00:66 from the virtual MAC, IPv4 TTL 1, UDP 1985 to 1985, checksums right",
          fr[:6] == bytes.fromhex("01005e000066") and fr[6:12] == bytes.fromhex("00000c9ff001") and fr[12:14] == b"\x08\x00"
          and ip[8] == 1 and ip[9] == 17 and hsrpd._csum(ip) == 0 and udp[:4] == struct.pack("!HH", 1985, 1985)
          and hsrpd._csum(pseudo + udp) == 0 and udp[8:] == v2)
    check("version 1 hellos go to 224.0.0.2 (01:00:5e:00:00:02)", hsrpd.mcast_mac(hsrpd.V1_GROUP) == "01:00:5e:00:00:02")
    g = hsrpd.garp_frame("00:00:0c:07:ac:01", "10.80.0.1")
    check("gratuitous ARP: broadcast from the virtual MAC, sender and target the virtual address",
          g[:6] == b"\xff" * 6 and g[12:14] == b"\x08\x06" and g[14 + 8:14 + 14] == bytes.fromhex("00000c07ac01")
          and g[14 + 14:14 + 18] == g[14 + 24:14 + 28] == bytes.fromhex("0a500001") and len(g) == 60)

    conf = ("interface eth1\n standby version 2\n standby 1 ip 10.80.0.1\n standby 1 ip 10.80.0.5 secondary\n"
            " standby 1 priority 90\n standby 1 preempt delay minimum 30\n standby 1 timers 1 4\n"
            f" standby 1 authentication {text}\n standby 1 track eth0 decrement 20\n standby 1 name OFFICE\n"
            "interface eth2\n standby ip 10.81.0.1\n")
    cfgs = hsrpd.parse_conf(conf)
    a, b = cfgs
    check("the configuration file is IOS's own lines: version, ip, secondary, priority, preempt delay, timers, "
          "authentication, track, name; a group with no number is group 0",
          a["version"] == 2 and a["vip"] == "10.80.0.1" and a["secondary"] == ["10.80.0.5"] and a["prio"] == 90
          and a["preempt"] and a["delay"] == 30 and (a["hello"], a["hold"]) == (1.0, 4.0) and a["auth"] == text
          and a["tracks"] == [{"iface": "eth0", "decrement": 20}] and a["name"] == "OFFICE"
          and b["group"] == 0 and b["version"] == 1 and not b["preempt"] and b["prio"] == 100)
    bad = []
    for txt in ("interface e\n standby 1 authentication md5 key-string x\n", "interface e\n standby 300 ip 10.0.0.1\n",
                "interface e\n standby 1 timers 5 5\n", " standby 1 ip 10.0.0.1\n", "interface e\n standby 1 frob\n"):
        try:
            hsrpd.parse_conf(txt)
        except hsrpd.ConfError as e:
            bad.append(str(e))
    check("the file's mistakes are named: md5, a version 1 group above 255, hold not above hello, no interface, "
          "an unknown word", len(bad) == 5 and "MD5" in bad[0] and "0 to 255" in bad[1], str(bad))

    # Two speakers in one process over a fake wire.
    def pair(pa, pb, pre_a=True, pre_b=True, extra=""):
        wire, logs = [], []

        def mk(ip, prio, pre):
            c = hsrpd.parse_conf(f"interface eth1\n standby version 2\n standby 1 ip 10.80.0.1\n"
                                 f" standby 1 priority {prio}\n" + (" standby 1 preempt\n" if pre else "") + extra)[0]
            grp = hsrpd.Group(c, None, log=lambda t, ip=ip: logs.append((ip, t)))
            grp.send = lambda op, grp=grp: wire.append((grp.my_ip, hsrpd.decode(grp.payload(op, ident))))
            return grp
        ga, gb = mk("10.80.0.2", pa, pre_a), mk("10.80.0.3", pb, pre_b)
        return ga, gb, wire, logs

    def run(ga, gb, wire, t0, t1, up=(True, True)):
        t = t0
        while t < t1:
            t = round(t + 0.1, 1)
            for x, on in zip((ga, gb), up):
                if on:
                    x.tick(t)
            while wire:
                src, msg = wire.pop(0)
                for x, on in zip((ga, gb), up):
                    if on and x.my_ip != src:
                        x.receive(msg, src, t)
        return t

    ga, gb, wire, logs = pair(110, 100)
    ga.start("10.80.0.2", 0)
    gb.start("10.80.0.3", 0.5)
    t = run(ga, gb, wire, 0, 40)
    seen = [s for ip, s in logs if ip == "10.80.0.2"]
    check("alone at first, the better router goes Listen, Speak, Standby, Active; the other ends Standby",
          (ga.state, gb.state) == ("Active", "Standby")
          and [x.split("state ")[1] for x in seen] == ["Init -> Listen", "Listen -> Speak", "Speak -> Standby",
                                                      "Standby -> Active"], str(logs))
    act = ga.status(t)
    check("the Active knows its Standby, the Standby its Active", act["active"] == "local" and act["standby"] == "10.80.0.3"
          and gb.status(t)["active"] == "10.80.0.2" and gb.status(t)["standby"] == "local")
    t2 = run(ga, gb, wire, t, t + 6, up=(False, True))
    check("the Active falls silent: the Standby waits out the hold time", gb.state == "Standby")
    t2 = run(ga, gb, wire, t2, t2 + 4.5, up=(False, True))
    check("then takes over: Standby -> Active", gb.state == "Active")
    ga.stop(t2)
    wire.clear()
    ga.start("10.80.0.2", t2)
    t3 = run(ga, gb, wire, t2, t2 + 15)
    check("the better router comes back and preempts with a coup; the other goes Speak then Standby",
          (ga.state, gb.state) == ("Active", "Standby") and any("Active -> Speak" in s for ip, s in logs if ip == "10.80.0.3"))

    ga, gb, wire, logs = pair(110, 100, pre_a=False)
    gb.start("10.80.0.3", 0)
    t = run(ga, gb, wire, 0, 25)
    ga.start("10.80.0.2", t)
    t = run(ga, gb, wire, t, t + 30)
    check("without preempt the better router waits as Standby", (ga.state, gb.state) == ("Standby", "Active"))

    ga, gb, wire, logs = pair(110, 100, extra=" standby 1 track eth0 decrement 20\n")
    ga.start("10.80.0.2", 0)
    gb.start("10.80.0.3", 0)
    t = run(ga, gb, wire, 0, 30)
    ga.track_down = {"eth0"}
    t = run(ga, gb, wire, t, t + 5)
    check("tracking: eth0 down takes 20 off (110 -> 90) and the other router (100, preempt) takes Active",
          ga.prio() == 90 and gb.state == "Active" and ga.state != "Active",
          f"{ga.state} {gb.state}")
    ga.track_down = set()
    t = run(ga, gb, wire, t, t + 5)
    check("eth0 back: 110 again and the lab router takes it back", ga.state == "Active" and gb.state == "Standby")
    ga.stop(t)
    t = run(ga, gb, wire, t, t + 0.3, up=(False, True))
    check("a resign makes the Standby Active at once, without waiting for the hold time", gb.state == "Active")

    ga, gb, wire, logs = pair(100, 100)
    ga.start("10.80.0.2", 0)
    gb.start("10.80.0.3", 0)
    run(ga, gb, wire, 0, 40)
    check("equal priorities: the higher address wins", (ga.state, gb.state) == ("Standby", "Active"))

    ga, gb, wire, logs = pair(110, 100)
    gb.cfg["auth"] = "other"
    ga.start("10.80.0.2", 0)
    gb.start("10.80.0.3", 0)
    run(ga, gb, wire, 0, 40)
    check("different authentication text: each ignores the other, both Active, and it is logged",
          (ga.state, gb.state) == ("Active", "Active") and any("BADAUTH" in s for _, s in logs))
    out = hsrpd.show_brief([ga.status(40), gb.status(40)], names={"eth1": "GigabitEthernet0/1/0"},
                           short=lambda n: n.replace("GigabitEthernet", "Gi"))
    check("show standby brief: IOS's columns", "Interface   Grp  Pri P State   Active          Standby         Virtual IP"
          in out and "Gi0/1/0     1    110 P Active  local" in out, out)
    det = hsrpd.show_detail([ga.status(40)])
    check("show standby: state, virtual IP and MAC, timers, preemption, priority, group name",
          "eth1 - Group 1 (version 2)\n  State is Active" in det and "Active virtual MAC address is 0000.0c9f.f001 "
          "(MAC In Use)" in det and "Hello time 3 sec, hold time 10 sec" in det and "Preemption enabled" in det
          and "Priority 110 (configured 110)" in det and "Authentication mismatch with 10.80.0.3" in det, det)




def test_w11_hsrp_two_speakers_netns():
    """Two real winlab-hsrpd processes in two Linux network namespaces on a
    bridge, with a PC namespace: election, the PC pinging the virtual
    address at the virtual MAC, failover when the Active's link goes down.
    Needs root, ip netns and ping; skipped (said so) without them."""
    import os
    import shutil
    import subprocess
    import time
    from winlab import hsrpd

    if getattr(os, "geteuid", lambda: -1)() != 0 or not shutil.which("ip") or not shutil.which("ping"):
        print("  skip   two speakers in network namespaces (needs root, ip and ping)")
        return
    tag = f"wlh{os.getpid() % 10000}"
    ns = [f"{tag}a", f"{tag}b", f"{tag}p", f"{tag}s"]

    def sh(cmd):
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

    if sh(f"ip netns add {ns[3]}").returncode != 0:
        print("  skip   two speakers in network namespaces (ip netns add refused)")
        return
    procs = []
    td = Path(tempfile.mkdtemp())
    try:
        sh(f"ip -n {ns[3]} link add br0 type bridge && ip -n {ns[3]} link set br0 up")
        for n, addr in zip(ns[:3], ("10.80.0.2/24", "10.80.0.3/24", "10.80.0.10/24")):
            sh(f"ip netns add {n}; ip -n {n} link set lo up; ip link add {n}x type veth peer name eth1 netns {n}; "
               f"ip link set {n}x netns {ns[3]}; ip -n {ns[3]} link set {n}x master br0; ip -n {ns[3]} link set {n}x up; "
               f"ip -n {n} addr add {addr} dev eth1; ip -n {n} link set eth1 up")
        for n, prio in ((ns[0], 110), (ns[1], 100)):
            (td / f"{n}.conf").write_text(f"interface eth1\n standby version 2\n standby 1 ip 10.80.0.1\n"
                                          f" standby 1 priority {prio}\n standby 1 preempt\n standby 1 timers 1 3\n")
            procs.append(subprocess.Popen(["ip", "netns", "exec", n, sys.executable, hsrpd.__file__, "-c",
                                           str(td / f"{n}.conf"), "-s", str(td / f"{n}.json")],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

        def states():
            out = []
            for n in ns[:2]:
                try:
                    out.append(json.loads((td / f"{n}.json").read_text())["groups"][0]["state"])
                except (OSError, ValueError, KeyError, IndexError):
                    out.append("")
            return out
        import json
        deadline = time.time() + 20
        while time.time() < deadline and states() != ["Active", "Standby"]:
            time.sleep(0.5)
        check("two real speakers elect the better one Active, the other Standby", states() == ["Active", "Standby"],
              str(states()))
        ping = sh(f"ip netns exec {ns[2]} ping -c 2 -W 1 10.80.0.1")
        neigh = sh(f"ip -n {ns[2]} neigh show 10.80.0.1").stdout
        check("the PC reaches the virtual address at the virtual MAC", ping.returncode == 0
              and "00:00:0c:9f:f0:01" in neigh, ping.stdout + neigh)
        sh(f"ip -n {ns[0]} link set eth1 down")
        deadline = time.time() + 10
        while time.time() < deadline and states()[1] != "Active":
            time.sleep(0.5)
        ping = sh(f"ip netns exec {ns[2]} ping -c 2 -W 1 10.80.0.1")
        check("the Active's link goes down: the Standby takes over and the PC still reaches the gateway",
              states()[1] == "Active" and ping.returncode == 0, str(states()) + ping.stdout)
        sh(f"ip -n {ns[0]} link set eth1 up")
        deadline = time.time() + 15
        while time.time() < deadline and states() != ["Active", "Standby"]:
            time.sleep(0.5)
        check("it comes back and preempts", states() == ["Active", "Standby"], str(states()))
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        for n in ns:
            sh(f"ip netns del {n}")
        shutil.rmtree(td, ignore_errors=True)


def _pagp_cfg(dev, mode, sw_no, port_no, group=1):
    return {"dev": dev, "mode": mode, "group": group, "device_id": f"02:57:4c:00:00:0{sw_no}",
            "device_name": f"SW{sw_no}", "port_name": f"Gi0/{port_no}", "ifindex": 24 + port_no,
            "bond": f"stp{sw_no}po{group}", "bridge": f"stp{sw_no}", "native": 4094, "vids": [], "cost": 4,
            "priority": 32, "switch": f"sw{sw_no}", "port": f"GigabitEthernet0/{port_no}"}


def _pagp_wire(cfgs, peer, seconds=10.0, step=0.25, start=0.0, eng=None, quiet=()):
    """Runs winlab-pagpd's Engine over a fake wire: what a port sends arrives
    at its peer (unless that cable is in `quiet`)."""
    from winlab import pagpd
    eng = eng or pagpd.Engine(cfgs, log=lambda _t: None)
    t = start
    while t < start + seconds:
        for dev in eng.ports:
            eng.link(dev, True, t)
        for dev, pdu in eng.tick(t):
            if dev not in quiet and peer.get(dev) in eng.ports:
                eng.receive(peer[dev], pagpd.unframe(pagpd.frame("02:00:00:00:00:01", pdu)), t)
        t += step
    return eng, t


def test_w11_pagp_speaker():
    """winlab-pagpd, winlab's own PAgP speaker (winlab/pagpd.py): its frames
    byte for byte against the layout Wireshark's PAgP dissector decodes,
    PAgP's rules emerging from the protocol over a fake wire (desirable with
    auto forms, auto with auto never does, a silent far end stands alone,
    two neighbours on one group suspend the odd one out), and what the
    router and the switch's console make of it."""
    from winlab import etherchannel, pagpd
    local = {"device_id": "02:57:4c:00:00:01", "learn_cap": 1, "priority": 128, "ifindex": 26,
             "group_cap": 2, "group_ifindex": 0x1002}
    partner = {"device_id": "02:57:4c:00:00:02", "learn_cap": 1, "priority": 128, "ifindex": 27,
               "group_cap": 2, "group_ifindex": 0}
    pdu = pagpd.encode_info(pagpd.F_CONSISTENT | pagpd.F_AUTO, local, partner,
                            [(pagpd.TLV_DEVICE_NAME, b"SW1"), (pagpd.TLV_PORT_NAME, b"Gi0/2")])
    check("the Info PDU: version 1, flags, then the local fields at Wireshark's offsets (2, 8, 9, 10, 14, 18)",
          pdu[0] == 1 and pdu[1] == 0x06 and pdu[2:8] == bytes.fromhex("02574c000001") and pdu[8] == 1
          and pdu[9] == 128 and pdu[10:14] == (26).to_bytes(4, "big") and pdu[14:18] == (2).to_bytes(4, "big")
          and pdu[18:22] == (0x1002).to_bytes(4, "big"), pdu.hex())
    check("the partner's fields at 22 to 41, the partner count at 42 and the TLV count at 44",
          pdu[22:28] == bytes.fromhex("02574c000002") and pdu[30:34] == (27).to_bytes(4, "big")
          and pdu[42:44] == b"\0\1" and pdu[44:46] == b"\0\2", pdu.hex())
    check("TLVs from offset 46: type and length 2 octets each, the length counting the header",
          pdu[46:53] == b"\0\1\0\7SW1" and pdu[53:62] == b"\0\2\0\x09Gi0/2" and len(pdu) == 62, pdu[46:].hex())
    m = pagpd.decode(pdu)
    check("and back: the decoder reads what the encoder wrote",
          m["local"] == local and m["partner"] == partner and m["device_name"] == "SW1" and m["port_name"] == "Gi0/2"
          and m["partner_count"] == 1, str(m))
    fr = pagpd.frame("aa:bb:cc:00:00:01", pdu)
    check("the frame: to 01:00:0c:cc:cc:cc, an 802.3 length, LLC AA-AA-03, SNAP OUI 00-00-0C PID 0x0104",
          fr[:6] == bytes.fromhex("01000ccccccc") and fr[6:12] == bytes.fromhex("aabbcc000001")
          and int.from_bytes(fr[12:14], "big") == 8 + len(pdu) and fr[14:22] == bytes.fromhex("aaaa0300000c0104")
          and pagpd.unframe(fr) == pdu, fr[:24].hex())
    cdp = bytearray(fr)
    cdp[20:22] = b"\x20\x00"
    check("a CDP frame (same address, PID 0x2000) is not PAgP", pagpd.unframe(bytes(cdp)) is None)
    fl = pagpd.decode(pagpd.encode_flush("02:57:4c:00:00:01", "02:57:4c:00:00:02", 7))
    check("the Flush PDU (version 2) decodes: both device ids and the transaction id",
          fl["version"] == 2 and fl["partner_id"] == "02:57:4c:00:00:02" and fl["transaction"] == 7, str(fl))
    check("a short or foreign PDU is refused", pagpd.decode(b"\1\0") is None and pagpd.decode(b"\3" + b"\0" * 50) is None)

    peer = {"a2": "b2", "b2": "a2", "a3": "b3", "b3": "a3"}

    def cfgs(ma, mb):
        return [_pagp_cfg("a2", ma, 1, 2), _pagp_cfg("a3", ma, 1, 3), _pagp_cfg("b2", mb, 2, 2), _pagp_cfg("b3", mb, 2, 3)]

    def states(e):
        return {d: p.state for d, p in e.ports.items()}
    eng, t = _pagp_wire(cfgs("desirable", "auto"), peer, 3)
    check("desirable with auto: both cables bundle at both ends within a few hellos",
          set(states(eng).values()) == {"P"}, str(states(eng)))
    nb = eng.ports["a2"].nb
    check("each end knows its neighbour: device id, name, port, and the auto flag from the auto end",
          nb["local"]["device_id"] == "02:57:4c:00:00:02" and nb["device_name"] == "SW2" and nb["port_name"] == "Gi0/2"
          and nb["flags"] & pagpd.F_AUTO and nb["flags"] & pagpd.F_CONSISTENT, str(nb))
    sent = eng.ports["a2"].sent
    eng, t = _pagp_wire(None, peer, 60, start=t, eng=eng)
    check("once bundled the hellos slow to one every 30 s", eng.ports["a2"].sent - sent <= 3
          and set(states(eng).values()) == {"P"}, str(eng.ports["a2"].sent - sent))
    eng, _ = _pagp_wire(cfgs("desirable", "desirable"), peer, 3)
    check("desirable with desirable bundles", set(states(eng).values()) == {"P"}, str(states(eng)))
    eng, _ = _pagp_wire(cfgs("auto", "auto"), peer, 10)
    check("auto with auto never forms: neither end asks, nothing is sent, both stand alone",
          set(states(eng).values()) == {"I"} and all(p.sent == 0 for p in eng.ports.values()), str(states(eng)))
    lone = [_pagp_cfg("a2", "desirable", 1, 2), _pagp_cfg("a3", "desirable", 1, 3)]
    eng, _ = _pagp_wire(lone, peer, 10)
    check("desirable facing a switch that speaks no PAgP: it asks every second and stands alone",
          set(states(eng).values()) == {"I"} and eng.ports["a2"].sent >= 9, str(states(eng)))
    eng, t = _pagp_wire(cfgs("desirable", "auto"), peer, 3)
    eng, t = _pagp_wire(None, peer, 120, start=t, eng=eng, quiet=("b3",))
    check("a neighbour that falls silent is lost after 3.5 slow hellos: that cable leaves the bundle, the other stays",
          states(eng)["a3"] == "I" and states(eng)["a2"] == "P" and eng.ports["a3"].nb is None, str(states(eng)))
    eng.link("a2", False, t)
    eng.link("a2", False, t + 1)
    eng.tick(t + 1)
    check("a link down (two polls) drops the neighbour and the port at once", states(eng)["a2"] == "D")
    three = cfgs("desirable", "auto") + [_pagp_cfg("c4", "auto", 3, 4)]
    three[1] = dict(three[1], dev="a3")
    peer3 = {"a2": "b2", "b2": "a2", "a3": "c4", "c4": "a3"}
    eng, _ = _pagp_wire([three[0], three[1], three[2], three[4]], peer3, 4)
    check("one group, cables to two different switches: one bundles, the odd one is suspended (s)",
          sorted([states(eng)["a2"], states(eng)["a3"]]) == ["P", "s"], str(states(eng)))
    st = eng.status(10.0)
    check("the state file's rows: switch, port, state and the neighbour",
          {r["dev"]: r for r in st}["b2"]["neighbor"]["name"] == "SW1" and st[0]["switch"] == "sw1", str(st[0]))
    check("the speaker's flag on the console: P only once the port sits in the bond, w while it waits",
          etherchannel.pagp_flag({"state": "P", "bundled": True}) == "P"
          and etherchannel.pagp_flag({"state": "P", "bundled": False}) == "w"
          and etherchannel.pagp_flag({"state": "I"}) == "I" and etherchannel.pagp_flag({}) == "D")
    root = Path(__file__).resolve().parent.parent
    text = (root / "winlab" / "pagpd.py").read_text(encoding="utf-8")
    check("the speaker is standard library only, and says what it does not do and that it met only itself",
          "What it does not do" in text and "tested against itself only" in text
          and {a or b for a, b in re.findall(r"^(?:import (\w+)|from (\w+) import )", text, re.M)}
          <= {"__future__", "json", "os", "select", "signal", "socket", "struct", "subprocess", "sys", "time"})
    check("the nftables rule matches PAgP's LLC/SNAP header right after the Ethernet header",
          "@ll,112,64 0xaaaa0300000c0104 drop" in etherchannel.PAGP_NFT)


def test_w11_pagp_console_and_router():
    """PAgP typed at two switch consoles: the router script runs winlab-pagpd
    on the desirable and auto ports (and nothing new for a lab without them),
    and show pagp neighbor / show etherchannel summary read the speaker."""
    import json as _json
    import os
    from winlab import devcli, editor, etherchannel, netplan, paths, schema, stp, workbench
    from winlab.model import CUSTOM
    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("pagp-lab")
            lab = schema.load(dest)
            for n, c in (("sw1", "192.168.10.0/24"), ("sw2", "192.168.20.0/24")):
                editor.add_network(lab, n, cidr=c)
            editor.set_routed(lab, "sw2", False)
            editor.add_node(lab, "pc01", kind=CUSTOM, image="win11")
            editor.cable(lab, "pc01", 0, "sw1")
            editor.save(lab)

            class _Dash:
                def reload(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
            d = _Dash()
            d.reload()
            workbench._running = lambda _n: {"fabric"}
            workbench.act(d, "wb-cable", {"node": "switch", "network": "sw2", "to": "sw1"})
            workbench.act(d, "wb-stp-cable", {"a": "sw1", "b": "sw2"})
            d.reload()
            plain = stp.render(d.plan)
            check("a lab with no PAgP: no speaker, no nftables table in its script",
                  "winlab-pagpd" not in "\n".join(plain) and etherchannel.PAGP_TABLE not in "\n".join(plain))
            check("its rebuild only stops a speaker left from before",
                  "kill" in "\n".join(stp.render(d.plan, reset=True)).split("# PAgP: no desirable or auto port")[1])
            state = {"text": ""}

            def runner(cmd, timeout=0):
                return state["text"] if etherchannel.SPEAKER_STATE in cmd else ""
            con = {s: devcli.Console(d, f"sw:{s}", runner_factory=lambda: (runner, "")) for s in ("sw1", "sw2")}
            for c in con.values():
                c.run("enable")
                c.run("configure terminal")
            s1, s2 = con["sw1"], con["sw2"]
            s1.run("interface range gi0/2 - 3")
            out = s1.run("channel-group 1 mode desirable")
            check("desirable: the console says who speaks PAgP here", etherchannel.PAGP_NOTE in out
                  and "winlab-pagpd" in out and "not against a Cisco switch" in out, out)
            s2.run("interface range gi0/1 - 2")
            s2.run("channel-group 1 mode auto")
            d.reload()
            conf = etherchannel.pagp_conf(d.plan)
            by = {(c["switch"], c["port"]): c for c in conf}
            c1 = by.get(("sw1", "GigabitEthernet0/2"), {})
            check("the speaker's file: each desirable and auto port, its veth, bond, bridge and the switch's id",
                  len(conf) == 4 and c1.get("dev") == "stp1g2" and c1.get("bond") == "stp1po1" and c1.get("bridge") == "stp1"
                  and c1.get("mode") == "desirable" and c1.get("device_id") == stp.bridge_mac(d.lab, "sw1")
                  and c1.get("ifindex") == 26 and by[("sw2", "GigabitEthernet0/1")]["mode"] == "auto", str(conf[:1]))
            text = "\n".join(stp.render(d.plan))
            check("the router: empty balance-xor bonds, the members ports of the bridge, nftables, the speaker",
                  "stp1po1 type bond mode balance-xor" in text and "stp2po1 type bond mode balance-xor" in text
                  and "ip link set stp1g2 master stp1\n" in text and f"table bridge {etherchannel.PAGP_TABLE}" in text
                  and etherchannel.speaker_hash() in text and "base64 -d > /usr/local/sbin/winlab-pagpd.gz" in text
                  and "apk add --no-network python3" in text, text[-600:])
            blob = text.split("<<'WLPAGPD'\n")[1].split("\nWLPAGPD")[0]
            import base64
            import gzip
            check("the speaker on the router is this one, byte for byte",
                  gzip.decompress(base64.b64decode(blob.replace("\n", ""))) == etherchannel.speaker_source())
            summ = s1.run("do show etherchannel summary")
            check("router answering nothing yet: the summary shows what PAgP's rules predict", "Po1(SU)" in summ
                  and "PAgP" in summ, summ)
            rows = [{"dev": "stp1g2", "switch": "sw1", "port": "GigabitEthernet0/2", "group": 1, "mode": "desirable",
                     "state": "P", "bundled": True, "neighbor": {"device_id": stp.bridge_mac(d.lab, "sw2"), "name": "Switch",
                                                                 "port": "Gi0/1", "ifindex": 25, "group_cap": 1,
                                                                 "flags": 7, "age": 12.4}},
                    {"dev": "stp1g3", "switch": "sw1", "port": "GigabitEthernet0/3", "group": 1, "mode": "desirable",
                     "state": "I", "bundled": False, "neighbor": None}]
            state["text"] = _json.dumps({"ports": rows})
            summ = s1.run("do show etherchannel summary")
            check("the speaker's state wins: one member bundled (P), one stand-alone (I)",
                  "Po1(SU)" in summ and "Gi0/2(P)" in summ and "Gi0/3(I)" in summ, summ)
            nb = s1.run("do show pagp neighbor")
            check("show pagp neighbor reads the speaker: the partner's name, id, port, age and flags",
                  "Gi0/2     Switch" in nb and devcli.dotted_mac(stp.bridge_mac(d.lab, "sw2")) in nb and "12s" in nb
                  and "SCAP" in nb and "Gi0/3" not in nb.split("Cap.")[1] and "read from winlab-pagpd" in nb, nb)
            rows[0]["bundled"] = False
            state["text"] = _json.dumps({"ports": rows})
            check("agreed but not yet in the bond: w (waiting to be aggregated)",
                  "Gi0/2(w)" in s1.run("do show etherchannel summary"))
            state["text"] = ""
            s2.run("no channel-group")
            s2.run("channel-group 1 mode auto")
            s1.run("no channel-group")
            s1.run("channel-group 1 mode auto")
            nb = s1.run("do show pagp neighbor")
            check("auto with auto, router off: no neighbour predicted, and the summary stands them alone",
                  "Gi0/2 " not in nb.split("Cap.")[1] and "Gi0/2(I)" in s1.run("do show etherchannel summary"), nb)
            d.reload()
            check("the speaker still runs on auto ports (they answer), so the protocol decides",
                  len(etherchannel.pagp_conf(d.plan)) == 4)
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]
            workbench._running = saved[4]


def test_w11_pagp_two_speakers_netns():
    """winlab-pagpd for real: two kernel bridges in a network namespace (the
    router's switch bridges), two veth pairs between them, one speaker
    process for all four ports as on the lab router. PAgP frames cross the
    veths, desirable with auto agrees on both cables, auto with auto stays
    silent, and the nftables rule keeps PAgP frames from being flooded onto
    the other cable. Where the kernel has Linux bonding the ports must end
    up in the bonds; where it has none (said so) only the agreement is
    checked. Needs root and ip; skipped (said so) without them."""
    import json as _json
    import os
    import shutil
    import subprocess
    import time
    from winlab import etherchannel, pagpd

    if getattr(os, "geteuid", lambda: -1)() != 0 or not shutil.which("ip"):
        print("  skip   PAgP speakers in a network namespace (needs root and ip)")
        return
    ns = f"wlp{os.getpid() % 10000}"

    def sh(cmd):
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

    if sh(f"ip netns add {ns}").returncode != 0:
        print("  skip   PAgP speakers in a network namespace (ip netns add refused)")
        return
    td = Path(tempfile.mkdtemp())
    X = f"ip netns exec {ns}"
    proc = None
    try:
        bonding = sh(f"{X} ip link add stp1po1 type bond mode balance-xor miimon 100").returncode == 0
        for b in (1, 2):
            sh(f"{X} ip link add stp{b} type bridge stp_state 1 forward_delay 400; {X} ip link set stp{b} up")
            if bonding:
                sh(f"{X} ip link add stp{b}po1 type bond mode balance-xor miimon 100; "
                   f"{X} ip link set stp{b}po1 master stp{b}; {X} ip link set stp{b}po1 up")
        for g in (2, 3):
            sh(f"{X} ip link add stp1g{g} type veth peer name stp2g{g}")
            for b in (1, 2):
                sh(f"{X} ip link set stp{b}g{g} master stp{b}; {X} ip link set stp{b}g{g} up")

        def run(ma, mb, wait):
            cfgs = [dict(_pagp_cfg(f"stp1g{g}", ma, 1, g), vids=[]) for g in (2, 3)] + \
                   [dict(_pagp_cfg(f"stp2g{g}", mb, 2, g), vids=[]) for g in (2, 3)]
            (td / "c.json").write_text(_json.dumps({"ports": cfgs}))
            (td / "s.json").unlink(missing_ok=True)
            p = subprocess.Popen(["ip", "netns", "exec", ns, sys.executable, pagpd.__file__, "-c",
                                  str(td / "c.json"), "-s", str(td / "s.json")],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.time() + wait
            rows = {}
            while time.time() < deadline:
                time.sleep(0.5)
                try:
                    rows = {r["dev"]: r for r in _json.loads((td / "s.json").read_text())["ports"]}
                except (OSError, ValueError, KeyError):
                    continue
                if wait > 5 and rows and all(r["state"] == "P" and (r["bundled"] or not bonding) for r in rows.values()):
                    break
            return p, rows
        proc, rows = run("desirable", "auto", 15)
        check("two real speakers over veth pairs: desirable with auto agree on both cables at both ends",
              len(rows) == 4 and all(r["state"] == "P" for r in rows.values())
              and rows["stp1g2"]["neighbor"]["name"] == "SW2" and rows["stp2g3"]["neighbor"]["port"] == "Gi0/3",
              str({k: (v["state"], v.get("error", "")) for k, v in rows.items()}))
        if bonding:
            check("and the speaker moved each veth into its bond", all(r["master"] == r["dev"][:4] + "po1"
                                                                      for r in rows.values()), str(rows))
        else:
            print("  skip   bundling into the bond (this kernel has no Linux bonding: CONFIG_BONDING off)")
        proc.terminate()
        proc.wait(timeout=10)
        proc, rows = run("auto", "auto", 4)
        check("auto with auto, for real: nothing sent, no neighbour, all stand-alone",
              rows and all(r["state"] == "I" and r["sent"] == 0 and r["neighbor"] is None for r in rows.values()),
              str(rows))
        proc.terminate()
        proc.wait(timeout=10)
        proc = None
        # Flooding: a PAgP frame into stp1g2 must not leave stp1 by stp1g3 once the nftables rule is in.
        if shutil.which("nft") and sh(f"{X} nft -f - <<'E'\n{etherchannel.PAGP_NFT}\nE").returncode == 0:
            # stp1 without spanning tree (its ports forward at once), the far ends out of stp2: no loop.
            sh(f"{X} ip link del stp1; {X} ip link add stp1 type bridge stp_state 0; {X} ip link set stp1 up")
            for g in (2, 3):
                sh(f"{X} ip link set stp2g{g} nomaster; {X} ip link set stp1g{g} master stp1; "
                   f"{X} ip link set stp1g{g} up; {X} ip link set stp2g{g} up")
            time.sleep(0.5)
            code = ("import socket,sys,time\nsys.path.insert(0, %r)\nimport pagpd\n"
                    "r=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); r.bind(('stp2g3',0)); r.settimeout(2)\n"
                    "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind(('stp2g2',0))\n"
                    "time.sleep(0.2)\n"
                    "for _ in range(3): s.send(pagpd.frame('02:00:00:00:00:09', pagpd.encode_info(0,{'device_id':'02:00:00:00:00:09'},None,[])))\n"
                    "n=0\nt=time.time()+1.5\n"
                    "while time.time()<t:\n"
                    " try:\n  d,a=r.recvfrom(2048)\n except OSError: break\n"
                    " if a[2]!=4 and pagpd.unframe(d) is not None: n+=1\n"
                    "print(n)\n") % str(Path(pagpd.__file__).parent)
            (td / "flood.py").write_text(code)
            got = sh(f"{X} {sys.executable} {td / 'flood.py'}").stdout.strip()
            sh(f"{X} nft delete table bridge {etherchannel.PAGP_TABLE}")
            again = sh(f"{X} {sys.executable} {td / 'flood.py'}").stdout.strip()
            check("nftables keeps PAgP off the bridge: none flooded onto the other cable with the rule, "
                  "flooded without it", got == "0" and again not in ("", "0"), f"with {got!r}, without {again!r}")
        else:
            print("  skip   the nftables flood check (no nft, or bridge nftables refused)")
        sh(f"{X} ip link set stp1g2 nomaster")
        cfg = _json.dumps(dict(_pagp_cfg("stp1g2", "desirable", 1, 2), bridge="stp1"))
        (td / "cfg.json").write_text(cfg)
        (td / "unb.py").write_text(f"import sys, json\nsys.path.insert(0, {str(Path(pagpd.__file__).parent)!r})\n"
                                   f"import pagpd\npagpd.unbundle(json.loads(open({str(td / 'cfg.json')!r}).read()))\n")
        sh(f"{X} {sys.executable} {td / 'unb.py'}")
        check("a port that leaves the bundle goes back into its switch's bridge, up",
              "master stp1" in sh(f"{X} ip link show stp1g2").stdout, sh(f"{X} ip link show stp1g2").stdout)
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        sh(f"ip netns del {ns}")
        shutil.rmtree(td, ignore_errors=True)



# ===== the network diagram is diagrams.net's =====










# ===== the edge-firewall lab: OPNsense rules, NAT, IPsec, WireGuard, IDS =====



# ===== monitoring dashboards: the monitoring-dashboards lab (winlab/dashlab.py) =====






# ===== PowerShell automation track (module powershell, lab automation) =====
def _corp_sam(given: str, surname: str) -> str:
    """The naming rule the track's brief states, as a reference for the
    checks' expected values: accents off, a to z only, lower case, joined
    with a dot, 20 characters, never ending on the dot."""
    import unicodedata

    def part(s: str) -> str:
        s = "".join(c for c in unicodedata.normalize("NFD", s.strip()) if unicodedata.category(c) != "Mn")
        return re.sub(r"[^a-z]", "", s.lower())
    return (part(given) + "." + part(surname))[:20].rstrip(".")










# ===== remote support: MeshCentral on the IT ops server (winlab/remotesupport.py) =====






def test_linux_host():
    """winlab on a Linux PC: the distribution's QEMU and OVMF laid out in
    runtime/qemu as links, the KVM and QEMU lines of the PC checklist, the
    desktop's own file dialogs, and the Linux package."""
    import json as _json
    import os as _os
    import tempfile
    from types import SimpleNamespace
    from winlab import bootstrap, linuxhost, paths, readiness, webui

    class _SkipLinks(Exception):
        pass

    fam = linuxhost.family
    check("distribution families from os-release",
          fam(linuxhost.os_release('ID=ubuntu\nID_LIKE=debian\n')) == "debian"
          and fam(linuxhost.os_release('ID="linuxmint"\nID_LIKE="ubuntu debian"')) == "debian"
          and fam({"ID": "fedora"}) == "fedora" and fam({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}) == "fedora"
          and fam({"ID": "manjaro", "ID_LIKE": "arch"}) == "arch"
          and fam({"ID": "opensuse-tumbleweed", "ID_LIKE": "opensuse suse"}) == "suse"
          and fam({"ID": "gentoo"}) == "")
    check("the install command per package manager, never with sudo baked in",
          linuxhost.install_argv("debian")[:3] == ["apt-get", "install", "-y"]
          and "ovmf" in linuxhost.install_argv("debian") and "swtpm" in linuxhost.install_argv("arch")
          and linuxhost.install_argv("") == [] and "sudo apt-get install" in linuxhost.install_hint("debian")
          and "package manager" in linuxhost.install_hint(""))

    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        fw = t / "fw"; fw.mkdir()
        good_vars = fw / "VARS_4M.fd"; good_vars.write_bytes(b"\0" * linuxhost.VARS_SIZE)
        small_vars = fw / "VARS_2M.fd"; small_vars.write_bytes(b"\0" * 0x20000)
        for n in ("CODE_4M.fd", "CODE_4M.secboot.fd", "CODE_2M.fd", "SEV.fd", "CODE.qcow2"):
            (fw / n).write_bytes(b"x")

        def desc(name, code, nv, feats, fmt="raw", mode=None):
            m = {"device": "flash", "executable": {"filename": str(fw / code), "format": fmt}}
            if nv:
                m["nvram-template"] = {"filename": str(nv), "format": fmt}
            if mode:
                m["mode"] = mode
            (t / "d" / name).write_text(_json.dumps({
                "interface-types": ["uefi"], "mapping": m, "features": feats,
                "targets": [{"architecture": "x86_64", "machines": ["pc-q35-*"]}]}))
        (t / "d").mkdir()
        desc("10-sev.json", "SEV.fd", None, ["amd-sev", "amd-sev-es"], mode="stateless")
        desc("20-qcow.json", "CODE.qcow2", good_vars, [], fmt="qcow2")
        desc("30-2m.json", "CODE_2M.fd", small_vars, [])
        desc("40-enrolled.json", "CODE_4M.secboot.fd", good_vars, ["secure-boot", "requires-smm", "enrolled-keys"])
        desc("50-secure.json", "CODE_4M.secboot.fd", good_vars, ["secure-boot", "requires-smm"])
        desc("60-plain.json", "CODE_4M.fd", good_vars, ["acpi-s3"])
        f = linuxhost.find_firmware(dirs=(t / "d",), fallbacks=())
        check("firmware from QEMU's descriptors: raw, 4 MB layout, empty store, not SEV",
              f is not None and f.code == fw / "CODE_4M.fd" and f.vars == good_vars
              and f.secure == fw / "CODE_4M.secboot.fd", str(f))
        f2 = linuxhost.find_firmware(dirs=(t / "none",),
                                     fallbacks=((str(fw / "CODE_2M.fd"), str(small_vars), ""),
                                                (str(fw / "CODE_4M.fd"), str(good_vars), str(fw / "nope.fd"))))
        check("without descriptors the known paths are tried, a 2 MB build skipped",
              f2 is not None and f2.code == fw / "CODE_4M.fd" and f2.secure is None)

        saved = (linuxhost.find_qemu, linuxhost.find_img, linuxhost.find_firmware, linuxhost.qemu_version)
        try:
            if _os.name == "nt":
                raise _SkipLinks()  # symbolic links need a privilege Windows rarely grants
            (t / "usr").mkdir()
            q, i = t / "usr" / "qemu-system-x86_64", t / "usr" / "qemu-img"
            q.write_text(""); i.write_text("")
            linuxhost.find_qemu, linuxhost.find_img = (lambda which=None: q), (lambda which=None: i)
            linuxhost.find_firmware = lambda *a, **k: linuxhost.Firmware(fw / "CODE_4M.fd", good_vars,
                                                                         fw / "CODE_4M.secboot.fd")
            linuxhost.qemu_version = lambda exe, run=None: "QEMU emulator version 9.9"
            rt = t / "rt" / "qemu"
            (rt / "bin").mkdir(parents=True); (rt / "bin" / "old.exe").write_text("")
            exe = linuxhost.link_runtime(rt)
            share = rt / "share" / "qemu"
            check("the system QEMU and firmware are linked where winlab looks for them",
                  exe.is_symlink() and exe.resolve() == q.resolve()
                  and (rt / "bin" / "qemu-img").resolve() == i.resolve()
                  and (share / "edk2-x86_64-code.fd").resolve() == (fw / "CODE_4M.fd").resolve()
                  and (share / "edk2-i386-vars.fd").resolve() == good_vars.resolve()
                  and (share / "edk2-x86_64-secure-code.fd").resolve() == (fw / "CODE_4M.secboot.fd").resolve()
                  and not (rt / "bin" / "old.exe").exists())
            check("what was linked is recorded for doctor",
                  linuxhost.linked_info(rt).get("version") == "QEMU emulator version 9.9")
            linuxhost.find_qemu = lambda which=None: None
            try:
                linuxhost.link_runtime(rt); raised = ""
            except linuxhost.LinuxHostError as exc:
                raised = str(exc)
            check("no QEMU: the error says how to install it", "QEMU" in raised and "install" in raised, raised)
        except _SkipLinks:
            pass
        finally:
            linuxhost.find_qemu, linuxhost.find_img, linuxhost.find_firmware, linuxhost.qemu_version = saved

        # bootstrap on Linux links instead of downloading MSYS2's Windows build
        calls = []
        from winlab import psmodules
        saved_b = (bootstrap.is_linux, bootstrap._link_linux_qemu, bootstrap._fetch_windows_qemu, psmodules.fetch)
        try:
            def _stop(*a, **k):
                raise psmodules.ModuleError("stop here: no network in the tests")
            psmodules.fetch = _stop
            bootstrap._link_linux_qemu = lambda say: calls.append("link")
            bootstrap._fetch_windows_qemu = lambda *a: calls.append("msys2")
            bootstrap.is_linux = lambda: True
            try:
                bootstrap.bootstrap()
            except bootstrap.BootstrapError:
                pass
            check("bootstrap on Linux uses the system QEMU, never MSYS2's", calls[:1] == ["link"]
                  and "msys2" not in calls, str(calls))
        finally:
            bootstrap.is_linux, bootstrap._link_linux_qemu, bootstrap._fetch_windows_qemu, psmodules.fetch = saved_b

        # pickers
        have = lambda names: (lambda n: f"/usr/bin/{n}" if n in names else None)
        z = linuxhost._picker_argv("file", "Pick", "/home/u/Downloads", have({"zenity"}))
        k = linuxhost._picker_argv("folder", "Pick", "", have({"kdialog"}))
        check("GNOME's dialog through zenity, KDE's through kdialog",
              z[:2] == ["zenity", "--file-selection"] and "--filename=/home/u/Downloads/" in z
              and any("*.iso" in a for a in z) and k[:3] == ["kdialog", "--title", "Pick"]
              and "--getexistingdirectory" in k and linuxhost._picker_argv("file", "x", "", have(set())) == [])
        ran = lambda rc, out: (lambda argv, **kw: SimpleNamespace(returncode=rc, stdout=out, stderr=b"boom"))
        ok_pick = linuxhost.pick("file", "t", "", ran(0, b"/home/u/ws.iso\n"), have({"zenity"}))
        cancel = linuxhost.pick("file", "t", "", ran(1, b""), have({"zenity"}))
        try:
            linuxhost.pick("file", "t", "", ran(0, b""), have(set())); none = ""
        except RuntimeError as exc:
            none = str(exc)
        check("the chosen path, '' on cancel, and type-the-path when no dialog exists",
              ok_pick == "/home/u/ws.iso" and cancel == "" and "zenity" in none and "type the path" in none)

        # Downloads from XDG user dirs
        home = t / "home"; (home / ".config").mkdir(parents=True); (home / "Téléchargements").mkdir()
        (home / ".config" / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="$HOME/Téléchargements"\n', encoding="utf-8")
        saved_env = _os.environ.pop("XDG_CONFIG_HOME", None)
        try:
            check("a localised Downloads folder from user-dirs.dirs",
                  readiness._xdg_download_dir(home) == home / "Téléchargements")
        finally:
            if saved_env is not None:
                _os.environ["XDG_CONFIG_HOME"] = saved_env

        # the PC checklist
        saved_var = paths.VAR
        paths.VAR = t / "var"; paths.VAR.mkdir()
        try:
            rep = SimpleNamespace(accel="kvm")
            by = lambda items: {c["id"]: c for c in items}
            c = by(readiness.linux_checks(rep, kvm="ok", missing=[]))
            check("KVM usable and QEMU installed: both green",
                  c["kvm"]["status"] == "ok" and c["qemu"]["status"] == "ok")
            c = by(readiness.linux_checks(rep, kvm="missing", missing=["QEMU (qemu-system-x86_64)"]))
            check("no /dev/kvm is red and names the BIOS switch and the module",
                  c["kvm"]["status"] == "fail" and "modprobe" in c["kvm"]["detail"] and "VT-x" in c["kvm"]["detail"]
                  and c["qemu"]["status"] == "warn")
            c = by(readiness.linux_checks(rep, kvm="no-access", missing=[]))
            check("no access to /dev/kvm: winlab offers to add the user to the kvm group",
                  c["kvm"]["fix"] == "kvm-access" and c["kvm"]["status"] == "warn")
            (paths.VAR / linuxhost.KVM_MARKER).write_text("u")
            c = by(readiness.linux_checks(rep, kvm="no-access", missing=[]))
            check("once added, the line says to sign out and back in", c["kvm"]["fix"] == ""
                  and "sign out" in c["kvm"]["detail"])
        finally:
            paths.VAR = saved_var

    check("the Setup jobs exist for the Linux fixes",
          "install-qemu" in webui.JOB_INFO and "kvm-access" in webui.JOB_INFO
          and hasattr(webui.Dashboard, "stream_install_qemu") and hasattr(webui.Dashboard, "stream_kvm_access"))
    page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    check("the page runs them from the checklist", "fix==='install-qemu'" in page and "fix==='kvm-access'" in page)
    root = Path(__file__).resolve().parent.parent
    build = (root / "packaging" / "build-linux.sh").read_text(encoding="utf-8")
    inst = (root / "packaging" / "linux" / "install.sh").read_text(encoding="utf-8")
    check("the Linux package: one-file binary, per-user install with a data folder, menu entry",
          "--onefile" in build and "protect.py" in build and "winlab-home.txt" in inst
          and "applications" in inst and "lab down --all" in inst
          and "@EXEC@" in (root / "packaging" / "linux" / "winlab.desktop").read_text(encoding="utf-8"))




def test_desktop_languages():
    """Spanish, Hebrew and Arabic tables: every one loads, every translation keeps
    the English text's {} values, and the choice holds in var/language.json."""
    import json as _json
    from winlab import i18n, paths
    root = Path(__file__).resolve().parent.parent
    for code in ("es", "he", "ar"):
        raw = _json.loads((root / "content" / "i18n" / f"{code}.json").read_text(encoding="utf-8"))
        check(f"{code}: the table loads and covers the desktop", len(i18n.table(code)) > 3000, str(len(raw)))
        bad = []
        for k, v in raw.items():
            n = k.count("{}")
            nums = sorted(int(x) for x in re.findall(r"\{(\d+)\}", v))
            # numbered values may be reordered, and one glued to a word (an English
            # plural ending: machine{}) may be left out
            at = [m.start() for m in re.finditer(r"\{\}", k)]
            ok = (v.count("{}") == n and not nums) or (
                "{}" not in v and len(set(nums)) == len(nums) and all(1 <= x <= n for x in nums)
                and all(i in nums or (p > 0 and k[p - 1].isalpha()) for i, p in enumerate(at, 1)))
            if not ok:
                bad.append(k)
        check(f"{code}: every translation keeps the values the page fills in", not bad, str(bad[:3]))
    check("Hebrew and Arabic read right to left, Spanish left to right",
          i18n.LANGS["he"][1] and i18n.LANGS["ar"][1] and not i18n.LANGS["es"][1])
    saved = paths.VAR
    with tempfile.TemporaryDirectory() as td:
        paths.VAR = Path(td) / "var"
        try:
            check("English until a language is chosen", i18n.current() == "en" and i18n.view()["table"] == {})
            check("an unknown language is refused", "error" in i18n.choose("xx") and i18n.current() == "en")
            i18n.choose("he")
            v = i18n.view()
            check("the choice holds and the view carries direction and table",
                  v["lang"] == "he" and v["rtl"] and v["table"].get("Settings") and len(v["langs"]) == 4)
            from winlab import webui as _webui
            head = _webui.page_bytes()[:120]
            check("the page is sent with <html lang/dir> of the chosen language",
                  head.startswith(b'<!doctype html>\n<html lang="he" dir="rtl" translate="no"'), head)
            i18n.choose("en")
            check("and back to English, left to right",
                  b'<html lang="en" dir="ltr" translate="no"' in _webui.page_bytes()[:120])
        finally:
            paths.VAR = saved
    page = (root / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    import subprocess as _sp
    for code in ("es", "he", "ar"):
        r = _sp.run([sys.executable, str(root / "tools" / "i18n_extract.py"), "--missing", code],
                    capture_output=True, text=True, encoding="utf-8")
        miss = _json.loads(r.stdout or "[]")
        check(f"{code}: every desktop text has a translation (docs/TRANSLATING.md)", not miss, str(miss[:5]))
    check("the browser is told not to offer translating the page (it translates itself)",
          'translate="no"' in page.split("<head>", 1)[0] and '<meta name="google" content="notranslate">' in page)
    check("the Settings page has the language picker and the page translates as it draws",
          'id="pref-lang"' in page and "function setLanguage(" in page and "MutationObserver" in page
          and "/api/i18n" in page)



# ===== the AI data center: a pre-built scenario to run and fix (winlab/aidc.py) =====


def test_other_routers():
    """More routers than the lab router (winlab/routers.py): each its own
    console, settings, startup configuration and network stack in the
    router VM; cabled to switches as trunks; powered on and off on its own."""
    import os
    from winlab import devcli, editor, iosnv, livenet, netplan, paths, routers, schema, workbench

    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            dest = editor.new_workbench("two-routers")
            lab = schema.load(dest)
            for nid, cidr in (("office", "10.1.1.0/24"), ("transit", "10.0.12.0/24"), ("branch", "10.2.2.0/24")):
                editor.add_network(lab, nid, cidr=cidr)
                editor.set_routed(lab, nid, False)
            editor.save(lab)

            class Dash:
                def __init__(self):
                    self.reload()

                def reload(self):
                    self.lab = schema.load(dest)
                    self.plan = netplan.compile_topology(self.lab, check_ports=False)
                    self.wb_live = workbench.Live()

            d = Dash()
            workbench._running = lambda _n: {"fabric"}
            act = lambda action_, **p: workbench.act(d, action_, p)
            act("wb-cable", node="router", network="office")
            act("wb-cable", node="router", network="transit")
            r = act("wb-add", shelf="router", id="branch1", x=700, y=60)
            check("a router comes off the shelf as router:<id>", r["ok"] and r["id"] == "router:branch1", r.get("message", ""))
            check("a second router of the same id is refused", not act("wb-add", shelf="router", id="branch1")["ok"])
            check("it keeps its place on the canvas", d.lab.layout.get("router:branch1") == [700, 60])
            r = act("wb-cable", node="router:branch1", network="transit")
            check("its port takes a switch's cable", r["ok"] and "Gi0/0/0" in r["message"], r.get("message", ""))
            act("wb-cable", node="router:branch1", network="branch")
            check("the switch's uplink stays where it was (the lab router's)",
                  devcli.uplinked(d.lab, "transit") and not d.lab.networks["transit"].upstream)
            ran = []
            nf = lambda: ((lambda cmd, timeout=60: ran.append(cmd) or ""), "")

            def say(dev, lines):
                con = workbench.console(d, dev)
                con._runner_factory = nf
                return [con.run(x) for x in lines]
            say("router", ["", "en", "conf t", "hostname HQ", "int g0/0/0", "ip address 10.1.1.1 255.255.255.0",
                           "no shut", "int g0/0/1", "ip address 10.0.12.1 255.255.255.0", "no shut", "exit",
                           "router ospf 1", "network 10.0.0.0 0.255.255.255 area 0", "end", "write memory"])
            out = say("router:branch1", ["", "en", "conf t", "hostname BRANCH", "int g0/0/0",
                                         "ip address 10.0.12.2 255.255.255.0", "no shut", "int g0/0/1",
                                         "ip address 10.2.2.1 255.255.255.0", "no shut", "exit",
                                         "router ospf 1", "network 10.0.0.0 0.255.255.255 area 0", "end",
                                         "write memory", "show ip interface brief"])
            d.reload()
            lab = d.lab
            own = lab.devices["router:branch1"]
            check("the second router's console keeps its own settings",
                  own.get("hostname") == "BRANCH" and lab.devices["router"].get("hostname") == "HQ")
            check("its address on a shared switch is its own, the lab router's stays",
                  lab.networks["transit"].router_ip == "10.0.12.1" and own.get("gw:transit") == "10.0.12.2")
            check("show ip interface brief on it lists its own addresses",
                  "10.0.12.2" in out[-1] and "10.2.2.1" in out[-1] and "10.0.12.1" not in out[-1])
            check("the lab router does not route the branch switch; the second router does",
                  not lab.networks["branch"].routed and routers.view(lab, "branch1").networks["branch"].routed
                  and lab.networks["transit"].routed)
            nv = iosnv.load(lab.name)["devices"]
            check("each router's startup configuration is kept under its own name",
                  "hostname BRANCH" in nv["router:branch1"]["text"] and "hostname HQ" in nv["router"]["text"])
            script = netplan.render_fabric_setup(d.plan)
            ns = routers.netns("branch1")
            check("the router VM gives it a network namespace and its own processes and files",
                  f"ip netns add {ns}" in script and "unshare --pid --fork --mount" in script
                  and "lowerdir=/etc" in script)
            check("its cables are veth pairs: a trunk port on the switches' bridge carrying the switch's VLANs",
                  f"peer name gi0 netns {ns}" in script and "pvid untagged   # transit VLAN 1" in script)
            check("its FRRouting runs inside it with its own configuration",
                  "nsenter -t $(cat " in script and "hostname BRANCH" in script and "hostname HQ" in script)
            frr_in = script.split(f"<<'WLR_{routers.short('branch1').upper()}_EOF'")[1]
            check("its SVIs carry its own addresses", "ip addr replace 10.0.12.2/24 dev lab0.102" in frr_in
                  or "ip addr replace 10.0.12.2/24" in frr_in)
            check("packages go onto the VM before the router's private files would hide them",
                  script.index("apk add --no-network frr") < script.index(f"<<'WLR_{routers.short('branch1').upper()}_EOF'"))
            w = routers.wrap("branch1", "vtysh -c 'show ip route'")
            check("its console's commands run inside it", w.count("nsenter") == 1 and "-n -m -p" in w
                  and "the router is off" in w)
            # live changes
            pins = livenet.snapshot(d.plan, 1)
            check("a running router's state is recorded per router", "branch1" in pins["routers"])
            check("nothing changed, nothing to do", not livenet.changes(d.plan, pins)["routers"])
            say("router:branch1", ["", "en", "conf t", "ip route 0.0.0.0 0.0.0.0 10.0.12.1", "end"])
            d.reload()
            ch = livenet.changes(d.plan, pins)
            check("a route typed on it changes only that router", ch["routers"] == ["branch1"] and not ch["l3"])
            lines, _ = routers.live_lines(d.plan, "branch1", pins["routers"]["branch1"])
            check("and is applied inside it without building it again",
                  lines and "ip netns add" not in "\n".join(lines) and "nsenter" in "\n".join(lines))
            r = act("wb-rtpower", id="router:branch1", on="")
            ch = livenet.changes(d.plan, pins)
            lines, _ = routers.live_lines(d.plan, "branch1", pins["routers"]["branch1"])
            check("its power switch takes only it down", r["ok"] and "kill -9" in "\n".join(lines)
                  and "ip netns add" not in "\n".join(lines))
            check("its console goes dark", not workbench.console(d, "router:branch1").powered()
                  and workbench.console(d, "router").powered())
            r = act("wb-rtpower", id="router:branch1", on="1")
            check("powered on, it starts from its startup configuration (the route was never written)",
                  r["ok"] and not any(k.startswith("route:") for k in d.lab.devices["router:branch1"]))
            lab = d.lab
            before = {p["switch"]: p["shut"] for p in routers.ports(lab, d.plan, "branch1")}
            lab.devices.setdefault("sw:transit", {})["power"] = "off"
            after = {p["switch"]: p["shut"] for p in routers.ports(lab, d.plan, "branch1")}
            lab.devices["sw:transit"].pop("power")
            check("a switch powered off takes away its link to the second router too",
                  not before["transit"] and after["transit"] and after.get("branch") == before.get("branch"))
            v = workbench.view(d)
            rv = v["routers"][0]
            check("the canvas gets the other routers with their ports",
                  rv["id"] == "router:branch1" and rv["name"] == "BRANCH"
                  and [p["network"] for p in rv["ports"][:2]] == ["transit", "branch"])
            check("a router with cables in it is not removed", not act("wb-rm", id="router:branch1")["ok"])
            act("wb-unplug", node="router:branch1", network="transit")
            act("wb-unplug", node="router:branch1", network="branch")
            check("unplugged, its cables are gone and the lab router keeps its own",
                  not devcli.cabled_ports(routers.view(d.lab, "branch1")) and devcli.uplinked(d.lab, "transit"))
            r = act("wb-rm", id="router:branch1")
            check("an empty router is removed with its place on the canvas",
                  r["ok"] and "router:branch1" not in d.lab.devices and "router:branch1" not in d.lab.layout)
            ch = livenet.changes(d.plan, pins)
            check("a running router that was removed is taken down", ch["routers_gone"] == ["branch1"])
            # a cable straight from one router to another
            act("wb-add", shelf="router", id="edge")
            r = act("wb-rlink", a="router", aport="Gi0/1/0", b="router:edge")
            check("two routers take a direct cable, port to port", r["ok"] and r["id"] == "link1", r.get("message", ""))
            lk = routers.links(d.lab)
            check("the cable has the two routers' ports at its ends",
                  lk and {e["dev"] for e in lk[0]["ends"]} == {"router", "router:edge"})
            check("it is no switch on the canvas", "link1" not in devcli.switches(d.lab)
                  and all(sw_["id"] != "link1" for sw_ in workbench.view(d)["switches"]))
            check("a port with a cable in it takes no second one",
                  not act("wb-rlink", a="router", aport="Gi0/1/0", b="router:edge")["ok"])
            say("router", ["", "en", "conf t", "int g0/1/0", "ip address 10.9.9.1 255.255.255.252", "no shut", "end"])
            say("router:edge", ["", "en", "conf t", "int g0/0/0", "ip address 10.9.9.2 255.255.255.252", "no shut",
                                "exit", "snmp-server community lab RO", "end"])
            d.reload()
            ev = routers.view(d.lab, "edge")
            check("each end has its own address on the cable",
                  d.lab.networks["link1"].router_ip == "10.9.9.1" and ev.networks["link1"].router_ip == "10.9.9.2"
                  and d.lab.networks["link1"].routed and ev.networks["link1"].routed)
            mods = routers.module_lines(d.plan, "edge")
            check("the second router runs its own SNMP agent", any("rocommunity lab" in x for x in mods["nms"]))
            check("the lab router's scripts keep to its own processes",
                  "pkill()" in netplan.render_fabric_setup(d.plan) and "_wlroot" in routers.SHELL_GUARD)
            from winlab import iosssh
            say("router:edge", ["", "en", "conf t", "hostname EDGE", "ip domain-name corp.lab",
                                "crypto key generate rsa modulus 768", "username netops privilege 15 secret " + "".join(chr(c) for c in (108, 97, 98, 111, 112, 115, 55)),
                                "line vty 0 4", "login local", "transport input ssh", "end"])
            d.reload()
            srv = {dev: (ns, addrs) for dev, ns, addrs in iosssh.servers(d.plan)}
            check("the second router answers SSH on its own addresses, inside its own network stack",
                  srv.get("router:edge") == (routers.netns("edge"), ["10.9.9.2"]), str(srv))
            check("the SSH bridge takes sessions for it",
                  "routers.rid_of(dev)" in Path(iosssh.__file__).read_text(encoding="utf-8"))
            r = act("wb-unplug", node="link", network="link1")
            check("pulled out, the cable is gone from both routers", r["ok"] and "link1" not in d.lab.networks
                  and not routers.links(d.lab))
        finally:
            (paths.VAR, paths.STATE, paths.LABS, img, workbench._running) = saved
            if img is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = img










def test_lesson_translations():
    """Every lesson ships in Spanish, Hebrew and Arabic (docs/TRANSLATING.md):
    content/i18n/lessons/<lang>/<id>.json with the English fields' shape, and
    the desktop shows it when that language is chosen."""
    import importlib.util as _iu
    from winlab import lessons as _ls
    root = Path(__file__).resolve().parent.parent
    spec = _iu.spec_from_file_location("i18n_lessons", root / "tools" / "i18n_lessons.py")
    tool = _iu.module_from_spec(spec)
    spec.loader.exec_module(tool)
    ids = sorted(p.stem for p in (root / "content" / "lessons").glob("*.toml"))
    for code in ("es", "he", "ar"):
        bad = {i: p for i in ids if (p := tool.problems(code, i))}
        check(f"{code}: every lesson is translated, same shape as English", not bad,
              "; ".join(f"{i}: {', '.join(p)}" for i, p in list(bad.items())[:4]) + (f" (+{len(bad) - 4} more)" if len(bad) > 4 else ""))
    one = _ls.load(ids[0])
    he = _ls.translated(_ls.load(ids[0]), "he")
    check("a lesson reads in the chosen language, its checks unchanged",
          (he.title != one.title or not (root / "content" / "i18n" / "lessons" / "he" / f"{ids[0]}.json").exists())
          and [v.cmd for v in he.verify] == [v.cmd for v in one.verify] and he.further == one.further)


def test_content_translations():
    """Exercises, exams, guides, scenarios, sites, help topics and the command
    reference ship in Spanish, Hebrew and Arabic (docs/TRANSLATING.md), and a
    translation never touches a script."""
    import importlib.util as _iu
    import json as _json
    from winlab import content as _c
    root = Path(__file__).resolve().parent.parent
    spec = _iu.spec_from_file_location("i18n_content", root / "tools" / "i18n_content.py")
    tool = _iu.module_from_spec(spec)
    spec.loader.exec_module(tool)
    files = tool.files()
    for code in ("es", "he", "ar"):
        bad = {f: n for f in files if (n := len(tool.missing(code, f)))}
        check(f"{code}: every exercise, exam, guide and help text is translated", not bad,
              ", ".join(f"{f} ({n})" for f, n in list(bad.items())[:4]) + (f" (+{len(bad) - 4} more)" if len(bad) > 4 else ""))
    ex = sorted((root / "content" / "exercises").glob("*.toml"))[0]
    with tempfile.TemporaryDirectory() as td:
        doc = {"exercise": {"title": "T"}, "check": [{"name": "N", "script": "T", "hint": "H"}]}
        saved = _c.translation_file
        try:
            f = Path(td) / "t.json"
            f.write_text(_json.dumps({"T": "tt", "N": "nn", "H": "hh"}), encoding="utf-8")
            _c.translation_file = lambda p, l: f
            out = _c.localized(ex, doc, "he")
        finally:
            _c.translation_file = saved
    check("a translation swaps the texts and leaves every script alone",
          out["exercise"]["title"] == "tt" and out["check"][0] == {"name": "nn", "script": "T", "hint": "hh"})
    import re as _re
    bidi = [str(f.relative_to(root)) for f in (root / "content" / "i18n").rglob("*.json")
            if _re.search("[\u200e\u200f\u202a-\u202e\u2066-\u2069]", f.read_text(encoding="utf-8"))]
    check("no translation carries right-to-left control characters (the page sets direction)", not bidi, str(bidi[:3]))
    check("lab definitions are never translated (the desktop writes them back)",
          _c.translation_file(root / "content" / "labs" / "ad-ds-basics.toml", "he") is None)




# ===== the analyst's desk: blue-team lessons, problems and the CySA+ track =====
BLUETEAM_LESSONS = {"sec-sysmon-deploy": "sec-sysmon-deployed", "sec-threat-hunt": "hunt-quiet-foothold",
                    "sec-phishing-triage": "phish-reported", "sec-evidence-triage": "sec-evidence-collected",
                    "sec-vuln-management-cycle": "sec-vuln-cycle", "sec-detection-tuning": "sec-detection-tuned"}
BLUETEAM_PROBLEMS = {"ts-sysmon-log-disabled": "sysmon-log-disabled",
                     "ts-wazuh-tuning-too-broad": "wazuh-suppress-too-broad"}






# ===== desktop support (CompTIA A+ Core 2): Windows 11 by hand, the boot and recovery tools, startup,
# restore points, the command-line toolbox, performance, a nuisance clean-up, and the A+ practice track =====
_APLUS_LESSONS = {
    "aplus-install-windows11": ("exercise", "aplus-pc04-installed"),
    "aplus-boot-and-recovery": ("exercise", "aplus-recovery-ready"),
    "aplus-clean-boot": ("problem", "w11-startup-hog"),
    "aplus-system-restore": ("exercise", "aplus-restore-points"),
    "aplus-malware-removal": ("problem", "w11-nuisance-cleanup"),
    "aplus-command-line-toolbox": ("exercise", "aplus-support-toolbox"),
    "aplus-performance-tools": ("problem", "w11-memory-hog"),
}
_APLUS_TS = {"ts-pc-wont-boot": "w11-bcd-entry-deleted", "ts-stuck-in-safe-mode": "w11-stuck-safe-mode",
             "ts-hosts-file-redirect": "w11-hosts-redirect", "ts-home-ip-settings": "w11-home-ip-config"}








# ---------------------------------------------------------------------------
# Windows Server availability, branches and trusts (AZ-802 gap lessons):
# Hyper-V Replica, Storage Replica, an RODC, a forest trust, DHCP failover,
# DNSSEC and an RDS deployment, with three drills (winlab/serverha.py).
WSHA_LESSONS = {
    "hyperv-replica": ("workloads", "failover-cluster", "hyperv-replica-failover"),
    "storage-replica": ("workloads", "disaster-recovery", "storage-replica-to-dr"),
    "rds-session-farm": ("workloads", "every-role", "rds-farm-with-gateway"),
    "rodc-branch-office": ("identity", "enterprise-multisite", "rodc-for-the-branch"),
    "forest-trust-selective-auth": ("identity", "time-and-kerberos", "forest-trust-selective"),
    "dhcp-failover": ("network", "ad-ds-basics", "dhcp-failover-pair"),
    "dnssec-signed-zone": ("network", "enterprise-multisite", "dnssec-validated-zone"),
}
WSHA_DRILLS = {
    "ts-dhcp-failover-blocked": ("ad-ds-basics", "dc01", "dhcp-failover-blocked"),
    "ts-rodc-branch-denied": ("enterprise-multisite", "dc01", "rodc-branch-denied"),
    "ts-trust-auth-firewall": ("time-and-kerberos", "dc01", "trust-auth-firewall"),
}
WSHA_ORDERS = {"identity": (200, 249), "workloads": (700, 749), "network": (400, 419), "troubleshoot": (730, 759)}










# ---------------------------------------------------------------- CCNA device skills
def _ccna_dash(lab_name: str):
    from winlab import netplan, schema, workbench

    class Dash:
        def __init__(self):
            self.reload()

        def reload(self):
            self.lab = schema.load(lab_name)
            self.plan = netplan.compile_topology(self.lab, check_ports=False)
            self.wb_live = workbench.Live()
    return Dash()


def _ccna_fetch_out(img) -> str:
    import hashlib
    from winlab import iosimage
    data = iosimage.build(img)
    hl = len(iosimage.header(img, "0" * 64))
    head = data[:hl].decode().splitlines()[:5]
    return ("#rc=0\n#size %d\n#md5 %s\n#body %s\n" % (len(data), hashlib.md5(data).hexdigest(),
                                                   hashlib.sha256(data[hl:]).hexdigest())
            + "".join("#head " + h + "\n" for h in head) + "#via 10.1.1.9 dev lab0.10 src 10.1.1.1\n")


def test_ccna_device_images():
    """winlab's stand-in images: deterministic, the damaged one caught by its
    own hash and by the published MD5, and on the tftpd stick."""
    import hashlib
    from winlab import debpacks, iosimage
    good, bad = iosimage.RELEASES[0], iosimage.RELEASES[1]
    a, b = iosimage.build(good), iosimage.build(good)
    check("an image is the same bytes every time, with winlab's header",
          a == b and a.startswith(iosimage.MAGIC.encode() + b"\nplatform ISR4321\nversion 15.2(8)WL"))
    check("the published MD5 is the good build's", iosimage.published_md5(good) == hashlib.md5(a).hexdigest())
    check("the damaged image's MD5 is not the published one",
          hashlib.md5(iosimage.build(bad)).hexdigest() != iosimage.published_md5(bad))
    mb = iosimage.meta_from(iosimage.parse_fetch(_ccna_fetch_out(bad)))
    mg = iosimage.meta_from(iosimage.parse_fetch(_ccna_fetch_out(good)))
    check("what the router measures: the good image valid, the damaged one not",
          mg["valid"] and mg["kind"] == "image" and mg["version"] == "15.2(8)WL" and not mb["valid"], str(mb))
    check("a file that is no image is kept as a file",
          iosimage.meta_from({"head": ["hello"], "size": 5, "md5": "x", "body": "y"})["kind"] == "file")
    check("bootable: the platform and the hash decide",
          iosimage.bootable(mg, "router") == "" and "platform" in iosimage.bootable(mg, "sw:office")
          and "damaged" in iosimage.bootable(mb, "router"))
    stick = debpacks.own_tools("tftpd")
    check("the tftpd stick carries the images and their MD5 list",
          set(stick) >= {"IMAGES-MD5.txt", "IMAGES.txt", good.name, bad.name, iosimage.RELEASES[2].name}
          and iosimage.published_md5(good).encode() in stick["IMAGES-MD5.txt"] and bool(debpacks.own_tools("frr")))
    cmd = iosimage.fetch_cmd("10.80.0.10", good.name, "wlsw-office")
    check("the fetch runs busybox tftp (in the switch's namespace) and measures md5 and body hash",
          '"$T" -g -l $f -r' in cmd and "ip netns exec wlsw-office" in cmd and "md5sum" in cmd and "sha256sum" in cmd)


def test_ccna_password_recovery_and_upgrade():
    """The Break in the boot window, ROMMON's confreg and reset, the router
    starting empty and taking its configuration back, the register in show
    version and running-config; the switch's boot loader and config.text;
    an image copied, verified, booted; the console cable's Ctrl+C."""
    import os
    from winlab import (consolecable, devcli, editor, exercises, iosboot, iosimage, iosnv, paths, workbench)
    from winlab.model import CUSTOM
    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    secret_a = "".join(["s", "e", "k", "r", "1", "t"])
    secret_b = "".join(["n", "e", "w", "o", "n", "e", "2"])
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
        os.environ["WINLAB_IMAGES"] = str(td / "images")
        try:
            editor.new_workbench("boot-net")
            name = "boot-net"
            d = _ccna_dash(name)
            workbench._running = lambda _n: {"fabric", "pc01"}
            fetch = {"out": ""}

            def runner_factory():
                return (lambda cmd, timeout=60: fetch["out"] if "winlab-img" in cmd else ""), ""
            workbench.act(d, "wb-add", {"shelf": "switch", "id": "office", "x": 200, "y": 240})
            editor.add_node(d.lab, "pc01", kind=CUSTOM, image="win11")
            editor.cable(d.lab, "pc01", 0, "office")
            d.lab.layout["pc01"] = [100, 400]
            editor.save(d.lab)
            d.reload()
            workbench.act(d, "wb-cable", {"node": "router", "network": "office"})
            con = devcli.Console(d, "router", runner_factory=runner_factory, link=lambda l, up: None)
            say = con.run
            for line in ("", "en", "conf t", "hostname R1", "enable secret " + secret_a, "int g0/0/0",
                         "ip address 10.1.1.1 255.255.255.0", "no shut", "end", "write"):
                say(line)
            ver = say("show version")
            check("show version: the factory image and register 0x2102",
                  'System image file is "bootflash:router-universal.bin"' in ver
                  and "Version 15.2(7)WL" in ver and "register is 0x2102" in ver, ver)
            check("a Ctrl+C long after the start is ignored", say(iosboot.BREAK) == "" and con.prompt() == "R1#")
            iosnv.power_on(d.lab)
            out = say(iosboot.BREAK)
            check("a Break in the boot window: ROMMON", "aborted due to user interrupt" in out
                  and con.prompt() == "rommon 1 > ", out)
            check("ROMMON's help and an unknown word", "confreg" in say("help")
                  and 'monitor: command "bogus" not found' in say("bogus") and con.prompt() == "rommon 3 > ")
            out = say("confreg 0x2142")
            rec = iosimage.device(name, "router")
            check("confreg sets the next start's value", "reset or power cycle" in out
                  and rec.get("next") == "0x2142", f"{out!r} {rec}")
            check("a bad value is refused", "bad value" in say("confreg 2142"))
            out = say("reset")
            check("reset: the router starts with the register applied", "Configuration register is 0x2142" in out
                  and "Press RETURN to get started." in out and con.prompt() == "", out)
            check("and offers the setup dialog", "Configuration Dialog" in say("")
                  and "initial configuration dialog" in con.prompt())
            say("no")
            say("")
            say("en")
            check("it started empty, no secret asked, NVRAM still full",
                  con.prompt() == "Router#" and "hostname R1" in say("show startup-config")
                  and not d.lab.networks["office"].routed)
            check("show version: the register now", "Configuration register is 0x2142" in say("show version"))
            check("before the fix the checks say what is missing",
                  not iosboot.check_router_recovered(d.lab)[0] and not iosboot.check_router_register(d.lab)[0])
            say("copy startup-config running-config")
            check("copy startup-config running-config brings it back", con.prompt() == "R1#"
                  and d.lab.networks["office"].routed)
            for line in ("conf t", "enable secret " + secret_b, "config-register 0x2102"):
                say(line)
            check("config-register: show version says what the next reload uses",
                  "0x2142 (will be 0x2102 at next reload)" in say("do show version"))
            say("config-register 0x2142")
            check("a non-default register is a running-config line", "config-register 0x2142" in say("do show run"))
            say("config-register 0x2102")
            say("end")
            check("the secret is new but not saved yet", not iosboot.check_router_secret(d.lab)[0])
            say("write")
            res = [exercises._WINLAB_CHECKS[n](d.lab) for n in
                   ("iosboot-router-recovered", "iosboot-router-secret", "iosboot-router-register")]
            check("the recovery's checks pass", all(r[0] for r in res), str(res))

            # images: archive, copy from TFTP, verify, boot system, reload
            good, bad = iosimage.RELEASES[0], iosimage.RELEASES[1]
            say("copy running-config bootflash:pre-upgrade-confg")
            check("a configuration archive in flash", "bytes copied" in say("")
                  and "pre-upgrade-confg" in say("dir"))
            fetch["out"] = _ccna_fetch_out(good)
            say("copy tftp: bootflash:")
            say("10.1.1.9")
            say(good.name)
            out = say("")
            check("copy tftp: bootflash: fetches and keeps the image",
                  f"[OK - {len(iosimage.build(good))} bytes]" in out and good.name in say("show flash:"), out)
            check("verify /md5 against the published sum",
                  "Verified" in say(f"verify /md5 bootflash:{good.name} {iosimage.published_md5(good)}"))
            check("verify checks the embedded hash", "Image verified" in say(f"verify bootflash:{good.name}"))
            fetch["out"] = _ccna_fetch_out(bad)
            o1 = say(f"copy tftp://10.1.1.9/{bad.name} bootflash:")
            o1 += say("") + say("") + say("")
            o2 = say(f"verify /md5 bootflash:{bad.name} {iosimage.published_md5(bad)}")
            o3 = say(f"verify bootflash:{bad.name}")
            check("the damaged image fails both checks", "%Error verifying" in o2 and "damaged" in o3,
                  f"{o1!r} {o2!r} {o3!r}")
            say(f"delete bootflash:{bad.name}")
            say("")
            say("")
            check("delete asks twice and removes it", bad.name not in say("dir"))
            for line in ("conf t", f"boot system bootflash:{good.name}", "boot system bootflash:router-universal.bin",
                         "end"):
                say(line)
            run = say("show running-config")
            check("boot system lines sit between the markers", f"boot-start-marker\nboot system bootflash:{good.name}\n"
                  "boot system bootflash:router-universal.bin\nboot-end-marker" in run, run[:400])
            check("not in the startup configuration until saved", "(not set)" in say("show boot"))
            say("write")
            say("reload")
            out = say("")
            check("reload loads the new image", f"Loading bootflash:{good.name}" in out and "15.2(8)WL" in out, out)
            say("")
            say("en")
            say(secret_b)
            ver = say("show version")
            check("show version: the new version and image file", "Version 15.2(8)WL" in ver
                  and f'"bootflash:{good.name}"' in ver, ver)
            res = [exercises._WINLAB_CHECKS[n](d.lab) for n in
                   ("iosimage-router-flash", "iosimage-router-boot", "iosimage-config-archive")]
            check("the upgrade's router checks pass", all(r[0] for r in res), str(res))
            fl = iosimage.files(name, "router")
            fl[good.name] = dict(fl[good.name], valid=False)
            iosimage.put_files(name, "router", fl)
            say("reload")
            out = say("")
            check("a boot system file that does not boot: the next one loads", "BOOTFAIL" in out
                  and "Loading bootflash:router-universal.bin" in out, out)
            fl = {k: dict(v, valid=False) for k, v in iosimage.files(name, "router").items()
                  if v.get("kind") == "image"}
            iosimage.put_files(name, "router", fl)
            say("")
            say("en")
            say(secret_b)
            say("reload")
            out = say("")
            check("nothing bootable: ROMMON", "NOIMAGE" in out and con.prompt().startswith("rommon"), out)
            iosimage.put_files(name, "router", {"router-universal.bin": iosimage.meta_of(iosimage.FACTORY["router"])})
            check("boot <file> from ROMMON", "Press RETURN" in say("boot bootflash:router-universal.bin"))

            # the switch's boot loader
            sw = devcli.Console(d, "sw:office", runner_factory=runner_factory, link=lambda l, up: None)
            for line in ("", "en", "conf t", "hostname SW1", "enable secret " + secret_a, "end", "write"):
                sw.run(line)
            workbench.act(d, "wb-swpower", {"network": "office", "on": False})
            workbench.act(d, "wb-swpower", {"network": "office", "on": True})
            sw = devcli.Console(d, "sw:office", runner_factory=runner_factory, link=lambda l, up: None)
            check("a switch powered on opens its Break window", iosboot.window_open(iosimage.device(name, "sw:office")))
            sw.s.mode = "idle"
            check("the Break: the switch's boot loader", "flash_init" in sw.run(iosboot.BREAK)
                  and sw.prompt() == "switch: ")
            check("flash is unreadable before flash_init", "flash_init first" in sw.run("dir flash:"))
            sw.run("flash_init")
            check("dir after flash_init lists config.text", "config.text" in sw.run("dir flash:"))
            sw.run("rename flash:config.text flash:config.old")
            check("the switch starts without config.text", "Press RETURN" in sw.run("boot")
                  and bool(iosimage.device(name, "sw:office").get("recovery")))
            for line in ("", "no", "", "en"):
                sw.run(line)
            check("empty, no secret, the old file kept", sw.prompt() == "Switch#" and "config.old" in sw.run("dir")
                  and sw.run("show startup-config") == "startup-config is not present")
            sw.run("rename flash:config.old flash:config.text")
            sw.run("copy flash:config.text running-config")
            check("renamed back and copied in", sw.prompt() == "SW1#")
            for line in ("conf t", "enable secret " + secret_b, "end", "write"):
                sw.run(line)
            check("the switch recovery's checks pass", iosboot.check_switch_recovered(d.lab)[0]
                  and iosboot.check_switch_secret(d.lab)[0])

            # the console cable: Ctrl+C is the Break
            iosnv.power_on(d.lab)
            term = consolecable.Terminal(devcli.Console(d, "router", runner_factory=runner_factory,
                                                        link=lambda l, up: None))
            term.wake()
            out = term.feed(b"\x03").decode("latin-1")
            check("the console cable's Ctrl+C in the window: ROMMON", "rommon 1 >" in out, out)
            out = term.feed(b"reset\r").decode("latin-1")
            check("and reset from it", "Press RETURN" in out, out)
        finally:
            paths.VAR, paths.STATE, paths.LABS = saved[:3]
            if saved[3] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[3]
            workbench._running = saved[4]














def test_desktop_look_and_accessibility():
    """Settings > Personalization and Accessibility as Windows has them: light,
    dark or the PC's mode, contrast themes, a text size slider, animation
    effects; and the desktop works with a screen reader and the keyboard."""
    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    head = page.split("</head>")[0]
    check("dark mode is picked by hand or follows the PC, before the first paint",
          "r.dataset.theme=" in head and "prefers-color-scheme: dark" in head and 'id="pref-theme"' in page
          and '<option value="system">Same as this PC</option>' in page and "darkHost.addEventListener" in page)
    check("every dark rule hangs on data-theme, so the choice wins over the PC's",
          "@media(prefers-color-scheme:dark)" not in page.replace(" ", "") and ":root[data-theme=dark]{" in page)
    check("four contrast themes with their own colours",
          all(f":root[data-contrast={k}]" in page for k in ("night", "aquatic", "dusk", "desert")) and 'id="pref-contrast"' in page)
    check("a machine's screen keeps its own colours under a contrast theme",
          ":not(:is(.vnc,.xterm,.llscreen,pre" in page)
    check("text size from 100 to 225 percent scales the page's own text",
          'id="pref-text" min="100" max="225"' in page and "calc(${m[1]}px * var(--ts, 1))" in page and "function textScaleOn(" in page)
    check("animation effects is a switch and follows the PC's reduced motion",
          'role="switch" class="tgl" id="pref-motion"' in page and "reduceMotion.matches" in page)
    check("Settings has pages as Windows does", all(f'data-page="{k}"' in page for k in ("lab", "look", "access", "lang", "act"))
          and 'role="tablist"' in page and "function setPage(" in page)
    check("windows are dialogs named by their title; the shell has roles",
          "w.setAttribute('role','dialog')" in page and "aria-labelledby" in page and 'id="taskbar" role="toolbar"' in page
          and 'id="start" role="dialog"' in page and 'id="ctx" role="menu"' in page and 'role="menuitem"' in page
          and 'id="toast" role="status"' in page)
    check("buttons drawn as divs get a role, the Tab order and Enter/Space",
          "function axFix(" in page and "el.setAttribute('role','button')" in page and "t.click();return;" in page)
    check("visible focus, arrow keys in menus and lists, Shift+F10, a window switcher",
          ":focus-visible{outline:2px solid var(--focus)" in page and "ArrowDown" in page and "e.key==='F10'&&e.shiftKey" in page
          and 'id="winswitch"' in page and "function wsShow(" in page and "e.code==='KeyW'" in page)
    check("a lesson's step boxes are named by their step", 'aria-labelledby="stp-${i}-n stp-${i}-t"' in page)


# ===== DevOps track (module devops, lab devops-pipeline) =====
def _forgejo_fixture(td: Path) -> Path:
    """A Forgejo-shaped data folder for the devops checks: app.ini, a SQLite
    database with the tables and columns the checks read, and bare
    repositories corp/web, corp/infra and corp/deploy."""
    import os
    import sqlite3
    import subprocess
    work = td / "forgejo"
    repos = work / "repos"
    db = work / "forgejo.db"
    (work).mkdir(parents=True)
    ini = work / "app.ini"
    ini.write_text("APP_NAME = Forgejo\n\n[database]\nDB_TYPE = sqlite3\nPATH = " + str(db).replace("\\", "/")
                   + "\n\n[repository]\nROOT = " + str(repos).replace("\\", "/")
                   + "\n\n[server]\nROOT_URL = http://10.83.0.20:3000/\n\n[security]\nINSTALL_LOCK = true\n",
                   encoding="utf-8")
    con = sqlite3.connect(db)
    con.executescript("""
        create table "user" (id integer primary key, lower_name text, type integer, is_admin integer);
        create table repository (id integer primary key, owner_id integer, lower_name text, is_private integer);
        create table protected_branch (id integer primary key, repo_id integer, rule_name text, can_push integer,
                                       required_approvals integer);
        create table pull_request (id integer primary key, base_repo_id integer, has_merged integer, base_branch text);
        create table action_runner (id integer primary key, name text, last_online integer, deleted integer);
        create table action_run (id integer primary key, repo_id integer, ref text, event text, status integer);
        create table secret (id integer primary key, owner_id integer, repo_id integer, name text);
        create table package (id integer primary key, owner_id integer, type text, lower_name text);
        create table package_version (id integer primary key, package_id integer, lower_version text);
        insert into "user" values (1, 'labadmin', 0, 1), (2, 'ada', 0, 0), (3, 'ci-bot', 0, 0), (4, 'corp', 1, 0);
        insert into repository values (10, 4, 'web', 0), (11, 4, 'infra', 0), (12, 4, 'deploy', 0);
        insert into protected_branch values (1, 10, 'main', 0, 1);
        insert into pull_request values (1, 10, 1, 'main'), (2, 10, 1, 'main'), (3, 10, 0, 'main');
        insert into action_run values (1, 10, 'refs/pull/1/head', 'pull_request', 1),
            (2, 10, 'refs/heads/main', 'push', 2), (3, 10, 'refs/heads/main', 'push', 1),
            (4, 11, 'refs/heads/main', 'push', 1), (5, 12, 'refs/heads/main', 'push', 1);
        insert into secret values (1, 0, 10, 'REGISTRY_TOKEN'), (2, 4, 0, 'DEPLOY_SSH_KEY');
        insert into package values (1, 4, 'container', 'web');
        insert into package_version values (1, 1, '0a1b2c3d4e5f'), (2, 1, '1a2b3c4d5e6f'),
            (3, 1, 'sha256:' || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
    """)
    import time as _t
    con.execute("insert into action_runner values (1, 'ci01', ?, 0)", (int(_t.time()) - 30,))
    con.commit()
    con.close()
    env = dict(os.environ, GIT_AUTHOR_NAME="Ada Lovelace", GIT_AUTHOR_EMAIL="ada@corp.lab",
               GIT_COMMITTER_NAME="Ada Lovelace", GIT_COMMITTER_EMAIL="ada@corp.lab")
    files = {
        "web": [("index.html", "<title>Corp web</title>\n"), ("about.html", "about\n"),
                (".forgejo/workflows/ci.yml", "on: [push, pull_request]\njobs:\n  test:\n    runs-on: lab\n"
                 "    env:\n      TOKEN: ${{ secrets.REGISTRY_TOKEN }}\n    steps:\n      - run: sh tests/check.sh\n")],
        "infra": [(".forgejo/workflows/infra.yml", "jobs:\n  infra:\n    runs-on: lab\n    steps:\n"
                   "      - run: tofu init && tofu apply -auto-approve && ansible-playbook site.yml\n")],
        "deploy": [("release.env", "WEB_TAG=1a2b3c4d5e6f\n"),
                   (".forgejo/workflows/reconcile.yml", "on:\n  push:\n    branches: [main]\n  schedule:\n"
                    "    - cron: '*/15 * * * *'\njobs:\n  reconcile:\n    runs-on: lab\n")],
    }
    for name, content in files.items():
        wt = td / "wt" / name
        wt.mkdir(parents=True)
        run = lambda *a: subprocess.run(["git", "-c", "init.defaultBranch=main", *a], cwd=wt, env=env,
                                        capture_output=True, text=True, check=True)
        run("init", "-q")
        for path, text in content:
            (wt / path).parent.mkdir(parents=True, exist_ok=True)
            (wt / path).write_text(text, encoding="utf-8")
            run("add", path)
            run("commit", "-q", "-m", f"Add {path}")
        if name == "web":
            run("revert", "--no-edit", "HEAD~1")
        (repos / "corp").mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--bare", str(wt), str(repos / "corp" / f"{name}.git")],
                       capture_output=True, check=True)
    return ini




# ===== incident response in depth: Velociraptor, Zeek, Sigma, YARA and the runbook (winlab/irtools.py) =====
_IR_LESSONS = {
    "ir-velociraptor-server": ("exercise", "ir-velociraptor-server"),
    "ir-velociraptor-clients": ("exercise", "ir-velociraptor-fleet"),
    "ir-velociraptor-hunt": ("problem", "ir-fleet-beacon"),
    "ir-velociraptor-triage": ("exercise", "ir-triage-collected"),
    "zeek-sensor": ("exercise", "zeek-sensor-logs"),
    "zeek-notice": ("exercise", "zeek-notice-raised"),
    "sigma-rules": ("exercise", "sigma-rules-converted"),
    "sigma-to-wazuh": ("exercise", "sigma-wazuh-rule"),
    "yara-share-scan": ("problem", "yara-share-samples"),
    "ir-runbook": ("problem", "ir-dns-beacon"),
}
_IR_TS = {"ts-velociraptor-client-offline": "velo-client-wrong-server", "ts-zeek-crashed": "zeek-script-broken",
          "ts-sigma-rule-silent": "sigma-field-case"}












# The aws-cloud lab's optional lessons on the student's own AWS account and
# Google Cloud trial, done in the browser like the Azure ones (test_aws_cloud).
BROWSER_LESSONS |= {"aws-free-account", "aws-real-iam-cloudshell", "aws-real-vpc-ec2", "aws-real-s3-cleanup",
                    "gcp-free-trial", "gcp-iam-vpc", "gcp-compute-engine"}






def test_vm_tuning():
    """Lighter machines: Hyper-V enlightenments for Windows on KVM, no HPET
    for Windows (hpet = true puts it back), zero writes not stored, and the
    balloon reporting free pages where the host can take them back."""
    from winlab import balloon, netplan, schema
    from winlab.providers import qemu
    from winlab.providers.qemu import QemuProvider
    lab = schema.load("ad-ds-basics")
    plan = netplan.compile_topology(lab, check_ports=False)
    win = next(n for n in lab.node_list() if n.is_windows)
    arg = lambda argv, flag: argv[argv.index(flag) + 1]
    kvm = QemuProvider(plan, accel="kvm").build_node(win).argv
    check("a Windows machine on KVM gets the Hyper-V enlightenments and a delayed PIT",
          arg(kvm, "-cpu").startswith(f"host,{qemu.HV_KVM}") and "hv-stimer" in qemu.HV_KVM
          and "kvm-pit.lost_tick_policy=delay" in kvm, arg(kvm, "-cpu"))
    whpx = QemuProvider(plan, accel="whpx").build_node(win).argv
    check("on WHPX the CPU model is unchanged and there is no KVM-only global; HPET off",
          arg(whpx, "-cpu") == qemu.cpu_model("whpx") and not any("kvm-pit" in a for a in whpx)
          and arg(whpx, "-machine") == "q35,hpet=off", arg(whpx, "-machine"))
    check("the system disk skips storing zeros and passes TRIM through",
          any("id=sys," in a and "discard=unmap,detect-zeroes=unmap" in a for a in whpx))
    win.vars["hpet"] = True
    try:
        back = QemuProvider(plan, accel="whpx").build_node(win).argv
        check("hpet = true on a machine puts the HPET back", arg(back, "-machine") == "q35")
    finally:
        win.vars.pop("hpet", None)
    fab = QemuProvider(plan, accel="kvm").build_fabric().argv
    check("the router's CPU stays plain host and keeps its HPET (Linux)",
          arg(fab, "-cpu") == "host" and arg(fab, "-machine") == "q35")
    saved = balloon.host_can_reclaim
    try:
        balloon.host_can_reclaim = lambda: True
        on = qemu.balloon_device()
        balloon.host_can_reclaim = lambda: False
        off = qemu.balloon_device()
    finally:
        balloon.host_can_reclaim = saved
    check("free page reporting where the host can discard pages, the plain balloon on Windows",
          on == "virtio-balloon-pci,free-page-reporting=on" and off == "virtio-balloon-pci", str((on, off)))


def test_desktop_page_script_parses():
    """The desktop page's script is one program: a stray quote in any string
    (an apostrophe in a single-quoted hint) stops every window. node checks
    it when it is on this PC."""
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        print("  skip node is not installed")
        return
    text = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    code = "\n".join(re.findall(r"<script>(.*?)</script>", text, re.S))
    with tempfile.TemporaryDirectory() as td:
        f = Path(td, "page.js")
        f.write_text(code, encoding="utf-8")
        r = subprocess.run([node, "--check", str(f)], capture_output=True, text=True)
    check("the desktop page's script parses (node --check)", r.returncode == 0, (r.stderr or "")[-400:])


def test_problem_engine_is_robust():
    """The problems engine (winlab/problemengine.py) against a fake guest:
    nothing runs with a missing value, a break that did not take is put
    back, a failed break is rolled back, a second Break does not apply
    twice, a put-back is safe to repeat, a check that cannot run is no
    try, one action per problem and machine at a time, a log for support,
    and every {name} in the catalog is one a lab can fill."""
    import json as _json
    from winlab import guestfaults as gf, paths, problemengine as pe, progress, webui

    class Guest:
        """healthy flips with the apply and the undo; knobs make it misbehave."""
        def __init__(self):
            self.healthy = True
            self.calls = []
            self.apply_takes = True
            self.apply_rc = 0
            self.undo_rc = 0
            self.undo_heals = True
            self.reachable = True
            self.verify_reachable = True
            self.slow = 0          # checks that still say healthy after a good apply

        def __call__(self, node, cmd, shell):
            self.calls.append(cmd.split()[0].rstrip(";"))
            if not self.reachable:
                return pe.Ran(False, err="cannot reach the guest channel")
            if cmd.startswith("VERIFY"):
                if not self.verify_reachable:
                    return pe.Ran(False, err="no reply within 120s")
                if self.slow and not self.healthy:
                    self.slow -= 1
                    return pe.Ran(True, True, "True")
                return pe.Ran(True, True, "checking\n" + ("True" if self.healthy else "False"))
            if cmd.startswith("APPLY"):
                if self.apply_takes:
                    self.healthy = False
                return pe.Ran(True, self.apply_rc == 0, "", "Access is denied.\nthe disk is write-protected"
                              if self.apply_rc else "")
            if cmd.startswith("UNDO"):
                if self.undo_heals:
                    self.healthy = True
                return pe.Ran(True, self.undo_rc == 0, "", "nothing to undo" if self.undo_rc else "")
            return pe.Ran(True, True, "")

    sid, rsid, msid = "zz-engine-test", "zz-engine-restart", "zz-engine-mail"
    gf._reg(gf.GuestFault(id=sid, title="t", os=gf.WINDOWS, teaches="t", symptom="the {share} share is gone",
                          apply="APPLY {share}", clear="UNDO {share}", verify="VERIFY {share}", hints=("a", "b", "c")))
    gf._reg(gf.GuestFault(id=rsid, title="t", os=gf.WINDOWS, teaches="t", symptom="s",
                          apply="APPLY; shutdown.exe /r /t 15", clear="UNDO", verify="VERIFY"))
    gf._reg(gf.GuestFault(id=msid, title="t", os=gf.WINDOWS, teaches="t", symptom="s",
                          apply="APPLY {mailip}", clear="UNDO {mailip}", verify="VERIFY {mailip}"))
    saved = (pe.SETTLE, paths.VAR, progress.progress_file)
    try:
        with tempfile.TemporaryDirectory() as td:
            paths.VAR = Path(td) / "var"
            progress.progress_file = lambda: Path(td) / "progress.json"
            pe.SETTLE = (0, 0)
            lab = "zz-lab"

            g = Guest()
            r = pe.apply_break(g, lab, sid, "pc01", {"share": "Company"})
            check("engine: a clean break is checked before and after",
                  r.ok and r.status == pe.BROKEN and r.broken and g.calls == ["VERIFY", "APPLY", "VERIFY"]
                  and "the Company share is gone" in r.message, f"{r} {g.calls}")
            g.calls.clear()
            r = pe.apply_break(g, lab, sid, "pc01", {}, known_broken=True)
            check("engine: Break on a machine that already has it applies nothing a second time",
                  r.ok and r.status == pe.ALREADY_BROKEN and r.broken and g.calls == ["VERIFY"], f"{r} {g.calls}")

            g = Guest(); g.apply_takes = False
            r = pe.apply_break(g, lab, sid, "pc01", {})
            check("engine: a break that did not take is put back and said, nothing to hunt",
                  not r.ok and r.status == pe.DID_NOT_TAKE and not r.broken and "UNDO" in g.calls
                  and "nothing to fix" in r.message, f"{r} {g.calls}")

            g = Guest(); g.slow = 2
            r = pe.apply_break(g, lab, sid, "pc01", {})
            check("engine: a problem that needs a moment to show is waited for, not undone",
                  r.ok and r.status == pe.BROKEN and "UNDO" not in g.calls, f"{r} {g.calls}")

            g = Guest(); g.apply_rc = 1
            r = pe.apply_break(g, lab, sid, "pc01", {})
            check("engine: a break that fails part way is rolled back at once and says why",
                  not r.ok and r.status == pe.REFUSED and not r.broken and g.healthy
                  and "write-protected" in r.message and "put it back" in r.message, f"{r}")
            g = Guest(); g.apply_rc = 1; g.undo_heals = False
            r = pe.apply_break(g, lab, sid, "pc01", {})
            check("engine: when the rollback fails too, the problem stays marked and Give up is the way out",
                  not r.ok and r.broken and "Give up" in r.message, f"{r}")

            g = Guest(); g.reachable = False
            r = pe.apply_break(g, lab, sid, "pc01", {})
            check("engine: a machine that does not answer is not touched",
                  not r.ok and r.status == pe.UNREACHABLE and not r.broken and g.calls == ["VERIFY"], f"{r} {g.calls}")

            g = Guest(); g.healthy = False
            r = pe.apply_break(g, lab, sid, "pc01", {})
            check("engine: a machine that already fails the check is still broken (the fix is the lesson)",
                  r.ok and r.status == pe.BROKEN and g.calls == ["VERIFY", "APPLY"], f"{r} {g.calls}")

            g = Guest()
            r = pe.apply_break(g, lab, msid, "pc01", {})
            check("engine: a lab without the machine a problem needs refuses it before running anything",
                  not r.ok and r.status == pe.MISSING_VALUES and "mailip" in r.message and not g.calls, f"{r}")
            check("engine: missing_values sees empty and absent values",
                  pe.missing_values(msid, {}) == ["mailip"] and not pe.missing_values(msid, {"mailip": "10.0.0.5"}))

            g = Guest(); g.undo_rc = 1
            r = pe.restore(g, lab, sid, "pc01", {})
            check("engine: Give up on a healthy machine is safe to repeat",
                  r.ok and r.status == pe.RESTORED and not r.broken, f"{r}")
            g = Guest(); g.healthy = False; g.undo_heals = False
            r = pe.restore(g, lab, sid, "pc01", {})
            check("engine: an undo that leaves the problem in place says so",
                  not r.ok and r.status == pe.RESTORE_INCOMPLETE and r.broken, f"{r}")

            g = Guest(); g.healthy = False; g.verify_reachable = False
            r = pe.verify_fix(g, lab, sid, "pc01", {})
            check("engine: a check that cannot run is a CHECK_ERROR, not a failed try",
                  not r.ok and r.status == pe.CHECK_ERROR and "Nothing was counted" in r.message, f"{r}")
            g.verify_reachable = True
            check("engine: verify tells fixed from not fixed",
                  pe.verify_fix(g, lab, sid, "pc01", {}).status == pe.NOT_FIXED)
            g.healthy = True
            check("engine: verify tells fixed", pe.verify_fix(g, lab, sid, "pc01", {}).status == pe.FIXED)

            g = Guest()
            r = pe.apply_break(g, lab, rsid, "pc01", {})
            check("engine: a break that restarts the machine is not judged by a check racing the restart",
                  r.ok and r.status == pe.RESTARTING and g.calls == ["VERIFY", "APPLY"], f"{r} {g.calls}")

            pe._claim((lab, sid, "pc01"))
            try:
                g = Guest()
                r = pe.apply_break(g, lab, sid, "pc01", {})
                check("engine: a second Break while the first still runs is told to wait",
                      not r.ok and r.status == pe.BUSY and not g.calls, f"{r}")
            finally:
                pe._release((lab, sid, "pc01"))

            def boom(node, cmd, shell):
                raise RuntimeError("agent bug")
            r = pe.apply_break(boom, lab, sid, "pc01", {})
            check("engine: a bug in a runner is an answer, not a crashed request",
                  not r.ok and r.status == pe.REFUSED and "agent bug" in r.message, f"{r}")

            recs = [_json.loads(x) for x in (paths.lab_dir(lab) / "problems.log").read_text(encoding="utf-8").splitlines()]
            check("engine: every action is logged for support, with the raw output",
                  len(recs) >= 15 and {"break", "restore", "verify"} <= {x["action"] for x in recs}
                  and any("write-protected" in x["detail"] for x in recs), str(len(recs)))

            # The Problems window through the engine: Break, Break again, a check
            # that cannot run, Give up.
            d = webui.Dashboard(webui.load_lab("ad-ds-basics"), accel="tcg")
            node = next(n for n, nd in d.lab.nodes.items() if nd.kind != "linux")

            class _NS:
                pid, serial_port = 1, 1
            st = type("St", (), {"nodes": {node: _NS()}})()
            g = Guest()
            orig = (webui.state.load, webui.state.pid_alive, pe.guest_runner)
            webui.state.load = lambda name: st
            webui.state.pid_alive = lambda pid: True
            pe.guest_runner = lambda name, timeout=120: g
            try:
                r = d._guest_fault({"node": node, "scenario": sid})
                e = progress.load()["problems"][sid]
                check("Problems window: Break goes through the engine and marks the machine",
                      r["ok"] and r["broken"] and r["status"] == pe.BROKEN and e.get("broken_on") == node, str(r))
                g.calls.clear()
                r = d._guest_fault({"node": node, "scenario": sid})
                check("Problems window: Break again does not apply twice",
                      r["ok"] and r["status"] == pe.ALREADY_BROKEN and "APPLY" not in g.calls, str(r))
                g.verify_reachable = False
                r = d._guest_fault_verify({"node": node, "scenario": sid})
                e = progress.load()["problems"][sid]
                check("Problems window: a check that cannot run counts no try",
                      not r["ok"] and not r["fixed"] and int(e.get("tries") or 0) == 0
                      and not int(e.get("attempts") or 0), f"{r} {e}")
                g.verify_reachable = True
                r = d._guest_fault_verify({"node": node, "scenario": sid})
                check("Problems window: a real failed check counts one try",
                      r["ok"] and not r["fixed"] and r["tries"] == 1, str(r))
                r = d._guest_fault({"node": node, "scenario": sid, "clear": "1"})
                e = progress.load()["problems"][sid]
                check("Problems window: Give up puts it back and clears the mark",
                      r["ok"] and not r["broken"] and "given up" in r["message"] and not e.get("broken_on"), str(r))
                g.apply_takes = False
                r = d._guest_fault({"node": node, "scenario": sid})
                e = progress.load()["problems"][sid]
                check("Problems window: a break that did not take leaves no mark and no Give up",
                      not r["ok"] and not r["broken"] and not e.get("broken_on"), str(r))
                progress.problem_break_failed(sid, node, "the checkpoint is gone")
                card = next(c for c in d.guest_faults() if c["id"] == sid)
                check("Problems window: a break from outside that failed is on the card",
                      "checkpoint is gone" in card["break_error"], str(card.get("break_error")))
                progress.problem_broken(sid, node, True)
                card = next(c for c in d.guest_faults() if c["id"] == sid)
                check("Problems window: the next break clears that note", not card["break_error"])
            finally:
                webui.state.load, webui.state.pid_alive, pe.guest_runner = orig
    finally:
        pe.SETTLE, paths.VAR, progress.progress_file = saved
        for x in (sid, rsid, msid):
            gf.SCENARIOS.pop(x, None)

    bad = {s: pe.unknown_tokens(s) for s in gf.SCENARIOS if pe.unknown_tokens(s)}
    check("engine: every {name} in the catalog is a value a lab can fill (no typo reaches a guest)", not bad, str(bad))
    page = (Path(__file__).resolve().parent.parent / "winlab" / "webui_page.html").read_text(encoding="utf-8")
    check("Problems window: Give up follows whether the problem is still in place",
          "r.broken!==undefined" in page and "The last break did not happen" in page)
    import json as _j
    root = Path(__file__).resolve().parent.parent
    msgs = ["broke {} — symptom: {}", "the break did not take on {}: it still checks out healthy, so winlab put it back. "
            "There is nothing to fix", "could not check {}: it did not answer. Nothing was counted; try again in a moment",
            "{} refused the break: {}. winlab put it back as it was", "The last break did not happen: {}"]
    for code in ("he", "ar", "es"):
        t = _j.loads((root / "content" / "i18n" / f"{code}.json").read_text(encoding="utf-8"))
        check(f"{code}: the engine's messages are translated", all(t.get(m) for m in msgs),
              str([m for m in msgs if not t.get(m)]))


# ===== guides: a small office from a bare switch and router, a new hire's PC from box to desk (winlab/guide.py) =====


# ---- pc-core: A+ desktop support (troubleshooting method, change management,
# backup, disks, workgroups, PC network problems) ----



# ===== pc-extras: blue screens, Hyper-V and Sandbox, Ubuntu Desktop, printer faults =====
PCX_LESSONS = {
    "aplus-blue-screen-dump": ("endpoint", 630, "windows11-desktops", "pc02", "", "aplus-bsod-dump-read"),
    "pc-hyperv-and-sandbox": ("endpoint", 631, "windows11-desktops", "pc01", "", "w11-hyperv-and-sandbox"),
    "ubuntu-desktop-for-support": ("endpoint", 632, "linux-by-hand", "lxpc01", "", "ubuntu-desktop-installed"),
    "printer-status-from-the-device": ("endpoint", 633, "print-support", "prn01", "printer-tray-empty", ""),
    "ts-bsod-after-driver-update": ("troubleshoot", 990, "windows11-desktops", "pc02", "w11-bsod-storage-driver", ""),
    "ts-printer-paper-jam": ("troubleshoot", 991, "print-support", "prn01", "printer-paper-jam", ""),
    "ts-printer-toner-empty": ("troubleshoot", 992, "print-support", "prn01", "printer-toner-empty", ""),
}






def test_pcx_printer_reports_its_state():
    """The printer appliance serves its real panel state over SNMP (Host
    Resources and the Printer MIB) and IPP, knows an empty cartridge, and
    the cups pack carries the snmp tools to read it."""
    from winlab import appliance, debpacks
    sh = Path("content/roles/netprinter.sh").read_text(encoding="utf-8")
    check("snmpd passes the printer rows and the Printer MIB to winlab's script",
          "pass .1.3.6.1.2.1.25.3.5" in sh and "pass .1.3.6.1.2.1.43" in sh and "winlab-printer-mib" in sh
          and "-I -hr_device" in sh)
    check("IPP printer-state-reasons follow the panel",
          "winlab-printer-reasons" in sh and "printer-state-reasons=" in sh
          and all(r in sh for r in ("media-jam-error", "media-empty-error", "toner-empty-error", "door-open-error")))
    s = appliance.panel_state("flag toner-low\nflag toner-empty\njobs 1\n")
    check("an empty cartridge stops the printer", s["state"] == "toner-empty" and s["toner_empty"])
    s = appliance.panel_state("flag jam\nflag toner-empty\n")
    check("a jam still wins over the toner on the panel", s["state"] == "jam")
    check("a new cartridge clears low and empty", appliance.PRINTER_OPS["toner-new"][1] >= {"toner-low", "toner-empty"}
          and "toner-empty" in appliance.PRINTER_OPS)
    check("the cups pack carries net-snmp's tools", "snmp" in debpacks.PACKS["cups"].packages)
    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    check("the printer window shows an empty cartridge", "'toner-empty':['Toner empty'" in page)




def test_pcx_windbg_on_the_toolkit():
    """WinDbg goes on the toolkit stick only after the customer accepts
    Microsoft's licence; the App Installer file must name Microsoft.WinDbg
    on a microsoft.com host, and the bundle must say it is WinDbg."""
    import io
    import zipfile
    from winlab import toolkit
    xml = ('<AppInstaller Uri="https://aka.ms/windbg/download" Version="1.2510.7001.0">'
           '<MainBundle Name="Microsoft.WinDbg" Version="1.2510.7001.0" Publisher="CN=Microsoft"'
           ' Uri="https://windbg.download.prss.microsoft.com/dbazure/prod/1-2510-7001-0/windbg.msixbundle" /></AppInstaller>')
    v, url = toolkit.parse_appinstaller(xml)
    check("the App Installer file gives the version and the bundle", v == "1.2510.7001.0" and url.endswith("windbg.msixbundle"))
    refused = 0
    for bad in (xml.replace("Microsoft.WinDbg", "Other.App"), xml.replace("prss.microsoft.com", "example.net"),
                xml.replace("https://windbg", "http://windbg"), "<AppInstaller/>"):
        try:
            toolkit.parse_appinstaller(bad)
        except toolkit.ToolkitError:
            refused += 1
    check("another package, host or plain http is refused", refused == 4)

    def bundle(name):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("AppxMetadata/AppxBundleManifest.xml",
                       f'<Bundle><Identity Name="{name}" Publisher="CN=Microsoft" Version="1.2510.7001.0"/></Bundle>')
        return b.getvalue()
    check("a WinDbg bundle is read for its version", toolkit.check_windbg(bundle("Microsoft.WinDbg")) == "1.2510.7001.0")
    refused = 0
    for data in (bundle("Microsoft.Other"), b"not a zip"):
        try:
            toolkit.check_windbg(data)
        except toolkit.ToolkitError:
            refused += 1
    check("anything else is refused", refused == 2)
    got = []
    try:
        toolkit.fetch(("windbg",), get=lambda *a, **k: got.append(a) or b"", download=lambda *a, **k: got.append(a))
        ok = False
    except toolkit.ToolkitError as exc:
        ok = "licence" in str(exc) and not got
    check("WinDbg is never fetched unless the customer accepts Microsoft's licence", ok)
    check("the toolkit window offers the fetch", "toolkit-windbg-fetch" in Path("winlab/webui.py").read_text(encoding="utf-8")
          and "tkWinDbg" in Path("winlab/webui_page.html").read_text(encoding="utf-8"))





# ---- net-physical: cable tester and toner, PoE budgets, guest Wi-Fi portal

def _np_lab(td, name):
    """A copy of a shipped lab in a scratch WINLAB root."""
    import shutil
    from winlab import paths, schema
    paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
    paths.LABS.mkdir(parents=True, exist_ok=True)
    shutil.copy(Path(f"content/labs/{name}.toml"), paths.LABS / f"{name}.toml")
    return schema.load(name)


def test_np_physfault_kinds():
    """The new cable faults: a split pair is on the router's side of the
    link (loss and corruption); an open, a short and crossed pairs take the
    link down at the card, like a dead card."""
    from winlab import physfaults
    for k in ("split", "open", "short", "crossed"):
        check(f"physfaults knows the {k} cable fault", k in physfaults.KINDS)
    check("a split pair is shaped on the router side", physfaults.KINDS["split"].side == "router"
          and "split" in physfaults._TC)
    check("open, short and crossed pairs are card-side, like a dead card",
          all(physfaults.card_side(k) for k in ("nic", "open", "short", "crossed"))
          and not physfaults.card_side("split") and not physfaults.card_side("bad")
          and not physfaults.card_side("nope"))












# --- net-core: VLANs, IPv4 static routes, IOS ACLs, NAT/PAT and their tickets ---

_NETCORE_LESSONS = ("vlans-access-trunks", "ipv4-static-routes", "ios-acls-standard-extended", "ios-nat-pat")
_NETCORE_TICKETS = {
    "ts-trunk-native-mismatch": "trunk-native-mismatch", "ts-trunk-vlan-not-allowed": "trunk-vlan-not-allowed",
    "ts-access-port-wrong-vlan": "access-port-wrong-vlan", "ts-port-err-disabled": "port-err-disabled",
    "ts-speed-duplex-mismatch": "speed-duplex-mismatch", "ts-acl-wrong-direction": "acl-wrong-direction",
    "ts-nat-inside-outside-swapped": "nat-inside-outside-swapped", "ts-pc-wrong-gateway": "pc-wrong-gateway",
    "ts-pc-wrong-mask": "pc-wrong-mask", "ts-pc-duplicate-ip": "pc-duplicate-ip"}


class _NetcoreEnv:
    """A scratch copy of the two labs, with the VMs and the guests mocked:
    the console, the breaks and the checks write real lab files and read
    them back, but nothing starts."""

    def __enter__(self):
        import shutil
        from unittest import mock
        from winlab import paths, workbench, netbasics
        self.td = Path(tempfile.mkdtemp())
        (self.td / "labs").mkdir()
        for n in ("campus-vlans", "router-protocols"):
            shutil.copy(paths.LABS / f"{n}.toml", self.td / "labs" / f"{n}.toml")
        self.saved = (paths.LABS, paths.VAR, paths.STATE)
        paths.LABS, paths.VAR, paths.STATE = self.td / "labs", self.td / "var", self.td / "var" / "state"
        self.cmds = []
        self.patches = [
            mock.patch.object(workbench, "_running",
                              lambda _n: {"fabric", "pc-a", "pc-b", "pc-c", "srv01", "pc-office", "pc-guest"}),
            mock.patch.object(netbasics, "_guest", lambda lab, node, cmd: (self.cmds.append((node, cmd)), (True, ""))[1])]
        for p in self.patches:
            p.start()
        return self

    def __exit__(self, *exc):
        import shutil
        from winlab import paths
        for p in self.patches:
            p.stop()
        paths.LABS, paths.VAR, paths.STATE = self.saved
        shutil.rmtree(self.td, ignore_errors=True)

    def dash(self, name):
        from winlab import schema, netplan, workbench

        class Dash:
            def __init__(d):
                d.name = name
                d.reload()

            def reload(d):
                d.lab = schema.load(name)
                d.plan = netplan.compile_topology(d.lab, check_ports=False)
                d.wb_live = workbench.Live()
        return Dash()

    @staticmethod
    def console(d, dev):
        from winlab import devcli
        c = devcli.Console(d, dev, runner_factory=lambda: ((lambda cmd, timeout=60: ""), ""), link=lambda l, up: None)
        c.powered = lambda: True
        for line in ("", "en"):
            c.run(line)
        return c

    @staticmethod
    def run(c, *lines):
        return "\n".join(c.run(line) for line in lines)




def test_netcore_problems_and_hosts():
    """Each ticket's problem has three hints, a verify, runs on the Ubuntu
    PCs, and is broken from outside (a quick host break) unless it is a PC's
    own setting changed inside it (gateway, mask)."""
    from winlab import guestfaults
    inside = {"pc-wrong-gateway", "pc-wrong-mask"}
    for pid in _NETCORE_TICKETS.values():
        f = guestfaults.SCENARIOS[pid]
        check(f"{pid} has a 3-step hint ladder and a verify", len(f.hints) == 3 and bool(f.verify.strip()), str(len(f.hints)))
        check(f"{pid} runs on ubuntu", "ubuntu" in f.images, str(f.images))
        if pid in inside:
            check(f"{pid} is broken inside the PC with a clear", not f.host and bool(f.apply.strip()) and bool(f.clear.strip()))
        else:
            check(f"{pid} is broken from outside, quickly", bool(f.host) and f.host in guestfaults.HOST_BREAKS
                  and guestfaults.host_break_is_quick(pid), f.host)
    blob = "\n".join(f"{f.apply}\n{f.clear}\n{f.verify}\n" + "\n".join(f.hints)
                     for f in (guestfaults.SCENARIOS[p] for p in _NETCORE_TICKETS.values()))
    check("no password-looking literal in the net-core problems",
          not re.search(r"(?i)password\s*[:=]\s*\S|-Password\s+'", blob))













# --- net-extras: TACACS+ (tac_plus-ng pack, command authorization and accounting), FTP and SCP copies,
# SNMPv3 and LibreNMS, the network tools lessons (iperf3, mtr, nmap, tshark) and their drills.

def _nx_workbench(td: Path, name: str):
    """A workbench with one routed switch and a PC, and a dashboard stand-in."""
    import os
    from winlab import editor, images, netplan, paths, schema, workbench
    from winlab.model import CUSTOM
    paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
    os.environ["WINLAB_IMAGES"] = str(td / "images")
    dest = editor.new_workbench(name)
    lab = schema.load(dest)
    paths.downloads_dir().mkdir(parents=True, exist_ok=True)
    images.installer_path("win11").write_bytes(b"\0" * 2048)
    editor.add_network(lab, "sw1", cidr="10.10.10.0/24")
    editor.add_node(lab, "pc01", kind=CUSTOM, image="win11")
    editor.cable(lab, "pc01", 0, "sw1")
    editor.save(lab)

    class _Dash:
        def reload(self):
            self.lab = schema.load(dest)
            self.plan = netplan.compile_topology(self.lab, check_ports=False)
    d = _Dash()
    d.reload()
    workbench._running = lambda _n: {"fabric"}
    return d


def _nx_saved():
    import os
    from winlab import paths, workbench
    return (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)


def _nx_restore(saved) -> None:
    import os
    from winlab import paths, workbench
    paths.VAR, paths.STATE, paths.LABS = saved[:3]
    workbench._running = saved[4]
    if saved[3] is None:
        os.environ.pop("WINLAB_IMAGES", None)
    else:
        os.environ["WINLAB_IMAGES"] = saved[3]




class _NxTacWire(_L2secWire):
    """The TACACS+ server, with command authorization (refuses any hostname
    command) and accounting (keeps every record)."""

    def __init__(self, key: str, users: dict):
        super().__init__(key, users)
        self.asked: list[list[str]] = []
        self.acct: list[tuple[int, list[str]]] = []

    @staticmethod
    def _args(body: bytes, off: int) -> list[str]:
        ulen, plen, rlen, n = body[off + 4], body[off + 5], body[off + 6], body[off + 7]
        lens = list(body[off + 8:off + 8 + n])
        i = off + 8 + n + ulen + plen + rlen
        out = []
        for ln in lens:
            out.append(body[i:i + ln].decode("latin-1"))
            i += ln
        return out

    def _tacacs(self, data: bytes) -> bytes:
        import struct
        from winlab import aaa
        pk = aaa.tac_split(data, self.tkey)
        if not pk:
            return b""
        kind, _, body = pk[0]
        session = data[4:8]
        if kind == 3:
            self.acct.append((body[0], self._args(body, 1)))
            return aaa.tac_packet(3, 2, session, struct.pack(">HH", 0, 0) + bytes([1]), self.tkey)
        if kind == 2:
            args = self._args(body, 0)
            if any(a.startswith("cmd=") and a != "cmd=" for a in args):
                self.asked.append(args)
                ok = "cmd=hostname" not in args
                return aaa.tac_packet(2, 2, session, bytes([1 if ok else 0x10, 0]) + struct.pack(">HH", 0, 0),
                                      self.tkey)
        return super()._tacacs(data)


def test_netextras_aaa_commands():
    """aaa authorization commands and aaa accounting exec/commands
    (winlab/aaa.py): the packets on their own, the console's lines and
    running configuration, a TACACS+ server refusing one command over SSH,
    the stop records with the whole command, exec start and stop."""
    import struct
    from winlab import aaa, devcli, iosssh

    key = "-".join(["tac", "shared", "word"])
    upw = "-".join(["alice", "tac", "phrase"])
    w = _NxTacWire(key, {"alice": upw})
    pkt = aaa.tac_author_cmd("alice", "vty0", "10.10.10.50", key, ["configure", "terminal"], 15)
    check("a command AUTHOR REQUEST: service=shell, cmd= the first word, cmd-arg for the rest and <cr>",
          aaa.tac_author_reply(w._tacacs(pkt), key)[0] == aaa.PASS
          and w.asked[-1] == ["service=shell", "cmd=configure", "cmd-arg=terminal", "cmd-arg=<cr>"], str(w.asked))
    refused = aaa.tac_author_reply(w._tacacs(aaa.tac_author_cmd("alice", "vty0", "", key, ["hostname", "X"], 15)), key)
    check("the server's FAIL is a refusal", refused[0] == aaa.FAIL, str(refused))
    rep = w._tacacs(aaa.tac_acct("alice", "vty0", "", key, aaa.ACCT_STOP, 15, ["task_id=1", "cmd=show clock <cr>"]))
    check("an ACCOUNTING REQUEST decodes on the server, and its SUCCESS reply on the router",
          aaa.tac_acct_reply(rep, key) == (aaa.PASS, "SUCCESS") and w.acct[-1] == (aaa.ACCT_STOP, ["task_id=1", "cmd=show clock <cr>"]))
    check("an accounting reply under another key does not decode", aaa.tac_acct_reply(rep, key + "x")[0] == aaa.ERROR)
    check("the level a command is checked at: show at # is 1, configure is 15, everything in user mode 1",
          aaa.command_level("enable", ["show", "run"]) == 1 and aaa.command_level("enable", ["configure"]) == 15
          and aaa.command_level("config", ["hostname", "X"]) == 15 and aaa.command_level("user", ["ping"]) == 1)
    del struct

    saved = _nx_saved()
    with tempfile.TemporaryDirectory() as td:
        try:
            d = _nx_workbench(Path(td), "tac-lab")
            wire = _NxTacWire(key, {"alice": upw})
            con = devcli.Console(d, "router", runner_factory=lambda: (wire, ""))
            con.run("enable")
            con.run("configure terminal")
            check("command authorization needs aaa new-model",
                  "aaa new-model" in con.run("aaa authorization commands 15 default group tacacs+ local"))
            for line in ("aaa new-model", "tacacs server TAC", "address ipv4 10.10.10.11", "key " + key, "exit",
                         "aaa authentication login default group tacacs+ local",
                         "aaa authorization exec default group tacacs+ local"):
                con.run(line)
            warn = con.run("aaa authorization commands 15 default group tacacs+")
            check("a list that ends in group tacacs+ is warned about (no fallback while the server is down)",
                  "every command is refused" in warn, warn)
            check("RADIUS is not a command authorization method",
                  "RADIUS does not authorize commands" in con.run("aaa authorization commands 15 default group radius"))
            for line in ("aaa authorization commands 15 default group tacacs+ local",
                         "aaa accounting exec default start-stop group tacacs+",
                         "aaa accounting commands 15 default stop-only group tacacs+"):
                out = con.run(line)
                check(f"accepted: {line}", "%" not in out, out)
            run = con.run("do show running-config")
            check("show running-config keeps the command authorization and accounting lines",
                  "aaa authorization commands 15 default group tacacs+ local" in run
                  and "aaa accounting exec default start-stop group tacacs+" in run
                  and "aaa accounting commands 15 default stop-only group tacacs+" in run, run[:1500])
            con.run("end")
            check("the console is not asked (no aaa authorization console), so nothing went to the server",
                  wire.asked == [])

            vc = iosssh.VtyConsole(d, "router", "alice", "10.10.10.50", runner_factory=lambda: (wire, ""))
            vc.open()
            vc.run(upw)
            check("alice logs in over SSH at the server's level 15", vc.s.mode == "enable")
            check("and an exec start record went to the server",
                  any(f == aaa.ACCT_START and "service=shell" in a for f, a in wire.acct), str(wire.acct))
            n0 = len(wire.asked)
            vc.run("conf t")
            check("conf t is asked about as configure terminal, the words IOS spells out",
                  len(wire.asked) == n0 + 1 and wire.asked[-1][1:3] == ["cmd=configure", "cmd-arg=terminal"],
                  str(wire.asked[-1:]))
            out = vc.run("hostname EVIL")
            check("the server refuses hostname: Command authorization failed, and the name stays",
                  "Command authorization failed." in out and devcli.hostname(d.lab, devcli.ROUTER) != "EVIL", out)
            out = vc.run("interface g0/0/0")
            check("another configuration command passes", "authorization failed" not in out, out)
            vc.run("end")
            stops = [a for f, a in wire.acct if f == aaa.ACCT_STOP and any(x.startswith("cmd=") for x in a)]
            check("each level 15 command left a stop record with the whole command",
                  any("cmd=configure terminal <cr>" in a for a in stops)
                  and any(x.startswith("cmd=interface") for a in stops for x in a), str(stops[-3:]))
            check("the refused command was not accounted as run",
                  not any("cmd=hostname EVIL <cr>" in a for a in stops))
            con.run("configure terminal")
            con.run("aaa authorization config-commands")
            con.run("no aaa authorization config-commands")
            run = con.run("do show running-config")
            check("no aaa authorization config-commands is shown, as IOS does",
                  "no aaa authorization config-commands" in run, run[:1500])
            n1 = len(wire.asked)
            vc.run("conf t")
            vc.run("interface g0/0/0")
            check("with config-commands off, commands in configuration mode are not asked about",
                  len(wire.asked) == n1 + 1, str(wire.asked[n1:]))
            vc.run("end")
            wire.down = True
            out = vc.run("conf t")
            check("a server that does not answer falls back to local (alice is no local user: refused)",
                  "Command authorization failed." in out, out)
            wire.down = False
            vc.run("exit")
            check("logging out sends the exec stop record with the elapsed time",
                  any(f == aaa.ACCT_STOP and any(x.startswith("elapsed_time=") for x in a) for f, a in wire.acct),
                  str(wire.acct[-2:]))
        finally:
            _nx_restore(saved)


def test_netextras_ftp_scp():
    """copy running-config ftp: and scp:, copy ftp: running-config
    (winlab/ftpscp.py): ip ftp username/password, IOS's questions, curl's
    and Dropbear scp's command lines with the login kept off the command line,
    the server's refusals worded as IOS does, the backup folder fault."""
    import base64
    import os
    import shutil
    import subprocess
    from winlab import devcli, ftpscp, guestfaults

    check("URLs: scheme, user, password, host, path",
          ftpscp.parse_url("ftp://u:p@10.1.1.5/dir/r1-confg") == ("ftp", "u", "p", "10.1.1.5", "dir/r1-confg")
          and ftpscp.parse_url("scp:") == ("scp", "", "", "", ""))
    check("curl's and scp's failures, as IOS words them",
          ftpscp.ios_error("ftp", "curl: (67) Access denied: 530", 67).startswith("Not logged in")
          and ftpscp.ios_error("ftp", "curl: (25) Failed FTP upload: 553", 25) == "Permission denied"
          and ftpscp.ios_error("ftp", "curl: (7) Failed to connect", 7) == "Connection refused"
          and ftpscp.ios_error("scp", "Permission denied (password)", 1).startswith("Not logged in"))

    saved = _nx_saved()
    with tempfile.TemporaryDirectory() as td:
        try:
            d = _nx_workbench(Path(td), "ftp-lab")
            ran, out_ = [], {"x": ""}

            def runner():
                def r(cmd, timeout=0):
                    ran.append(cmd)
                    return out_["x"]
                return r, ""
            r = devcli.Console(d, "router", runner_factory=runner)
            r.run("")
            r.run("en")
            fpw = "".join(["b", "k", "p", "w", "4", "2", "x", "y"])
            r.run("conf t")
            for line in ("hostname R1", "ip ftp username netbackup", "ip ftp password " + fpw, "end"):
                r.run(line)
            run = r.run("show running-config")
            check("ip ftp username and password are in the running configuration",
                  "ip ftp username netbackup" in run and ("ip ftp password " + fpw) in run, run[:800])
            r.run("copy running-config ftp:")
            p1 = r.prompt()
            r.run("10.10.10.50")
            p2 = r.prompt()
            out_["x"] = "#rc=0\n"
            out = r.run("")
            check("copy running-config ftp: asks for the server and the file, hostname-confg by default",
                  p1 == "Address or name of remote host []? " and p2 == "Destination filename [r1-confg]? ", (p1, p2))
            cmd = ran[-1]
            cfg = base64.b64decode(cmd.split("printf %s '")[1].split("'")[0]).decode()
            check("curl stores it with the login in a -K file, never on its command line",
                  "Writing r1-confg" in out and "bytes copied in" in out and '-T $f ftp://10.10.10.50/r1-confg' in cmd
                  and "-K $k" in cmd and fpw not in cmd and cfg == f'user = "netbackup:{fpw}"\n', cmd[-300:])
            out_["x"] = "curl: (25) Failed FTP upload: 553\n#rc=25\n"
            r.run("copy running-config ftp://10.10.10.50/r1-confg")
            r.run("")
            out = r.run("")
            check("a 553 is Permission denied, with the hint about write_enable and the folder",
                  "%Error opening ftp://10.10.10.50/r1-confg (Permission denied)" in out and "write_enable" in out, out)
            # SCP: the user and the password asked for, the password in the environment
            spw = "".join(["s", "c", "p", "w", "9", "9", "q", "z"])
            r.run("copy running-config scp:")
            r.run("10.10.10.50")
            pu = r.prompt()
            r.run("netbackup")
            r.run("")
            pp = r.prompt()
            out_["x"] = "#rc=0\n"
            out = r.run(spw)
            cmd = ran[-1]
            check("copy running-config scp: asks the user, the file and the password",
                  pu.startswith("Destination username [") and pp == "Password: " and "bytes copied in" in out,
                  (pu, pp, out))
            check("Dropbear's scp through dbclient -y -y, the password only in DROPBEAR_PASSWORD",
                  "-S $w" in cmd and "-y -y" in cmd and "netbackup@10.10.10.50:r1-confg" in cmd and spw not in cmd
                  and base64.b64encode(spw.encode()).decode() in cmd, cmd[-300:])
            # a file brought back into the running configuration
            body = "hostname R2\nip route 10.9.9.0 255.255.255.0 10.10.10.50\n"
            out_["x"] = "#rc=0\n#data\n" + base64.encodebytes(body.encode()).decode()
            r.run("copy ftp: running-config")
            r.run("10.10.10.50")
            r.run("r2-confg")
            out = r.run("")
            check("copy ftp: running-config merges the file: the new hostname",
                  "Loading r2-confg" in out and devcli.hostname(d.lab, devcli.ROUTER) == "R2", out)
        finally:
            _nx_restore(saved)

    f = guestfaults.SCENARIOS.get("ftp-upload-dir-not-writable")
    check("the FTP drill is registered for Ubuntu with three hints and a verify",
          f is not None and f.images == ("ubuntu",) and len(f.hints) == 3 and "echo True" in f.verify)
    if f is not None:
        cmd, _ = guestfaults.build_command(f.id, {}, clear=False)
        # The verify runs in the Ubuntu guest; here sh stands in, which needs
        # getent for the account's home (Git's sh on Windows has none).
        with tempfile.TemporaryDirectory() as td:
            log = Path(td, "vsftpd.log")
            log.write_text('Sat Nov  7 10:00:00 2026 [pid 9] [root] OK UPLOAD: Client "::ffff:10.80.0.2", '
                           '"/backups/r1-confg", 1234 bytes, 5.00Kbyte/sec\n')
            probe = cmd.replace("/var/log/vsftpd.log", log.as_posix()).split('[ -n "$u" ]')[0] + 'echo "$u $d"'
            got = subprocess.run(["sh", "-c", probe], capture_output=True, text=True).stdout.strip()
        if shutil.which("getent"):
            home = subprocess.run(["getent", "passwd", "root"], capture_output=True, text=True).stdout.split(":")[5]
            check("the drill finds the account and the folder of the last upload from vsftpd's log, inside the chroot",
                  got == f"root {home}/backups", got)
        else:
            check("the drill reads the account of the last upload from vsftpd's log (no getent here for its home)",
                  got.startswith("root "), got)







# ---- wifi-air: real 802.11 to a Linux laptop over vwifi (winlab/vwifi.py), its lesson and two tickets
def test_wifiair_vwifi_pinned_and_fetched():
    """The first published build is pinned; fetching it checks the digest
    and the size, and it goes onto the router's volume, an air AP's volume
    and the wifi pack's stick."""
    from winlab import vwifi
    check("vwifi's release asset is pinned: release vwifi-c3822ba, its SHA-256 and size",
          vwifi.TAG == "vwifi-c3822ba" and vwifi.published()
          and vwifi.ASSET_SHA256 == "29c18f590ef85e6438b6b1649105ea42096f7fc3ab90f39adac1ec2a703f69b5"
          and vwifi.ASSET_SIZE == 2796700)
    saved = vwifi.store
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        vwifi.store = lambda: d
        try:
            got = []

            def fake(url, dest, expect_sha="", label=""):
                got.append((url, expect_sha))
                with open(dest, "wb") as fh:
                    fh.truncate(vwifi.ASSET_SIZE)

            check("nothing is on this PC before the fetch", not vwifi.ready() and vwifi.volume_files() == [])
            p = vwifi.fetch(progress=lambda _m: None, download=fake)
            check("the fetch asks for winlab's release asset with the pinned digest, and then it is ready",
                  p == d / vwifi.ASSET and got == [(f"{vwifi.RELEASE}/{vwifi.ASSET}", vwifi.ASSET_SHA256)]
                  and vwifi.ready() and vwifi.volume_files() == [(f"vwifi/{vwifi.ASSET}", p)])
            vwifi.fetch(progress=lambda _m: None, download=fake)
            check("a second fetch downloads nothing", len(got) == 1)
            stick = d / "stick"
            stick.mkdir()
            man = {"extra": vwifi.fetch_extra(None, stick, [], None, fake, lambda _m: None)}
            check("the wifi pack carries the whole build (programs, licence, source) beside its .debs",
                  (stick / vwifi.ASSET).stat().st_size == vwifi.ASSET_SIZE and vwifi.extra_ready(stick, man)
                  and vwifi.ExtraError is vwifi.VwifiError)
            with open(p, "ab") as fh:
                fh.write(b"x")
            check("a file of another size is not taken as the build", not vwifi.ready())
        finally:
            vwifi.store = saved
    root = Path(__file__).resolve().parent.parent
    check("preparation fetches it, the repository volume carries it",
          "vwifi.fetch(" in (root / "winlab" / "prepare.py").read_text(encoding="utf-8")
          and "files += vwifi.volume_files()" in (root / "winlab" / "apkrepo.py").read_text(encoding="utf-8"))








# ---- rstp
# Real rapid spanning tree: mstpd (GPL-2.0-or-later) built from its pinned
# release by winlab's own workflow, fetched at preparation like vwifi, run on
# the router for the rapid-pvst switches; the lesson, the BPDU guard ticket,
# the exam map and the licence row.

def test_rstp_mstpd_pin_fetch_and_pack():
    """mstpd is pinned to a release commit; nothing is fetched before a build
    is pinned; with a digest pinned the asset is fetched, checked and carried
    on the repository volume; the workflow builds it from source by hand only
    and refuses another digest; the pack is reproducible and carries the
    programs, the licence, the NOTICE and the complete source."""
    import gzip
    import hashlib
    import importlib.util
    import io
    import os
    import tarfile
    from winlab import apkrepo, mstpd, paths, prepare

    root = Path(__file__).resolve().parent.parent
    check("mstpd is pinned to release 0.2.0's commit, GPL-2.0-or-later, and its asset is winlab's own release",
          len(mstpd.COMMIT) == 40 and mstpd.VERSION == "0.2.0" and mstpd.LICENSE == "GPL-2.0-or-later"
          and mstpd.RELEASE.startswith("https://github.com/rdiol12/winlablite/releases/download/")
          and mstpd.ASSET == f"mstpd-0.2.0-{mstpd.COMMIT[:7]}.tar.gz" and mstpd.PROGRAMS == ("mstpd", "mstpctl"))
    said = []
    check("nothing is fetched before a build is pinned, and it says how to publish one",
          mstpd.published() or (mstpd.fetch(progress=said.append, download=lambda *a, **k: 1 / 0) is None
                                 and "Actions > mstpd" in said[0] and not mstpd.ready()))
    saved = (paths.VAR, os.environ.get("WINLAB_IMAGES"), mstpd.ASSET_SHA256)
    with tempfile.TemporaryDirectory() as td:
        os.environ["WINLAB_IMAGES"] = str(Path(td) / "images")
        try:
            blob = b"\x1f\x8b fake mstpd pack"
            mstpd.ASSET_SHA256 = hashlib.sha256(blob).hexdigest()
            got = []

            def dl(url, dest, expect_sha="", label=""):
                got.append((url, expect_sha))
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(blob)
                return dest
            path = mstpd.fetch(download=dl)
            check("with a digest pinned: fetched from the release, checked against it, recorded",
                  path == mstpd.asset_path() and got == [(f"{mstpd.RELEASE}/{mstpd.ASSET}", mstpd.ASSET_SHA256)]
                  and mstpd.ready() and mstpd.summary()["ready"], str(got))
            check("the repository volume carries it under mstpd/",
                  mstpd.volume_files() == [(f"mstpd/{mstpd.ASSET}", mstpd.asset_path())])
        finally:
            mstpd.ASSET_SHA256 = saved[2]
            if saved[1] is None:
                os.environ.pop("WINLAB_IMAGES", None)
            else:
                os.environ["WINLAB_IMAGES"] = saved[1]
    check("preparing the fabric fetches it (a failure is a warning) and the volume adds it",
          "mstpd.fetch(" in (root / "winlab" / "prepare.py").read_text(encoding="utf-8")
          and "except mstpd.MstpdError" in (root / "winlab" / "prepare.py").read_text(encoding="utf-8")
          and "files += mstpd.volume_files()" in (root / "winlab" / "apkrepo.py").read_text(encoding="utf-8"))
    del apkrepo, prepare
    wf = (root / ".github" / "workflows" / "mstpd.yml").read_text(encoding="utf-8")
    check("the workflow: by hand only, from the pinned commit, static in Alpine, packed with the source, "
          "refusing a different digest",
          "workflow_dispatch" in wf and "import winlab.mstpd as m" in wf and "rev-parse HEAD" in wf
          and "LDFLAGS=-all-static" in wf and "grep -q NEEDED" in wf and "tools/pack_mstpd.py" in wf
          and "not published." in wf and "steps.pin.outputs.alpine" in wf and "push:" not in wf)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "bin").mkdir()
        for prog in mstpd.PROGRAMS:
            (d / "bin" / prog).write_bytes(b"\x7fELF " + prog.encode())
        (d / "src.tar.gz").write_bytes(b"source")
        (d / "LICENSE").write_bytes(b"GNU GENERAL PUBLIC LICENSE Version 2")
        spec = importlib.util.spec_from_file_location("pack_mstpd", root / "tools" / "pack_mstpd.py")
        pm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pm)
        a = pm.pack(d / "bin", d / "src.tar.gz", d / "LICENSE")
        b = pm.pack(d / "bin", d / "src.tar.gz", d / "LICENSE")
        with tarfile.open(fileobj=io.BytesIO(a), mode="r:gz") as tar:
            names = tar.getnames()
            notice = tar.extractfile("mstpd/NOTICE").read().decode()
            modes = {m.name: m.mode for m in tar.getmembers()}
        check("the pack is reproducible and carries the programs, licence, notice and complete source",
              a == b and gzip.decompress(a)[:5] == b"mstpd"
              and set(names) == {"mstpd/LICENSE", "mstpd/NOTICE", "mstpd/source/src.tar.gz",
                                 "mstpd/bin/mstpd", "mstpd/bin/mstpctl"}
              and modes["mstpd/bin/mstpd"] == 0o755, str(names))
        check("the NOTICE names upstream, the commit, the licence and how it was built",
              mstpd.UPSTREAM in notice and mstpd.COMMIT in notice and "General Public License" in notice
              and "-all-static" in notice)
        (d / "bin" / "mstpctl").write_bytes(b"#!/bin/sh")
        try:
            pm.pack(d / "bin", d / "src.tar.gz", d / "LICENSE")
            refused = False
        except SystemExit:
            refused = True
        check("a program that is not a Linux binary is refused", refused)
    lines = "\n".join(mstpd.router_lines())
    check("the router: the two programs from the volume into /usr/local/sbin once per build, and winlab's "
          "bridge-stp that hands only the listed bridges to mstpd",
          "/media/*/mstpd/mstpd-*.tar.gz" in lines and "blkid -L WLAPK" in lines
          and f"{mstpd.ROUTER_BIN}/" in lines and "/sbin/bridge-stp" in lines and "wl_mstpd=1" in lines
          and f"grep -qx \"$1\" {mstpd.RSTP_LIST}" in lines and "pidof mstpd" in lines and ".version" in lines)
    licensing = (root / "LICENSING.md").read_text(encoding="utf-8")
    check("LICENSING.md lists mstpd: GPL, built from source, the source shipped in the asset, fetched",
          "| mstpd and mstpctl (rapid spanning tree" in licensing and "GPL-2.0-or-later" in licensing
          and "yes, with the complete corresponding source" in licensing.split("| mstpd and mstpctl")[1].split("\n")[0])


def _rstp_ring():
    """A workbench lab with three switches in a ring (two uplinks into sw1
    and a spare cable), its dash, and the paths to put back."""
    import os
    from winlab import editor, images, netplan, paths, schema, workbench
    from winlab.model import CUSTOM
    saved = (paths.VAR, paths.STATE, paths.LABS, os.environ.get("WINLAB_IMAGES"), workbench._running)
    td = Path(tempfile.mkdtemp())
    paths.VAR, paths.STATE, paths.LABS = td / "var", td / "var" / "state", td / "labs"
    os.environ["WINLAB_IMAGES"] = str(td / "images")
    dest = editor.new_workbench("rstp-ring")
    lab = schema.load(dest)
    paths.downloads_dir().mkdir(parents=True, exist_ok=True)
    images.installer_path("win11").write_bytes(b"\0" * 2048)
    for n, c in (("sw1", "192.168.10.0/24"), ("sw2", "192.168.20.0/24"), ("sw3", "192.168.30.0/24")):
        editor.add_network(lab, n, cidr=c)
    for s in ("sw2", "sw3"):
        editor.set_routed(lab, s, False)
    for nid, net in (("pc01", "sw1"), ("pc02", "sw2"), ("pc03", "sw3")):
        editor.add_node(lab, nid, kind=CUSTOM, image="win11")
        editor.cable(lab, nid, 0, net)
    editor.save(lab)

    class _Dash:
        def reload(self):
            self.lab = schema.load(dest)
            self.plan = netplan.compile_topology(self.lab, check_ports=False)
    d = _Dash()
    d.reload()
    workbench._running = lambda _n: {"fabric"}
    workbench.act(d, "wb-cable", {"node": "switch", "network": "sw2", "to": "sw1"})
    workbench.act(d, "wb-cable", {"node": "switch", "network": "sw3", "to": "sw1"})
    workbench.act(d, "wb-stp-cable", {"a": "sw2", "b": "sw3"})
    d.reload()
    return d, saved, td


def _rstp_restore(saved, td):
    import os
    import shutil
    from winlab import paths, workbench
    paths.VAR, paths.STATE, paths.LABS = saved[:3]
    workbench._running = saved[4]
    if saved[3] is None:
        os.environ.pop("WINLAB_IMAGES", None)
    else:
        os.environ["WINLAB_IMAGES"] = saved[3]
    shutil.rmtree(td, ignore_errors=True)


def test_rstp_render_and_console():
    """rapid-pvst on the router: mstpd started and the bridges listed before
    they are made, each rapid bridge handed to mstpd with mstpctl (rstp, the
    priority, per port cost, priority, edge and BPDU guard) and the links set
    after; pvst alone keeps 802.1D and empties the list; a BPDU-guarded port
    is left for mstpd to shut; the consoles say what runs the tree, and show
    spanning-tree prints what mstpctl reports."""
    from unittest import mock
    from winlab import devcli, mstpd, stp
    d, saved, td = _rstp_ring()
    try:
        con = {s: devcli.Console(d, f"sw:{s}", runner_factory=lambda: (lambda *a, **k: "", "")) for s in ("sw1", "sw2", "sw3")}
        for c in con.values():
            c.run("enable")
            c.run("configure terminal")
        text = "\n".join(stp.render(d.plan))
        check("all pvst: the kernel's 802.1D, the RSTP list emptied, no mstpctl",
              f"rm -f {mstpd.RSTP_LIST}" in text and "mstpctl" not in text and "stp_state 1" in text, text[:300])
        with mock.patch.object(mstpd, "ready", lambda: False):
            out = con["sw1"].run("spanning-tree mode rapid-pvst")
        check("without mstpd fetched the console says rapid-pvst is 802.1D with short timers",
              "mstpd is not on the router yet" in out and "4 s forward delay" in out, out)
        with mock.patch.object(mstpd, "ready", lambda: True):
            out = con["sw2"].run("spanning-tree mode rapid-pvst")
            out3 = con["sw3"].run("spanning-tree mode rapid-pvst")
            mst = con["sw3"].run("spanning-tree mode mst")
        check("with mstpd fetched it says rapid spanning tree runs in mstpd", "runs in mstpd" in out and "802.1w" in out3, out)
        check("mst is taken now (winlab/mst.py) and says it runs in mstpd", "MSTP (802.1s)" in mst, mst)
        con["sw3"].run("spanning-tree mode rapid-pvst")
        con["sw1"].run("spanning-tree vlan 1 root primary")
        con["sw2"].run("interface gi0/2")
        con["sw2"].run("spanning-tree cost 19")
        con["sw2"].run("spanning-tree port-priority 64")
        con["sw2"].run("exit")
        d.reload()
        idx = {s: i for i, s in enumerate(devcli.switches(d.lab), 1)}
        names = stp.ifnames(d.lab)
        lines = stp.render(d.plan)
        text = "\n".join(lines)
        b1, b2 = f"stp{idx['sw1']}", f"stp{idx['sw2']}"
        start = text.index(f"printf '%s\\n' ")
        check("mstpd is started and the rapid bridges listed before any bridge is made",
              start < text.index(f"ip link add {b1} type bridge")
              and f"printf '%s\\n' stp1 stp2 stp3 > {mstpd.RSTP_LIST}" in text and mstpd.MSTPD in text, text[:900])
        g = names["sw2 GigabitEthernet0/2"]
        m = mstpd.MSTPCTL
        check("each rapid bridge is handed to mstpd only when the kernel gave it over (stp_state 2): rstp, priority",
              f'[ "$(cat /sys/class/net/{b2}/bridge/stp_state 2>/dev/null)" = 2 ]' in text
              and f"{m} addbridge {b2}" in text and f"{m} setforcevers {b2} rstp" in text
              and f"{m} settreeprio {b1} 0 6" in text and f"{m} settreeprio {b2} 0 8" in text)
        check("and per port: point-to-point, the cost and priority the console set, edge and BPDU guard",
              f"{m} setportp2p {b2} {g} yes" in text and f"{m} setportpathcost {b2} {g} 19" in text
              and f"{m} settreeportprio {b2} {g} 0 4" in text and f"{m} setportadminedge {b2} {g} no" in text
              and f"{m} setbpduguard {b2} {g} no" in text)
        check("the way into the router's bridge is an edge port", f"{m} setportadminedge {b1} {b1}fa yes" in text)
        check("the ports' links come up after mstpd has its bridges (BPDU guard sees the first BPDU)",
              text.index(f"{m} addbridge {b2}") < text.index(f"ip link set {g} up"))
        check("the kernel bridge keeps its fallback timers (4 s) in case mstpd is not there",
              "forward_delay 400" in text)

        # BPDU guard on sw1's port to sw2: mstpd shuts it itself, both ends are left up for it.
        con["sw1"].run("interface gi0/2")
        con["sw1"].run("spanning-tree portfast trunk")
        out = con["sw1"].run("spanning-tree bpduguard enable")
        d.reload()
        text = "\n".join(stp.render(d.plan))
        mine, far = names["sw1 GigabitEthernet0/2"], names["sw2 GigabitEthernet0/1"]
        check("BPDU guard on a port to a switch err-disables it (the console logs it)", "BLOCK_BPDUGUARD" in out, out)
        check("the router leaves the guarded port and its far end up for mstpd, down without it",
              f'if [ -n "$wl_mstpd" ]; then ip link set {mine} up; else ip link set {mine} down; fi' in text
              and f'if [ -n "$wl_mstpd" ]; then ip link set {far} up; else ip link set {far} down; fi' in text
              and f"{m} setbpduguard {b1} {mine} yes" in text and f"{m} setportadminedge {b1} {mine} yes" in text)

        # What the running router answers: mstpctl's roles and states.
        sample = (f"#stp\nB {b1} 2 6000.02574c 6000.02574c\nP {b1} {mine} 0\nM {b1} rstp\n"
                  f"R {b1} {mine} no Disabled discarding yes yes \n"
                  f"R {b1} {names['sw1 GigabitEthernet0/3']} yes Designated forwarding no no \n"
                  f"B {b2} 2 8000.02574c 8000.02574c\nM {b2} rstp\n"
                  f"R {b2} {names['sw2 GigabitEthernet0/2']} yes Root forwarding no no \n"
                  f"B stp3 2 8000.0 8000.0\nM stp3 rstp\n"
                  f"R stp3 {names['sw3 GigabitEthernet0/1']} yes Root forwarding no no \n"
                  f"R stp3 {names['sw3 GigabitEthernet0/2']} yes Alternate discarding no no \n"
                  "C cpu 1 0 1 100 0 0 0 0 0 0\n")
        live = stp.parse_live(sample)
        check("parse_live reads mstpd's protocol and each port's role, state, guard and edge",
              live["rstp"] == {b1: "rstp", b2: "rstp", "stp3": "rstp"}
              and live["roles"][mine] == {"bridge": b1, "enabled": False, "role": "Disabled", "state": "discarding",
                                          "guard_err": True, "edge": True}
              and live["roles"][names["sw3 GigabitEthernet0/2"]]["role"] == "Alternate")
        check("the live read asks mstpctl only for bridges mstpd runs",
              "stp_state)\" = 2 ]" in stp.LIVE_CMD and "mstpctl showportparams" in stp.LIVE_CMD
              and "bpdu-guard-error oper-edge-port" in stp.LIVE_CMD)
        lc = {s: devcli.Console(d, f"sw:{s}", runner_factory=lambda: ((lambda cmd, timeout=60: sample), ""))
              for s in ("sw1", "sw3")}
        for c in lc.values():
            c.powered = lambda: True
            c.run("enable")
        sh3 = lc["sw3"].run("show spanning-tree")
        check("show spanning-tree on a rapid switch: protocol rstp, mstpctl's roles and states, timers of RSTP",
              "Spanning tree enabled protocol rstp" in sh3 and "Root FWD" in sh3 and "Altn BLK" in sh3
              and "Forward Delay 15 sec" in sh3 and "as mstpctl reports them" in sh3, sh3)
        sh1 = lc["sw1"].run("show spanning-tree")
        check("a port mstpd shut for BPDU guard reads BKN* *BPDU_GUARD (err-disabled), Edge",
              "BKN*" in sh1 and "*BPDU_GUARD (err-disabled)" in sh1 and "Desg FWD" in sh1, sh1)
        ifc = lc["sw3"].run("show spanning-tree interface gi0/2")
        check("show spanning-tree interface reads mstpctl too", "Altn BLK" in ifc, ifc)
        check("cells in IOS's words", stp._rstp_cell({"enabled": True, "role": "Designated", "state": "learning",
                                                     "guard_err": False, "edge": False}) == ("Desg", "LRN")
              and stp._rstp_cell({"enabled": False, "role": "Disabled", "state": "discarding",
                                  "guard_err": False, "edge": False}) == ("Disa", "DIS"))
        with mock.patch.object(mstpd, "ready", lambda: True):
            off = con["sw2"].run("do show spanning-tree")
        check("router off, mstpd fetched: worked out by winlab, and it says so",
              "protocol rstp" in off and "until the router runs" in off and "Forward Delay 15 sec" in off, off)
        with mock.patch.object(mstpd, "ready", lambda: False):
            off = con["sw2"].run("do show spanning-tree")
        check("router off, no mstpd: the honest kernel note and the kernel's 4 s", stp.KERNEL_NOTE in off
              and "Forward Delay 4 sec" in off, off)
    finally:
        _rstp_restore(saved, td)






# ---- android: a company phone (winlab/android.py) and Headwind MDM (winlab/hmdm.py)
def _test_apk(path, package):
    """A minimal APK: a zip whose binary AndroidManifest.xml names `package`."""
    import struct
    import zipfile

    strings = ["package", "manifest", package]
    data = b""
    offsets = []
    for st in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(st)) + st.encode("utf-16-le") + b"\0\0"
    while len(data) % 4:
        data += b"\0"
    hs = 28
    start = hs + 4 * len(strings)
    pool = struct.pack("<HHIIIIII", 0x0001, hs, start + len(data), len(strings), 0, 0, start, 0)
    pool += struct.pack(f"<{len(strings)}I", *offsets) + data
    attr = struct.pack("<IIIHBBI", 0xFFFFFFFF, 0, 2, 8, 0, 0x03, 2)
    ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, 1, 20, 20, 1, 0, 0, 0) + attr
    tag = struct.pack("<HHIII", 0x0102, 16, 16 + len(ext), 1, 0xFFFFFFFF) + ext
    body = pool + tag
    xml = struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", xml)
        z.writestr("classes.dex", b"dex\n035\0")
    return path



# ---- vendor Wi-Fi lessons (wireless-vendors lab, winlab/wifivendors.py)
WIFI_VENDOR_LESSONS = {
    "wifi-ruckus-unleashed": (600, "wifi-ruckus-unleashed", "ruckus01"),
    "wifi-aruba-instant": (601, "wifi-aruba-instant", "aruba01"),
    "wifi-mikrotik-routeros": (602, "wifi-mikrotik-routeros", "mikrotik01"),
    "wifi-cisco-ewc": (603, "wifi-cisco-ewc", "ewc01"),
    "wifi-wlc-ap-join": (604, "wifi-wlc-ap-join", "wlc01"),
    "wifi-wlc-wlans-tags": (605, "wifi-wlc-wlans-tags", "wlc01"),
    "wifi-channel-plan-roaming": (606, "wifi-channel-plan", "wlc01"),
    "wifi-unifi-controller": (607, "wifi-unifi-controller", "ctl01"),
    "wifi-openwisp-openwrt": (608, "wifi-openwisp-openwrt", "wisp01"),
    "wifi-enterprise-aruba": (609, "wifi-enterprise-aruba", "aruba01"),
}
WIFI_VENDOR_PROBLEMS = {
    "ts-wlc-wlan-not-in-tag": (1000, "wlc-wlan-not-in-tag", "wlc01"),
    "ts-lap-cannot-find-wlc": (1001, "lap-cannot-find-wlc", "cap02"),
    "ts-ewc-config-lost-on-reload": (1002, "ewc-config-lost-on-reload", "ewc01"),
    "ts-aruba-not-committed": (1003, "aruba-change-not-committed", "aruba01"),
    "ts-wifi-radius-secret-wrong": (1004, "wifi-radius-secret-wrong", "aruba01"),
}


class _ApBench:
    """Vendor APs (winlab/apos) in folders on this PC, each as its own root,
    and a way to run a check or a ticket's script on one of them the way
    the device's console runs it: sh, with python3 importing apos from the
    folder the AP keeps it in."""

    def __init__(self, td: str):
        import os
        self.td = td
        self.lib = Path(td, "lib")
        self.lib.mkdir()
        os.symlink(str(Path(__file__).resolve().parent.parent / "winlab" / "apos"), str(self.lib / "apos"))
        self.roots: dict[str, str] = {}

    def add(self, name: str, vendor: str, ip: str, mac: str, mask: str = "255.255.255.0") -> str:
        import json as _json
        from winlab.apos import core
        r = Path(self.td, name)
        for d in ("etc/winlab-ap", "etc/config", "tmp"):
            (r / d).mkdir(parents=True, exist_ok=True)
        (r / "etc/winlab-ap/ident.json").write_text(_json.dumps({"vendor": vendor, "mac": mac, "domain": "corp.lab"}))
        (r / "etc/config/network").write_text(f"config interface 'lan'\n\toption ipaddr '{ip}'\n\toption netmask '{mask}'\n")
        self.roots[name] = str(r)
        self.at(name)
        core.factory_reset()
        return str(r)

    def at(self, name: str) -> None:
        from winlab.apos import core
        core.ROOT, core.LIVE = self.roots[name], False

    def cli(self, name: str, lines: list[str]) -> str:
        from winlab.apos import core, term, vendors
        self.at(name)
        t = term.Term(lines)
        vendors.module(core.ident()["vendor"]).cli(t)
        return t.text()

    def sh(self, name: str, script: str, env: dict | None = None) -> str:
        import os
        import subprocess
        e = dict(os.environ, APOS_ROOT=self.roots.get(name, self.td), **(env or {}))
        e.pop("PYTHONPATH", None)
        r = subprocess.run(["sh", "-c", script], cwd=str(self.lib), env=e, capture_output=True, text=True, timeout=60)
        return r.stdout.strip()


def _grade_here(ex, bench: "_ApBench", env: dict | None = None) -> dict[str, tuple[bool, str]]:
    """Each sh check of an exercise run on the bench's device of its node;
    {check name: (passed, output)}. Checks on other machines are skipped."""
    from winlab import exercises
    out = {}
    for c in ex.checks:
        if c.shell != "sh" or "systemctl" in c.script or (c.node not in bench.roots
                                                           and c.node not in (env or {}).get("_nodes", ())):
            continue
        got = bench.sh(c.node, c.script, {k: v for k, v in (env or {}).items() if not k.startswith("_")})
        out[c.name] = (exercises.output_matches(c, got), got)
    return out







def _gap8_tools():
    sys.path.insert(0, str(Path("tools").resolve()))
    try:
        import i18n_lessons
        import i18n_content
    finally:
        sys.path.pop(0)
    return i18n_lessons, i18n_content




_GAP8_THIN = ("promote-first-dc", "defender-antivirus", "bitlocker-auto-unlock",
              "azure-peering-hub-spoke", "aws-cost-tags-budget", "aidc-share-the-gpus")








# ---- console-l2: private VLANs, storm control, RA/DHCPv6 guard (winlab/l2sec.py), IPv6 ACLs (winlab/acl6.py), MST (winlab/mst.py)
_L2_LESSONS = {"private-vlans": (650, "campus-vlans"), "storm-control": (652, "switch-security"),
               "mst-regions": (654, "campus-vlans"), "ipv6-acls-router": (656, "router-protocols"),
               "ipv6-ra-guard": (658, "switch-security")}
_L2_TICKETS = {"ts-storm-control-errdisabled": (1020, "storm-control-errdisabled", "switch-security", "nas01"),
               "ts-pvlan-wrong-community": (1022, "pvlan-wrong-community", "campus-vlans", "pc-b"),
               "ts-ipv6-acl-blocks-nd": (1024, "ipv6-acl-blocks-nd", "router-protocols", "pc-guest"),
               "ts-ra-guard-uplink": (1026, "ra-guard-uplink", "router-protocols", "pc-office")}


class _L2Env(_NetcoreEnv):
    """_NetcoreEnv with switch-security too."""

    def __enter__(self):
        import shutil
        super().__enter__()
        shutil.copy(self.saved[0] / "switch-security.toml", self.td / "labs" / "switch-security.toml")
        return self


def _l2_nft_check(text):
    """nft -c on every table a render feeds nft (where nft runs): [] or the errors."""
    import re
    import shutil
    import subprocess
    if not shutil.which("nft"):
        return []
    bad = []
    for b in re.findall(r"nft -f - <<'(?:WINLAB_EOF|WLACL6)'(?: \|\| true)?\n(.*?)\n(?:WINLAB_EOF|WLACL6)", text, re.S):
        r = subprocess.run(["nft", "-c", "-f", "-"], input=b, text=True, capture_output=True)
        if r.returncode != 0 and "Operation not permitted" not in r.stderr:
            bad.append(r.stderr[:300])
    return bad


















def _l3_console(d, answers=None, ran=None):
    """A console on the router-protocols lab's router whose runner answers
    from a dict of {substring: text or callable} (the first that matches)."""
    from winlab import devcli

    def runner_factory():
        def run(cmd, timeout=60):
            if ran is not None:
                ran.append(cmd)
            for k, v in (answers or {}).items():
                if k in cmd:
                    return v() if callable(v) else v
            return ""
        return run, ""
    con = devcli.Console(d, "router", runner_factory=runner_factory)
    con.powered = lambda: True
    return con


def _nft_body(script: str, table: str) -> str:
    for body in re.findall(r"nft -f - <<'EOF' \|\| true\n(.*?)\nEOF", script, re.S):
        if body.startswith(f"table ip {table}"):
            return body
    return ""


_NS_POOL = r'''
import fcntl, json, re, socket, struct, subprocess, sys
fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8914, struct.pack("16sH14s", b"lo", 0x1 | 0x8, b""))
body = sys.stdin.read()
body = body.replace("10.80.0.0/24", "127.0.0.0/8")
body = re.sub(r'iifname (\{[^}]*\}|"[^"]*") oifname (\{[^}]*\}|"[^"]*") jump', 'oifname "lo" jump', body, count=1)
r = subprocess.run(["nft", "-f", "-"], input=body, text=True, capture_output=True)
if r.returncode:
    print(json.dumps({"load": r.stderr})); sys.exit(0)
sent = {}
for i in (10, 11, 12, 13):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((f"127.0.0.{i}", 40000 + i))
    try:
        s.sendto(b"x", ("127.0.0.1", 9)); sent[i] = "sent"
    except OSError as e:
        sent[i] = e.strerror
    s.close()
listing = subprocess.run(["nft", "list", "table", "ip", "wlnat"], capture_output=True, text=True).stdout
checks = [subprocess.run(["sh", "-c", c], capture_output=True, text=True).stdout.strip() for c in sys.argv[1:]]
print(json.dumps({"sent": sent, "list": listing, "checks": checks}))
'''






def test_l3_ospf_ntp_auth():
    """OSPF authentication (per interface, per area, key chains) and NTP
    authentication at the console: show running-config, FRRouting's
    configuration, chrony's key file and server line, and show ntp
    associations detail from chrony's own answers."""
    from winlab import iosrouting, ntpauth, paths, workbench
    root = Path(__file__).resolve().parent.parent
    saved = (paths.VAR, paths.STATE, paths.LABS, workbench._running)
    with tempfile.TemporaryDirectory() as td:
        try:
            d = _router_console_dash(root, Path(td))
            vid = lambda n: d.plan.segment_of(n).svi  # noqa: E731
            answers = {"authdata": "Name/IP address             Mode KeyID Type KLen Last Atmp  NAK Cook CLen\n"
                                   "=========================================================================\n"
                                   "10.20.0.123                   SK     1  MD5  128    7    0    0    0    0\n"
                                   "#src\n^* 10.20.0.123                   3   6   377    12   +20us[  +25us] +/-  1ms\n"}
            con = _l3_console(d, answers)
            say = con.run
            for line in ("en", "conf t", "key chain OSPF", "key 1", "key-string Own-key-1",
                         "cryptographic-algorithm hmac-sha-256", "exit", "exit", "router ospf 1",
                         "network 10.80.0.0 0.0.0.255 area 0", "area 0 authentication message-digest", "exit",
                         "int g0/1/0", "ip ospf message-digest-key 1 md5 Own-key-2",
                         "ip ospf authentication message-digest", "int g0/0/0", "ip ospf authentication key-chain OSPF",
                         "exit", "ntp authentication-key 1 md5 Own-key-3", "ntp trusted-key 1",
                         "ntp server 10.20.0.123 key 1", "ntp authenticate", "end"):
                out = say(line)
                check(f"'{line}' is taken", not out.startswith("%") or line == "end", out)
            run = say("show running-config")
            check("show running-config: the key chain, the interface keys, area authentication, NTP's four lines",
                  "key chain OSPF\n key 1\n  key-string Own-key-1\n  cryptographic-algorithm hmac-sha-256" in run
                  and " ip ospf authentication message-digest\n ip ospf message-digest-key 1 md5 Own-key-2" in run
                  and " ip ospf authentication key-chain OSPF" in run and " area 0 authentication message-digest" in run
                  and "ntp authenticate" in run and "ntp trusted-key 1" in run and "ntp server 10.20.0.123 key 1" in run
                  and re.search(r"ntp authentication-key 1 md5 [0-9A-F]+ 7", run), run)
            check("the NTP key is shown scrambled (type 7), as IOS does, never in clear",
                  "Own-key-3" not in run)
            frr = iosrouting.frr_conf(d.plan)
            check("FRRouting's ospfd gets the chain, the interface keys and the area's authentication",
                  "key chain OSPF\n key 1\n  key-string Own-key-1\n  cryptographic-algorithm hmac-sha-256" in frr
                  and f"interface {vid('office')}\n ip ospf authentication message-digest\n"
                      f" ip ospf message-digest-key 1 md5 Own-key-2" in frr
                  and f"interface {vid('guest')}\n ip ospf authentication key-chain OSPF" in frr
                  and "area 0 authentication message-digest" in frr, frr)
            keyfile = ntpauth.keyfile_text(d.lab)
            check("chrony's key file holds key 1 as MD5, hex-encoded", keyfile.strip() == "1 MD5 HEX:" + b"Own-key-3".hex().upper(),
                  keyfile)
            lines = ntpauth.chrony_lines(d.lab, ["10.20.0.123"])
            check("chrony: the key file, authselectmode require, the server signed with key 1",
                  "authselectmode require" in lines and "server 10.20.0.123 iburst key 1" in lines
                  and any(x.startswith("keyfile ") for x in lines), str(lines))
            out = say("show ntp associations detail")
            check("show ntp associations detail: authenticated and selected, key 1 in use",
                  "10.20.0.123 configured, ipv4, authenticated, our_master" in out and "key id 1 (in use)" in out
                  and "Authentication required" in out, out)
            answers["authdata"] = answers["authdata"].replace("^* 10.20.0.123", "^? 10.20.0.123")
            out = say("show ntp associations detail")
            check("a signing source that never answered usably is not authenticated",
                  "not authenticated, unreachable" in out, out)
            say("conf t")
            say("no ntp trusted-key 1")
            say("end")
            check("an untrusted key is not used", "not defined or not trusted" in say("show ntp associations detail")
                  and "key 1" not in "\n".join(ntpauth.chrony_lines(d.lab, ["10.20.0.123"])))
            check("chronyc authdata is read per source", ntpauth.parse_authdata(answers["authdata"].split("#src")[0])
                  == {"10.20.0.123": {"mode": "SK", "key": 1}})
            say("conf t")
            say("int g0/1/0")
            say("no ip ospf authentication")
            say("no ip ospf message-digest-key 1")
            say("end")
            frr = iosrouting.frr_conf(d.plan)
            check("no ip ospf authentication and no ... message-digest-key take the lines away",
                  "Own-key-2" not in frr and "Own-key-2" not in say("show running-config"))
        finally:
            paths.VAR, paths.STATE, paths.LABS, workbench._running = saved


def test_l3_glbp():
    """winlab-glbpd, winlab's own GLBP speaker: its packets both ways, the
    AVG election, forwarders handed out round-robin by ARP, a dead member's
    virtual MAC taken over and given back, its configuration and check; and
    glbp at the router's console: show running-config, the file the
    router's speaker reads, the refusals, one group per virtual address."""
    import json
    from winlab import debpacks, glbpd, iosglbp, paths, workbench
    msg = glbpd.decode(glbpd.encode(1, "52:54:00:00:00:02",
                                    {"state": "Active", "prio": 110, "hello": 3, "hold": 10, "vip": "10.80.0.1"},
                                    [{"fwd": 1, "state": "Active", "owner": "52:54:00:00:00:02", "vmac": glbpd.vmac(1, 1)}],
                                    auth="lab"))
    check("a GLBP packet decodes back: group, hello, forwarder, plain-text authentication",
          msg and msg["group"] == 1 and msg["hello"]["vip"] == "10.80.0.1" and msg["hello"]["prio"] == 110
          and msg["fwds"][0]["vmac"] == "00:07:b4:00:01:01" and msg["auth"] == "lab", str(msg))
    check("virtual MACs are 0007.b400.XXYY", glbpd.cisco_mac(glbpd.vmac(1, 2)) == "0007.b400.0102")
    check("a frame that is not GLBP is refused", glbpd.decode(b"\x02" + b"\0" * 40) is None)
    wire: list = []

    def mk(ip, mac, prio, preempt=False):
        cfg = glbpd.parse_conf(f"interface eth1\n glbp 1 ip 10.80.0.1\n glbp 1 priority {prio}\n"
                               + (" glbp 1 preempt\n" if preempt else ""))[0]
        g = glbpd.Group(cfg, mac, log=lambda t: None)
        g.send = lambda p, ip=ip: wire.append((ip, p))
        g.forward = lambda m, on: None
        return g
    a = mk("10.80.0.2", "52:54:00:00:00:02", 110, True)
    b = mk("10.80.0.3", "52:54:00:00:00:03", 100)
    routers = {"10.80.0.2": a, "10.80.0.3": b}
    alive = set(routers)
    clock = [0.0]

    def run(secs):
        for _ in range(int(secs * 10)):
            clock[0] += 0.1
            for ip, g in routers.items():
                if ip in alive:
                    g.tick(clock[0])
            while wire:
                src, p = wire.pop(0)
                m = glbpd.decode(p)
                for ip, g in routers.items():
                    if ip != src and ip in alive and src in alive:
                        g.receive(m, src, clock[0])
    a.start("10.80.0.2", 0.0)
    b.start("10.80.0.3", 0.0)
    run(30)
    check("priority 110 is the AVG, the other the Standby VG; each forwards for its own virtual MAC",
          a.state == "Active" and b.state == "Standby" and a.mine == {1} and b.mine == {2}, f"{a.state} {b.state} {a.mine} {b.mine}")
    macs = [a.arp(f"aa:bb:cc:00:00:{i:02x}", clock[0]) for i in range(4)]
    check("round-robin: the AVG answers ARP with each forwarder's MAC in turn",
          set(macs) == {"00:07:b4:00:01:01", "00:07:b4:00:01:02"} and macs[0] != macs[1], str(macs))
    check("only the AVG answers ARP for the virtual address", not b.arp("aa:bb:cc:00:00:09", clock[0]))
    alive.discard("10.80.0.2")
    run(15)
    check("the AVG dies: the other takes over the group and both virtual MACs",
          b.state == "Active" and b.mine == {1, 2}, f"{b.state} {b.mine}")
    alive.add("10.80.0.2")
    a.stop(clock[0])
    a.start("10.80.0.2", clock[0])
    run(30)
    check("it comes back: preempt makes it the AVG again and forwarder 2 goes home",
          a.state == "Active" and b.state == "Standby" and a.mine == {1} and b.mine == {2})
    brief = glbpd.show_brief([a.status(clock[0])])
    check("show glbp brief: the group row and one row per forwarder",
          re.search(r"eth1\s+1\s+-\s+110\s+Active\s+10\.80\.0\.1\s+local\s+10\.80\.0\.3", brief)
          and "0007.b400.0102" in brief, brief)
    try:
        glbpd.parse_conf("interface eth1\n glbp 1 load-balancing random\n")
        bad = False
    except glbpd.ConfError:
        bad = True
    check("the speaker's configuration refuses what it does not know", bad)
    tools = debpacks.own_tools("frr")
    check("the frr stick carries winlab-glbpd, its unit and GLBP.txt (winlab's own code, nothing fetched)",
          {"winlab-glbpd", "winlab-glbpd.service", "GLBP.txt"} <= set(tools)
          and b"winlab-glbpd" in tools["winlab-glbpd.service"])
    root = Path(__file__).resolve().parent.parent
    saved = (paths.VAR, paths.STATE, paths.LABS, workbench._running)
    with tempfile.TemporaryDirectory() as td:
        try:
            d = _router_console_dash(root, Path(td))
            vid = lambda n: d.plan.segment_of(n).svi  # noqa: E731
            st = {"groups": [dict(a.status(clock[0]), iface=vid("office"))]}
            con = _l3_console(d, {"winlab-glbp.json": lambda: json.dumps(st) + "\n#running"})
            say = con.run
            for line in ("en", "conf t", "int g0/1/0", "glbp 1 ip 10.80.0.1", "glbp 1 priority 110", "glbp 1 preempt",
                         "glbp 1 load-balancing round-robin"):
                out = say(line)
                check(f"'{line}' is taken", not out.startswith("%"), out)
            check("glbp weighting track is refused with its reason", "not in this router" in say("glbp 1 weighting track 3"))
            check("a second protocol on the same virtual address is refused",
                  "already the virtual address of GLBP group 1" in say("standby 1 ip 10.80.0.1"))
            say("end")
            run = say("show running-config")
            check("show running-config keeps the group under its interface",
                  "interface GigabitEthernet0/1/0\n ip address 10.80.0.2 255.255.255.0\n glbp 1 ip 10.80.0.1\n"
                  " glbp 1 priority 110\n glbp 1 preempt" in run, run)
            conf = iosglbp.conf_text(d.plan)
            check("the router's speaker reads the same lines under its Linux interface",
                  f"interface {vid('office')}\n glbp 1 ip 10.80.0.1\n glbp 1 priority 110\n glbp 1 preempt" in conf
                  and glbpd.parse_conf(conf)[0]["prio"] == 110, conf)
            out = say("show glbp brief")
            check("show glbp brief at the console reads the speaker's state with IOS names",
                  re.search(r"Gi0/1/0\s+1\s+-\s+110\s+Active\s+10\.80\.0\.1\s+local", out), out)
        finally:
            paths.VAR, paths.STATE, paths.LABS, workbench._running = saved


_L3_ISIS_NBR = """Area winlab:
 rtr-edge
    Interface: {office}, Level: 1, State: Up, Expires in 28s
    Adjacency flaps: 1, Last: 2m1s ago
    Circuit type: L1L2, Speaks: IPv4
    SNPA: 5254.0012.3456, LAN id: rtr-edge.01
    Area Address(es):
      49.0001
    IPv4 Address(es):
      10.80.0.3

 rtr-edge
    Interface: {office}, Level: 2, State: Up, Expires in 27s
    Adjacency flaps: 1, Last: 2m1s ago
    Circuit type: L1L2, Speaks: IPv4
    SNPA: 5254.0012.3456, LAN id: rtr-edge.01
    Area Address(es):
      49.0001
    IPv4 Address(es):
      10.80.0.3
"""

_L3_ISIS_RT = """Area winlab:
IS-IS L1 IPv4 routing table:

 Prefix          Metric  Interface  Nexthop    Label(s)
 ---------------------------------------------------------
 10.81.0.0/24    20      {office}   10.80.0.3  -
"""


def test_l3_pim_isis():
    """Multicast (FRRouting's pimd) and IS-IS (isisd) at the console:
    show running-config, frr.conf and the daemons file, IOS's warning and
    refusals, the shows read from pimd's JSON and isisd's text, i L1 in
    show ip route, and what goes back when the lines are taken away."""
    import json
    from winlab import iosisis, iospim, iosrouting, paths, workbench
    check("NETs: area, system ID, the 00 selector", iosisis.valid_net("49.0001.0000.0000.0002.00")
          and iosisis.area_of("49.0001.0000.0000.0002.00") == "49.0001"
          and iosisis.system_id("49.0001.0000.0000.0002.00") == "0000.0000.0002"
          and not iosisis.valid_net("49.0001.0000.0000.0002.01") and not iosisis.valid_net("10.80.0.0"))
    root = Path(__file__).resolve().parent.parent
    saved = (paths.VAR, paths.STATE, paths.LABS, workbench._running)
    with tempfile.TemporaryDirectory() as td:
        try:
            d = _router_console_dash(root, Path(td))
            vid = lambda n: d.plan.segment_of(n).svi  # noqa: E731
            office, guest = vid("office"), vid("guest")
            fill = {"office": office}
            mr = {"239.1.1.1": {"*": {"installed": 1, "iif": "pimreg", "oil": {office: {
                      "outboundInterface": office, "protocolIgmp": 1, "upTime": "00:00:41"}}},
                  "10.80.20.10": {"installed": 1, "iif": guest, "oil": {office: {
                      "outboundInterface": office, "protocolPim": 1, "upTime": "00:00:30"}}}}}
            answers = {
                "pim neighbor json": json.dumps({office: {"10.80.0.3": {"interface": office, "neighbor": "10.80.0.3",
                                                                        "upTime": "00:02:10", "holdTime": "00:01:35",
                                                                        "drPriority": 1}}}),
                "pim interface json": json.dumps({office: {"address": "10.80.0.2", "state": "up",
                                                           "pimDesignatedRouter": "10.80.0.3", "pimNeighbors": 1}}),
                "mroute json": json.dumps(mr),
                "igmp groups json": json.dumps({"totalGroups": 1, office: {"groups": [
                    {"group": "239.1.1.1", "timer": "00:04:01", "uptime": "00:00:41", "version": 2}]}}),
                "isis neighbor detail": _L3_ISIS_NBR.format(**fill),
                "show isis route": _L3_ISIS_RT.format(**fill),
                "show ip route json": json.dumps({"10.81.0.0/24": [
                    {"prefix": "10.81.0.0/24", "protocol": "isis", "selected": True, "distance": 115, "metric": 20,
                     "uptime": "00:01:02", "nexthops": [{"ip": "10.80.0.3", "interfaceName": office, "active": True}]}]}),
            }
            con = _l3_console(d, answers)
            say = con.run
            for line in ("en", "conf t", "access-list 10 permit 239.1.1.0 0.0.0.255", "int g0/1/0"):
                say(line)
            check("ip pim sparse-mode before ip multicast-routing: IOS's warning",
                  'WARNING: "ip multicast-routing" is not configured' in say("ip pim sparse-mode"))
            check("dense mode is refused: pimd is sparse mode only", "sparse mode only" in say("ip pim dense-mode"))
            for line in ("int g0/0/0", "ip pim sparse-mode", "exit", "ip multicast-routing", "ip pim rp-address 10.80.0.2 10",
                         "int g0/1/0", "ip igmp version 3", "exit", "router isis", "net 49.0001.0000.0000.0002.00",
                         "metric-style wide", "passive-interface g0/0/1", "log-adjacency-changes", "exit",
                         "int g0/1/0", "ip router isis", "isis metric 30"):
                out = say(line)
                check(f"'{line}' is taken", not out.startswith("%") and "Invalid" not in out, out)
            check("a NET that does not end in 00 is refused", say("router isis") == "" and
                  say("net 49.0001.0000.0000.0002.01").startswith("%"))
            check("redistribute under router isis is refused with its reason", "not in this router" in say("redistribute static"))
            check("'net 10.80.0.0 ...' under router ospf is still network (the abbreviation is not stolen)",
                  (say("exit"), say("router ospf 1"), say("net 10.80.0.0 0.0.0.255 area 0"))[2] == ""
                  and "network 10.80.0.0 0.0.0.255 area 0" in say("do show running-config"))
            say("no router ospf 1")
            say("end")
            run = say("show running-config")
            check("show running-config: multicast routing, PIM and IGMP per interface, the RP with its ACL, IS-IS",
                  "ip multicast-routing\n" in run and " ip pim sparse-mode\n ip igmp version 3\n ip router isis\n isis metric 30" in run
                  and "ip pim rp-address 10.80.0.2 10" in run
                  and "router isis\n net 49.0001.0000.0000.0002.00\n metric-style wide\n log-adjacency-changes\n"
                      " passive-interface GigabitEthernet0/0/1" in run, run)
            frr = iosrouting.frr_conf(d.plan)
            check("frr.conf: pimd's RP for the ACL's range, ip pim and igmp version per interface",
                  "ip pim rp 10.80.0.2 239.1.1.0/24" in frr
                  and f"interface {office}\n ip pim\n ip igmp\n ip igmp version 3" in frr
                  and f"interface {guest}\n ip pim\n ip igmp" in frr, frr)
            check("frr.conf: isisd's router (IOS's narrow default written out where asked), the interfaces, the passive one",
                  "router isis winlab\n net 49.0001.0000.0000.0002.00\n is-type level-1-2\n metric-style wide" in frr
                  and f"interface {office}\n ip router isis winlab\n isis metric 30" in frr
                  and f"interface {vid('isp-link')}\n ip router isis winlab\n isis passive" in frr, frr)
            daemons = iosrouting.daemons_file(d.lab.devices["router"])
            check("the daemons file starts pimd and isisd", "pimd=yes" in daemons and "isisd=yes" in daemons, daemons)
            out = say("show ip pim neighbor")
            check("show ip pim neighbor from pimd's JSON, with IOS's names",
                  re.search(r"10\.80\.0\.3\s+Gi0/1/0\s+00:02:10/00:01:35 v2\s+1 / DR", out), out)
            out = say("show ip pim rp mapping")
            check("show ip pim rp mapping: the ACL's range, the static RP", "Group(s): 239.1.1.0/24, Static (ACL 10)" in out
                  and "RP: 10.80.0.2" in out, out)
            out = say("show ip mroute")
            check("show ip mroute: (*,G) from the RP (Null upstream) and (S,G) in on the guest interface",
                  "(*, 239.1.1.1), 00:00:41/stopped, RP 10.80.0.2, flags: SC" in out
                  and "Incoming interface: Null, RPF nbr 0.0.0.0" in out
                  and "(10.80.20.10, 239.1.1.1)" in out and "Incoming interface: Gi0/0/0" in out
                  and "Gi0/1/0, Forward/Sparse" in out, out)
            check("show ip igmp groups", re.search(r"239\.1\.1\.1\s+Gi0/1/0\s+00:00:41\s+00:04:01", say("show ip igmp groups")))
            out = say("show isis neighbors")
            check("show isis neighbors: one row, L1L2 from the two adjacencies, UP",
                  re.search(r"rtr-edge\s+L1L2\s+Gi0/1/0\s+10\.80\.0\.3\s+UP", out)
                  and sum(x.startswith("rtr-edge") for x in out.splitlines()) == 1, out)
            out = say("show ip route")
            check("show ip route: i L1 at distance 115 and the IS-IS codes",
                  "i L1     10.81.0.0/24 [115/20] via 10.80.0.3" in out and "L1 - IS-IS level-1" in out, out)
            check("show ip protocols names IS-IS", 'Routing Protocol is "isis"' in say("show ip protocols"))
            check("the neighbour parser keeps level and state", [(n["level"], n["state"]) for n in
                  iosisis.parse_neighbors(_L3_ISIS_NBR.format(**fill))] == [(1, "Up"), (2, "Up")])
            say("conf t")
            say("no ip multicast-routing")
            say("no router isis")
            say("end")
            frr = iosrouting.frr_conf(d.plan)
            daemons = iosrouting.daemons_file(d.lab.devices["router"])
            check("without multicast routing pimd stops; without router isis isisd does",
                  "pimd=no" in daemons and "isisd=no" in daemons and "router isis" not in frr
                  and "ip pim rp" not in frr, daemons)
        finally:
            paths.VAR, paths.STATE, paths.LABS, workbench._running = saved















# ---- gapx-selftest ----
# The self-test (winlab/selftest.py) with fake machines, and the worked
# solutions every exercise must have (content/solutions, winlab/solutions.py).
# Exercises whose solutions are still being written (other builders' lists):
# reported as skipped, not failed. Temporary: shrinks to nothing as they land.
PENDING_SOLUTIONS = frozenset()




# ---- gapx-capstones ----
_CAPSTONES = {"capstone-network": ("capstone-network", 20, "network-services", "network"),
              "capstone-linux": ("capstone-linux", 30, "linux", "linux"),
              "capstone-cloud": ("capstone-cloud", 40, "hybrid-cloud", "cloud"),
              "capstone-security": ("security-ops", 50, "security", "security"),
              "capstone-helpdesk": ("capstone-helpdesk", 60, "endpoint", "helpdesk")}




# ---- gapx-small-lessons ----


# ---- gapx-quiz-review ----
def test_gapx_quiz_review():
    """Every lesson asks at least three recall questions, in every language,
    and the questions of finished lessons come back on a spaced schedule
    (winlab/review.py): Leitner boxes 1, 3, 7, 14, 30, 60 days, a wrong
    answer back tomorrow, at most twenty a day, kept in var/review.json,
    carried in the .wlprogress file, shown in the Learn window and by
    `winlab learn review`."""
    import contextlib
    import datetime as dt
    import io
    import json
    import subprocess
    import time
    import tomllib
    from winlab import cli, i18n, lessons, paths, progress, progressfile, review, schema, webui

    # --- three recall questions everywhere --------------------------------
    allx = lessons.list_available()
    few = [l.id for l in allx if len(l.quiz) < 3]
    check("every lesson has at least three recall questions", not few, ", ".join(few[:10]))
    check("learn check asks for three", "fewer than three recall questions" in Path("winlab/lessons.py").read_text(encoding="utf-8")
          and not [p for p in lessons.validate_all() if "recall questions" in p])
    odd = [l.id for l in allx if any(len(q.wrong) != len(l.quiz[0].wrong) or q.answer in q.wrong or not q.why.strip()
                                     or len(set(q.wrong)) != len(q.wrong) for q in l.quiz[-1:])]
    check("each lesson's last question: as many wrong answers as its first, the answer apart, a why", not odd, str(odd[:5]))
    short = []
    for lang in ("es", "he", "ar"):
        for l in allx:
            f = Path("content/i18n/lessons", lang, f"{l.id}.json")
            if not f.is_file():
                continue
            tq = json.loads(f.read_text(encoding="utf-8")).get("quiz") or []
            raw = tomllib.loads(Path("content/lessons", f"{l.id}.toml").read_text(encoding="utf-8"))["quiz"]
            if len(tq) != len(raw) or any(len(a.get("wrong") or []) != len(b["wrong"]) for a, b in zip(tq, raw)):
                short.append(f"{lang}/{l.id}")
    check("every translated lesson has every question, with as many wrong answers", not short, str(short[:5]))
    bidi = re.compile("[‎‏‪-‮⁦-⁩]")
    marked = [str(f) for f in Path("content/i18n/lessons").glob("*/*.json") if bidi.search(f.read_text(encoding="utf-8"))]
    check("no direction marks in the lesson translations", not marked, str(marked[:3]))
    for lang in ("es", "he", "ar"):
        r = subprocess.run([sys.executable, "tools/i18n_lessons.py", "check", lang], capture_output=True, text=True)
        check(f"i18n_lessons check {lang} is clean", r.returncode == 0 and not r.stdout.strip(), r.stdout[:300])

    # --- the schedule ----------------------------------------------------
    D = dt.date(2026, 3, 2)
    c = review.new_card(time.mktime((2026, 3, 1, 12, 0, 0, 0, 0, -1)))
    check("a question enters review the day after its lesson, in box 0",
          c["box"] == 0 and c["due"] == "2026-03-02" and c["right"] == c["wrong"] == 0)
    seen = []
    day = D
    for _ in range(8):
        c = review.schedule(c, True, day)
        seen.append(c["box"])
        nd = dt.date.fromisoformat(c["due"])
        seen.append((nd - day).days)
        day = nd
    check("right answers climb the boxes: 1, 3, 7, 14, 30 days, then every 60",
          seen == [1, 1, 2, 3, 3, 7, 4, 14, 5, 30, 6, 60, 6, 60, 6, 60] and c["right"] == 8, str(seen))
    w = review.schedule(c, False, D)
    check("a wrong answer goes back to box 0, due tomorrow",
          w["box"] == 0 and w["due"] == "2026-03-03" and w["wrong"] == 1 and w["last"] == "2026-03-02")
    allc = {"a#0": {"box": 2, "due": "2026-03-01"}, "b#0": {"box": 0, "due": "2026-03-01"},
            "c#0": {"box": 0, "due": "2026-02-20"}, "d#0": {"box": 0, "due": "2026-03-05"}}
    check("due questions: the longest-waiting first, then the lower box; nothing from the future",
          review.due_keys(allc, D) == ["c#0", "b#0", "a#0"])
    prog = {"lessons": {f"l{i:02d}": {"status": progress.STATUS_DONE, "passed_at": time.mktime((2026, 2, 1, 9, 0, 0, 0, 0, -1))}
                        for i in range(10)}}
    prog["lessons"]["open"] = {"status": "in_progress"}
    sizes = {f"l{i:02d}": 3 for i in range(10)}
    sizes["open"] = 3
    st0 = review.clean({})
    s = review.status(D, st0, prog, sizes)
    check("only finished lessons are reviewed; a day's set is capped at twenty",
          s["questions"] == 30 and s["due"] == 30 and s["today"] == review.DAILY == 20 and s["boxes"][0] == 30)
    st0["log"]["2026-03-02"] = {"answered": 15, "right": 9}
    s = review.status(D, st0, prog, sizes)
    keys, _ = review.todays_keys(st0, prog, D, sizes)
    check("answered questions count toward the day's twenty",
          s["today"] == 5 and len(keys) == 5 and s["answered_today"] == 15 and s["right_today"] == 9)
    check("a review key names the lesson and the question",
          review.split_key(review.card_key("dns-zones", 2)) == ("dns-zones", 2))
    try:
        review.split_key("nonsense")
        check("a key without a question number is refused", False)
    except ValueError:
        check("a key without a question number is refused", True)

    # --- the file, the desktop, the CLI, export and import ---------------
    saved = paths.VAR
    try:
        with tempfile.TemporaryDirectory() as td:
            paths.VAR = Path(td) / "a"
            check("no file: an empty review", review.load() == {"version": 1, "cards": {}, "log": {}})
            junk = {"cards": {"x#1": {"box": 9, "due": "2026-01-01"}, "nokey": {"due": "2026-01-01"},
                              "y#0": {"due": "not a day"}, "z#0": "?"},
                    "log": {f"2025-{m:02d}-{d:02d}": {"answered": 1, "right": 1} for m in range(1, 13) for d in range(1, 29)}}
            review.save(review.clean(junk))
            back = review.load()
            check("saved and read back: bad cards dropped, the box clamped, the log trimmed",
                  list(back["cards"]) == ["x#1"] and back["cards"]["x#1"]["box"] == review.TOP
                  and len(back["log"]) == review.LOG_DAYS and review.review_file().parent == paths.VAR)
            review.review_file().unlink()
            mine = ["create-ou-and-user", "dhcp-scopes", "ad-recycle-bin"]
            for lid in mine:
                progress.mark(lid, progress.STATUS_DONE)
            p = progress.load()
            for lid in mine:
                p["lessons"][lid]["passed_at"] = time.time() - 3 * 86400
            progress.save(p)
            nq = sum(len(lessons.load(l).quiz) for l in mine)
            d = webui.Dashboard(schema.load("ad-ds-basics"), accel="tcg")
            rv = d.lessons()["review"]
            check("the Learn window's data carries the review: every question of the finished lessons, due",
                  rv["questions"] == nq and rv["today"] == nq and rv["daily"] == 20, str(rv))
            ts = review.todays_set()
            it = ts["items"]
            check("today's set: each question with its lesson and shuffled choices, no answers",
                  len(it) == nq and all(set(x) == {"key", "lesson", "lesson_title", "q", "choices", "box"} for x in it)
                  and review.todays_set()["items"] == it)
            right_of = {x["key"]: lessons.load(x["lesson"]).quiz[review.split_key(x["key"])[1]].answer for x in it}
            wrong_of = {x["key"]: lessons.load(x["lesson"]).quiz[review.split_key(x["key"])[1]].wrong[0] for x in it}
            k0, k1, k2 = it[0]["key"], it[1]["key"], it[2]["key"]
            r = d.act("review-answer", {"picked": {k0: right_of[k0], k1: wrong_of[k1], k2: ""}})
            today = review.today()
            got = {x["key"]: x for x in r["results"]}
            check("the desktop grades an answer: right goes to box 1, wrong to box 0 for tomorrow, skipped stays due",
                  r.get("ok") and r["right"] == 1 and r["total"] == 2 and r["message"] == "1 of 2 right"
                  and got[k0]["box"] == 1 and got[k0]["due"] == (today + dt.timedelta(days=1)).isoformat()
                  and got[k1]["box"] == 0 and got[k1]["answer"] == right_of[k1] and got[k1]["why"]
                  and got[k2].get("skipped") and k2 in {x["key"] for x in review.todays_set()["items"]},
                  str(r)[:400])
            st = review.load()
            check("the answers are saved in var/review.json, with the day's count",
                  review.review_file().is_file() and set(st["cards"]) == {k0, k1}
                  and st["log"][today.isoformat()] == {"answered": 2, "right": 1})
            check("a question of a lesson not finished is refused",
                  "error" in review.answer({"dns-basics#0": "x"})["results"][0])
            check("a bad pick is refused by the desktop", d.act("review-answer", {"picked": "x"}).get("ok") is False)
            # the CLI, in the student's language
            i18n.choose("he")
            s = review.todays_set()
            he = json.loads(Path("content/i18n/lessons/he", f"{s['items'][0]['lesson']}.json").read_text(encoding="utf-8"))
            n0 = review.split_key(s["items"][0]["key"])[1]
            check("the questions are shown in the desktop's language",
                  s["items"][0]["q"] == he["quiz"][n0]["q"] and he["quiz"][n0]["answer"] in s["items"][0]["choices"])
            letters = []
            for x in s["items"]:
                ans = lessons.load(x["lesson"]).quiz[review.split_key(x["key"])[1]].answer
                letters.append(chr(97 + x["choices"].index(ans)))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cli._learn_review(answers=",".join(letters))
            text = out.getvalue()
            check("winlab learn review: today's set by letter, each right answer with its next day",
                  rc == 0 and text.count("right: back on") == len(letters)
                  and f"{len(letters)} of {len(letters)} right" in text, text[-400:])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli._learn_review(only_status=True)
            check("winlab learn review --status: the counts and the boxes",
                  f"{nq} questions from finished lessons" in out.getvalue() and "boxes (0 = learning" in out.getvalue()
                  and "nothing more to review today" in out.getvalue(), out.getvalue())
            ns = cli.build_parser().parse_args(["learn", "review", "--status"])
            check("the subcommand exists", ns.learncmd == "review" and ns.status is True)
            mine_a = review.load()
            data = progressfile.dumps()
            check("the progress file carries the review", progressfile.read(data)["review"]["cards"] == mine_a["cards"])
            # PC B: one question answered later there
            paths.VAR = Path(td) / "b"
            later = review.schedule(review.new_card(0, today), True, today)
            later["updated"] = time.time() + 60
            review.save({"version": 1, "cards": {k0: later}, "log": {}})
            rep = progressfile.import_bytes(data)
            got_b = review.load()
            check("importing merges: the newer answer per question wins, the rest come along, the day's counts too",
                  set(got_b["cards"]) == set(mine_a["cards"]) and got_b["cards"][k0]["updated"] == later["updated"]
                  and got_b["log"][today.isoformat()]["answered"] == mine_a["log"][today.isoformat()]["answered"]
                  and rep["review"] == len(mine_a["cards"]) - 1 and "review schedule" in rep["message"], str(rep))
            before = review.review_file().read_text(encoding="utf-8")
            again = progressfile.import_bytes(data)
            check("importing the same file twice changes nothing",
                  again["review"] == 0 and review.review_file().read_text(encoding="utf-8") == before)
            m, n = review.merge(got_b, got_b)
            check("merging a state with itself changes nothing", n == 0 and m == review.clean(got_b))
    finally:
        paths.VAR = saved
    page = Path("winlab/webui_page.html").read_text(encoding="utf-8")
    src = Path("winlab/webui.py").read_text(encoding="utf-8")
    check("the Learn window has a Review (N due) button and the review page",
          "function reviewBtn(" in page and "Review (${r.today} due)" in page and "function loadReview(" in page
          and "/api/review" in page and "do:'review-answer'" in page)
    check("the server answers /api/review", '"/api/review"' in src and "review.todays_set()" in src)
    tables = {lang: json.loads(Path("content/i18n", f"{lang}.json").read_text(encoding="utf-8")) for lang in ("es", "he", "ar")}
    check("the review's desktop text is translated",
          all(t.get("Review ({} due)") and t.get("Spaced review") for t in tables.values()))


# ---- gapx-powershell ----
_GAPX_PS_LESSONS = {
    "ps-hashtables-compare": "ps-staff-reconcile",
    "ps-json-config": "ps-baseline-json",
    "ps-parameter-sets": "ps-staff-lookup",
    "ps-shouldprocess-risk": "ps-stale-computers",
    "ps-errors-on-purpose": "ps-error-handling",
    "ps-text-to-objects": "ps-log-parsing",
    "ps-registry": "ps-registry-baseline",
    "ps-cim-sessions": "ps-cim-hardware",
    "ps-sessions-jobs": "ps-health-jobs",
    "ps-html-reports": "ps-html-report",
    "ps-logging-transcripts": "ps-script-logging",
    "ps-event-triggered-tasks": "ps-event-task",
    "ps-pester-mocking": "ps-pester-mocks",
    "ps-script-signing": "ps-signed-scripts",
}




# ---- gapx-ccnp ----


# ---- gapx-sol-net ----
GAPX_SOL_NET = """
    aaa-radius-login aaa-tacacs-commands bind-in-the-domain cable-tester-trace campus-vlans-trunks
    devops-ci-pipeline devops-deploy-and-iac devops-source-control dhcp-failover-pair
    dhcp-relay-across-subnets dhcp-reserve-and-exclude dhcp-snooping-dai dmvpn-hub-and-spokes
    dns-forwarders-aging-records dnssec-validated-zone ebgp-to-the-isp etherchannel-lacp-bundle fast-failover
    fortigate-policy-nat-ipsec freeipa-access-rules freeipa-ad-trust freeipa-domain freeipa-kerberos-ssh
    freepbx-extensions ftp-scp-config-backup guest-portal-isolation haproxy-keepalived-vip inter-vlan-routing
    ios-image-upgrade ipv6-acls-router ipv6-addresses-handed-out ipv6-dual-stack-office ipv6-ra-guard
    ipv6-routers-addressed junos-ospf-with-the-lab-router linux-chrony-sources linux-client-in-the-domain
    linux-logins-for-a-group lx-console-rescue-ready lx-disk-check-script lx-lvm-and-swap lx-own-service
    lx-packages-from-the-stick lx-persistent-journal lx-team-folders lx-timers-and-cron mst-regions
    net-tools-baseline netauto-ansible-ios netauto-napalm-json netauto-netmiko-backup netauto-restconf
    netflow-flows-to-collector nmap-inventory-check nms-link-down nps-network-policy ospf-neighbours-up
    ospf-three-sites paloalto-zones-and-policy pdc-from-lab-ntp poe-budget-plan port-security-dot1x
    private-vlans rapid-spanning-tree rocky-joins-the-domain rocky-nfs-autofs rocky-selinux-intranet
    rocky-web-through-firewalld router-acls router-ebgp-to-isp router-eigrp-neighbour router-glbp-gateway
    router-guest-vrf router-hsrp-gateway router-ipv4-static router-ipv6-addressing router-ipv6-static
    router-isis-adjacency router-multicast-pim router-nat-pat router-nat-pool router-ntp-auth router-ospf-md5
    router-ospf-neighbour router-password-recovery router-qos-mqc router-sla-tracking router-vrrp-gateway
    routes-from-the-isp rras-static-route run-the-company-edge samba-file-server snmpv3-librenms
    span-mirror-capture spanning-tree-root ssh-to-the-switch storm-control subnetting-drill
    switch-named-from-console switch-password-recovery tcp-handshake-capture tftp-config-backup
    time-pdc-sources vlsm-address-plan voice-vlan-lldp-med vxlan-evpn-two-racks wifi-aruba-instant
    wifi-channel-plan wifi-cisco-ewc wifi-enterprise-aruba wifi-mikrotik-routeros wifi-openwisp-openwrt
    wifi-real-air wifi-ruckus-unleashed wifi-unifi-controller wifi-wlc-ap-join wifi-wlc-wlans-tags
    work-from-home wpa2-enterprise
""".split()




# ---- gapx-engine-i18n ----


# ---- gapx-sol-ops ----
SOL_OPS_IDS = """
    aidc-first-morning aidc-inference-gateway aidc-share-the-gpus alerts-that-page ansible-linux-fleet
    aplus-change-in-glpi aplus-ticket-method automation-at-scale backup-to-the-nas bad-update-rollback
    bare-metal-restore bareos-backup-jobs bareos-clients-connected bareos-database-backup
    bareos-offsite-copy bareos-restore-test bareos-server-ready be-on-call build-a-file-cluster
    build-alerting build-the-helpdesk build-the-wiki certs-before-they-expire choco-internal-feed
    choco-patch-rings cluster-a-virtual-machine connect-iscsi-lun daily-report-by-mail
    dashboards-for-the-servers database-replication databases-online dedup-and-auto-quota
    deploy-enterprise-ca deploy-hall-printer dfs-conflict-recovered dfs-namespace-and-replication
    dfsn-company-files dfsr-software docker-host-by-hand docs-helpdesk-real-tickets
    docs-inventory-every-machine docs-inventory-parts-swap docs-runbook-per-server
    docs-vault-service-accounts dr-drill-recovered dr-second-site dsc-catches-drift
    fileshare-abe-and-hidden fileshare-departments fileshare-previous-versions filter-the-web
    finance-folder-permissions finance-quota-and-screen fixed-by-the-runbook forward-security-events
    helpdesk-phone-line helpdesk-shift hyperv-export-and-checkpoints hyperv-replica-failover
    inherited-as-built inherited-audit inherited-certs-dns inherited-file-shares inherited-gpo-cleanup
    inherited-leavers inherited-old-dc inherited-privileged inherited-scheduled-tasks
    inherited-service-accounts inplace-upgrade-client inplace-upgrade-server intranet-site
    jea-helpdesk-endpoint k3s-air-gapped kvm-host-on-the-lab-network lifecycle-desk-ready
    mail-between-two-users mail-to-the-internet manage-server-core manage-servers-remotely
    migrate-file-server monitoring-online move-dhcp-and-print msi-by-group-policy nested-hyperv-host
    netdocs-ipam-every-address netdocs-netbox-rack-and-cables netops-librenms netops-oxidized
    netops-uptime-kuma patch-by-hand permission-audit-report pki-autoenroll-web pki-ldaps pki-rdp-cert
    pki-revoke-and-crl postgresql-kerberos-login power-cycle-hung-server print-support-two-servers
    print-support-windows-queue printers-by-preference proxmox-backup-jobs proxmox-backup-server-ready
    proxmox-offsite-sync proxmox-restores rack-the-comms-room rdp-for-helpdesk rds-farm-with-gateway
    rebuild-a-mirror repair-a-storage-pool restore-a-deleted-user restore-drill-graded runbook-written
    samba-archive-share san-mpio-volume scheduled-backup-ran server-core-first-steps
    server-room-remote-only smb-security-and-open-files sql-backup-and-restore sql-server-online
    sql-windows-logins storage-replica-to-dr ups-graceful-shutdown veeam-backup-copy veeam-backup-job
    veeam-installed-and-connected veeam-restores vmbackup-host-ready wac-manage-servers wake-a-pc
    web-farm-intranet web-https-san web-kerberos-spn web-two-names wef-collector who-is-hammering
    windows-containers wsb-backs-up-the-vms wsus-clients-report wsus-groups-and-targeting
    wsus-offline-approve
""".split()




# ---- gapx-sol-sec ----
GAPX_SOL_SEC = """
    ad-replication-over-vpn advanced-audit-policy android-tablet-basics
    aplus-bsod-dump-read aplus-disks-and-stick aplus-file-history-restore
    aplus-pc04-installed aplus-recovery-ready aplus-restore-points aplus-support-toolbox
    aplus-workgroup-share app-control-base-and-supplemental apps-and-applocker
    aws-account-ready aws-cloudformation-stack aws-cloudwatch-alarm aws-cost-tags-budget
    aws-ec2-user-data aws-iam-assume-role aws-iam-least-privilege
    aws-route53-private-zone aws-s3-bucket-secure aws-sg-and-nacl aws-site-to-site-vpn
    aws-vpc-design azure-arc-onboarded azure-backup-restore azure-files-mapped
    azure-files-share azure-peering-hub-spoke azure-s2s-vpn azure-subscription-ready
    azure-vm-in-the-vnet azure-vnet-and-nsg baseline-gpos-imported bastion-jump-host
    bitlocker-data-auto-unlock bitlocker-data-drive bitlocker-os-startup-key
    bitlocker-recover-moved-disk bitlocker-tpm-and-pin bring-up-the-vpn
    capture-dns-with-wireshark cloud-apps-encryption cloud-managed-devices
    cloud-mfa-roles cloud-nsg-rules cloud-tenant-reached compliance-baseline
    configmgr-bare-metal-deployment configmgr-client-and-collections
    configmgr-deploy-an-application configmgr-microsoft-365-apps
    configmgr-patch-tuesday-offline configmgr-read-only-analysts
    configmgr-refresh-keeps-user-data configmgr-software-update-point
    configmgr-windows11-upgrade credential-guard-by-policy dc-backup-in-the-cloud
    default-profile-and-cleanup defender-on-the-pc domain-admins-review
    edge-central-store edge-home-and-ie-mode edge-msi-deployed enrol-the-pcs
    exploit-protection-by-gpo fence-the-dmz first-rules-on-your-firewall fix-sync-errors
    golden-image-captured harden-and-catch-drift hello-for-business-groundwork
    hmdm-device-policy hmdm-phone-enrolled hmdm-server-built hybrid-identity-sync
    ir-triage-collected ir-velociraptor-fleet ir-velociraptor-server jea-helpdesk-unlock
    know-the-edge local-policy-baseline office-deploy-from-share
    office-updates-from-share pc-deployed-over-pxe pki-issuing-ca pki-offline-root
    pki-step-ca-acme pki-supersede-template pki-templates-autoenrol prepare-ad-for-entra
    prepare-forest-for-sync private-dns-across-sites profiles-and-scripts
    publish-the-dmz-web-server real-azure-arc real-azure-backup real-azure-online
    real-tenant-connect-sync real-tenant-hybrid-join real-tenant-intune-enrolled
    real-tenant-online redirect-documents-desktop remote-support-desk
    remove-task-persistence router-ipsec-vti router-zone-firewall scan-fix-rescan
    scoped-winrm-and-logging sec-detection-tuned sec-endpoint-logging
    sec-evidence-collected sec-risk-register sec-ssh-hardened sec-sysmon-deployed
    sec-vuln-cycle secure-boot-on-pc03 sigma-rules-converted sigma-wazuh-rule
    spot-the-attack sspr-writeback standalone-baseline-audited sync-agent-installed
    tier0-logon-restrictions tier0-silo ubuntu-desktop-installed
    usmt-custom-xml-and-logs usmt-hardlink-refresh usmt-replace-pc02-to-pc03
    w11-delivery-optimization w11-hyperv-and-sandbox w11-update-rings
    w11-wsus-scan-source watch-the-wire wazuh-alerts-to-helpdesk wazuh-linux-agents
    wazuh-siem-alerts workstation-baseline-gpo zeek-notice-raised zeek-sensor-logs
    zone-firewall-rules
""".split()







# ---------------------------------------------------------------- srvmd
# CompTIA Server+ hardware and storage (RAID 5, 6 and 10 with mdadm and
# Storage Spaces, firmware through the BMC, drive sanitising recorded in
# GLPI, two storage drills) and the MD-102 cloud endpoint lessons on a real
# tenant (compliance with Conditional Access, app protection, AVD and
# Windows 365). The last two are done in the browser.
BROWSER_LESSONS |= {"real-tenant-app-protection", "real-tenant-cloud-pc-avd"}


def test_srvmd_firmware_packages():
    """winlab/bmcfw.py: the vendor's packages, the support disc, and the
    versions the BMC keeps (staged BIOS written at power-on, SMBIOS type 0)."""
    import hashlib
    import io
    import tarfile
    import tempfile
    import types
    from winlab import bmcfw, paths, power
    a = bmcfw.package("bmc", "2.15.0", bmcfw.MACHINE, "08/18/2026")
    b = bmcfw.package("bmc", "2.15.0", bmcfw.MACHINE, "08/18/2026")
    with tarfile.open(fileobj=io.BytesIO(a)) as tar:
        names = tar.getnames()
        man = tar.extractfile("MANIFEST").read().decode()
        img = tar.extractfile("image-bmc").read()
    check("a firmware package is the same bytes every time: a USTAR tar of MANIFEST and the image",
          a == b and names == ["MANIFEST", "image-bmc"])
    check("its MANIFEST names the purpose, version, model and the image's SHA-256",
          "VersionPurpose.BMC" in man and "version=2.15.0" in man and "MachineName=WL-R200" in man
          and f"ImageSHA256={hashlib.sha256(img).hexdigest()}" in man)
    check("two versions have different images", bmcfw.image_bytes("bios", "1.4.0") != bmcfw.image_bytes("bios", "1.2.0"))
    check("package names carry model, kind and version",
          bmcfw.package_name("bios", "2.0.1", "WL-R300") == "r300-bios-2.0.1.tar"
          and bmcfw.package_name("bmc", "2.15.0") == "r200-bmc-2.15.0.tar")
    with tempfile.TemporaryDirectory() as td:
        disc = Path(td) / "disc"
        got = bmcfw.write_disc(disc)
        sums = {}
        for line in (disc / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
            if line:
                h, _, n = line.partition("  ")
                sums[n] = h
        check("the support disc: three packages, one for another model, each hash in SHA256SUMS",
              len(got) == 3 and "r300-bios-2.0.1.tar" in got
              and all(sums.get(n) == hashlib.sha256((disc / n).read_bytes()).hexdigest() for n in got))
        check("the release notes say a warm restart does not apply a BIOS image",
              "warm restart does not apply it" in (disc / "RELEASE-NOTES.txt").read_text(encoding="utf-8"))
        saved = paths.VAR
        paths.VAR = Path(td) / "var"
        try:
            lab = "fwtest"
            check("a server starts at the default versions", bmcfw.state(lab, "fs01") == bmcfw.DEFAULTS)
            sev, msg = bmcfw.keep(lab, "fs01", "bmc:2.15.0")
            s = bmcfw.state(lab, "fs01")
            check("a BMC image is active at once, the old one becomes the backup",
                  s["bmc"] == "2.15.0" and s["bmc_backup"] == "2.14.0" and sev == "Info", msg)
            bmcfw.keep(lab, "fs01", "bmc-switch")
            s = bmcfw.state(lab, "fs01")
            check("switching to the backup swaps the two BMC images", s["bmc"] == "2.14.0" and s["bmc_backup"] == "2.15.0")
            bmcfw.keep(lab, "fs01", "bmc:2.15.0")
            check("a BIOS request that is not understood changes nothing",
                  bmcfw.keep(lab, "fs01", "bios:1.4.0;rm:x")[0] == "Warning" and "pending" not in bmcfw.state(lab, "fs01"))
            bmcfw.keep(lab, "fs01", "bios:1.4.0:09/02/2026")
            s = bmcfw.state(lab, "fs01")
            check("a BIOS image is staged, not written", s["bios"] == "1.2.0" and s.get("pending") == "1.4.0")
            node = types.SimpleNamespace(id="fs01", vars={power.PORT_VAR: "corp"})
            bare = types.SimpleNamespace(id="pc01", vars={})
            check("QEMU gets SMBIOS type 0 only for a server with a management port, a staged image counting",
                  bmcfw.smbios_args(lab, node) == ["-smbios", "type=0,vendor=winlab,version=1.4.0,date=09/02/2026"]
                  and bmcfw.smbios_args(lab, bare) == [])
            lines = " ".join(bmcfw.router_lines(lab, "fs01", "/x"))
            check("the router's BMC files carry the versions and the staged image",
                  "'2.15.0' > /x/fw_bmc" in lines and "'1.2.0 03/14/2025' > /x/fw_bios" in lines
                  and "'1.4.0 09/02/2026' > /x/fw_bios_pending" in lines, lines)
            said = bmcfw.power_on(lab, "fs01")
            s = bmcfw.state(lab, "fs01")
            check("power-on from off writes the staged BIOS",
                  s["bios"] == "1.4.0" and s["bios_date"] == "09/02/2026" and "pending" not in s
                  and "from 1.2.0 to 1.4.0" in said, said)
            check("a second power-on has nothing to write", bmcfw.power_on(lab, "fs01") == ""
                  and "rm -f /x/fw_bios_pending" in " ".join(bmcfw.router_lines(lab, "fs01", "/x")))
        finally:
            paths.VAR = saved


def test_srvmd_bmc_firmware_update():
    """content/agent/bmc.sh's UpdateService: inventory, the package checks
    (model, hash, format, the signed-in Administrator), staging and the
    switch to the backup image."""
    import base64
    import os
    import json
    import shutil
    import tempfile
    from winlab import bmcfw
    if not shutil.which("sh") or not shutil.which("tar") or not shutil.which("sha256sum"):
        check("the BMC's firmware update (no sh, tar or sha256sum here: skipped)", True)
        return
    if os.name == "nt":
        # bmc.sh unpacks a package with the router's busybox tar. Under Git's
        # sh on a hosted Windows runner its tar step refuses valid packages
        # (rdiol12/winlablite release run 42589408703); the router is Alpine.
        check("the BMC's firmware update (it runs on the router's Alpine, not under Windows: skipped)", True)
        return
    with tempfile.TemporaryDirectory() as td:
        folder, tag = _bmc_folder(Path(td))
        auth = {"Authorization": "Basic " + base64.b64encode(f"Administrator:{tag}".encode()).decode()}

        def text(name):
            f = folder / name
            return f.read_text().strip() if f.exists() else ""
        st, _, body = _bmc_http(folder, "GET", "/redfish/v1/UpdateService", headers=auth)
        us = json.loads(body or b"{}")
        check("UpdateService takes a pushed package", st.endswith("200 OK") and us.get("ServiceEnabled") is True
              and us.get("HttpPushUri") == "/redfish/v1/UpdateService/update", st)
        st, _, body = _bmc_http(folder, "GET", "/redfish/v1/UpdateService/FirmwareInventory", headers=auth)
        ids = [m["@odata.id"].rsplit("/", 1)[-1] for m in json.loads(body or b"{}").get("Members", [])]
        check("the inventory lists the BMC's two images and the BIOS",
              ids == ["bmc_active", "bmc_backup", "bios_active"], str(ids))
        st, _, body = _bmc_http(folder, "GET", "/redfish/v1/Systems/system", headers=auth)
        check("the system says its BIOS version", json.loads(body or b"{}").get("BiosVersion") == "1.2.0")
        url = "/redfish/v1/UpdateService/update"
        st, _, body = _bmc_http(folder, "POST", url, bmcfw.package("bios", "2.0.1", "WL-R300", "07/30/2026"), auth)
        check("a package for another model is refused, and says why",
              st.startswith("HTTP/1.0 400") and b"WL-R300; this server is WL-R200" in body, st)
        bad = bmcfw.package("bios", "1.4.0", bmcfw.MACHINE, "09/02/2026", image=b"x" * 4096)
        st, _, body = _bmc_http(folder, "POST", url, bad, auth)
        check("an image that does not match its MANIFEST's hash is refused",
              st.startswith("HTTP/1.0 400") and b"SHA-256" in body, st)
        st, _, _ = _bmc_http(folder, "POST", url, b"not a package", auth)
        check("a file that is not a package is refused", st.startswith("HTTP/1.0 400"), st)
        st, _, _ = _bmc_http(folder, "POST", url, bmcfw.package("bmc", "2.15.0", bmcfw.MACHINE, "08/18/2026"))
        check("without a sign-in nothing is taken", st.startswith("HTTP/1.0 401")
              and not (folder / "upload.tar").exists() and text("fw_bmc") != "2.15.0", st)
        st, _, _ = _bmc_http(folder, "POST", url, bmcfw.package("bmc", "2.15.0", bmcfw.MACHINE, "08/18/2026"), auth)
        check("the BMC image is verified and active, the old one kept as the backup",
              st.startswith("HTTP/1.0 202") and text("fw_bmc") == "2.15.0" and text("fw_bmc_backup") == "2.14.0", st)
        st, _, _ = _bmc_http(folder, "POST", url, bmcfw.package("bios", "1.4.0", bmcfw.MACHINE, "09/02/2026"), auth)
        st2, _, body = _bmc_http(folder, "GET", "/redfish/v1/UpdateService/FirmwareInventory/bios_staged",
                                 headers=auth)
        check("the BIOS image is staged, not active", st.startswith("HTTP/1.0 202")
              and text("fw_bios_pending") == "1.4.0 09/02/2026"
              and json.loads(body or b"{}").get("Version") == "1.4.0", st2)
        patch = json.dumps({"Links": {"ActiveSoftwareImage": {
            "@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/bmc_backup"}}}).encode()
        st, _, _ = _bmc_http(folder, "PATCH", "/redfish/v1/Managers/bmc", patch,
                             {**auth, "Content-Type": "application/json"})
        check("switching the Manager to its backup image swaps them", st.endswith("200 OK") and text("fw_bmc") == "2.14.0", st)
        queue = text("queue")
        check("each change is queued for winlab to keep (bmc, bios, switch)",
              "Firmware=bmc:2.15.0" in queue and "Firmware=bios:1.4.0:09/02/2026" in queue
              and "Firmware=bmc-switch" in queue, queue)
        events = text("events")
        check("the event log records the refusals and the updates with the address they came from",
              events.count("refused") == 3 and "from 10.10.10.50" in events
              and "BMC firmware 2.15.0 verified" in events, events[-300:])
        st, _, page = _bmc_http(folder, "GET", "/firmware", headers=auth)
        check("winlab's own Firmware page is there", st.endswith("200 OK") and b"Firmware" in page, st)



# ---------------------------------------------------------------------------
# Windows Server hybrid gaps (AZ-802): Switch Embedded Teaming, Storage Spaces
# Direct on hand-installed Datacenter nodes, the file share witness,
# Cluster-Aware Updating, SMB over QUIC, IPAM, BranchCache hosted cache, and
# four real-tenant Azure lessons (File Sync, Migrate, Site Recovery,
# Defender/Sentinel), with four drills (winlab/wshybrid.py).
WSHYB_LESSONS = {
    "hyperv-set-team": ("hyperv-host", "hyperv-set-team"),
    "s2d-datacenter-cluster": ("s2d-cluster", "s2d-cluster-built"),
    "s2d-pool-and-sofs": ("s2d-cluster", "s2d-sofs-volume"),
    "cluster-quorum-witness": ("failover-cluster", "cluster-quorum-witness"),
    "cluster-aware-updating": ("failover-cluster", "cluster-aware-updating"),
    "smb-over-quic": ("enterprise-multisite", "smb-over-quic"),
    "ipam-server": ("enterprise-multisite", "ipam-server"),
    "branchcache-hosted-cache": ("enterprise-multisite", "branchcache-hosted-cache"),
    "real-azure-file-sync": ("azure-hybrid", "real-azure-file-sync"),
    "real-azure-migrate": ("azure-hybrid", "real-azure-migrate"),
    "real-azure-site-recovery": ("hyperv-host", "real-azure-site-recovery"),
    "real-azure-defender-sentinel": ("azure-hybrid", "real-azure-defender-sentinel"),
}
WSHYB_DRILLS = {
    "ts-set-team-one-card": ("hyperv-host", "hv01", "set-team-member-removed"),
    "ts-cluster-witness-failed": ("failover-cluster", "san01", "witness-share-denied"),
    "ts-smb-quic-blocked": ("enterprise-multisite", "fs01", "smbquic-udp-blocked"),
    "ts-branchcache-misses": ("enterprise-multisite", "fs01", "branchcache-share-off"),
}







# ===== pcsw: PC technician calls, the PC technician break-fix topic, the technician's endpoint lessons =====



def post_video(lab) -> str:
    from winlab import pcbuild
    return pcbuild.post(lab.name, lab.nodes["pc01"])["video"]

# ---- gapc-aws: AWS Solutions Architect and CloudOps (SysOps) operations ------------------
AWS_OPS_GRADED = ("aws-alb-asg-web", "aws-rds-multiaz-replica", "aws-dynamodb-table-backups", "aws-kms-encryption",
                  "aws-ebs-snapshot-ami", "aws-backup-plan", "aws-cloudtrail-config", "aws-ssm-parameter-store",
                  "aws-ssm-fleet-ops", "aws-efs-shared", "aws-sqs-lambda-sns", "aws-cloudfront-alb-s3",
                  "aws-transit-gateway", "aws-organizations-scp")
AWS_OPS_REAL = ("aws-real-lambda-sqs", "aws-real-ssm-backup")



# ===== OpenTofu in depth and Google Cloud (Associate Cloud Engineer): test_iacgcp =====
# The Google Cloud lessons are done in the student's own free trial, in the
# browser and Cloud Shell, like gcp-free-trial (no emulator covers them).
_GCP_LESSONS = ("gcp-gcloud-configurations", "gcp-billing-budgets", "gcp-cloud-storage", "gcp-cloud-run",
                "gcp-gke-autopilot", "gcp-mig-load-balancer", "gcp-cloud-sql", "gcp-logging-monitoring")
BROWSER_LESSONS |= set(_GCP_LESSONS)
_TOFU_LESSONS = {   # lesson -> (lab, exercise)
    "devops-tofu-variables-loops": ("devops-pipeline", "devops-iac-state-and-modules"),
    "devops-tofu-modules": ("devops-pipeline", "devops-iac-state-and-modules"),
    "devops-tofu-remote-state-pg": ("devops-pipeline", "devops-iac-state-and-modules"),
    "devops-tofu-workspaces": ("devops-pipeline", "devops-iac-state-and-modules"),
    "devops-tofu-import": ("devops-pipeline", "devops-iac-state-and-modules"),
    "devops-tofu-aws": ("aws-cloud", "aws-iac-opentofu"),
    "devops-tofu-s3-backend": ("aws-cloud", "aws-iac-opentofu"),
}











if __name__ == "__main__":
    sys.exit(main())
