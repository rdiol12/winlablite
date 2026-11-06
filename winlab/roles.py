"""Role runner: configure a booted machine into its target services.

Reads content/roles/_manifest.toml, topologically orders the roles a node
asks for, pushes the scripts over the serial agent and runs them, waiting
across the reboots that promotion and domain-join require.
"""

from __future__ import annotations

import json
import shlex
import time
import tomllib
from dataclasses import dataclass, field

from . import paths
from .guestctl import GuestChannel, GuestError, GuestRebooted
from .model import LINUX, Lab, Node
from .netplan import TopologyPlan


class RoleError(Exception):
    pass


@dataclass
class RoleDef:
    name: str
    script: str
    needs: list[str] = field(default_factory=list)
    reboots: bool = False
    description: str = ""
    engine: str = "script"   # script | dsc
    # A sh role on a Linux appliance: the pack (winlab/debpacks.py) plugged
    # in as a stick before it runs, and the appliance image it is written for.
    pack: str = ""
    image: str = ""
    # A Windows role that installs a product from its own installation media
    # (a catalog image of kind media, imported by the user): the ISO goes into
    # the machine's DVD drive before the role runs.
    media: str = ""
    # A Windows role that installs something winlab fetches onto this PC from
    # its publisher (the Prometheus Windows exporter): the id in DOWNLOADS;
    # the file rides on the provisioning volume, or over the agent channel.
    download: str = ""
    # How long applying it may take, when that is longer than the default
    # hour (Configuration Manager's setup on a small machine).
    minutes: int = 0
    # The machine kind `media` is for, when only that kind installs from it
    # (RSAT: Features on Demand on Windows 11, Windows features on a server).
    media_on: str = ""
    # Alpine packages a role on an Alpine appliance needs (alpineovl).
    apk: list[str] = field(default_factory=list)

    @property
    def shell(self) -> str:
        if self.engine == "dsc":
            return "powershell"
        return "sh" if self.script.endswith(".sh") else "powershell"


def load_manifest() -> dict[str, RoleDef]:
    man = paths.ROLES / "_manifest.toml"
    if not man.exists():
        raise RoleError(f"role manifest missing at {man}")
    with man.open("rb") as fh:
        raw = tomllib.load(fh)
    out: dict[str, RoleDef] = {}
    for name, body in raw.items():
        engine = str(body.get("engine", "script"))
        if engine not in ("script", "dsc"):
            raise RoleError(f"role '{name}': engine must be script or dsc, not {engine!r}")
        out[name] = RoleDef(
            name=name,
            script=body.get("script", "" if engine == "dsc" else f"{name}.ps1"),
            needs=list(body.get("needs", [])),
            reboots=bool(body.get("reboots", False)),
            description=body.get("description", ""),
            engine=engine,
            pack=str(body.get("pack", "")),
            image=str(body.get("image", "")),
            media=str(body.get("media", "")),
            download=str(body.get("download", "")),
            minutes=int(body.get("minutes", 0)),
            media_on=str(body.get("media_on", "")),
            apk=[str(x) for x in body.get("apk", [])],
        )
    for rd in out.values():
        if rd.download and rd.download not in DOWNLOADS:
            raise RoleError(f"role '{rd.name}': download '{rd.download}' is not one winlab knows "
                            f"({', '.join(DOWNLOADS)})")
    # A DSC role is applied in one configuration before any script role runs,
    # so it cannot depend on a script role.
    for rd in out.values():
        if rd.engine == "dsc":
            from .dsc import BUILDERS
            if rd.name not in BUILDERS:
                raise RoleError(f"role '{rd.name}' is engine=dsc but has no builder in dsc.py")
            bad = [d for d in rd.needs if out.get(d) and out[d].engine != "dsc"]
            if bad:
                raise RoleError(f"dsc role '{rd.name}' cannot depend on script role(s) {bad}")
        if rd.pack:
            from .debpacks import PACKS
            if rd.pack not in PACKS:
                raise RoleError(f"role '{rd.name}': no pack '{rd.pack}' in debpacks.PACKS")
            if rd.engine == "dsc" or not rd.script.endswith(".sh"):
                raise RoleError(f"role '{rd.name}': only a sh role can take a pack")
    return out


def effective_roles(node: Node) -> list[str]:
    """A node's declared roles plus ones implied by its shape: hosting a device
    implies the 'devices' role, so the user does not have to remember it, and
    a Windows machine with lean on (the default) gets the 'lean' profile,
    always last so it sees what the other roles asked for (the hardening
    role keeps Defender)."""
    roles = [r for r in node.roles if r != "lean"]
    if node.devices and "devices" not in roles:
        roles.append("devices")
    if node.is_windows and (node.lean or "lean" in node.roles):
        roles.append("lean")
    return roles


def order_roles(requested: list[str], manifest: dict[str, RoleDef]) -> list[RoleDef]:
    """Depth-first topological sort. Dependencies that the node did not request
    are pulled in automatically (a node asking for 'gpo' needs 'ad-ds')."""
    ordered: list[RoleDef] = []
    seen: set[str] = set()
    visiting: set[str] = set()

    def visit(name: str) -> None:
        if name in seen:
            return
        if name in visiting:
            raise RoleError(f"dependency cycle through role '{name}'")
        rd = manifest.get(name)
        if rd is None:
            raise RoleError(f"unknown role '{name}' (not in manifest)")
        visiting.add(name)
        for dep in rd.needs:
            visit(dep)
        visiting.discard(name)
        seen.add(name)
        ordered.append(rd)

    for name in requested:
        visit(name)
    return ordered


def _script_bundle(shell: str) -> dict[str, bytes]:
    suffix = ".sh" if shell == "sh" else ".ps1"
    out: dict[str, bytes] = {}
    for f in paths.ROLES.glob(f"*{suffix}"):
        out[f.name] = f.read_bytes()
    return out


def node_shell(node: Node) -> str:
    return "sh" if node.kind == LINUX else "powershell"


def check_images(node: Node, plan: list[RoleDef]) -> list[str]:
    """Roles written for one appliance image (realmd and SSSD on Ubuntu, say)
    applied to a machine running something else: what would go wrong, as
    sentences, empty when all is well."""
    out = []
    for rd in plan:
        if rd.image and rd.image != node.image:
            from .images import catalog_root
            want = catalog_root(rd.image)
            out.append(f"role '{rd.name}' is written for {want.short if want else rd.image} "
                       f"(image = \"{rd.image}\"); {node.id} runs image '{node.image}'")
    return out


def check_media(node: Node, plan: list[RoleDef]) -> list[str]:
    """Roles that install from media the user has not imported yet (the SQL
    Server ISO, say): what is missing, as sentences; empty when all is there."""
    from . import images as im
    out = []
    for rd in plan:
        if not rd.media or (rd.media_on and rd.media_on != node.kind):
            continue
        if not im.installer_path(rd.media).exists():
            entry = im.CATALOG.get(rd.media)
            if entry and entry.get:
                out.append(f"role '{rd.name}' on {node.id} installs from the {entry.short} media, "
                           f"which is not prepared yet: {entry.note}. Then run {entry.get}, or "
                           "Prepare it in Setup")
                continue
            out.append(f"role '{rd.name}' on {node.id} installs from the "
                       f"{entry.short if entry else rd.media} installation media, which is not "
                       f"imported yet: download it ({entry.page if entry else ''}) and run "
                       f"winlab images import {rd.media} <file.iso>, or import it in Setup")
    return out


# What a role with `download =` needs on this PC: a human name, the command
# that fetches it, and the module (lazily imported) with ready()/files().
# Roles that stand for somebody else's equipment, such as the cloud
# provider's VPN gateway. Every lab starts empty for the student, but the
# student is not that party, so the lab brings these up itself at start.
PROVIDER_ROLES = ("vpn-gateway",)
# Roles that are a device's own firmware (a network printer, a NAS): they run
# by themselves every time the device powers on, as the real ones do.
APPLIANCE_ROLES = ("netprinter", "nas", "pbx", "ipphone", "ntp-server", "san", "admin-desktop", "doc-tools", "ipcam")
# The Internet side of a lab: a test host a firewall lesson reaches from the
# inside (content/roles/inet-host.sh), the web sites and DNS a proxy lesson
# filters (content/roles/inet-sites.sh), the broadband router of a home
# worker's house (content/roles/home-router.sh); nobody in the lab owns them.
INTERNET_ROLES = ("inet-host", "inet-sites", "home-router")
SELF_STARTING = PROVIDER_ROLES + APPLIANCE_ROLES + INTERNET_ROLES


def apk_packages(node: Node) -> list[str]:
    """The Alpine packages a node's roles need, beyond the router's own."""
    out: list[str] = []
    try:
        man = load_manifest()
    except RoleError:
        return out
    try:
        plan = order_roles([r for r in node.roles if r in man], man)   # with what they need (webmin)
    except RoleError:
        plan = [man[r] for r in node.roles if r in man]
    for rd in plan:
        for p in rd.apk:
            if p not in out:
                out.append(p)
    return out

DOWNLOADS: dict[str, tuple[str, str, str]] = {
    "windows-exporter": ("the Prometheus Windows exporter (windows_exporter)", "winlab exporter fetch",
                         "exporters"),
    "windows-admin-center": ("Windows Admin Center (Microsoft)", "winlab wac fetch", "wac"),
}


def download_module(download_id: str):
    """The module behind a download: MAIN_FILE, ready(), files(), fetch()."""
    import importlib
    return importlib.import_module(f"winlab.{DOWNLOADS[download_id][2]}")


def download_ready(download_id: str) -> bool:
    return bool(download_module(download_id).ready())


def check_downloads(node: Node, plan: list[RoleDef]) -> list[str]:
    """Roles that install something winlab has not fetched yet: what is
    missing, as sentences; empty when all is there."""
    out = []
    for rd in plan:
        if rd.download and not download_ready(rd.download):
            title, cmd, _ = DOWNLOADS[rd.download]
            out.append(f"role '{rd.name}' on {node.id} installs {title}, which is not fetched yet: "
                       f"run {cmd}, or fetch it in Setup")
    return out


def downloads_for(plan: list[RoleDef]) -> list[str]:
    out: list[str] = []
    for rd in plan:
        if rd.download and rd.download not in out:
            out.append(rd.download)
    return out


def media_for(plan: list[RoleDef], node: Node | None = None) -> list[str]:
    """The media image ids a role plan installs from, in order, once each
    (on this node, when given: media for another kind of machine is left out)."""
    out: list[str] = []
    for rd in plan:
        if rd.media_on and node is not None and rd.media_on != node.kind:
            continue
        if rd.media and rd.media not in out:
            out.append(rd.media)
    return out


def _insert_media(lab: Lab | None, node: Node, image_id: str) -> str:
    """Puts the role's installation media in the running machine's DVD
    drive (QMP) so the role finds it; it stays there (mediashelf.py) until
    it is ejected or the lab definition names another disc."""
    from . import images as im, media
    iso = im.installer_path(image_id)
    if lab is None:
        return f"{image_id}: no lab given, media not inserted"
    try:
        if media.insert(lab.name, node.id, iso):
            return f"{image_id}: {iso.name} is in {node.id}'s DVD drive"
        return f"{image_id}: {node.id} is not running, media not inserted"
    except media.MediaError as exc:
        raise RoleError(f"could not put the {image_id} media in {node.id}'s drive: {exc}") from exc


def check_shells(node: Node, plan: list[RoleDef]) -> None:
    """A PowerShell role cannot run on the Alpine probe, nor a sh role on
    Windows. Caught at plan time instead of as a confusing in-guest error."""
    want = node_shell(node)
    wrong = [rd.name for rd in plan if rd.shell != want]
    if wrong:
        raise RoleError(
            f"{node.id} is {node.kind}; role(s) {', '.join(wrong)} need a "
            f"{'Linux' if want == 'powershell' else 'Windows'} node"
        )


def sh_env(node: Node, plan: TopologyPlan | None, lab: Lab | None = None) -> str:
    """Shell variable assignments a sh role starts with. Linux nodes get no
    facts.json disk, so the addressing a role needs travels with the script:
    WINLAB_NODE, and per NIC i: WINLAB_NICi_IP / _PREFIX / _GW / _TRUNK_VIDS.
    With the lab: WINLAB_HOSTNAME, WINLAB_DOMAIN, WINLAB_NETBIOS, WINLAB_DNS
    (the domain's DNS servers), WINLAB_ADMIN_PASSWORD (the lab's one
    password, for a domain join), and where a pack stick mounts."""
    lines = [f"WINLAB_NODE={shlex.quote(node.id)}"]
    if lab is not None:
        from .debpacks import MOUNT, STICK_LABEL
        from .provision import _dns_servers
        facts = (
            ("HOSTNAME", (node.hostname or node.id).lower()),
            ("DOMAIN", lab.domain),
            ("NETBIOS", lab.netbios),
            ("DNS", " ".join(_dns_servers(lab))),
            # The lab's one generated password, for the domain join; the
            # script travels over the agent channel, which never leaves this PC.
            ("ADMIN_PASSWORD", lab.admin_password),
            ("TIMEZONE", lab.timezone or "UTC"),
            ("PACK_LABEL", STICK_LABEL),
            ("PACK_MOUNT", MOUNT),
        )
        lines += [f"WINLAB_{key}={shlex.quote(value)}" for key, value in facts]
    # The phone system and the phones are told nothing about each other: the
    # student makes the extensions in FreePBX and signs each phone in.
    for key, var in (("PRINTER_LOCATION", "location"), ("BACKENDS", "backends"),
                     ("INET_NAMES", "inet_names")):
        if node.vars.get(var):
            v = node.vars[var]
            lines.append(f"WINLAB_{key}={shlex.quote(' '.join(map(str, v)) if isinstance(v, list) else str(v))}")
    if lab is not None:
        # The NTP server's stratum and networks; a time client's source.
        from .timesync import sh_env_lines
        lines += sh_env_lines(lab, node)
    if plan is None:
        return "\n".join(lines) + "\n"
    for link in plan.links_for(node.id):
        nic = node.nics[link.nic_index]
        seg = plan.segment_of(link.network_id)
        vids = " ".join(str(plan.segment_of(n).vid) for n in link.trunk_vlans)
        i = link.nic_index
        lines += [
            f"WINLAB_NIC{i}_IP={shlex.quote(nic.ip or '')}",
            f"WINLAB_NIC{i}_PREFIX={seg.network.prefixlen}",
            f"WINLAB_NIC{i}_GW={shlex.quote(seg.network.default_gateway)}",
            f"WINLAB_NIC{i}_TRUNK_VIDS={shlex.quote(vids)}",
            f"WINLAB_NIC{i}_WAN={'1' if seg.network.wan else '0'}",
        ]
    # A site gateway gets its tunnel: peer, prefixes and the pre-shared key
    # (the lab password; the agent channel never leaves this PC).
    from . import sites
    t = sites.tunnel_for(plan.lab, node.id)
    if t:
        lines += [
            f"WINLAB_VPN_PEER={shlex.quote(t.peer_outside_ip)}",
            f"WINLAB_VPN_PEER_NODE={shlex.quote(t.peer_node)}",
            f"WINLAB_VPN_LOCAL_IP={shlex.quote(t.local_outside_ip)}",
            f"WINLAB_VPN_LOCAL_SUBNETS={shlex.quote(' '.join(t.local_prefixes))}",
            f"WINLAB_VPN_REMOTE_SUBNETS={shlex.quote(' '.join(t.remote_prefixes))}",
            f"WINLAB_VPN_PSK={shlex.quote(t.psk)}",
        ]
    return "\n".join(lines) + "\n"


REBOOT_TOKEN = "WINLAB:REBOOT"
MAX_PASSES = 4


@dataclass
class RoleResult:
    node: str
    applied: list[str]
    skipped: list[str]
    log: list[str]


DSC_TOKEN = "WINLAB:DSC "


class _Runner:
    """Shell-specific bits of running a role in the guest."""

    def __init__(self, channel: GuestChannel, shell: str, env: str = "") -> None:
        self.ch = channel
        self.shell = shell
        self.env = env

    def stage(self, bundle: dict[str, bytes], dsc_config: str = "") -> None:
        if self.shell == "powershell":
            for name, data in bundle.items():
                self.ch.put_file(rf"C:\winlab\{name}", data)
            if dsc_config:
                self.stage_dsc(dsc_config)
        # sh roles are sent inline with each run; the probe has no PowerShell
        # for put_file to drive.

    def stage_dsc(self, config: str) -> None:
        from . import psmodules

        self.ch.put_file(r"C:\winlab\node.dsc.ps1", config.encode("utf-8"))
        apply = paths.CONTENT / "agent" / "apply-dsc.ps1"
        self.ch.put_file(r"C:\winlab\apply-dsc.ps1", apply.read_bytes())
        # The module bundle normally arrives on the provisioning data disk; a
        # lab built before the modules were fetched gets it over serial.
        have = self.ch.run(r"Test-Path 'C:\winlab\dsc-modules.zip'")
        if not (have.ok and have.out.strip().lower() == "true"):
            z = psmodules.zip_path()
            if not z.exists():
                raise RoleError(
                    f"{psmodules.ZIP_NAME} is missing; run 'winlab bootstrap' to fetch the "
                    f"DSC resource modules")
            self.ch.put_file(r"C:\winlab\dsc-modules.zip", z.read_bytes())

    def dsc_apply(self, timeout: float):
        return self.ch.run_script(r"& C:\winlab\apply-dsc.ps1", timeout=timeout, reboot_ok=True)

    def dsc_status(self, timeout: float):
        return self.ch.run_script(r"& C:\winlab\apply-dsc.ps1 -Status", timeout=timeout)

    def mark_done(self, names: list[str]) -> None:
        items = ", ".join(f"'{n}'" for n in names)
        self.ch.run(
            "New-Item -ItemType Directory -Path 'C:\\winlab\\done' -Force | Out-Null; "
            f"foreach ($n in @({items})) {{ Set-Content -Path \"C:\\winlab\\done\\$n\" "
            "-Value (Get-Date -Format o) -Encoding ascii }"
        ).raise_for_status("mark roles done")

    def is_done(self, name: str) -> bool:
        if self.shell == "powershell":
            res = self.ch.run(f"Test-Path 'C:\\winlab\\done\\{name}'")
        else:
            res = self.ch.run(f"test -f /var/lib/winlab/done/{name} && echo True",
                              shell="sh")
        return res.ok and res.out.strip().lower() == "true"

    def run(self, rd: RoleDef, timeout: float):
        if self.shell == "powershell":
            return self.ch.run_script(f"& C:\\winlab\\{rd.script}", timeout=timeout,
                                      reboot_ok=rd.reboots)
        script = (paths.ROLES / rd.script).read_text(encoding="utf-8")
        return self.ch.run(self.env + script, shell="sh", timeout=timeout,
                           reboot_ok=rd.reboots)


def role_stick_files(lab: Lab | None, node: Node, role_name: str) -> dict[str, bytes]:
    """Files a role wants beside its pack on the stick, generated from the
    lab: the grafana role's Prometheus targets, provisioning and dashboards."""
    if lab is None:
        return {}
    if role_name == "grafana":
        from . import metrics
        return metrics.stick_files(lab)
    return {}


def _plug_pack(lab: Lab | None, node: Node, pack_id: str, role_name: str = "") -> str:
    """Plugs a role's pack into the machine as a stick (a flat apt repository
    the role installs from, offline), with the role's generated files beside
    it. The pack must be fetched on this PC."""
    from . import debpacks
    if lab is None:
        return f"{pack_id}: no lab given, pack not plugged in"
    try:
        files = debpacks.pack_files(pack_id)
    except debpacks.PackError as exc:
        raise RoleError(str(exc)) from exc
    files.update(role_stick_files(lab, node, role_name))
    from . import media
    try:
        r = media.plug(lab.name, node.id, files, debpacks.STICK_LABEL)
    except media.MediaError as exc:
        raise RoleError(f"pack {pack_id}: {exc}") from exc
    return (f"{pack_id}: pack stick plugged in ({len(files)} files, {r['size_mb']} MB"
            f"{', live' if r.get('live') else ', at next start'})")


def _stage_downloads(runner: "_Runner", channel: GuestChannel, plan: list[RoleDef], log: list[str]) -> None:
    """A fetched download normally reaches the guest on its provisioning
    volume (built at every start) and lands in C:\\winlab at first logon; a
    machine that was started before the fetch gets it over the agent channel."""
    for download_id in downloads_for(plan):
        if download_id not in DOWNLOADS:
            continue
        mod = download_module(download_id)
        path = rf"C:\winlab\{mod.MAIN_FILE}"
        have = channel.run(f"Test-Path '{path}'")
        if have.ok and have.out.strip().lower() == "true":
            continue
        # The provisioning volume is a drive too: a big installer stays there.
        on_vol = channel.run("$v = Get-Volume -FileSystemLabel 'WLDATA' -ErrorAction SilentlyContinue | "
                             "Where-Object DriveLetter | Select-Object -First 1; "
                             f"[bool]($v -and (Test-Path ('{{0}}:\\{mod.MAIN_FILE}' -f $v.DriveLetter)))")
        if on_vol.ok and on_vol.out.strip().lower() == "true":
            continue
        data = mod.files()
        if not data:
            raise RoleError(f"{mod.MAIN_FILE} is not fetched: {DOWNLOADS[download_id][1]}")
        for name, blob in data.items():
            channel.put_file(rf"C:\winlab\{name}", blob)
        log.append(f"{download_id}: {mod.MAIN_FILE} sent to the guest ({len(data[mod.MAIN_FILE]) >> 10} KB)")


def _parse_dsc_status(out: str) -> dict | None:
    for line in reversed(out.splitlines()):
        if line.startswith(DSC_TOKEN):
            try:
                return json.loads(line[len(DSC_TOKEN):])
            except json.JSONDecodeError:
                return None
    return None


def _wait_back(channel: GuestChannel, shell: str, timeout: float) -> None:
    try:
        channel.wait_for_reboot(timeout=timeout)
    except GuestError:
        channel.close()
        channel.connect(retries=120, delay=5)
    channel.wait_responsive(shell=shell, timeout=timeout)


def _apply_dsc(
    runner: _Runner, channel: GuestChannel, dsc_roles: list[RoleDef],
    log: list[str], wait_ready_timeout: float, per_role_timeout: float,
) -> None:
    """One configuration for every DSC role on the node. The LCM reboots the
    machine when a resource asks (promotion, join) and resumes on its own; each
    pass here ends with Test-DscConfiguration, the only success criterion."""
    names = [rd.name for rd in dsc_roles]
    for attempt in range(1, MAX_PASSES + 1):
        log.append(f"dsc ({', '.join(names)}): applying configuration (pass {attempt})")
        rebooted = False
        try:
            res = runner.dsc_apply(per_role_timeout)
        except GuestRebooted:
            log.append("dsc: guest rebooted mid-apply (expected for promotion/join)")
            rebooted = True
            res = None
        except GuestError as exc:
            log.append(f"dsc: channel dropped ({exc}); reconnecting")
            channel.close()
            time.sleep(5)
            channel.connect(retries=120, delay=5)
            rebooted = True
            res = None

        if rebooted:
            _wait_back(channel, runner.shell, wait_ready_timeout)
            log.append("dsc: guest is back; waiting for the LCM to finish")
            res = runner.dsc_status(per_role_timeout)

        if not res.ok:
            raise RoleError(f"dsc apply failed rc={res.rc}: {(res.err or res.out).strip()[-400:]}")
        status = _parse_dsc_status(res.out)
        if status is None:
            raise RoleError("dsc apply gave no status line; see C:\\winlab\\dsc.log in the guest")
        drift = list(status.get("drift") or [])
        if status.get("in_desired_state"):
            log.append(f"dsc: {len(status.get('ok') or [])} resources in desired state")
            runner.mark_done(names)
            return
        log.append(f"dsc: {len(drift)} resource(s) not yet in desired state: {', '.join(drift[:6])}")
    raise RoleError(f"dsc configuration still drifting after {MAX_PASSES} passes: {drift}")


def apply_roles(
    node: Node,
    channel: GuestChannel,
    wait_ready_timeout: float = 2400.0,
    per_role_timeout: float = 3600.0,
    topology: TopologyPlan | None = None,
    lab: Lab | None = None,
) -> RoleResult:
    """Applies the node's roles. DSC-backed roles are compiled into one
    configuration the guest's LCM applies and verifies (see dsc.py); script
    roles then run in order. A script role that reboots prints REBOOT_TOKEN
    (or the channel drops, or the agent re-announces mid-call); the runner
    waits for the guest and runs it again, so two-pass roles finish in one
    apply. A script role that returns rc=0 without marking itself done is an
    error, not a success."""
    manifest = load_manifest()
    plan = order_roles(effective_roles(node), manifest)
    if not plan:
        return RoleResult(node.id, [], [], ["no roles requested"])
    shell = node_shell(node)
    check_shells(node, plan)
    from .servercore import role_errors
    wrong_image = check_images(node, plan) + role_errors(node)
    if wrong_image:
        raise RoleError("; ".join(wrong_image))
    missing_media = check_media(node, plan)
    if missing_media:
        raise RoleError("; ".join(missing_media))
    missing_downloads = check_downloads(node, plan)
    if missing_downloads:
        raise RoleError("; ".join(missing_downloads))
    runner = _Runner(channel, shell, sh_env(node, topology, lab) if shell == "sh" else "")

    dsc_roles = [rd for rd in plan if rd.engine == "dsc"]
    dsc_config = ""
    if dsc_roles:
        if lab is None or topology is None:
            raise RoleError("DSC roles need the lab and its topology (apply_roles(lab=, topology=))")
        from . import dsc
        cfg = dsc.compile_node(node, lab, topology, [rd.name for rd in dsc_roles])
        dsc_config = dsc.render(cfg)

    log: list[str] = []
    log.append(f"waiting for agent on {node.id}")
    channel.wait_responsive(shell=shell, timeout=wait_ready_timeout)

    bundle = _script_bundle(shell)
    runner.stage(bundle, dsc_config)
    log.append(f"staged {len(bundle)} role scripts"
               + (f" + DSC configuration ({len(cfg.resources)} resources)" if dsc_config else ""))

    applied: list[str] = []
    skipped: list[str] = []

    if dsc_roles:
        pending = [rd for rd in dsc_roles if not runner.is_done(rd.name)]
        for rd in dsc_roles:
            if rd not in pending:
                skipped.append(rd.name)
                log.append(f"{rd.name}: already applied")
        if pending:
            for image_id in media_for(pending, node):
                log.append(_insert_media(lab, node, image_id))
            _stage_downloads(runner, channel, pending, log)
            budget = max([per_role_timeout] + [rd.minutes * 60.0 for rd in pending])
            _apply_dsc(runner, channel, pending, log, wait_ready_timeout, budget)
            applied.extend(rd.name for rd in pending)

    for rd in plan:
        if rd.engine == "dsc":
            continue
        if runner.is_done(rd.name):
            skipped.append(rd.name)
            log.append(f"{rd.name}: already applied")
            continue

        if rd.pack:
            log.append(_plug_pack(lab, node, rd.pack, rd.name))
        for attempt in range(1, MAX_PASSES + 1):
            log.append(f"{rd.name}: running {rd.script} (pass {attempt})")
            rebooted = False
            try:
                res = runner.run(rd, per_role_timeout)
            except GuestRebooted:
                log.append(f"{rd.name}: guest rebooted before replying")
                rebooted = True
                res = None
            except GuestError as exc:
                if not rd.reboots:
                    raise RoleError(f"{rd.name} failed: {exc}") from exc
                # A reboot mid-role can drop the channel; reconnect.
                log.append(f"{rd.name}: channel dropped (expected reboot), reconnecting")
                channel.close()
                time.sleep(5)
                channel.connect(retries=120, delay=5)
                rebooted = True
                res = None

            if res is not None:
                out = res.out.strip()
                if out:
                    tail = [l for l in out.splitlines() if l.strip() != REBOOT_TOKEN]
                    if tail:
                        log.append(f"{rd.name}: {tail[-1]}")
                if not res.ok:
                    raise RoleError(
                        f"{rd.name} returned rc={res.rc}: {res.err.strip()[:300]}")
                if REBOOT_TOKEN in out:
                    log.append(f"{rd.name}: rebooting, waiting for the guest")
                    try:
                        channel.wait_for_reboot(timeout=wait_ready_timeout)
                    except GuestError:
                        channel.close()
                        channel.connect(retries=120, delay=5)
                    rebooted = True

            if rebooted:
                channel.wait_responsive(shell=shell, timeout=wait_ready_timeout)
            if runner.is_done(rd.name):
                applied.append(rd.name)
                break
            if not rebooted:
                raise RoleError(
                    f"{rd.name} exited cleanly but never marked itself done; "
                    f"see its log in the guest")
        else:
            raise RoleError(f"{rd.name} still not done after {MAX_PASSES} passes")

    return RoleResult(node.id, applied, skipped, log)


def test_roles(
    node: Node, channel: GuestChannel, topology: TopologyPlan, lab: Lab,
    timeout: float = 1800.0,
) -> dict:
    """Drift report: re-renders the node's configuration, compiles it in the
    guest and runs Test-DscConfiguration against it. Nothing is changed."""
    manifest = load_manifest()
    plan = order_roles(effective_roles(node), manifest)
    names = [rd.name for rd in plan if rd.engine == "dsc"]
    if not names:
        raise RoleError(f"{node.id} has no DSC-backed roles to test")
    from . import dsc
    cfg = dsc.compile_node(node, lab, topology, names)
    runner = _Runner(channel, "powershell")
    channel.wait_responsive(timeout=timeout)
    runner.stage_dsc(dsc.render(cfg))
    res = channel.run_script(
        r"& C:\winlab\node.dsc.ps1 | Out-Null; & C:\winlab\apply-dsc.ps1 -Status",
        timeout=timeout)
    if not res.ok:
        raise RoleError(f"dsc test failed rc={res.rc}: {(res.err or res.out).strip()[-400:]}")
    status = _parse_dsc_status(res.out)
    if status is None:
        raise RoleError("dsc test gave no status line; see C:\\winlab\\dsc.log in the guest")
    status["roles"] = names
    return status


def render_status(node: Node, status: dict) -> str:
    lines = [f"desired-state check for {node.id} ({', '.join(status.get('roles', []))})"]
    for rid in status.get("ok") or []:
        lines.append(f"  ok     {rid}")
    for rid in status.get("drift") or []:
        lines.append(f"  DRIFT  {rid}")
    verdict = "in desired state" if status.get("in_desired_state") else \
        f"{len(status.get('drift') or [])} resource(s) differ from the lab definition"
    lines.append(f"result: {verdict}")
    return "\n".join(lines)


def describe_plan(node: Node, lab: Lab | None = None, topology: TopologyPlan | None = None) -> str:
    manifest = load_manifest()
    eff = effective_roles(node)
    plan = order_roles(eff, manifest)
    check_shells(node, plan)
    lines = [f"role plan for {node.id} (requested: {', '.join(eff) or 'none'})"]
    dsc_names = [rd.name for rd in plan if rd.engine == "dsc"]
    if dsc_names:
        lines.append(f"  one DSC configuration: {', '.join(dsc_names)}")
        if lab is not None and topology is not None:
            from . import dsc
            cfg = dsc.compile_node(node, lab, topology, dsc_names)
            lines.append(dsc.describe(cfg))
    for i, rd in enumerate([r for r in plan if r.engine != "dsc"], 1):
        auto = "" if rd.name in effective_roles(node) else "  (pulled in as dependency)"
        reboot = "  [reboots]" if rd.reboots else ""
        lines.append(f"  {i}. {rd.name}{reboot}{auto}")
        if rd.description:
            lines.append(f"       {rd.description}")
    return "\n".join(lines)
