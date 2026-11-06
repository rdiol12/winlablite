"""Each device's real management software, and where the student opens it.

A real printer, NAS, phone system or firewall is managed from its own web
pages: CUPS on the printer, OpenMediaVault on the NAS, FreePBX on the phone
system, LuCI on an OpenWrt access point. In winlab each of those runs inside
the device, on the lab network only, exactly as the real one does. The
student reaches it the way an admin does at work: from a browser on a PC of
the same lab (Edge on a Windows machine, Firefox on the Admin workstation),
typing the device's address, through that PC's own screen.

Nothing here talks to a device. This module only says, for the device's
window, which software the device runs, the address and port to type, and
which lab machines have a browser to type it into. The app never forwards a
device's port to this PC, never opens its pages in the host's browser and
never signs in for the student (hands-on rule): the "Manage from..." picker
only brings the chosen PC's screen to the front.

Device modules add what they serve with ``register``: a function from
(lab, node) to an ``AdminGui`` (or None for a node that is not theirs), and,
for devices that are not machines (a BMC on the router, a UPS network
card), a function from a lab to a list of ``Target``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from . import servercore


@dataclass(frozen=True)
class AdminGui:
    software: str          # "CUPS 2.4", "OpenMediaVault 7"
    scheme: str = "http"   # what the student types: http or https
    port: int = 80
    path: str = "/"
    sign_in: str = ""      # who signs in, in words (never a password)
    license: str = ""      # the software's own licence, as LICENSING.md lists it
    note: str = ""         # one sentence on what is done there

    def url(self, host: str) -> str:
        default = {"http": 80, "https": 443}.get(self.scheme)
        port = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{host}{port}{self.path}"

    def view(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Target:
    """A management page that is not a lab machine of its own: the BMC of a
    server, a UPS's network card. ``key`` is the device window it belongs to."""
    key: str
    title: str
    host: str              # its address on the lab network
    gui: AdminGui

    def view(self) -> dict:
        return {"key": self.key, "title": self.title, "host": self.host,
                "url": self.gui.url(self.host), **self.gui.view()}


_NODE_GUIS: list = []
_TARGETS: list = []


def register(node_gui=None, targets=None) -> None:
    if node_gui is not None and node_gui not in _NODE_GUIS:
        _NODE_GUIS.append(node_gui)
    if targets is not None and targets not in _TARGETS:
        _TARGETS.append(targets)


def _load_providers() -> None:
    # Device modules register at import; import them here so a view never
    # depends on what else happened to be imported first.
    from . import appliance, bsdfw, opnsense  # noqa: F401
    for mod in ("wifi", "ups", "power", "mail", "san", "adminpc", "omv", "voip", "webmin", "linuxiso", "doctools"):
        try:
            __import__(f"{__package__}.{mod}")
        except ImportError:
            pass


def gui_of(lab, node) -> AdminGui | None:
    """The management software the machine serves on the lab network."""
    _load_providers()
    for fn in _NODE_GUIS:
        gui = fn(lab, node)
        if gui is not None:
            return gui
    return None


def targets(lab) -> list[Target]:
    _load_providers()
    out: list[Target] = []
    for fn in _TARGETS:
        out.extend(fn(lab))
    return out


def has_browser(node) -> bool:
    """A machine the student can open a device's pages from: Windows with a
    desktop (Server Core has no browser), or the Admin workstation."""
    if node.is_windows:
        return not servercore.is_core_image(node.image)
    from . import appliance
    return appliance.device_of(node) == "adminpc"


def node_view(lab, node) -> dict:
    """The fields the workbench adds to a machine."""
    gui = gui_of(lab, node)
    return {"admin": gui.view() if gui else None, "browser": has_browser(node)}


def lab_view(lab) -> list[dict]:
    return [t.view() for t in targets(lab)]


# ---- the firewalls: their own web GUI, already the real thing.

def _firewall_gui(lab, node):
    from . import bsdfw
    image = node.image
    if image in getattr(bsdfw, "FIREWALLS", {}) or image == "opnsense":
        title = "pfSense CE" if image.startswith("pfsense") else "OPNsense"
        who = ("root, with the lab's password (Start > Lab password)" if image == "opnsense"
               else "root, with the password you set during its install")
        return AdminGui(software=f"{title} web GUI", scheme="https", port=443, path="/", sign_in=who,
                        license="BSD-2-Clause" if title == "OPNsense" else "Apache-2.0",
                        note="Interfaces, firewall rules, NAT, DHCP and VPN, on its LAN address.")
    return None


register(node_gui=_firewall_gui)
