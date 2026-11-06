"""Server Core: Windows Server without the desktop, as a choice wherever a
Windows Server is picked (the workbench shelf, `edition =` on a lab node,
templates made from a Core machine).

Microsoft's evaluation ISOs for Server 2025, 2022 and 2019 carry both
installation options as separate install.wim images (SERVERSTANDARDCORE and
SERVERSTANDARD, the same for Datacenter). A ready-made Core machine is a
separate base, `ws2025-core` and so on, prepared from the same ISO:
images.pick_edition chooses the Core image of the media, unattend.py tells
Setup to install it. A hand-installed server is the student's own choice in
Setup, so there is nothing to choose here.

Core runs every role winlab applies except the ones Microsoft does not ship
on it (role_errors), and its screen opens on sconfig, not a desktop, which
the console helpers (dropped files, typed text) allow for.
"""
from __future__ import annotations

CORE = "core"
DESKTOP = "desktop"
# What a lab file may write for `edition =`.
EDITIONS = {"core": CORE, "server core": CORE, "servercore": CORE,
            "desktop": DESKTOP, "desktop experience": DESKTOP, "gui": DESKTOP}

# Roles that need what Server Core does not have: the installation option
# is fixed at setup, so the message says to pick the Desktop base instead.
NOT_ON_CORE = {
    "rds": "Remote Desktop Session Host is not available on Server Core",
    "nps": "Network Policy Server (NPAS) is not available on Server Core",
    "mecm": "a Configuration Manager site server needs the Desktop Experience",
}

# Where a file dropped on a Core machine's screen goes: no desktop to put it
# on, so a short path that is quick to type at its prompt.
DROP_FOLDER = "C:\\FromPC"

# What a Core machine saves against the Desktop base of the same release,
# for the memory budget's advice: the floor winlab boots it at (model.py)
# and, loosely, the system disk a fresh install takes.
DISK_SAVED_GB = 5


def core_image(image: str) -> str:
    return image if image.endswith("-core") else f"{image}-core"


def desktop_image(image: str) -> str:
    return image[:-5] if image.endswith("-core") else image


def with_edition(image: str, edition) -> str:
    """The catalog image for `image` in the edition asked for ('' keeps it).
    ValueError when the edition is unknown or the image has no Core base."""
    from .images import CATALOG
    if edition in (None, ""):
        return image
    want = EDITIONS.get(str(edition).strip().lower())
    if want is None:
        raise ValueError(f"edition is 'core' (Server Core, no desktop) or 'desktop' "
                         f"(Desktop Experience), not {edition!r}")
    base = desktop_image(image)
    if base not in CATALOG or core_image(base) not in CATALOG:
        raise ValueError(f"edition applies to the Windows Server images "
                         f"({', '.join(i for i in CATALOG if core_image(i) in CATALOG and not i.endswith('-core'))}), "
                         f"not {image!r}")
    return core_image(base) if want == CORE else base


def is_core_image(image: str) -> bool:
    """A Core catalog image, or a template whose machine was made from one."""
    if image.endswith("-core"):
        return True
    try:
        from .images import CATALOG, catalog_root
        if not image or image in CATALOG:
            return False
        root = catalog_root(image)
    except Exception:
        return False
    return bool(root and root.id.endswith("-core"))


def role_errors(node) -> list[str]:
    """The node's roles Server Core cannot run, as sentences; empty when all
    is well or the machine is not Core."""
    if not node.is_server_core:
        return []
    return [f"node '{node.id}': role '{r}' cannot run on Server Core: {NOT_ON_CORE[r]}; "
            f"use the Desktop base (image = \"{desktop_image(node.image)}\" or edition = \"desktop\")"
            for r in node.roles if r in NOT_ON_CORE]


def budget_hint(lab, ids: list[str]) -> list[str]:
    """When the host is short of memory: the Desktop servers that would fit
    as Server Core, and what that would free."""
    from .model import RECOMMENDED_CORE_MEMORY_MB, WINDOWS_SERVER
    from .images import CATALOG
    could = [lab.nodes[n] for n in ids
             if lab.nodes[n].kind == WINDOWS_SERVER and not lab.nodes[n].is_server_core
             and core_image(lab.nodes[n].image) in CATALOG
             and not any(r in NOT_ON_CORE for r in lab.nodes[n].roles)]
    freed = sum(max(0, n.memory_mb - RECOMMENDED_CORE_MEMORY_MB) for n in could)
    if not could or freed <= 0:
        return []
    return [f"  as Server Core (no desktop), {', '.join(n.id for n in could)} would boot in "
            f"{RECOMMENDED_CORE_MEMORY_MB} MB each, freeing about {freed / 1024:.1f} GiB "
            f"(and about {DISK_SAVED_GB} GB of disk each): edition = \"core\" on the node, "
            f"or pick Server Core when adding a server on the workbench"]
