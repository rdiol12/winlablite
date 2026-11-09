"""The parts of winlab the trial does not ship.

The winlab trial is the full program's engine with three labs. The code of
everything else (the other labs, exam prep, scenarios, the Building window,
the career game's helpdesk and the rest) is not in this source tree at all,
so nothing in it can be switched back on.

The engine still names those parts where the full app plugs them in: a
registry of drills, a role builder, an API route of a window the trial hides.
Importing one of them here gives an empty stand-in instead of an error. Every
attribute of the stand-in is another stand-in: calling it does nothing and
returns a stand-in, it is false, empty and iterates over nothing, and its
Error classes are real exception classes that nothing raises. So a registry
gains no entries, a route answers with nothing, and the trial runs on.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import sys
import types

ABSENT = frozenset({
    "activity", "advnet", "aidc", "alerts", "apos", "automation", "aws", "azure",
    "bareos", "bluescreen", "blueteam", "breakfix", "building", "buildlife",
    "buildlive", "buildsys", "cabletest", "calab", "campus", "capstones", "castplayer",
    "ccnpfaults", "certshare", "classes", "company", "consolel3", "containers",
    "dashlab", "databases", "dayops", "dcrollback", "deskops", "desksupport", "devops",
    "doctools", "drsite", "edge", "exams", "fileops", "filesharing", "freeload",
    "guide", "helpdesk", "hmdm", "hwfaults", "identityops", "ids", "incidents",
    "inherited", "interview", "irtools", "itops", "kubeadm", "l2checks", "lifecycle",
    "linuxadmin", "linuxdomain", "linuxidentity", "linuxplus", "mail", "mecm",
    "metrics", "netdocs", "netops", "officemedia", "omv", "oncall", "openwisp",
    "pcsupport", "people", "phonedesk", "pixiview", "pki", "practice_exam",
    "printerfaults", "printing", "rack", "recordings", "remoteaccess", "remotesupport",
    "san", "scenariofaults", "scenarios", "secops", "serverha", "serverhw",
    "serverroom", "servicedesk", "shift", "softphone", "ticketgame", "traffic", "unifi",
    "updates", "usmtmedia", "vmbackup", "voip", "wac", "wear", "wearfaults", "webfarm",
    "webproxy", "wifiplan", "wifivendors", "workday", "wsbackup", "wshybrid",
})


class _Nothing:
    """A part the trial leaves out: does nothing, holds nothing."""

    __slots__ = ("_name",)

    def __init__(self, name: str = "") -> None:
        object.__setattr__(self, "_name", name)

    def __getattr__(self, attr: str):
        if attr.startswith("__"):
            raise AttributeError(attr)
        if attr.endswith("Error") or attr.endswith("Exception"):
            return _error(f"{self._name}.{attr}")
        return _Nothing(f"{self._name}.{attr}")

    def __call__(self, *args, **kwargs):
        return _Nothing(self._name)

    def __bool__(self) -> bool:
        return False

    def __len__(self) -> int:
        return 0

    def __iter__(self):
        return iter(())

    def __contains__(self, item) -> bool:
        return False

    def __getitem__(self, key):
        return _Nothing(self._name)

    def __setitem__(self, key, value) -> None:
        return None

    def keys(self):
        return ()

    def items(self):
        return ()

    def values(self):
        return ()

    def get(self, key, default=None):
        return default

    def __int__(self) -> int:
        return 0

    def __float__(self) -> float:
        return 0.0

    def __repr__(self) -> str:
        return f"<not in the winlab trial: {self._name}>"

    def __str__(self) -> str:
        return ""


_errors: dict[str, type] = {}


def _error(name: str) -> type:
    if name not in _errors:
        _errors[name] = type(name.rsplit(".", 1)[-1], (Exception,), {"__module__": name.rsplit(".", 1)[0]})
    return _errors[name]


class _Absent(types.ModuleType):
    def __getattr__(self, attr: str):
        if attr.startswith("__"):
            raise AttributeError(attr)
        if attr.endswith("Error") or attr.endswith("Exception"):
            return _error(f"{self.__name__}.{attr}")
        return _Nothing(f"{self.__name__}.{attr}")


class _Finder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        pkg, _, leaf = fullname.rpartition(".")
        if pkg == "winlab" and leaf in ABSENT:
            return importlib.machinery.ModuleSpec(fullname, self)
        return None

    def create_module(self, spec):
        mod = _Absent(spec.name, "not in the winlab trial")
        mod.__file__ = None
        mod.TRIAL_ABSENT = True
        return mod

    def exec_module(self, module):
        return None


def install() -> None:
    if not any(isinstance(f, _Finder) for f in sys.meta_path):
        sys.meta_path.append(_Finder())


def as_json(obj):
    """json.dumps' default=: a left-out part is null."""
    if isinstance(obj, _Nothing):
        return None
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def absent(name: str) -> bool:
    """Whether the trial leaves out winlab.<name>."""
    return name in ABSENT
