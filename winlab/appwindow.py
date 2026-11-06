"""Open the desktop in a window of its own, the way an installed program looks.

A plain ``webbrowser.open`` drops the desktop into a tab of whatever browser
the user has, beside their mail, with an address bar and tabs above it: it
reads as a web page. Every Windows 10/11 PC has Microsoft Edge, and Edge (like
Chrome and Chromium) has an app mode: ``--app=<url>`` opens one window with no
tabs, no address bar and no browser menus, its own taskbar button and the
page's title and icon. That is how winlab opens.

Nothing is bundled: the browser is the one already on the PC, started as a
separate process with its own profile folder under ``var/appwindow`` so the
window is never merged into the user's open browser session and none of their
extensions or sign-ins come along. When no such browser is found, or
``WINLAB_BROWSER=tab`` is set, the default browser opens the page as before.

On Windows, winlab's own native window comes first (``nativewin``: a Win32
window with WebView2 drawing the desktop, no browser behind it), started as
``winlab window <url>``. If it cannot start, the Edge app window opens
instead; ``WINLAB_BROWSER=edge`` asks for the Edge window outright.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

# Edge first: it ships with Windows, so it is there on every customer's PC.
_WINDOWS = (
    ("PROGRAMFILES(X86)", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", r"Microsoft\Edge\Application\msedge.exe"),
    ("LOCALAPPDATA", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", r"Google\Chrome\Application\chrome.exe"),
    ("PROGRAMFILES(X86)", r"Google\Chrome\Application\chrome.exe"),
    ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
)
_MAC = (
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)
_PATH_NAMES = ("msedge", "microsoft-edge", "microsoft-edge-stable", "google-chrome",
               "google-chrome-stable", "chromium", "chromium-browser", "chrome")


def find_browser(env: dict | None = None, platform: str | None = None,
                 exists=os.path.isfile, which=shutil.which) -> str | None:
    """The first Chromium-family browser on this PC that has an app mode."""
    env = os.environ if env is None else env
    platform = platform or sys.platform
    if platform.startswith("win"):
        for var, rel in _WINDOWS:
            base = env.get(var)
            if base and exists(str(Path(base) / rel)):
                return str(Path(base) / rel)
    elif platform == "darwin":
        for p in _MAC:
            if exists(p):
                return p
    for name in _PATH_NAMES:
        found = which(name)
        if found:
            return found
    return None


def app_args(browser: str, url: str, profile: Path) -> list[str]:
    """The command line for one app window on ``url``."""
    return [browser, f"--app={url}", f"--user-data-dir={profile}",
            "--no-first-run", "--no-default-browser-check", "--start-maximized"]


def _detached() -> int:
    if sys.platform.startswith("win"):
        return subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    return 0


def open_native(url: str, wait: float = 2.0, popen=subprocess.Popen) -> bool:
    """Start winlab's native window; False if it is not there or quit at once."""
    from . import nativewin

    try:
        proc = popen(nativewin.window_command(url), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=_detached(), close_fds=True)
    except OSError:
        return False
    # A window that cannot start (no runtime, a policy blocking it) exits
    # within a moment; one that runs is still there.
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        code = proc.poll()
        if code is not None:
            return code == 0
        time.sleep(0.1)
    return True


def open_window(url: str, profile: Path, env: dict | None = None,
                native=None) -> str:
    """Open ``url`` as a program window; return how it opened
    ("native", "app" or "tab")."""
    env = os.environ if env is None else env
    if native is None:
        from . import nativewin
        native = nativewin.env_allows(env) and nativewin.available()
    if native and open_native(url):
        return "native"
    browser = None if env.get("WINLAB_BROWSER", "").lower() == "tab" else find_browser(env)
    if browser:
        try:
            profile.mkdir(parents=True, exist_ok=True)
            subprocess.Popen(app_args(browser, url, profile), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             creationflags=_detached(), close_fds=True)
            return "app"
        except OSError:
            pass
    webbrowser.open(url)
    return "tab"
