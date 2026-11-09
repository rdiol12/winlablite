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

winlab's own native window comes first (``nativewin``: WebView2 on Windows,
WebKitGTK on Linux, no browser behind it), started as ``winlab window <url>``.
If it cannot start, the Edge app window opens instead and the desktop says
why; ``WINLAB_BROWSER=edge`` asks for the Edge window outright. Closing the
window (native or app window) stops the desktop.
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
               "google-chrome-stable", "chromium", "chromium-browser", "chrome",
               "brave-browser", "vivaldi-stable", "vivaldi")


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


# `winlab window` exits with this when the desktop went to a browser tab it
# cannot follow: the desktop then keeps running until it is stopped.
UNTRACKED = 4
# A browser process that ends this fast handed the window to one already open
# (the same profile), so its end is not the window closing.
HANDED_OFF = 5.0


def open_native(url: str, wait: float = 2.0, popen=subprocess.Popen):
    """Start winlab's own window as a process of its own: that process, or
    None when it could not start or quit at once with an error."""
    from . import nativewin

    try:
        proc = popen(nativewin.window_command(url), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=_detached(), close_fds=True)
    except OSError:
        return None
    # A window that cannot start at all (the program missing, an import
    # error) exits within a moment; one that runs is still there. A window
    # that fails later falls back to the browser window by itself.
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        code = proc.poll()
        if code is not None:
            return proc if code in (0, UNTRACKED) else None
        time.sleep(0.1)
    return proc


def open_browser_window(url: str, profile: Path, env: dict | None = None):
    """The Edge/Chrome app window, else a tab of the default browser:
    ("app", process) or ("tab", None)."""
    env = os.environ if env is None else env
    browser = None if env.get("WINLAB_BROWSER", "").lower() == "tab" else find_browser(env)
    if browser:
        try:
            profile.mkdir(parents=True, exist_ok=True)
            proc = subprocess.Popen(app_args(browser, url, profile), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    creationflags=_detached(), close_fds=True)
            return "app", proc
        except OSError:
            pass
    webbrowser.open(url)
    return "tab", None


def wait_browser(proc) -> bool:
    """Wait for an app window's browser process; True when that was the
    window closing (not a hand-off to a window already open)."""
    start = time.monotonic()
    proc.wait()
    return time.monotonic() - start >= HANDED_OFF


def _follow(target, *args) -> None:
    import threading

    threading.Thread(target=target, args=args, daemon=True).start()


def _follow_browser(proc, on_closed) -> None:
    if wait_browser(proc):
        on_closed()


def _follow_native(proc, url: str, profile: Path, env: dict, on_closed) -> None:
    from . import nativewin

    code = proc.wait()
    if code == 0:
        on_closed()
    elif code != UNTRACKED:
        # The window process ended by itself (a crash): the desktop is still
        # running, so bring it back in the browser window, saying why.
        nativewin.note_fallback("crashed", f"winlab's window ended unexpectedly (exit code {code})")
        how, again = open_browser_window(url, profile, env)
        if again is not None:
            _follow_browser(again, on_closed)


def open_window(url: str, profile: Path, env: dict | None = None,
                native=None, on_closed=None) -> str:
    """Open ``url`` as a program window; return how it opened ("native",
    "app" or "tab"). ``on_closed`` is called (from another thread) when the
    user closes that window; a browser tab cannot be followed."""
    from . import nativewin

    env = os.environ if env is None else env
    if native is None:
        native = False
        if nativewin.env_allows(env):
            code, detail = nativewin.unavailable(env)
            if code:
                nativewin.note_fallback(code, detail)
            else:
                native = True
    if native:
        nativewin.clear_fallback()
        proc = open_native(url)
        if proc is not None:
            if on_closed:
                _follow(_follow_native, proc, url, profile, env, on_closed)
            return "native"
        nativewin.note_fallback("crashed", "winlab's window ended as it started")
    how, proc = open_browser_window(url, profile, env)
    if on_closed and proc is not None:
        _follow(_follow_browser, proc, on_closed)
    return how
