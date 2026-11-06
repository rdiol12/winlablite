"""winlab's own program window on Windows: a native Win32 window with the
desktop drawn inside by Microsoft Edge WebView2, so no browser is behind it.

WebView2 is the web view Windows 10 and 11 carry as a system component (the
"Evergreen" runtime): Windows keeps it updated and nothing of it is bundled.
Hosting it takes ``WebView2Loader.dll`` from Microsoft's WebView2 SDK. Like
QEMU and noVNC, it is fetched on the customer's PC at setup (``fetch``,
from nuget.org, the SDK's home), never shipped with winlab.

The host is written against the WebView2 COM interfaces with ``ctypes`` only:
a window class and message loop (user32), the environment created by the
loader, a controller filling the window's client area, and the web view on
the desktop's URL. Two events are handled: the page's title becomes the
window's, and an element going full screen (a machine's screen, View > Full
screen) makes the window cover its monitor, as a full-screen program does.

When anything is missing (not Windows, no loader, no runtime) or the host
fails to start, ``appwindow`` falls back to the Edge/Chrome app window.
"""

from __future__ import annotations

import ctypes
import io
import json
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

from . import paths

# The WebView2 SDK on nuget.org: this version, or the newest stable one when
# the feed no longer has it. Only the loader DLL is taken from the package.
SDK_PACKAGE = "microsoft.web.webview2"
SDK_VERSION = "1.0.2903.40"
FEED = "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2"
LOADER_IN_PACKAGE = "runtimes/win-x64/native/WebView2Loader.dll"
APP_ID = "winlab.desktop"

# Vtable slots (after IUnknown's QueryInterface, AddRef, Release), in the
# order of WebView2.idl.
ENV_CREATE_CONTROLLER = 3
CTL_PUT_IS_VISIBLE = 4
CTL_PUT_BOUNDS = 6
CTL_MOVE_FOCUS = 12
CTL_CLOSE = 24
CTL_GET_COREWEBVIEW2 = 25
WV_GET_SETTINGS = 3
WV_NAVIGATE = 5
WV_ADD_DOCUMENT_TITLE_CHANGED = 46
WV_GET_DOCUMENT_TITLE = 48
WV_ADD_FULLSCREEN_CHANGED = 52
WV_GET_CONTAINS_FULLSCREEN = 54
SET_PUT_STATUS_BAR = 10
SET_PUT_DEV_TOOLS = 12
SET_PUT_ZOOM_CONTROL = 18

S_OK = 0
E_NOINTERFACE = 0x80004002 - (1 << 32)
# Interfaces a callback object must not claim: COM would then call it from
# other threads or try to marshal it.
_REFUSED_IIDS = {
    0x94EA2B94,  # IAgileObject
    0x00000003,  # IMarshal
}


class NativeWindowError(Exception):
    pass


def loader_path() -> Path:
    return paths.RUNTIME / "webview2" / "WebView2Loader.dll"


def _get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "winlab-bootstrap"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def pick_version(index: dict, wanted: str = SDK_VERSION) -> str:
    """The pinned SDK version if the feed has it, else its newest stable one."""
    versions = [v for v in index.get("versions", []) if "-" not in v]
    if wanted in versions:
        return wanted
    if not versions:
        raise NativeWindowError("nuget.org lists no WebView2 SDK version")
    return max(versions, key=lambda v: tuple(int(p) for p in v.split(".") if p.isdigit()))


def loader_from_package(nupkg: bytes) -> bytes:
    """WebView2Loader.dll (64-bit) out of the SDK package, checked to be one."""
    try:
        with zipfile.ZipFile(io.BytesIO(nupkg)) as z:
            dll = z.read(LOADER_IN_PACKAGE)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise NativeWindowError(f"the WebView2 SDK package has no 64-bit loader: {exc}") from None
    if not is_x64_dll(dll):
        raise NativeWindowError("the WebView2 loader in the package is not a 64-bit Windows DLL")
    return dll


def is_x64_dll(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    pe = int.from_bytes(data[0x3C:0x40], "little")
    return data[pe:pe + 4] == b"PE\0\0" and int.from_bytes(data[pe + 4:pe + 6], "little") == 0x8664


def fetch(refresh: bool = False, get=_get, say=print) -> Path:
    """Put WebView2Loader.dll under runtime/webview2 (setup calls this)."""
    dest = loader_path()
    if dest.exists() and not refresh:
        say(f"WebView2 loader already fetched ({dest})")
        return dest
    version = pick_version(json.loads(get(f"{FEED}/index.json")))
    nupkg = get(f"{FEED}/{version}/{SDK_PACKAGE}.{version}.nupkg")
    dll = loader_from_package(nupkg)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    tmp.write_bytes(dll)
    tmp.replace(dest)
    (dest.parent / "VERSION").write_text(version + "\n", encoding="utf-8")
    say(f"WebView2 loader {version} ready in {dest.parent}")
    return dest


def runtime_version() -> str:
    """The installed WebView2 runtime's version ("" when there is none)."""
    if sys.platform != "win32" or not loader_path().exists():
        return ""
    try:
        loader = ctypes.WinDLL(str(loader_path()))
        out = ctypes.c_wchar_p()
        hr = loader.GetAvailableCoreWebView2BrowserVersionString(None, ctypes.byref(out))
        if hr != S_OK or not out.value:
            return ""
        version = out.value
        ctypes.windll.ole32.CoTaskMemFree(ctypes.cast(out, ctypes.c_void_p))
        return version
    except (OSError, AttributeError):
        return ""


def available() -> bool:
    return bool(runtime_version())


# ---------------------------------------------------------------- COM glue
HRESULT = ctypes.c_long
_FN = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]


class RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


class Token(ctypes.Structure):  # EventRegistrationToken
    _fields_ = [("value", ctypes.c_int64)]


class Callback:
    """A COM object of one method beyond IUnknown (``Invoke``): what WebView2
    takes as a completion or event handler. ``argtypes`` are Invoke's
    arguments after ``this``; ``fn`` gets them and returns an HRESULT."""

    def __init__(self, argtypes: list, fn):
        self._refs = 1
        self._fn = fn
        qi = _FN(HRESULT, ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.POINTER(ctypes.c_void_p))(self._qi)
        add = _FN(ctypes.c_ulong, ctypes.c_void_p)(self._addref)
        rel = _FN(ctypes.c_ulong, ctypes.c_void_p)(self._release)
        inv = _FN(HRESULT, ctypes.c_void_p, *argtypes)(self._invoke)
        self._keep = (qi, add, rel, inv)
        self._vtbl = (ctypes.c_void_p * 4)(*(ctypes.cast(f, ctypes.c_void_p).value for f in self._keep))
        self._obj = (ctypes.c_void_p * 1)(ctypes.addressof(self._vtbl))
        self.ptr = ctypes.addressof(self._obj)

    def _qi(self, this, riid, ppv):
        if riid and riid.contents.Data1 in _REFUSED_IIDS:
            ppv[0] = None
            return E_NOINTERFACE
        ppv[0] = this
        self._refs += 1
        return S_OK

    def _addref(self, this):
        self._refs += 1
        return self._refs

    def _release(self, this):
        self._refs = max(0, self._refs - 1)
        return self._refs

    def _invoke(self, this, *args):
        try:
            return self._fn(*args) or S_OK
        except Exception:  # an exception must not cross back into COM
            return S_OK


def vcall(obj: int, slot: int, argtypes: list, *args, restype=HRESULT):
    """Call method ``slot`` of the COM object at address ``obj``."""
    vtbl = ctypes.cast(ctypes.c_void_p(obj), ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    fn = _FN(restype, ctypes.c_void_p, *argtypes)(vtbl[slot])
    hr = fn(obj, *args)
    if restype is HRESULT and hr < 0:
        raise NativeWindowError(f"WebView2 call {slot} failed: 0x{hr & 0xFFFFFFFF:08X}")
    return hr


# ---------------------------------------------------------------- the window
WS_OVERLAPPEDWINDOW = 0x00CF0000
WS_POPUP = 0x80000000
WS_VISIBLE = 0x10000000
GWL_STYLE = -16
CW_USEDEFAULT = -0x80000000
SW_SHOWMAXIMIZED = 3
WM_DESTROY = 0x0002
WM_SIZE = 0x0005
WM_SETFOCUS = 0x0007
WM_CLOSE = 0x0010
IMAGE_ICON = 1
LR_LOADFROMFILE = 0x10
LR_DEFAULTSIZE = 0x40
SWP_FRAMECHANGED = 0x0020
SWP_NOZORDER = 0x0004
SWP_NOOWNERZORDER = 0x0200
MONITOR_DEFAULTTONEAREST = 2


def run(url: str, profile: Path, title: str = "winlab") -> int:
    """Open the window on ``url`` and run until it is closed. Raises
    NativeWindowError when WebView2 cannot start, so the caller falls back."""
    if sys.platform != "win32":
        raise NativeWindowError("the native window is a Windows program")
    if not loader_path().exists():
        raise NativeWindowError("the WebView2 loader is not fetched yet (run setup)")
    from ctypes import wintypes as W

    user32, kernel32, ole32 = ctypes.windll.user32, ctypes.windll.kernel32, ctypes.windll.ole32
    loader = ctypes.WinDLL(str(loader_path()))
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
        user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))  # per monitor v2
    except (AttributeError, OSError):
        pass
    ole32.CoInitializeEx(None, 2)  # apartment threaded, as WebView2 wants

    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, W.HWND, W.UINT, W.WPARAM, W.LPARAM)
    # Handles are 64-bit: every call that takes or returns one is typed, or
    # ctypes would cut them to a C int.
    for fn, res, args in (
        (user32.DefWindowProcW, LRESULT, [W.HWND, W.UINT, W.WPARAM, W.LPARAM]),
        (kernel32.GetModuleHandleW, W.HMODULE, [W.LPCWSTR]),
        (user32.LoadImageW, W.HANDLE, [W.HINSTANCE, W.LPCWSTR, W.UINT, ctypes.c_int, ctypes.c_int, W.UINT]),
        (user32.LoadCursorW, W.HANDLE, [W.HINSTANCE, ctypes.c_void_p]),
        (user32.CreateWindowExW, W.HWND, [W.DWORD, W.LPCWSTR, W.LPCWSTR, W.DWORD, ctypes.c_int, ctypes.c_int,
                                          ctypes.c_int, ctypes.c_int, W.HWND, W.HMENU, W.HINSTANCE, W.LPVOID]),
        (user32.GetClientRect, W.BOOL, [W.HWND, ctypes.POINTER(RECT)]),
        (user32.GetWindowRect, W.BOOL, [W.HWND, ctypes.POINTER(RECT)]),
        (user32.SetWindowTextW, W.BOOL, [W.HWND, W.LPCWSTR]),
        (user32.ShowWindow, W.BOOL, [W.HWND, ctypes.c_int]),
        (user32.IsZoomed, W.BOOL, [W.HWND]),
        (user32.DestroyWindow, W.BOOL, [W.HWND]),
        (user32.MonitorFromWindow, W.HMONITOR, [W.HWND, W.DWORD]),
        (user32.GetWindowLongPtrW, ctypes.c_ssize_t, [W.HWND, ctypes.c_int]),
        (user32.SetWindowLongPtrW, ctypes.c_ssize_t, [W.HWND, ctypes.c_int, ctypes.c_ssize_t]),
        (user32.SetWindowPos, W.BOOL, [W.HWND, W.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                       ctypes.c_int, W.UINT]),
        (user32.GetMessageW, W.BOOL, [ctypes.POINTER(W.MSG), W.HWND, W.UINT, W.UINT]),
        (user32.TranslateMessage, W.BOOL, [ctypes.POINTER(W.MSG)]),
        (user32.DispatchMessageW, LRESULT, [ctypes.POINTER(W.MSG)]),
        (ole32.CoTaskMemFree, None, [ctypes.c_void_p]),
    ):
        fn.restype, fn.argtypes = res, args

    class WNDCLASSEXW(ctypes.Structure):
        _fields_ = [("cbSize", W.UINT), ("style", W.UINT), ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                    ("hInstance", W.HINSTANCE), ("hIcon", W.HICON), ("hCursor", W.HANDLE),
                    ("hbrBackground", W.HBRUSH), ("lpszMenuName", W.LPCWSTR),
                    ("lpszClassName", W.LPCWSTR), ("hIconSm", W.HICON)]

    class MONITORINFO(ctypes.Structure):
        _fields_ = [("cbSize", W.DWORD), ("rcMonitor", RECT), ("rcWork", RECT), ("dwFlags", W.DWORD)]

    st = {"controller": None, "webview": None, "error": None, "full": False, "placement": None}
    keep: list = []

    def fit(hwnd):
        if st["controller"]:
            rc = RECT()
            user32.GetClientRect(hwnd, ctypes.byref(rc))
            vcall(st["controller"], CTL_PUT_BOUNDS, [RECT], rc)

    def wndproc(hwnd, msg, wp, lp):
        try:
            if msg == WM_SIZE:
                fit(hwnd)
                return 0
            if msg == WM_SETFOCUS and st["controller"]:
                vcall(st["controller"], CTL_MOVE_FOCUS, [ctypes.c_int], 0)
                return 0
            if msg == WM_DESTROY:
                if st["controller"]:
                    vcall(st["controller"], CTL_CLOSE, [])
                user32.PostQuitMessage(0)
                return 0
        except NativeWindowError:
            pass
        return user32.DefWindowProcW(hwnd, msg, wp, lp)

    proc = WNDPROC(wndproc)
    keep.append(proc)
    hinst = kernel32.GetModuleHandleW(None)
    icon = None
    try:
        from . import appicon
        ico = appicon.write(profile / "winlab.ico")
        icon = user32.LoadImageW(None, str(ico), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE)
    except Exception:  # an icon is a nicety
        icon = None
    wc = WNDCLASSEXW(cbSize=ctypes.sizeof(WNDCLASSEXW), lpfnWndProc=proc, hInstance=hinst,
                     hIcon=icon, hIconSm=icon, hCursor=user32.LoadCursorW(None, ctypes.c_void_p(32512)),
                     lpszClassName="winlabDesktop")
    if not user32.RegisterClassExW(ctypes.byref(wc)):
        raise NativeWindowError("could not register the window class")
    hwnd = user32.CreateWindowExW(0, "winlabDesktop", title, WS_OVERLAPPEDWINDOW,
                                  CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                                  None, None, hinst, None)
    if not hwnd:
        raise NativeWindowError("could not create the window")

    def on_title(sender, args):
        out = ctypes.c_wchar_p()
        vcall(st["webview"], WV_GET_DOCUMENT_TITLE, [ctypes.POINTER(ctypes.c_wchar_p)], ctypes.byref(out))
        if out.value:
            user32.SetWindowTextW(hwnd, out.value)
        if out:
            ole32.CoTaskMemFree(ctypes.cast(out, ctypes.c_void_p))

    def on_fullscreen(sender, args):
        full = ctypes.c_int()
        vcall(st["webview"], WV_GET_CONTAINS_FULLSCREEN, [ctypes.POINTER(ctypes.c_int)], ctypes.byref(full))
        if full.value and not st["full"]:
            st["full"] = True
            rc = RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rc))
            st["placement"] = (user32.GetWindowLongPtrW(hwnd, GWL_STYLE), rc, user32.IsZoomed(hwnd))
            mi = MONITORINFO(cbSize=ctypes.sizeof(MONITORINFO))
            user32.GetMonitorInfoW.argtypes = [W.HMONITOR, ctypes.POINTER(MONITORINFO)]
            user32.GetMonitorInfoW(user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), ctypes.byref(mi))
            m = mi.rcMonitor
            user32.SetWindowLongPtrW(hwnd, GWL_STYLE, WS_POPUP | WS_VISIBLE)
            user32.SetWindowPos(hwnd, None, m.left, m.top, m.right - m.left, m.bottom - m.top,
                                SWP_FRAMECHANGED | SWP_NOOWNERZORDER)
        elif not full.value and st["full"]:
            st["full"] = False
            style, rc, zoomed = st["placement"]
            user32.SetWindowLongPtrW(hwnd, GWL_STYLE, style)
            user32.SetWindowPos(hwnd, None, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
                                SWP_FRAMECHANGED | SWP_NOOWNERZORDER)
            if zoomed:
                user32.ShowWindow(hwnd, SW_SHOWMAXIMIZED)

    def on_controller(hr, controller):
        if hr < 0 or not controller:
            st["error"] = f"WebView2 could not make its view (0x{hr & 0xFFFFFFFF:08X})"
            user32.PostQuitMessage(1)
            return S_OK
        vcall(controller, 1, [], restype=ctypes.c_ulong)  # AddRef: we keep it
        st["controller"] = controller
        wv = ctypes.c_void_p()
        vcall(controller, CTL_GET_COREWEBVIEW2, [ctypes.POINTER(ctypes.c_void_p)], ctypes.byref(wv))
        st["webview"] = wv.value
        settings = ctypes.c_void_p()
        vcall(wv.value, WV_GET_SETTINGS, [ctypes.POINTER(ctypes.c_void_p)], ctypes.byref(settings))
        for slot in (SET_PUT_STATUS_BAR, SET_PUT_DEV_TOOLS, SET_PUT_ZOOM_CONTROL):
            vcall(settings.value, slot, [ctypes.c_int], 0)
        for slot, fn in ((WV_ADD_DOCUMENT_TITLE_CHANGED, on_title),
                         (WV_ADD_FULLSCREEN_CHANGED, on_fullscreen)):
            cb = Callback([ctypes.c_void_p, ctypes.c_void_p], fn)
            keep.append(cb)
            tok = Token()
            vcall(wv.value, slot, [ctypes.c_void_p, ctypes.POINTER(Token)], cb.ptr, ctypes.byref(tok))
        fit(hwnd)
        vcall(controller, CTL_PUT_IS_VISIBLE, [ctypes.c_int], 1)
        vcall(wv.value, WV_NAVIGATE, [ctypes.c_wchar_p], url)
        return S_OK

    def on_environment(hr, env):
        if hr < 0 or not env:
            st["error"] = f"the WebView2 runtime did not start (0x{hr & 0xFFFFFFFF:08X})"
            user32.PostQuitMessage(1)
            return S_OK
        cb = Callback([HRESULT, ctypes.c_void_p], on_controller)
        keep.append(cb)
        vcall(env, ENV_CREATE_CONTROLLER, [ctypes.c_void_p, ctypes.c_void_p], hwnd, cb.ptr)
        return S_OK

    data = profile / "webview2"
    data.mkdir(parents=True, exist_ok=True)
    env_cb = Callback([HRESULT, ctypes.c_void_p], on_environment)
    keep.append(env_cb)
    hr = loader.CreateCoreWebView2EnvironmentWithOptions(None, ctypes.c_wchar_p(str(data)), None,
                                                         ctypes.c_void_p(env_cb.ptr))
    if hr != S_OK:
        user32.DestroyWindow(hwnd)
        raise NativeWindowError(f"the WebView2 runtime is not usable (0x{hr & 0xFFFFFFFF:08X})")
    user32.ShowWindow(hwnd, SW_SHOWMAXIMIZED)
    msg = W.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))
    if st["error"]:
        raise NativeWindowError(st["error"])
    return 0


def render_status() -> str:
    if sys.platform != "win32":
        return "program window: Edge/Chrome app window (the native window is for Windows)"
    if not loader_path().exists():
        return "program window: WebView2 loader not fetched yet (setup fetches it); Edge app window meanwhile"
    version = runtime_version()
    return (f"program window: native, WebView2 runtime {version}" if version else
            "program window: WebView2 runtime missing (Windows Update installs it); Edge app window meanwhile")


def window_command(url: str) -> list[str]:
    """How to start the native window as a process of its own."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "window", url]
    return [sys.executable, "-m", "winlab", "window", url]


def env_allows(env: dict | None = None) -> bool:
    """WINLAB_BROWSER=edge (or tab) keeps the browser windows."""
    env = os.environ if env is None else env
    return env.get("WINLAB_BROWSER", "").lower() not in ("edge", "tab", "browser")
