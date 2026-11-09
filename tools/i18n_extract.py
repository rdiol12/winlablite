"""Collect the English text the winlab desktop shows, for translation.

Reads winlab/webui_page.html (its markup and the strings its script builds
markup from) and prints the text segments as JSON: one entry per text node
or title/placeholder attribute, with ${...} interpolations written as {}.
The runtime translator (I18N in webui_page.html) matches text nodes against
these keys: exact keys first, then the {} ones as patterns.

    python tools/i18n_extract.py > keys.json
    python tools/i18n_extract.py --missing es   # keys content/i18n/es.json lacks
                                                # (minus content/i18n/keep-english.json: code, names, keys)
"""
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "winlab" / "webui_page.html"
I18N = ROOT / "content" / "i18n"

PH = "\x00"  # stands for one ${...} while scanning

ATTRS = ("title", "placeholder", "aria-label", "data-tip", "alt")


def js_strings(src: str):
    """Yield the bodies of string literals in a script, ${...} replaced by PH.

    Template literals nested inside ${...} are yielded on their own."""
    i, n = 0, len(src)
    prev = ""  # last significant char, to tell a regex literal from a division

    def template(i):
        out = []
        while i < n:
            c = src[i]
            if c == "\\":
                out.append(src[i:i + 2]); i += 2; continue
            if c == "`":
                return "".join(out), i + 1
            if c == "$" and i + 1 < n and src[i + 1] == "{":
                i = expr(i + 2)
                out.append(PH); continue
            out.append(c); i += 1
        return "".join(out), i

    def quoted(i, q):
        out = []
        while i < n:
            c = src[i]
            if c == "\\":
                out.append(src[i:i + 2]); i += 2; continue
            if c == q or c == "\n":
                return "".join(out), i + 1
            out.append(c); i += 1
        return "".join(out), i

    found = []

    def expr(i):
        depth = 1
        p = "("
        while i < n:
            c = src[i]
            if c in "'\"":
                s, i = quoted(i + 1, c); found.append(s); p = "a"; continue
            if c == "`":
                s, i = template(i + 1); found.append(s); p = "a"; continue
            if c == "/" and src[i + 1:i + 2] == "/":
                i = src.find("\n", i); i = n if i < 0 else i; continue
            if c == "/" and src[i + 1:i + 2] == "*":
                i = src.find("*/", i + 2) + 2; continue
            if c == "/" and p in "(,=:[!&|?{};+-*%<>~^":
                i = regex(i + 1); p = "a"; continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            if not c.isspace():
                p = c
            i += 1
        return i

    def regex(i):
        cls = False
        while i < n:
            c = src[i]
            if c == "\\":
                i += 2; continue
            if c == "[":
                cls = True
            elif c == "]":
                cls = False
            elif c == "/" and not cls:
                return i + 1
            elif c == "\n":
                return i
            i += 1
        return i

    while i < n:
        c = src[i]
        if c in "'\"":
            s, i = quoted(i + 1, c); found.append(s); prev = "a"; continue
        if c == "`":
            s, i = template(i + 1); found.append(s); prev = "a"; continue
        if c == "/" and src[i + 1:i + 2] == "/":
            j = src.find("\n", i); i = n if j < 0 else j; continue
        if c == "/" and src[i + 1:i + 2] == "*":
            i = src.find("*/", i + 2) + 2; continue
        if c == "/" and (prev in "(,=:[!&|?{};+-*%<>~^" or src[max(0, i - 7):i].rstrip().endswith("return")):
            i = regex(i + 1); prev = "a"; continue
        if not c.isspace():
            prev = c if not (c.isalnum() or c in "_$") else "a"
        i += 1
    return found


TAG = re.compile(r"<(/?)([a-zA-Z][\w-]*)((?:[^>\"']|\"[^\"]*\"|'[^']*')*)>")
ATTR = re.compile(r"""\b(%s)\s*=\s*("([^"]*)"|'([^']*)')""" % "|".join(ATTRS))
SKIP_BLOCKS = re.compile(r"<(style|script|svg|pre|code)\b.*?</\1>", re.S | re.I)


def clean(s: str) -> str:
    s = html.unescape(s.replace("\\n", " ").replace("\\'", "'").replace('\\"', '"').replace("\\`", "`"))
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\s+", " ", s).strip()
    s = s.replace(PH, "{}")
    s = re.sub(r"(\{\}\s*)+\{\}", "{}", s)
    return s


WORD = re.compile(r"[A-Za-z]{2,}")


def looks_like_text(s: str, markup: bool) -> bool:
    """True for something a person reads, not code, CSS, a path or a key."""
    t = s.replace("{}", "").strip(" .,:;()-–—·/|+*'\"…?!")
    if not WORD.search(t):
        return False
    if re.match(r"[#%@]|\d+(?:px|em|%|s|ms)\b", s) or re.fullmatch(r"[\w-]+:[\w:./-]+", t):
        return False  # a selector, a CSS value, a key like disk:sata
    if re.fullmatch(r"[a-z0-9]+(?:[-_][a-z0-9]+)+", t):
        return False  # a kebab or snake id
    if re.fullmatch(r"[\w.-]+", t) and not markup:
        # one bare word: only a capitalised one in a string (a label), not a key
        if not re.fullmatch(r"[A-Z][a-z]+(?: [A-Za-z]+)*", t):
            return False
    if re.search(r"(?<!\{)[{};]\s*$|(?<=\{)\}\s*;\s*$|^\s*[.#][\w-]+\s*[{,]|=>|\bfunction\b|\bconst\b|\breturn\b|===|!==|&&|\|\||\bvar\(--", s):
        return False
    if re.fullmatch(r"[\w./:?&=%-]*(?:\{\}[\w./:?&=%-]*)*", t) and ("/" in t or "." in t and " " not in t):
        return False  # a path, a URL or a dotted id
    if re.fullmatch(r"[a-z0-9_-]+(?: [a-z0-9_-]+)*", t) and not markup and " " not in t:
        return False
    if re.fullmatch(r"(?:[a-z][\w-]*)(?: [a-z][\w-]*)+", t) and not markup:
        # all-lowercase hyphenated words: CSS class lists like "btn primary"
        if all(re.fullmatch(r"[a-z]+(?:-[a-z0-9]+)*", w) for w in t.split()) and len(t.split()) <= 3 \
                and any("-" in w for w in t.split()) or t in CLASSY:
            return False
    if re.search(r"^[a-z-]+:\s*[\w#.%-]+", t) and ";" in s:
        return False  # inline style
    return True


CLASSY = {"btn primary", "btn danger", "wc x", "chip ok", "chip bad", "chip warn"}


def segments(fragment: str, markup: bool):
    """Text nodes and translatable attribute values in an HTML fragment."""
    fragment = SKIP_BLOCKS.sub("<x>", fragment)
    for m in ATTR.finditer(fragment):
        v = clean(m.group(3) if m.group(3) is not None else m.group(4))
        if looks_like_text(v, True):
            yield v
    for part in TAG.split(fragment)[0::4]:
        v = clean(part)
        if v and looks_like_text(v, markup):
            yield v


def collect(page: Path = PAGE) -> list[str]:
    text = page.read_text(encoding="utf-8")
    keys: dict[str, None] = {}
    body_start = text.index("<body>")
    script_start = text.index("<script>", body_start)
    markup = re.sub(r"<!--.*?-->", "", text[body_start:script_start], flags=re.S)
    for s in segments(markup, True):
        keys.setdefault(s)
    script = text[script_start + 8:text.rindex("</script>")]
    for lit in js_strings(script):
        is_markup = bool(TAG.search(lit))
        if lit.lstrip().startswith(("@media", ":root", "#", ".")) and "{" in lit and not is_markup:
            continue
        for s in segments(lit, is_markup):
            if "\x00" in s:
                continue
            keys.setdefault(s)
    return [k for k in keys if len(k) < 2000]


# ---- the engine: English the Python side sends to the page ----------------
#
# The desktop also shows text that comes from the engine as JSON (Setup's
# checks, the Workbench shelf, the image catalogue, track lines, status
# lines, the messages an action answers with). It stays English in Python;
# these are the modules that feed it, followed from webui.py's /api handlers.
# A module maps to None (all its text) or to the top-level names (functions,
# classes, constants) whose text the page shows. The same I18N translator
# swaps it on the page, so an f-string's {...} becomes {} in the key.
ENGINE: dict[str, tuple[str, ...] | None] = {
    # Setup: Check this PC, the steps, Get Windows, the image and pack catalogue
    "winlab/readiness.py": None,
    "winlab/hostprobe.py": ("probe", "_probe_nested", "_probe_linux", "_probe_dsc_modules", "_probe_qemu",
                            "_verdict"),
    "winlab/webui.py": None,
    "winlab/images.py": ("SERVER_EVAL", "CLIENT_EVAL", "_server", "CATALOG"),
    "winlab/appliances.py": ("UBUNTU", "OPNSENSE", "_debian", "DEBIAN12", "DEBIAN13", "OPENWRT"),
    "winlab/linuxiso.py": ("DISTROS", "setup_steps", "setup_rows"),
    "winlab/netos.py": ("VENDORS", "setup_steps", "setup_rows"),
    "winlab/bsdfw.py": ("FIREWALLS", "setup_steps", "setup_rows"),
    "winlab/android.py": ("BUILDS", "setup_steps"),
    "winlab/debpacks.py": ("PACKS.title",),
    "winlab/roles.py": ("DOWNLOADS",),
    "winlab/mail.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/exporters.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/wac.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/containers.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act", "CATALOG", "STICK_TITLES", "IMAGES_SIZE_TEXT", "K3S_SIZE_TEXT", "DOCKERWIN_SIZE_TEXT"),
    "winlab/databases.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act", "CLIENTS"),
    "winlab/ids.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/toolkit.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act", "TOOLS", "to_stick"),
    "winlab/softphone.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/remoteaccess.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/wireshark.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/webmin.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act", "GRAFANA_NOTE", "PROMETHEUS", "_node_gui"),
    "winlab/termshark.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/automation.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act", "STICK_TITLE"),
    "winlab/azure.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/aws.py": ("PRODUCT", "STEP_LABEL", "SIZE_TEXT", "LICENSE", "summary", "setup_steps", "setup_rows", "act"),
    "winlab/secops.py": ("SEVENZIP_LICENSE", "SOFTWARE_SIZE_TEXT", "SCT_LICENSE", "GB_SIZE_TEXT", "STICK_TITLES",
                         "setup_steps", "act", "stick_sets"),
    "winlab/doctools.py": ("AGENT_SIZE_TEXT", "AGENT_STEP_LABEL", "VAULTWARDEN_LICENSE", "STICKS", "setup_steps",
                           "act", "GLPI_GUI", "WIKI_GUI", "VAULT_GUI"),
    "winlab/itops.py": ("TITLE", "DESCRIPTION", "setup_steps", "UPS_STATES"),
    # Workbench: the shelf, the parts, the devices and what an action answers
    "winlab/workbench.py": None,
    "winlab/pcparts.py": None,
    "winlab/poe.py": ("MODELS", "PD_NAME", "set_model", "allocate", "dark", "set_port", "act"),
    "winlab/campus.py": ("SWITCH_MODELS", "MEDIA", "KIT", "SERVER_KIT"),
    "winlab/appliance.py": ("DEVICES",),
    "winlab/identity.py": ("MODELS",),
    "winlab/ups.py": ("MODELS",),
    "winlab/wan.py": ("PRESETS",),
    "winlab/nestedvirt.py": ("CLIENT_NOTE_ON", "CLIENT_NOTE_OFF", "view", "host_support", "drill_name"),
    "winlab/firmware.py": ("TITLES", "host_support"),
    "winlab/secureboot.py": ("TEMPLATES",),
    "winlab/vswitch.py": ("describe",),
    "winlab/virtio.py": ("PACKAGES",),
    "winlab/imaging.py": ("pxe_path",),
    "winlab/omv.py": ("SIGN_IN",),
    "winlab/servicedesk.py": ("OSTICKET_GUI",),
    "winlab/updates.py": ("FAMILIES",),
    # Helpdesk, Pager, Alerts, Shift, Scenario, Guide, Progress, Commands
    "winlab/helpdesk.py": ("PRIORITIES", "CATEGORIES", "GROUPS", "DEPARTMENT", "act"),
    "winlab/ticketgame.py": ("LEVELS", "DIFF_WORD", "RANKS", "BADGES", "act"),
    "winlab/breakfix.py": ("TOPICS", "topic_title", "LEVELS", "act"),
    "winlab/alerts.py": ("SOURCES", "_where", "add_colleague", "escalation_contact", "act"),
    "winlab/inherited.py": ("DEPARTMENTS", "PREV"),
    "winlab/people.py": ("DEPARTMENTS",),
    "winlab/identityops.py": ("JOINERS",),
    "winlab/shift.py": ("CHECKLIST", "WIKI_HANDOVER"),
    "winlab/wear.py": ("LEVELS",),
    "winlab/company.py": ("act",),
    "winlab/traffic.py": ("BACKGROUND", "PROFILES"),
    "winlab/labclock.py": ("describe_offset",),
    "winlab/guide.py": ("canvas_check", "evaluate", "facts"),
    "winlab/livenet.py": ("sync",),
    "winlab/perfmon.py": ("RULES", "set_rule", "act"),
    "winlab/commands.py": ("KINDS", "_AREAS"),
    "winlab/lessons.py": ("MODULES",),
    "winlab/incidents.py": ("view",),
    "winlab/licensing/client.py": ("status",),
    "winlab/firewall.py": ("DENY", "default_rules"),
}

# calls whose string arguments are code, a path, a log or the command line's
# help, never desktop text
CODE_CALLS = {
    "print", "write", "debug", "info", "warning", "exception", "log", "add_argument", "add_parser",
    "run", "Popen", "check_output", "check_call", "call", "system", "spawn", "_run", "run_ps", "ps",
    "compile", "match", "fullmatch", "search", "sub", "subn", "findall", "finditer", "split", "rsplit",
    "startswith", "endswith", "strip", "lstrip", "rstrip", "replace", "partition", "rpartition", "encode",
    "decode", "join_path", "Path", "open", "getenv", "environ", "glob", "rglob", "which", "joinpath",
    "removeprefix", "removesuffix", "count", "index", "find", "rfind", "setdefault", "pop", "getattr",
    "hasattr", "setattr", "isinstance", "urlopen", "Request", "quote", "unquote", "mkdir", "unlink",
    "read_text", "write_text", "with_suffix", "strftime", "strptime", "fromisoformat", "sh", "shell",
    "run_shell", "guest_run", "agent_run", "exec", "execute", "send", "sendline", "expect",
}
COMMAND_START = re.compile(
    r"(?:sudo|apt-get|apt|dnf|yum|winlab|powershell|pwsh|cmd(?:\.exe)?|netsh|reg|sc(?:\.exe)?|systemctl|"
    r"ssh|scp|curl|wget|qemu-img|qemu-system\S*|docker|kubectl|git|python3?|bash|sh|echo|cat|ls|cd|"
    r"(?:Get|Set|New|Remove|Add|Install|Import|Invoke|Start|Stop|Test|Enable|Disable|Restart|Update|"
    r"Export|Uninstall|Register|Mount|Format|Initialize|Clear|Write|Resolve|Out|Select|Where)-[A-Z]\w*)\b")


def _py_key(node, fmt: bool) -> str | None:
    import ast
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        s = node.value
        if fmt or re.search(r"\{[a-z_]+\}", s):  # "{name} of {total}".format(...), here or later
            s = re.sub(r"\{[^{}]*\}", PH, s.replace("{{", "\x01").replace("}}", "\x02"))
            s = s.replace("\x01", "{").replace("\x02", "}")
        return s
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else PH for v in node.values)
    return None


def py_strings(path: Path, names: tuple[str, ...] | None = None):
    """The text a Python module (or the named top-level parts of it) shows:
    string literals and f-strings, minus docstrings, dict keys, comparisons,
    code (commands, paths, ids) and what goes to code calls."""
    import ast
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parent: dict[int, ast.AST] = {}
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            parent[id(c)] = n
    skip: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body \
                and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant):
            skip.add(id(n.body[0].value))
        elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant):
            skip.add(id(n.value))  # a bare string: a comment
        if isinstance(n, ast.JoinedStr):
            for v in ast.walk(n):
                if v is not n:
                    skip.add(id(v))
        if isinstance(n, ast.Dict):
            skip.update(id(k) for k in n.keys if k is not None)
        if isinstance(n, (ast.Compare, ast.Subscript, ast.Assert)):
            for v in ast.walk(n.slice if isinstance(n, ast.Subscript) else n):
                skip.add(id(v))
        if isinstance(n, ast.Call):
            f = n.func
            fname = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            if fname in CODE_CALLS or fname.startswith(("_ps", "ps_", "run_")):
                for a in n.args + [k.value for k in n.keywords]:
                    for v in ast.walk(a):
                        if not isinstance(v, (ast.Call, ast.Lambda)):
                            skip.add(id(v))
            elif fname in ("get",) and n.args:
                skip.add(id(n.args[0]))
            for k in n.keywords:  # keyword names that carry code
                if k.arg in ("encoding", "errors", "mode", "sep", "shell", "cwd", "env", "help"):
                    skip.add(id(k.value))
    # "PACKS.title" is PACKS, only the values given as title= (or under a "title" key)
    want = {} if names is None else {n.split(".")[0]: (set(n.split(".")[1].split("|")) if "." in n else None)
                                     for n in names}

    def top_name(t):
        if isinstance(t, ast.Assign):
            return next((x.id for x in t.targets if isinstance(x, ast.Name) and x.id in want), None)
        if isinstance(t, ast.AnnAssign):
            return getattr(t.target, "id", None)
        return getattr(t, "name", None)

    tops = [(t, None) for t in tree.body] if names is None else [
        (t, want[top_name(t)]) for t in tree.body if top_name(t) in want]
    for top, fields in tops:
        only: set[int] | None = None
        if fields:
            only = set()
            for n in ast.walk(top):
                vals = [k.value for k in n.keywords if k.arg in fields] if isinstance(n, ast.Call) else \
                    [v for k, v in zip(n.keys, n.values) if isinstance(k, ast.Constant) and k.value in fields] \
                    if isinstance(n, ast.Dict) else []
                for v in vals:
                    only.update(id(x) for x in ast.walk(v))
        for n in ast.walk(top):
            if id(n) in skip or only is not None and id(n) not in only:
                continue
            p = parent.get(id(n))
            fmt = isinstance(p, ast.Attribute) and p.attr == "format"
            if fmt and isinstance(p, ast.Attribute):
                pp = parent.get(id(p))
                fmt = isinstance(pp, ast.Call)
            s = _py_key(n, fmt)
            if not s or "\n" in s.strip():
                continue
            if isinstance(p, ast.IfExp) and n is not p.test:  # msg + ("; more" if x else "")
                n, p = p, parent.get(id(p))
            if isinstance(p, ast.BinOp) and isinstance(p.op, ast.Add):  # msg + "; more": a pattern
                s = PH + s if n is p.right else s + PH
            elif isinstance(p, ast.AugAssign) and isinstance(p.op, ast.Add):
                s = PH + s
            v = re.sub(r"\s+", " ", s).strip().replace(PH, "{}")
            v = re.sub(r"(\{\}\s*)+\{\}", "{}", v)
            if not v or len(v) > 600 or not looks_like_text(v, False):
                continue
            t = v.replace("{}", "").strip()
            if COMMAND_START.match(t) or re.search(r"\$\w|\$\(|\|\s*[A-Z]\w+-|%[sd]|\\|<[a-z/][^>]*>|^\W*\{}\W*$", v):
                continue
            if re.search(r"^\(\?|^\^|\$$|charset=|^[a-z]+/[\w.+-]+$|^attachment;|\w=\S", v):
                continue  # a regular expression, a MIME type, a header, key=value
            if re.fullmatch(r"[\w.-]+(?: [\w.-]+)?", t) and not re.search(r"[a-z]{2,}", t):
                continue  # an all-caps id or a version
            yield v


def engine_keys() -> list[str]:
    keys: dict[str, None] = {}
    for mod, names in ENGINE.items():
        for s in py_strings(ROOT / mod, names):
            keys.setdefault(s)
    return list(keys)


def main(argv: list[str]) -> int:
    if argv[:1] == ["--engine"]:
        keys, argv = engine_keys(), argv[1:]
    else:
        keys = collect()
        keys += [k for k in engine_keys() if k not in set(keys)]
    if argv[:1] == ["--missing"]:
        have = json.loads((I18N / f"{argv[1]}.json").read_text(encoding="utf-8"))
        keep = set(json.loads((I18N / "keep-english.json").read_text(encoding="utf-8")))
        keys = [k for k in keys if k not in have and k not in keep]
    json.dump(keys, sys.stdout, ensure_ascii=False, indent=0)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
