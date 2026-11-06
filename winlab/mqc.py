"""What a class-map matches, as nftables rules: shared by the lab router's
zone-based firewall (winlab/zbf.py, ``class-map type inspect``) and its
QoS (winlab/qos.py, ``class-map``).

IOS's Modular QoS CLI (MQC) has the same three steps for both: a class-map
says which packets, a policy-map says what to do with each class, and the
policy is attached somewhere (a zone-pair, or an interface). Here a class is
turned into nftables rules that end in the policy's action (``tail``), so
the first class a packet matches decides, as on IOS:

* ``match-any``: each match line is tried on its own; the first that fits
  takes the action;
* ``match-all``: the match lines are chained, each one jumping to the next,
  and only a packet that passes every one reaches the action;
* ``match access-group``: the list's entries in order (winlab/iosl3.py keeps
  them): a deny entry stops the list matching (``return``), a permit entry
  matches.

``match protocol`` is by port here, as winlab names it. A real router's NBAR
looks inside the packets; this one knows a protocol by its well-known ports,
which is what the lessons say.
"""

from __future__ import annotations

import json
import re

from . import iosl3

# protocol name -> [(layer 4, destination port or None)], the names IOS uses.
PROTOCOLS: dict[str, list[tuple[str, int | None]]] = {
    "tcp": [("tcp", None)], "udp": [("udp", None)], "icmp": [("icmp", None)],
    "http": [("tcp", 80)], "https": [("tcp", 443)], "dns": [("udp", 53), ("tcp", 53)],
    "ssh": [("tcp", 22)], "telnet": [("tcp", 23)], "ftp": [("tcp", 21)], "smtp": [("tcp", 25)],
    "pop3": [("tcp", 110)], "imap": [("tcp", 143)], "ntp": [("udp", 123)], "snmp": [("udp", 161)],
    "syslog": [("udp", 514)], "tftp": [("udp", 69)], "bootps": [("udp", 67)], "bootpc": [("udp", 68)],
    "ldap": [("tcp", 389), ("udp", 389)], "ldaps": [("tcp", 636)],
    "kerberos": [("tcp", 88), ("udp", 88)], "msrpc": [("tcp", 135)], "netbios-ssn": [("tcp", 139)],
    "microsoft-ds": [("tcp", 445)], "cifs": [("tcp", 445)], "ms-sql": [("tcp", 1433)],
    "rdp": [("tcp", 3389)], "isakmp": [("udp", 500)], "ipsec-msft": [("udp", 4500)],
    "sip": [("udp", 5060), ("tcp", 5060)], "rtp": [("udp", None)],
}
# DSCP names IOS takes, and their values.
DSCP = {"default": 0, "ef": 46, "cs0": 0, "cs1": 8, "cs2": 16, "cs3": 24, "cs4": 32, "cs5": 40, "cs6": 48,
        "cs7": 56, "af11": 10, "af12": 12, "af13": 14, "af21": 18, "af22": 20, "af23": 22, "af31": 26,
        "af32": 28, "af33": 30, "af41": 34, "af42": 36, "af43": 38}
DSCP_NAME = {v: k for k, v in DSCP.items() if k not in ("cs0",)}


class MqcError(ValueError):
    """What the console prints for a match line it cannot take."""


def dscp_value(text: str) -> int:
    t = text.lower()
    if t in DSCP:
        return DSCP[t]
    if t.isdigit() and 0 <= int(t) <= 63:
        return int(t)
    raise MqcError("% Invalid input detected at '^' marker.")


def dscp_show(v: int) -> str:
    return DSCP_NAME.get(v, str(v))


# ------------------------------------------------------------------ class-maps
def load(own: dict, key: str) -> dict:
    """A class-map as kept: {"how": "match-any" | "match-all", "m": [lines]}."""
    try:
        data = json.loads(own.get(key, "") or "{}")
    except ValueError:
        data = {}
    return {"how": data.get("how", "match-all"), "m": list(data.get("m", [])),
            "desc": data.get("desc", "")}


def store(own: dict, key: str, cmap: dict) -> None:
    own[key] = json.dumps(cmap, separators=(",", ":"))


def match_line(words: list[str], qos: bool) -> str:
    """A match line typed in a class-map, checked and kept in one form:
    'protocol http', 'access-group 101', 'access-group name WEB', and for QoS
    'dscp 46 34', 'precedence 5', 'any'."""
    if not words:
        raise MqcError("% Incomplete command.")
    w0 = words[0].lower()
    if w0 == "protocol" and len(words) == 2:
        p = words[1].lower()
        if p not in PROTOCOLS:
            raise MqcError(f"% Protocol {words[1]} is not known here; known: {', '.join(sorted(PROTOCOLS))}")
        return f"protocol {p}"
    if w0 == "access-group" and len(words) == 2 and words[1].isdigit():
        return f"access-group {words[1]}"
    if w0 == "access-group" and len(words) == 3 and words[1].lower() == "name":
        return f"access-group name {words[2]}"
    if qos and w0 == "any" and len(words) == 1:
        return "any"
    if qos and w0 in ("dscp", "ip") and len(words) >= 2:
        vals = words[1:] if w0 == "dscp" else words[2:] if words[1].lower() == "dscp" else []
        if not vals or len(vals) > 8:
            raise MqcError("% Invalid input detected at '^' marker.")
        return "dscp " + " ".join(str(dscp_value(v)) for v in vals)
    if qos and w0 == "precedence" and 2 <= len(words) <= 5:
        vals = []
        for v in words[1:]:
            if not v.isdigit() or not 0 <= int(v) <= 7:
                raise MqcError("% Invalid input detected at '^' marker.")
            vals.append(v)
        return "precedence " + " ".join(vals)
    raise MqcError("% Invalid input detected at '^' marker.")


def show_match(line: str) -> str:
    """A kept match line as IOS prints it ('dscp ef (46)')."""
    w = line.split()
    if w[0] == "dscp":
        return "dscp " + " ".join(f"{dscp_show(int(v))} ({v})" for v in w[1:])
    return line


def run_match(line: str) -> str:
    w = line.split()
    if w[0] == "dscp":
        return "dscp " + " ".join(dscp_show(int(v)) for v in w[1:])
    return line


# ------------------------------------------------------------------ nftables
def _acl_match(entry: str) -> str:
    """An access list entry as nftables matches, without a verdict."""
    e = iosl3.parse(entry)
    proto = e["proto"]
    out = ""
    if proto in ("tcp", "udp", "icmp"):
        out += f"meta l4proto {proto} "
    elif proto != "ip":
        out += f"meta l4proto {iosl3.PROTOS.get(proto, proto)} "
    out += iosl3._nft_addr("saddr", e["src"]) + iosl3._nft_addr("daddr", e["dst"])
    out += iosl3._nft_ports(proto, "sport", e["sport"]) + iosl3._nft_ports(proto, "dport", e["dport"])
    if "established" in e["extra"]:
        out += "tcp flags & (ack | rst) != 0 "
    for t in e["extra"]:
        if t in iosl3.ICMP:
            out += f"icmp type {iosl3.ICMP[t]} "
    return out


def alternatives(line: str) -> list[str]:
    """The nftables matches for a simple match line (anything but an access
    list): one string per way it can match."""
    w = line.split()
    if w[0] == "protocol":
        out = []
        for l4, port in PROTOCOLS.get(w[1], []):
            out.append(f"meta l4proto {l4} " + (f"{l4} dport {port} " if port is not None else ""))
        return out
    if w[0] == "any":
        return [""]
    if w[0] == "dscp":
        vals = sorted({int(v) for v in w[1:]})
        return [f"ip dscp {vals[0]} " if len(vals) == 1 else "ip dscp { " + ", ".join(map(str, vals)) + " } "]
    if w[0] == "precedence":
        return [f"ip dscp {int(v) * 8}-{int(v) * 8 + 7} " for v in w[1:]]
    return []


def _chain_name(*parts: str) -> str:
    return "_".join(re.sub(r"[^A-Za-z0-9]", "_", p) for p in parts)[:200]


def class_rules(own: dict, cmap: dict, tail: str, prefix: str, chains: dict[str, list[str]]) -> list[str]:
    """The rules that send a packet of the class to `tail` (nftables
    statements ending in a verdict); helper chains the class needs are added
    to `chains`, named from `prefix`."""
    lines = list(cmap["m"])
    if not lines:
        return []   # a class with no match line matches nothing

    def acl_chain(line: str, k: int, then: str) -> str:
        name = line.split()[-1]
        ch = _chain_name(prefix, f"m{k}", "acl", name)
        body = []
        for seq, entry in iosl3.entries(own, name):
            m = _acl_match(entry)
            body.append(f"{m}return" if entry.startswith("deny") else f"{m}{then}")
        chains[ch] = body
        return f"jump {ch}"

    if cmap["how"] == "match-any":
        out = []
        for k, line in enumerate(lines):
            if line.startswith("access-group"):
                out.append(acl_chain(line, k, tail))
            else:
                out += [f"{a}{tail}" for a in alternatives(line)]
        return out

    # match-all: each line leads to the next; the last one to the action
    def level(k: int) -> list[str]:
        line = lines[k]
        if k == len(lines) - 1:
            then = tail
        else:
            ch = _chain_name(prefix, f"all{k + 1}")
            chains[ch] = level(k + 1)
            then = f"jump {ch}"
        if line.startswith("access-group"):
            return [acl_chain(line, k, then)]
        return [f"{a}{then}" for a in alternatives(line)]
    return level(0)


def counters(text: str, tag: str) -> dict[str, tuple[int, int]]:
    """'counter packets 5 bytes 300 ... comment "<tag> a b c"' -> {"a b c": (packets, bytes)}."""
    out: dict[str, tuple[int, int]] = {}
    for line in text.splitlines():
        m = re.search(r'counter packets (\d+) bytes (\d+).*comment "' + re.escape(tag) + r' ([^"]+)"', line)
        if m:
            p, b = out.get(m.group(3), (0, 0))
            out[m.group(3)] = (p + int(m.group(1)), b + int(m.group(2)))
    return out
