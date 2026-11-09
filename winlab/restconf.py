"""RESTCONF on the lab router (CCNA 6.5 REST APIs, 6.7 JSON): the router's
interfaces, routes and hostname as JSON over HTTPS, read and written with
curl, Python's requests or Postman from a lab machine.

As on IOS-XE the student turns it on at the console: a privilege 15 user
(``username admin privilege 15 secret ...``), ``ip http secure-server``,
``ip http authentication local`` and ``restconf``. Then, from a machine of
the lab::

    curl -k -u admin https://<router>/restconf/data/ietf-interfaces:interfaces \\
         -H 'Accept: application/yang-data+json'

How it is real. It is the same split as SSH to the consoles (winlab/iosssh.py):

* On the router, busybox tcpsvd listens on port 443 of the router's own
  addresses on the lab's routed VLANs, nowhere else, and runs the session
  line's program (``winlab-vty https:router``) for each connection, which
  carries its bytes over the router's ttyS2 to winlab here.
* Here, Session terminates TLS (Python's ssl, in memory) with the router's
  self-signed certificate: a 2048-bit RSA key generated when ``ip http
  secure-server`` is typed, and an X.509 certificate signed with it
  (``IOS-Self-Signed-Certificate-<serial>``, as IOS-XE names its own), kept
  in the lab's folder. Clients see a self-signed certificate, as against a
  real router: curl -k, or verify=False in requests.
* A request is answered from the router's running configuration, the same
  settings the console shows: GET reads them, PUT / PATCH / DELETE change
  them by running the console's own commands (``interface ...``,
  ``description``, ``ip address``, ``shutdown``, ``hostname``), so a change
  made over RESTCONF is in ``show running-config`` at once, is unsaved until
  ``write memory``, and reaches the running network the way a typed command
  does. HTTP basic authentication is checked against the device's local
  users (privilege 15, ``ip http authentication local``) or, without it,
  against the enable secret, as IOS's default ``ip http authentication
  enable`` does.

What is modelled (RFC 8040, application/yang-data+json): /.well-known/host-meta,
/restconf, and under /restconf/data: ietf-interfaces:interfaces (config:
name, description, enabled, ietf-ip:ipv4 address; GET, PUT, PATCH, DELETE
on an interface and on its leaves), ietf-interfaces:interfaces-state
(admin and oper status, MAC, counters), ietf-routing:routing-state (the
routes show ip route lists) and Cisco-IOS-XE-native:native/hostname. What is
not: the rest of the Cisco-IOS-XE-native tree, XML (application/yang-data+xml
is answered 406: winlab speaks JSON only), POST and RPC operations, NETCONF,
query parameters (depth, fields: ignored), Tunnel interfaces, and plain
HTTP: IOS-XE serves RESTCONF over HTTPS only, so ``ip http server`` is kept in
the configuration but serves nothing. A switch has no RESTCONF (a 2960
running IOS 15 has none).

Tested how: unit tests drive Session over in-memory TLS with Python's ssl
client and the request handling directly (tests/test_winlab.py); curl -k
and Python's requests against a local TCP front that hands bytes to
Session as the router's ttyS2 line does.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import ssl
import time
from urllib.parse import unquote, urlsplit

from . import devcli, iosssh, paths

MEDIA = "application/yang-data+json"
PORT = 443
TP_BITS = 2048
DEV = "https:"   # the session line's device word for an HTTPS connection: https:router


# ------------------------------------------------------------------ the console
def add_specs(con, add, U, C, I) -> None:
    add("ip http server", lambda a: _set(con, "http-server", "yes"), "Enable HTTP server", C)
    add("no ip http server", lambda a: _set(con, "http-server", ""), "Negate a command or set its defaults", C)
    add("ip http secure-server", lambda a: secure_on(con), "Enable HTTP secure server", C)
    add("no ip http secure-server", lambda a: _set(con, "https-server", ""), "Negate a command or set its defaults", C)
    add("ip http authentication local", lambda a: _set(con, "http-auth", "local", live=False),
        "Use local username and passwords", C)
    add("ip http authentication enable", lambda a: _set(con, "http-auth", "", live=False),
        "Use enable passwords", C)
    add("no ip http authentication", lambda a: _set(con, "http-auth", "", live=False),
        "Negate a command or set its defaults", C)
    add("restconf", lambda a: _set(con, "restconf", "yes"), "Enable RESTCONF", C)
    add("no restconf", lambda a: _set(con, "restconf", ""), "Negate a command or set its defaults", C)
    add("show ip http server status", lambda a: show_status(con), "HTTP server status", U)


def _set(con, key: str, value: str, live: bool = True) -> str:
    own = devcli.settings(con.lab, con.device)
    if value:
        own[key] = value
    else:
        own.pop(key, None)
    return con._save(live=live).strip()


def secure_on(con) -> str:
    """ip http secure-server: the self-signed trustpoint is made the first time."""
    own = devcli.settings(con.lab, con.device)
    if not tls_identity(con.lab, con.device):
        key = iosssh.generate(TP_BITS)
        kid = f"tp-{int(time.time() * 1000):x}"
        key["at"] = time.time()
        iosssh._keep(con.lab.name, kid, key)
        own["tp-key"] = kid
    return _set(con, "https-server", "yes")


def serving(lab) -> bool:
    own = lab.devices.get(devcli.ROUTER, {})
    return bool(own.get("https-server") and own.get("restconf") and tls_identity(lab, devcli.ROUTER))


def show_status(con) -> str:
    own = con.lab.devices.get(con.device, {})
    tp = _tp_name(con.lab, con.device) if tls_identity(con.lab, con.device) else ""
    return "\n".join([
        f"HTTP server status: {'Enabled' if own.get('http-server') else 'Disabled'}",
        "HTTP server port: 80",
        f"HTTP server authentication method: {own.get('http-auth') or 'enable'}",
        f"HTTP secure server status: {'Enabled' if own.get('https-server') else 'Disabled'}",
        f"HTTP secure server port: {PORT}",
        "HTTP secure server TLS version:  TLSv1.2 TLSv1.3",
        f"HTTP secure server trustpoint: {tp}".rstrip(),
        f"HTTP secure server active session modules: {'ALL' if serving(con.lab) else ''}".rstrip(),
    ])


def run_lines(lab, device: str) -> tuple[list[str], list[str]]:
    """(the ip http lines, the restconf line) for show running-config."""
    own = lab.devices.get(device, {})
    http = (["ip http server"] if own.get("http-server") else []) \
        + (["ip http authentication local"] if own.get("http-auth") == "local" else []) \
        + (["ip http secure-server"] if own.get("https-server") else [])
    return http, (["restconf"] if own.get("restconf") else [])


# ------------------------------------------------------------------ the certificate
def _tp_name(lab, device: str) -> str:
    from . import netauto
    return f"TP-self-signed-{int(netauto.serial(lab, device)[3:], 16)}"


def _tp_key(lab, device: str) -> dict | None:
    kid = lab.devices.get(device, {}).get("tp-key", "")
    raw = iosssh._load(lab.name).get(kid) if kid else None
    if not isinstance(raw, dict):
        return None
    try:
        key = {k: int(raw[k], 16) for k in ("n", "d", "p", "q")}
        key.update(e=int(raw["e"]), bits=int(raw["bits"]), at=float(raw.get("at", 0)))
    except (KeyError, TypeError, ValueError):
        return None
    return key


def _utc(t: float) -> bytes:
    return iosssh._der(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(t)).encode())


SHA256_RSA = bytes.fromhex("300d06092a864886f70d01010b0500")
SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def sign(key: dict, data: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5 with SHA-256."""
    k = (key["n"].bit_length() + 7) // 8
    t = SHA256_INFO + hashlib.sha256(data).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), key["d"], key["n"]).to_bytes(k, "big")


def certificate(key: dict, cn: str, serial: int, at: float) -> bytes:
    """A self-signed X.509 v3 certificate (DER) for the key, as IOS makes
    its trustpoint's: the subject is the issuer, valid until 2030."""
    der, dint = iosssh._der, iosssh._der_int
    name = der(0x30, der(0x31, der(0x30, der(0x06, bytes.fromhex("550403")) + der(0x0C, cn.encode()))))
    basic = der(0x30, der(0x06, bytes.fromhex("551d13")) + der(0x01, b"\xff") + der(0x04, der(0x30, der(0x01, b"\xff"))))
    tbs = der(0x30, der(0xA0, dint(2)) + dint(serial) + SHA256_RSA + name
              + der(0x30, _utc(at - 60) + iosssh._der(0x17, b"300101000000Z")) + name + iosssh.spki(key)
              + der(0xA3, der(0x30, basic)))
    return der(0x30, tbs + SHA256_RSA + der(0x03, b"\x00" + sign(key, tbs)))


def private_pem(key: dict) -> str:
    dint = iosssh._der_int
    n, e, d, p, q = key["n"], key["e"], key["d"], key["p"], key["q"]
    body = iosssh._der(0x30, dint(0) + dint(n) + dint(e) + dint(d) + dint(p) + dint(q)
                       + dint(d % (p - 1)) + dint(d % (q - 1)) + dint(pow(q, -1, p)))
    return _pem("RSA PRIVATE KEY", body)


def _pem(kind: str, der: bytes) -> str:
    b = base64.b64encode(der).decode()
    return f"-----BEGIN {kind}-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + f"\n-----END {kind}-----\n"


def tls_identity(lab, device: str):
    """(certificate file, key file) for the router's HTTPS, written beside the
    lab's machines from its trustpoint key; None without one."""
    key = _tp_key(lab, device)
    if key is None:
        return None
    d = paths.lab_dir(lab.name)
    tag = hashlib.sha256(str(key["n"]).encode()).hexdigest()[:10]
    crt, kf = d / f"restconf-{tag}.crt", d / f"restconf-{tag}.key"
    if not (crt.exists() and kf.exists()):
        d.mkdir(parents=True, exist_ok=True)
        from . import netauto
        cn = f"IOS-Self-Signed-Certificate-{int(netauto.serial(lab, device)[3:], 16)}"
        crt.write_text(_pem("CERTIFICATE", certificate(key, cn, 1, key.get("at") or time.time())), encoding="ascii")
        kf.write_text(private_pem(key), encoding="ascii")
        try:
            kf.chmod(0o600)
        except OSError:
            pass
    return crt, kf


# ------------------------------------------------------------------ the router
def listeners(plan) -> list[str]:
    """The router addresses port 443 listens on (its routed lab VLANs)."""
    if not serving(plan.lab):
        return []
    return sorted({seg.network.router_ip for seg in plan.segments.values()
                   if seg.network.routed and not seg.network.wan and seg.network.router_ip})


def render(plan, run: str) -> list[str]:
    """Shell for the router: busybox tcpsvd on 443 of each address, every
    connection the session line's program (`run`, winlab-vty)."""
    addrs = listeners(plan)
    if not addrs:
        return []
    out = ["# RESTCONF (winlab/restconf.py): HTTPS on the router's lab addresses, TLS and answers in winlab",
           "command -v tcpsvd >/dev/null 2>&1 || apk add --no-network busybox-extras >/dev/null 2>&1 || true"]
    for a in addrs:
        out.append(f"setsid tcpsvd -c 16 {a} {PORT} {run} {DEV}{devcli.ROUTER} </dev/null >/dev/null 2>&1 & "
                   f"echo $! > {iosssh.RUN}/https-{a}.pid")
    return out


# ------------------------------------------------------------------ requests
def _error(status: int, tag: str, message: str, kind: str = "application"):
    body = {"ietf-restconf:errors": {"error": [{"error-type": kind, "error-tag": tag, "error-message": message}]}}
    return status, body


REASONS = {200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request", 401: "Unauthorized",
           404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable", 409: "Conflict",
           415: "Unsupported Media Type", 500: "Internal Server Error"}


def authorized(lab, device: str, header: str) -> str:
    """The user a Basic authorization header signs in as, or ''."""
    from . import iosnv
    m = re.match(r"^\s*Basic\s+(\S+)\s*$", header or "", re.I)
    if not m:
        return ""
    try:
        user, _, pw = base64.b64decode(m.group(1)).decode("utf-8").partition(":")
    except (ValueError, UnicodeDecodeError):
        return ""
    own = lab.devices.get(device, {})
    if own.get("http-auth") == "local":
        priv, _, kept = own.get(f"user:{user}", "").partition(" ")
        return user if kept and priv == "15" and iosnv.matches(pw, kept) else ""
    kept = own.get("enable-secret") or own.get("enable-password") or ""
    return (user or "enable") if kept and iosnv.matches(pw, kept) else ""


class Device:
    """The router's configuration as RESTCONF sees it, read from and written
    through a console of its own (`con`, a devcli.Console)."""

    def __init__(self, con):
        self.con = con

    # ---- reading
    def _ifaces(self) -> list[tuple[str, object, bool]]:
        return [(n, net, up) for n, net, up in self.con.router_ifaces() if n.startswith("GigabitEthernet")]

    def interface(self, name: str, net, up: bool) -> dict:
        own = self.con.lab.devices.get(devcli.ROUTER, {})
        out = {"name": name}
        if own.get(f"desc:{name}"):
            out["description"] = own[f"desc:{name}"]
        out["type"] = "iana-if-type:l2vlan" if "." in name else "iana-if-type:ethernetCsmacd"
        out["enabled"] = bool(up)
        v4 = {}
        if net is not None and net.router_ip:
            v4 = {"address": [{"ip": net.router_ip, "netmask": devcli.mask_of(net.prefixlen)}]}
        out["ietf-ip:ipv4"] = v4
        out["ietf-ip:ipv6"] = {}
        return out

    def interfaces(self) -> dict:
        return {"ietf-interfaces:interfaces": {"interface": [self.interface(*i) for i in self._ifaces()]}}

    def find(self, name: str):
        for n, net, up in self._ifaces():
            if n.lower() == name.lower():
                return n, net, up
        return None

    def state(self) -> dict:
        rows = []
        for name, net, up in self._ifaces():
            status, proto = self.con._router_status(name, up)
            st = self.con._if_stats(self.con._router_dev(name)) if status == "up" else {}
            mac = st.get("mac") or "00:00:00:00:00:00"
            row = {"name": name, "type": "iana-if-type:l2vlan" if "." in name else "iana-if-type:ethernetCsmacd",
                   "admin-status": "down" if status.startswith("admin") else "up",
                   "oper-status": "up" if proto == "up" else "down",
                   "phys-address": mac, "speed": 1000000000,
                   "statistics": {"discontinuity-time": "1970-01-01T00:00:00+00:00",
                                  "in-octets": st.get("rx_bytes", 0), "in-unicast-pkts": st.get("rx_packets", 0),
                                  "in-errors": st.get("rx_errors", 0), "in-discards": st.get("rx_dropped", 0),
                                  "out-octets": st.get("tx_bytes", 0), "out-unicast-pkts": st.get("tx_packets", 0),
                                  "out-errors": st.get("tx_errors", 0), "out-discards": st.get("tx_dropped", 0)}}
            if net is not None and net.router_ip:
                row["ietf-ip:ipv4"] = {"address": [{"ip": net.router_ip, "prefix-length": net.prefixlen}]}
            rows.append(row)
        return {"ietf-interfaces:interfaces-state": {"interface": rows}}

    def routes(self) -> dict:
        """ietf-routing:routing-state from what show ip route lists."""
        text = self.con._show_route([])
        proto = {"C": "ietf-routing:direct", "L": "ietf-routing:direct", "S": "ietf-routing:static",
                 "O": "ietf-ospf:ospfv2", "B": "ietf-bgp:bgp"}
        out = []
        for line in text.splitlines():
            m = re.match(r"^([A-Z])\*?\s+(?:[A-Z0-9]{1,3}\s+)?(\d+\.\d+\.\d+\.\d+/\d+)\s+(.*)$", line)
            if not m:
                continue
            code, dest, rest = m.groups()
            r = {"destination-prefix": dest, "source-protocol": proto.get(code, "ietf-routing:direct")}
            pm = re.search(r"\[(\d+)/(\d+)\]", rest)
            r["route-preference"] = int(pm.group(1)) if pm else 0
            if pm:
                r["metric"] = int(pm.group(2))
            hop = {}
            via = re.search(r"via (\d+\.\d+\.\d+\.\d+)", rest)
            if via:
                hop["next-hop-address"] = via.group(1)
            dev = re.search(r"(?:connected, |, )((?:GigabitEthernet|Tunnel)\S+)$", rest)
            if dev:
                hop["outgoing-interface"] = dev.group(1)
            r["next-hop"] = hop
            out.append(r)
        rib = {"name": "ipv4-default", "address-family": "ietf-routing:ipv4", "default-rib": True,
               "routes": {"route": out}}
        return {"ietf-routing:routing-state": {"routing-instance": [{
            "name": "default", "type": "ietf-routing:default-routing-instance",
            "ribs": {"rib": [rib]}}]}}

    def hostname(self) -> str:
        return devcli.hostname(self.con.lab, devcli.ROUTER)

    # ---- writing: the console's own commands
    def apply(self, lines: list[str]) -> str:
        """Runs configuration lines; the first error the console printed, or ''."""
        c = self.con
        c.s.mode, c.s.ctx, c.s.authed, c.s.ask = "config", "", True, None
        try:
            for line in lines:
                out = c.run(line) or ""
                if c.s.ask:   # a question the device asked: not a RESTCONF thing
                    c.s.ask = None
                    return f"% {line}: the device asked a question"
                bad = [l for l in out.splitlines() if re.match(r"^% \S", l.strip())]
                if bad:
                    return bad[-1].strip()
        finally:
            c.s.mode, c.s.ctx = "enable", ""
        return ""

    def set_interface(self, name: str, body: dict, replace: bool) -> str:
        lines = [f"interface {name}"]
        if "description" in body:
            d = str(body["description"])
            lines.append(f"description {d}" if d.strip() else "no description")
        elif replace:
            lines.append("no description")
        v4 = body.get("ietf-ip:ipv4", body.get("ipv4", {}))
        addrs = v4.get("address", []) if isinstance(v4, dict) else None
        if not isinstance(addrs, list) or not all(isinstance(a, dict) for a in addrs):
            return "% ietf-ip:ipv4 is {\"address\": [{\"ip\": ..., \"netmask\": ...}]}"
        if len(addrs) > 1:
            return "% one IPv4 address per interface here (no secondary addresses)"
        if addrs:
            a = addrs[0]
            try:
                mask = a.get("netmask") or (devcli.mask_of(int(a["prefix-length"])) if "prefix-length" in a else "")
            except (TypeError, ValueError):
                mask = ""
            if not a.get("ip") or not mask:
                return "% an address needs ip and netmask (or prefix-length)"
            lines.append(f"ip address {a['ip']} {mask}")
        elif replace:
            lines.append("no ip address")   # PUT replaces: no address in the body, none on the port
        if "enabled" in body:
            if not isinstance(body["enabled"], bool):
                return "% enabled is true or false"
            lines.append("no shutdown" if body["enabled"] else "shutdown")
        elif replace:
            lines.append("no shutdown")
        lines.append("end")
        return self.apply(lines)


def handle(dev: Device, method: str, target: str, headers: dict, body: bytes):
    """One request: (status, JSON body or None or (content type, text))."""
    # Each segment is percent-decoded on its own: a key may carry an encoded slash (GigabitEthernet0%2F0%2F1).
    path = "/".join(unquote(s).replace("/", "%2F") for s in urlsplit(target).path.split("/")).rstrip("/") or "/"
    accept = headers.get("accept", "")
    if method == "GET" and path == "/.well-known/host-meta":
        return 200, ("application/xrd+xml", "<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>\n"
                                            "    <Link rel='restconf' href='/restconf'/>\n</XRD>\n")
    if "xml" in accept and "json" not in accept:
        return _error(406, "invalid-value", "winlab's RESTCONF answers application/yang-data+json only")
    if path == "/restconf":
        if method != "GET":
            return _error(405, "operation-not-supported", "method not allowed on /restconf", "protocol")
        return 200, {"ietf-restconf:restconf": {"data": {}, "operations": {}, "yang-library-version": "2016-06-21"}}
    if not path.startswith("/restconf/data"):
        return _error(404, "invalid-value", "uri keypath not found")
    rest = path[len("/restconf/data"):].lstrip("/")
    data = None
    if method in ("PUT", "PATCH"):
        ctype = headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype not in (MEDIA, "application/json"):
            return _error(415, "invalid-value", f"use Content-Type: {MEDIA}", "protocol")
        try:
            data = json.loads(body.decode("utf-8") or "null")
        except (ValueError, UnicodeDecodeError) as exc:
            return _error(400, "malformed-message", f"the body is not JSON: {exc}", "protocol")
        if not isinstance(data, dict):
            return _error(400, "malformed-message", "the body is a JSON object", "protocol")
    if method not in ("GET", "PUT", "PATCH", "DELETE"):
        return _error(405, "operation-not-supported", f"{method} is not supported here", "protocol")

    if rest == "":
        if method != "GET":
            return _error(405, "operation-not-supported", "the whole datastore is read-only here", "protocol")
        return 200, {**dev.interfaces(), **dev.routes(), "Cisco-IOS-XE-native:native": {"hostname": dev.hostname()}}
    if rest == "ietf-interfaces:interfaces-state":
        return (200, dev.state()) if method == "GET" else _error(405, "operation-not-supported", "state is read-only")
    if rest == "ietf-routing:routing-state":
        return (200, dev.routes()) if method == "GET" else _error(405, "operation-not-supported", "state is read-only")
    if rest == "Cisco-IOS-XE-native:native/hostname":
        if method == "GET":
            return 200, {"Cisco-IOS-XE-native:hostname": dev.hostname()}
        if method == "DELETE":
            err = dev.apply(["no hostname"])
        else:
            name = data.get("Cisco-IOS-XE-native:hostname", data.get("hostname"))
            if not isinstance(name, str):
                return _error(400, "malformed-message", "expected {\"Cisco-IOS-XE-native:hostname\": \"<name>\"}")
            err = dev.apply([f"hostname {name}"])
        return _error(400, "invalid-value", err) if err else (204, None)
    if rest == "ietf-interfaces:interfaces":
        if method == "GET":
            return 200, dev.interfaces()
        return _error(405, "operation-not-supported", "change one interface: .../interface=<name>")
    m = re.match(r"^ietf-interfaces:interfaces/interface=([^/]+)(?:/(.+))?$", rest)
    if not m:
        return _error(404, "invalid-value", "uri keypath not found")
    found = dev.find(unquote(m.group(1)))
    if found is None:
        return _error(404, "invalid-value", "uri keypath not found")
    name, net, up = found
    leaf = m.group(2) or ""
    if leaf not in ("", "description", "enabled", "ietf-ip:ipv4", "ietf-ip:ipv4/address", "type", "name"):
        return _error(404, "invalid-value", "uri keypath not found")
    item = dev.interface(name, net, up)
    if method == "GET":
        if not leaf:
            return 200, {"ietf-interfaces:interface": [item]}
        if leaf == "ietf-ip:ipv4/address":
            return 200, {"ietf-ip:address": item["ietf-ip:ipv4"].get("address", [])}
        if leaf not in item:
            return _error(404, "invalid-value", "uri keypath not found")
        mod = "ietf-ip" if leaf.startswith("ietf-ip") else "ietf-interfaces"
        return 200, {f"{mod}:{leaf.split(':')[-1]}": item[leaf]}
    if leaf in ("name", "type"):
        return _error(400, "invalid-value", f"{leaf} cannot be changed")
    if method == "DELETE":
        if not leaf:
            if "." in name:
                err = dev.apply([f"no interface {name}", "end"])
                return _error(400, "invalid-value", err) if err else (204, None)
            return _error(400, "invalid-value", "a physical interface cannot be deleted")
        lines = {"description": ["no description"], "enabled": ["shutdown"],
                 "ietf-ip:ipv4": ["no ip address"], "ietf-ip:ipv4/address": ["no ip address"]}[leaf]
        err = dev.apply([f"interface {name}"] + lines + ["end"])
        return _error(400, "invalid-value", err) if err else (204, None)
    # PUT or PATCH
    if not leaf:
        got = data.get("ietf-interfaces:interface", data.get("interface"))
        if isinstance(got, list):
            got = got[0] if len(got) == 1 else None
        if not isinstance(got, dict):
            return _error(400, "malformed-message", "expected {\"ietf-interfaces:interface\": {...}}")
        if got.get("name", name).lower() != name.lower():
            return _error(400, "invalid-value", "the name in the body is not the one in the URI")
        err = dev.set_interface(name, got, replace=method == "PUT")
    else:
        key = {"description": "ietf-interfaces:description", "enabled": "ietf-interfaces:enabled",
               "ietf-ip:ipv4": "ietf-ip:ipv4", "ietf-ip:ipv4/address": "ietf-ip:address"}[leaf]
        if key not in data and key.split(":")[-1] not in data:
            return _error(400, "malformed-message", f"expected {{\"{key}\": ...}}")
        value = data.get(key, data.get(key.split(":")[-1]))
        if leaf == "ietf-ip:ipv4/address":
            value = {"address": value if isinstance(value, list) else [value]}
            leaf = "ietf-ip:ipv4"
        err = dev.set_interface(name, {leaf: value}, replace=False)
    return _error(400, "invalid-value", err) if err else (204, None)


def http_response(status: int, payload) -> bytes:
    if payload is None:
        body, ctype = b"", ""
    elif isinstance(payload, tuple):
        ctype, body = payload[0], payload[1].encode("utf-8")
    else:
        ctype, body = MEDIA, (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    head = [f"HTTP/1.1 {status} {REASONS.get(status, 'OK')}", "Server: winlab-restconf",
            "Date: " + time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
            f"Content-Length: {len(body)}", "Connection: close"]
    if ctype:
        head.append(f"Content-Type: {ctype}")
    if status == 401:
        head.append('WWW-Authenticate: Basic realm="level_15 or view_access"')
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body


def answer(lab, con, raw: bytes) -> tuple[bytes, str]:
    """A whole HTTP request -> (the response, the user it signed in as)."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return http_response(*_error(400, "malformed-message", "not an HTTP request", "transport")), ""
    method, target = parts[0].upper(), parts[1]
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    user = authorized(lab, devcli.ROUTER, headers.get("authorization", ""))
    if not user and urlsplit(target).path != "/.well-known/host-meta":
        return http_response(*_error(401, "access-denied", "access denied", "protocol")), ""
    return http_response(*handle(Device(con), method, target, headers, body)), user


def request_done(buf: bytes) -> bool:
    if b"\r\n\r\n" not in buf:
        return False
    head, _, body = buf.partition(b"\r\n\r\n")
    m = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", head)
    return len(body) >= (int(m.group(1)) if m else 0)


# ------------------------------------------------------------------ a connection
class _State:
    def __init__(self):
        self.mode, self.ask = "open", None


class Session:
    """One HTTPS connection to the router's port 443, as the session line
    brings it (iosssh.Bridge): TLS in memory, one request, one answer."""

    MAX = 1 << 20

    def __init__(self, dash, device: str, peer: str, console_factory=None):
        self.dash, self.device, self.peer = dash, DEV + device, peer   # as the router's log names it
        self.user, self.logged = "", False
        self.s = _State()
        self.factory = console_factory or (lambda d: devcli.Console(d, devcli.ROUTER))
        ident = tls_identity(dash.lab, device)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(ident[0]), str(ident[1]))
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = ctx.wrap_bio(self.inc, self.out, server_side=True)
        self.buf = b""
        self.shaken = False

    def feed(self, data: bytes) -> bytes:
        if self.s.mode == "idle":
            return b""
        self.inc.write(data)
        try:
            if not self.shaken:
                self.tls.do_handshake()
                self.shaken = True
            while True:
                chunk = self.tls.read(65536)
                if not chunk:
                    break
                self.buf += chunk
        except ssl.SSLWantReadError:
            pass
        except (ssl.SSLError, OSError):
            self.s.mode = "idle"
            return self.out.read()
        if len(self.buf) > self.MAX:
            self._reply(http_response(*_error(400, "too-big", "request too large", "transport")))
        elif self.shaken and request_done(self.buf):
            con = self.factory(self.dash)
            resp, self.user = answer(self.dash.lab, con, self.buf)
            self.logged = bool(self.user)
            self._reply(resp)
        return self.out.read()

    def _reply(self, resp: bytes) -> None:
        try:
            self.tls.write(resp)
            self.tls.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLError, OSError):
            pass
        self.s.mode = "idle"
