"""Tunnel interfaces and site-to-site IPsec (IKEv2) on the lab router, as
typed at its console.

IOS builds a route-based VPN from parts that name each other:

* ``crypto ikev2 proposal`` (encryption, integrity, DH group), gathered by
  ``crypto ikev2 policy`` (optionally only for one local address);
* ``crypto ikev2 keyring`` with a ``peer``: its address and its pre-shared
  key;
* ``crypto ikev2 profile``: which peer identity it is for (``match identity
  remote address``), how both sides authenticate (``pre-share``), which
  keyring;
* ``crypto ipsec transform-set`` (ESP encryption and integrity) and
  ``crypto ipsec profile`` (``set transform-set``, ``set ikev2-profile``,
  ``set pfs``);
* ``interface Tunnel0`` with an address, ``tunnel source``, ``tunnel
  destination``, ``tunnel mode ipsec ipv4`` and ``tunnel protection ipsec
  profile``: a static virtual tunnel interface (VTI). What is routed into it
  (``ip route ... Tunnel0``) is encrypted to the peer.

On the router (an Alpine VM) this is the same design in Linux: the tunnel
interface is an XFRM interface (``ip link add wltun0 type xfrm if_id ...``),
and strongSwan's charon, driven by swanctl, does IKEv2 with the peer and
installs the IPsec SAs and policies for that interface ID with 0.0.0.0/0 on
both sides, as an IOS VTI proposes. A tunnel left in ``tunnel mode gre ip``
(IOS's default) is a plain GRE tunnel (``ip link add ... type gre``),
unencrypted, as on IOS.

The far end is another machine in the lab that the student sets up too: a
Linux server with strongSwan (the ``strongswan`` pack), or another router.
The lab is sealed, so "the Internet" between the two sites is a lab network.

Classic crypto maps (``crypto map``, an access list choosing what is
encrypted on a physical interface) are not built here: the lessons teach
the route-based VTI, which is what IOS and strongSwan recommend today.
Only pre-shared keys authenticate; certificates (``rsa-sig``) are not
modelled. The pre-shared key is kept in the lab file scrambled (type 7, as
IOS keeps a line password), shown in clear by show running-config as IOS
shows it, and written on the router only in strongSwan's own configuration
(mode 600).

Settings (JSON values): ``ikev2-proposal:<n>``, ``ikev2-policy:<n>``,
``ikev2-keyring:<n>``, ``ikev2-profile:<n>``, ``ipsec-tset:<n>``,
``ipsec-profile:<n>``, ``tunnel:<number>``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from . import iosl3

DEV = "wltun"
IF_ID = 0x100
SWAN_CONF = "/etc/swanctl/conf.d/winlab-router.conf"
CHARON = "/usr/lib/strongswan/charon"
TABLE = "wltun"

ENCR = {"aes-cbc-128": "aes128", "aes-cbc-192": "aes192", "aes-cbc-256": "aes256", "aes-gcm-128": "aes128gcm16",
        "aes-gcm-256": "aes256gcm16", "3des": "3des"}
INTEG = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
GROUPS = {"1": "modp768", "2": "modp1024", "5": "modp1536", "14": "modp2048", "15": "modp3072",
          "16": "modp4096", "19": "ecp256", "20": "ecp384", "21": "ecp521", "24": "modp2048s256"}
# IOS's default IKEv2 proposal, used when no policy names one.
DEFAULT_IKE = {"encryption": ["aes-cbc-256", "aes-cbc-192", "aes-cbc-128"],
               "integrity": ["sha512", "sha384", "sha256", "sha1"], "prf": [], "group": ["19", "14", "21", "5"]}
ESP_ENC = {"esp-aes": {"128": "aes128", "192": "aes192", "256": "aes256"},
           "esp-gcm": {"128": "aes128gcm16", "256": "aes256gcm16"}, "esp-3des": {"": "3des"},
           "esp-null": {"": "null"}}
ESP_AUTH = {"esp-md5-hmac": "md5", "esp-sha-hmac": "sha1", "esp-sha256-hmac": "sha256",
            "esp-sha384-hmac": "sha384", "esp-sha512-hmac": "sha512"}
DEFAULT_ESP = "aes128-sha1,3des-sha1"   # IOS's default transform sets
KEY_RE = re.compile(r"^[A-Za-z0-9!#$%&()*+,./:;<=>?@^_`{|}~-]{1,128}$")


# ------------------------------------------------------------------ settings
def _j(own: dict, key: str) -> dict:
    try:
        d = json.loads(own.get(key, "") or "{}")
    except ValueError:
        d = {}
    return d if isinstance(d, dict) else {}


def _put(own: dict, key: str, d: dict) -> None:
    own[key] = json.dumps(d, separators=(",", ":"), sort_keys=True)


def names(own: dict, kind: str) -> list[str]:
    p = f"{kind}:"
    return sorted(k[len(p):] for k in own if k.startswith(p))


def tunnel_name(text: str) -> str:
    """'Tunnel0', 'tu 0', 'tun1' -> 'Tunnel<n>'; '' when it is no tunnel."""
    m = re.match(r"^\s*tu(?:n(?:n(?:e(?:l)?)?)?)?\s*(\d{1,3})\s*$", text, re.I)
    return f"Tunnel{int(m.group(1))}" if m else ""


def tunnels(own: dict) -> list[tuple[str, dict]]:
    out = []
    for k in own:
        if k.startswith("tunnel:") and k[7:].isdigit():
            out.append((int(k[7:]), f"Tunnel{k[7:]}", _j(own, k)))
    return [(n, d) for _, n, d in sorted(out)]


def tunnel(own: dict, name: str) -> dict:
    return _j(own, f"tunnel:{name[6:]}")


def dev_of(name: str) -> str:
    return f"{DEV}{name[6:]}"


def tunnel_dev(lab, name: str) -> str:
    """The router's Linux interface for a tunnel that is up, or ''."""
    own = lab.devices.get("router", {})
    t = tunnel(own, name)
    if not t or t.get("shut") or not t.get("ip"):
        return ""
    return dev_of(name)


def _source(lab, plan, t: dict) -> tuple[str, str]:
    """(the router's own address the tunnel starts from, its Linux interface)."""
    from . import devcli
    src = t.get("src", "")
    if not src:
        return "", ""
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", src):
        for net in lab.networks.values():
            if net.routed and net.router_ip == src:
                try:
                    return src, plan.segment_of(net.id).svi
                except KeyError:
                    return src, ""
        return src, ""
    dev = iosl3.svi_for(lab, plan, src)
    net = devcli.iface_net(lab, src)
    return (net.router_ip, dev) if dev and net is not None else ("", "")


def _peer_for(own: dict, keyring: str, dst: str) -> dict:
    kr = _j(own, f"ikev2-keyring:{keyring}")
    for name in sorted(kr):
        p = kr[name]
        addr = p.get("address", "")
        try:
            if addr and ipaddress.IPv4Address(dst) in ipaddress.IPv4Network(addr.replace(" ", "/"), strict=False):
                return p
        except ValueError:
            continue
    for name in sorted(kr):
        if kr[name].get("identity") == dst:
            return kr[name]
    return {}


def _ike_proposals(own: dict, local: str) -> str:
    chosen: list[str] = []
    for pol in names(own, "ikev2-policy"):
        d = _j(own, f"ikev2-policy:{pol}")
        if d.get("local") and local not in d["local"]:
            continue
        chosen = d.get("proposal", [])
        if chosen:
            break
    out = []
    for p in chosen:
        d = _j(own, f"ikev2-proposal:{p}")
        s = proposal_string(d)
        if s:
            out.append(s)
    return ",".join(out) or proposal_string(DEFAULT_IKE)


def proposal_string(d: dict) -> str:
    enc = [ENCR[e] for e in d.get("encryption", []) if e in ENCR]
    integ = [INTEG[i] for i in d.get("integrity", []) if i in INTEG]
    prf = ["prf" + INTEG[i] for i in d.get("prf", []) if i in INTEG]
    grp = [GROUPS[g] for g in d.get("group", []) if g in GROUPS]
    aead = enc and all("gcm" in e for e in enc)
    if not enc or not grp or (not integ and not aead) or (aead and not prf and not integ):
        return ""
    if aead:
        prf = prf or ["prf" + i for i in integ]
        integ = []
    return "-".join(enc + integ + prf + grp)


def esp_string(own: dict, prof: dict) -> str:
    out = []
    for ts in prof.get("tsets", []):
        d = _j(own, f"ipsec-tset:{ts}")
        enc = [x for x in d.get("t", []) if x.split()[0] in ESP_ENC]
        auth = [ESP_AUTH[x] for x in d.get("t", []) if x in ESP_AUTH]
        if not enc:
            continue
        w = enc[0].split()
        e = ESP_ENC[w[0]].get(w[1] if len(w) > 1 else next(iter(ESP_ENC[w[0]])), "")
        s = "-".join([e] + ([] if "gcm" in e else auth))
        if prof.get("pfs"):
            s += "-" + GROUPS.get(prof["pfs"], "modp2048")
        out.append(s)
    if not out:
        return ",".join(x + ("-" + GROUPS.get(prof["pfs"], "") if prof.get("pfs") else "")
                        for x in DEFAULT_ESP.split(","))
    return ",".join(out)


def psk_clear(kept: str) -> str:
    from . import iosnv
    kind, _, value = kept.partition(" ")
    try:
        return iosnv.untype7(value) if kind == "7" else ""
    except ValueError:
        return ""


def swan_conn(lab, plan, name: str, t: dict) -> tuple[list[str], list[str], str]:
    """(connection lines, secret lines, why not) for an IPsec tunnel."""
    own = lab.devices.get("router", {})
    local, _dev = _source(lab, plan, t)
    dst = t.get("dst", "")
    if not local:
        return [], [], "its tunnel source has no address up"
    if not dst:
        return [], [], "no tunnel destination"
    prof = _j(own, f"ipsec-profile:{t.get('prot', '')}")
    if not t.get("prot") or not prof:
        return [], [], "no tunnel protection ipsec profile (or the profile does not exist)"
    ike = _j(own, f"ikev2-profile:{prof.get('ikev2', '')}")
    if not prof.get("ikev2") or not ike:
        return [], [], f"ipsec profile {t['prot']} names no IKEv2 profile (set ikev2-profile)"
    peer = _peer_for(own, ike.get("keyring", ""), dst)
    psk = psk_clear(peer.get("psk", "") or peer.get("psk-local", "") or peer.get("psk-remote", ""))
    if not psk or not KEY_RE.match(psk):
        return [], [], f"IKEv2 profile {prof['ikev2']}: no keyring peer with a pre-shared key for {dst}"
    if ike.get("auth-local") != "pre-share" or ike.get("auth-remote") != "pre-share":
        return [], [], f"IKEv2 profile {prof['ikev2']}: authentication local and remote must be pre-share"
    remote_id = dst
    for m in ike.get("match", []):
        net = ipaddress.IPv4Network(m.replace(" ", "/"), strict=False)
        if ipaddress.IPv4Address(dst) not in net:
            continue
        remote_id = dst if net.prefixlen < 32 else str(net.network_address)
        break
    else:
        return [], [], f"IKEv2 profile {prof['ikev2']} has no match identity remote address for {dst}"
    local_id = ike.get("identity", "") or local
    if_id = f"{IF_ID + int(name[6:]):#x}"
    conn = [f"    {name} {{", "        version = 2", f"        local_addrs = {local}", f"        remote_addrs = {dst}",
            f"        proposals = {_ike_proposals(own, local)}", "        keyingtries = 0",
            f"        rekey_time = {int(ike.get('lifetime', 86400))}s"]
    if ike.get("dpd"):
        conn.append(f"        dpd_delay = {int(ike['dpd'].split()[0])}s")
    conn += ["        local {", "            auth = psk", f"            id = {local_id}", "        }",
             "        remote {", "            auth = psk", f"            id = {remote_id}", "        }",
             "        children {", f"            {name} {{", "                local_ts = 0.0.0.0/0",
             "                remote_ts = 0.0.0.0/0", f"                esp_proposals = {esp_string(own, prof)}",
             "                mode = tunnel", f"                if_id_in = {if_id}", f"                if_id_out = {if_id}",
             f"                rekey_time = {int(prof.get('lifetime', 3600))}s",
             "                start_action = start", "                dpd_action = restart",
             "                close_action = start", "            }", "        }", "    }"]
    sec = [f"    ike-{name} {{", f"        id-a = {local_id}", f"        id-b = {remote_id}",
           f'        secret = "{psk}"', "    }"]
    return conn, sec, ""


# ------------------------------------------------------------------ rendering
def render(plan, reset: bool = False) -> list[str]:
    """Shell for the router: its tunnel interfaces, strongSwan for the IPsec
    ones, the routes into them; empty when there are none and nothing must
    be undone."""
    lab = plan.lab
    own = lab.devices.get("router", {})
    tuns = tunnels(own)
    if not tuns and not reset:
        return []
    out = ["### tunnel interfaces and IPsec typed at the router's console (winlab/vti.py)",
           f"for d in $(ip -o link show 2>/dev/null | sed -n 's/^[0-9]*: \\({DEV}[0-9]*\\)[@:].*/\\1/p'); do "
           "ip link del $d 2>/dev/null; done",
           f"nft delete table ip {TABLE} 2>/dev/null || true"]
    conns, secs, ipsec, mss = [], [], [], []
    for name, t in tuns:
        dev = dev_of(name)
        local, under = _source(lab, plan, t)
        if t.get("shut"):
            out.append(f"# {name} is shut down")
            continue
        if not t.get("ip"):
            out.append(f"# {name} has no ip address: not built")
            continue
        if t.get("mode") == "ipsec":
            out.append(f"ip link add {dev} type xfrm" + (f" dev {under}" if under else "")
                       + f" if_id {IF_ID + int(name[6:]):#x} || true")
            conn, sec, why = swan_conn(lab, plan, name, t)
            if why:
                out.append(f"# {name}: no IPsec yet: {why}")
            else:
                conns += conn
                secs += sec
                ipsec.append(name)
        else:
            if not local or not t.get("dst"):
                out.append(f"# {name}: GRE needs a tunnel source that is up and a tunnel destination")
                continue
            out.append(f"ip link add {dev} type gre local {local} remote {t['dst']} ttl 255 || true")
        if t.get("mtu"):
            out.append(f"ip link set {dev} mtu {t['mtu']} || true")
        out += [f"ip addr replace {t['ip']} dev {dev} || true", f"ip link set {dev} up || true"]
        if t.get("mss"):
            mss += [f'oifname "{dev}" tcp flags syn tcp option maxseg size set {t["mss"]}',
                    f'iifname "{dev}" tcp flags syn tcp option maxseg size set {t["mss"]}']
    # routes typed with the tunnel as their interface (winlab/iosl3.py keeps them)
    for net, target, dist in iosl3.routes(own):
        if target.startswith("Tunnel") and tunnel_dev(lab, target):
            out.append(f"ip route replace {net} dev {dev_of(target)} proto {iosl3.ROUTE_PROTO} metric {dist} "
                       "2>/dev/null || true")
    if mss:
        out += ["nft -f - <<'EOF' || true", f"table ip {TABLE} {{", "  chain forward {",
                "    type filter hook forward priority mangle; policy accept;"]
        out += [f"    {r}" for r in mss] + ["  }", "}", "EOF"]
    if conns:
        out += ["mkdir -p /etc/swanctl/conf.d /etc/strongswan.d",
                "cat > /etc/strongswan.d/winlab-router.conf <<'EOF'",
                "# winlab: the tunnel interfaces carry the routes, not charon's table 220",
                "charon {", "    install_routes = no", "}", "EOF",
                "umask 077",
                "cat > /run/winlab-swan.new <<'EOF'",
                "# generated by winlab from the router's console: crypto ikev2, crypto ipsec, interface Tunnel",
                "connections {"] + conns + ["}", "secrets {"] + secs + ["}", "EOF",
                "umask 022",
                "WLSWAN=0",
                f"if ! cmp -s /run/winlab-swan.new {SWAN_CONF}; then mv /run/winlab-swan.new {SWAN_CONF}; "
                "WLSWAN=1; else rm -f /run/winlab-swan.new; fi",
                f"pgrep -x charon >/dev/null 2>&1 || {{ setsid {CHARON} </dev/null >/dev/null 2>&1 & sleep 2; "
                "WLSWAN=1; }",
                "if [ $WLSWAN = 1 ]; then swanctl --load-all >/dev/null 2>&1 || { sleep 3; "
                "swanctl --load-all >/dev/null 2>&1; }",
                f"  for c in {' '.join(ipsec)}; do swanctl --terminate --ike $c --force >/dev/null 2>&1; "
                "(swanctl --initiate --child $c --timeout 20 >/dev/null 2>&1 &); done", "fi"]
    else:
        out += [f"if [ -e {SWAN_CONF} ]; then rm -f {SWAN_CONF}; pkill -x charon 2>/dev/null; "
                "ip xfrm state flush; ip xfrm policy flush; fi"]
    out.append("")
    return out


def render_hash(plan) -> str:
    return hashlib.sha256("\n".join(render(plan)).encode()).hexdigest()


# ------------------------------------------------------------------ reading
SAS_CMD = "swanctl --list-sas 2>/dev/null"


def parse_sas(text: str) -> list[dict]:
    """swanctl --list-sas -> [{name, id, state, local, lport, remote, rport,
    algs, age, children: [{name, state, alg, spi_in, spi_out, bytes_in,
    pkts_in, bytes_out, pkts_out, local_ts, remote_ts, rekey, expires}]}]."""
    out: list[dict] = []
    ike = child = None
    for raw in text.splitlines():
        line = raw.rstrip()
        m = re.match(r"^(\S+): #(\d+), (\w+), IKEv(\d)", line)
        if m:
            ike = {"name": m.group(1), "id": int(m.group(2)), "state": m.group(3), "local": "", "lport": "500",
                   "remote": "", "rport": "500", "algs": "", "age": 0, "children": []}
            out.append(ike)
            child = None
            continue
        if ike is None:
            continue
        m = re.match(r"^\s+(\S+): #(\d+), reqid \d+, (\w+), (\w+), (?:ESP|AH):(\S+)", line)
        if m:
            child = {"name": m.group(1), "state": m.group(3), "mode": m.group(4), "alg": m.group(5),
                     "spi_in": "", "spi_out": "", "bytes_in": 0, "pkts_in": 0, "bytes_out": 0, "pkts_out": 0,
                     "local_ts": "", "remote_ts": "", "rekey": 0, "expires": 0}
            ike["children"].append(child)
            continue
        m = re.match(r"^\s+(local|remote)\s+'[^']*' @ (\S+)\[(\d+)\]", line)
        if m and child is None:
            ike[m.group(1)] = m.group(2)
            ike["lport" if m.group(1) == "local" else "rport"] = m.group(3)
            continue
        m = re.match(r"^\s+([A-Z0-9_]+-?\d*(?:/[A-Z0-9_]+-?\d*)+)\s*$", line)
        if m and child is None:
            ike["algs"] = m.group(1)
            continue
        m = re.search(r"established (\d+)s ago", line)
        if m and child is None:
            ike["age"] = int(m.group(1))
            continue
        if child is not None:
            m = re.match(r"^\s+(in|out)\s+([0-9a-f]+)(?:_i|_o)?(?: \([^)]*\))?,\s+(\d+) bytes,\s+(\d+) packets", line)
            if m:
                k = m.group(1)
                child[f"spi_{k}"] = m.group(2)
                child[f"bytes_{k}"], child[f"pkts_{k}"] = int(m.group(3)), int(m.group(4))
                continue
            m = re.match(r"^\s+(local|remote)\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m:
                child[f"{m.group(1)}_ts"] = m.group(2)
                continue
            m = re.search(r"rekeying in (\d+)s, expires in (\d+)s", line)
            if m:
                child["rekey"], child["expires"] = int(m.group(1)), int(m.group(2))
    return out


def _alg_parts(algs: str) -> dict:
    out = {"encr": "", "keysize": "", "prf": "", "hash": "", "group": ""}
    for a in algs.split("/"):
        m = re.match(r"^(AES_CBC|AES_GCM_16|3DES_CBC)(?:-(\d+))?$", a)
        if m:
            out["encr"] = {"AES_CBC": "AES-CBC", "AES_GCM_16": "AES-GCM", "3DES_CBC": "3DES"}[m.group(1)]
            out["keysize"] = m.group(2) or ""
        elif a.startswith("PRF_"):
            out["prf"] = a.replace("PRF_HMAC_", "").replace("SHA2_", "SHA").replace("SHA1", "SHA1")
        elif a.startswith("HMAC_"):
            out["hash"] = re.sub(r"_\d+$", "", a.replace("HMAC_", "")).replace("SHA2_", "SHA")
        elif a.startswith(("MODP_", "ECP_", "CURVE_")):
            rev = {v.upper().replace("MODP", "MODP_").replace("ECP", "ECP_"): k for k, v in GROUPS.items()}
            out["group"] = rev.get(a, a)
    return out


# ------------------------------------------------------------------ the console
def _key_line(kept: str, enc: bool) -> str:
    from . import iosnv
    return iosnv.run_form(kept, enc)


def run_lines(own: dict) -> list[str]:
    """crypto ikev2 and crypto ipsec, as show running-config prints them."""
    enc = bool(own.get("service-pwenc"))
    out = []
    for n in names(own, "ikev2-proposal"):
        d = _j(own, f"ikev2-proposal:{n}")
        out.append(f"crypto ikev2 proposal {n} ")
        for k in ("encryption", "integrity", "prf", "group"):
            if d.get(k):
                out.append(f" {k} {' '.join(d[k])}")
        out.append("!")
    for n in names(own, "ikev2-policy"):
        d = _j(own, f"ikev2-policy:{n}")
        out.append(f"crypto ikev2 policy {n} ")
        out += [f" match address local {a}" for a in d.get("local", [])]
        out += [f" proposal {p}" for p in d.get("proposal", [])]
        out.append("!")
    for n in names(own, "ikev2-keyring"):
        out.append(f"crypto ikev2 keyring {n}")
        kr = _j(own, f"ikev2-keyring:{n}")
        for peer in sorted(kr):
            p = kr[peer]
            out.append(f" peer {peer}")
            out += [f"  description {p['desc']}"] if p.get("desc") else []
            out += [f"  address {p['address']}"] if p.get("address") else []
            out += [f"  identity address {p['identity']}"] if p.get("identity") else []
            for k, w in (("psk", ""), ("psk-local", "local "), ("psk-remote", "remote ")):
                if p.get(k):
                    out.append(f"  pre-shared-key {w}{_key_line(p[k], enc)}")
            out.append(" !")
        out.append("!")
    for n in names(own, "ikev2-profile"):
        d = _j(own, f"ikev2-profile:{n}")
        out.append(f"crypto ikev2 profile {n}")
        out += [f" match identity remote address {m}" for m in d.get("match", [])]
        out += [f" identity local address {d['identity']}"] if d.get("identity") else []
        out += [f" authentication remote {d['auth-remote']}"] if d.get("auth-remote") else []
        out += [f" authentication local {d['auth-local']}"] if d.get("auth-local") else []
        out += [f" keyring local {d['keyring']}"] if d.get("keyring") else []
        out += [f" lifetime {d['lifetime']}"] if d.get("lifetime") else []
        out += [f" dpd {d['dpd']}"] if d.get("dpd") else []
        out.append("!")
    for n in names(own, "ipsec-tset"):
        d = _j(own, f"ipsec-tset:{n}")
        out.append(f"crypto ipsec transform-set {n} {' '.join(d.get('t', []))} ")
        out.append(f" mode {d.get('mode', 'tunnel')}")
        out.append("!")
    for n in names(own, "ipsec-profile"):
        d = _j(own, f"ipsec-profile:{n}")
        out.append(f"crypto ipsec profile {n}")
        out += [f" set security-association lifetime seconds {d['lifetime']}"] if d.get("lifetime") else []
        out += [f" set transform-set {' '.join(d['tsets'])} "] if d.get("tsets") else []
        out += [f" set pfs group{d['pfs']}"] if d.get("pfs") else []
        out += [f" set ikev2-profile {d['ikev2']}"] if d.get("ikev2") else []
        out.append("!")
    return out


def iface_blocks(own: dict, extra) -> list[str]:
    """The tunnel interfaces' blocks; `extra(name)` gives the lines other
    features keep on an interface (zone-member, service-policy)."""
    out = []
    for name, t in tunnels(own):
        out.append(f"interface {name}")
        out += [f" description {t['desc']}"] if t.get("desc") else []
        if t.get("ip"):
            i = ipaddress.IPv4Interface(t["ip"])
            out.append(f" ip address {i.ip} {i.netmask}")
        else:
            out.append(" no ip address")
        out += [f" ip mtu {t['mtu']}"] if t.get("mtu") else []
        out += [f" ip tcp adjust-mss {t['mss']}"] if t.get("mss") else []
        out += extra(name)
        out += [" shutdown"] if t.get("shut") else []
        out += [f" tunnel source {t['src']}"] if t.get("src") else []
        out += [" tunnel mode ipsec ipv4"] if t.get("mode") == "ipsec" else []
        out += [f" tunnel destination {t['dst']}"] if t.get("dst") else []
        out += [f" tunnel protection ipsec profile {t['prot']}"] if t.get("prot") else []
        out.append("!")
    return out


def brief_rows(con) -> list[str]:
    own = con.lab.devices.get("router", {})
    rows = []
    for name, t in tunnels(own):
        ip = str(ipaddress.IPv4Interface(t["ip"]).ip) if t.get("ip") else "unassigned"
        how = "manual" if t.get("ip") else "unset"
        if t.get("shut"):
            st, pr = "administratively down", "down"
        else:
            st = "up"
            local, _ = _source(con.lab, con.plan, t)
            pr = "up" if local and t.get("dst") and con.powered() else "down"
        rows.append(f"{name:<23}{ip:<16}{'YES':<4}{how:<7}{st:<22}{pr}")
    return rows


def connected(con) -> list[tuple]:
    own = con.lab.devices.get("router", {})
    out = []
    for name, t in tunnels(own):
        row = next((r for r in brief_rows(con) if r.startswith(name + " ")), "")
        if t.get("ip") and row.endswith(" up"):
            i = ipaddress.IPv4Interface(t["ip"])
            out.append((i.network, name, str(i.ip)))
    return out


def add_specs(con, add, U, E, C, IF, sub) -> None:
    PR, PO, KR, KP, PF = ("config-ikev2-proposal",), ("config-ikev2-policy",), ("config-ikev2-keyring",), \
        ("config-ikev2-keyring-peer",), ("config-ikev2-profile",)
    TS, IP, T = ("config-crypto-trans",), ("config-ipsec-profile",), ("config-if-tunnel",)
    sub(PR + PO + KR + KP + PF + TS + IP + T)
    CR = C + PR + PO + KR + KP + PF + TS + IP
    for kind, mode, help_ in (("proposal", PR, "Define IKEv2 proposals"), ("policy", PO, "Define IKEV2 policies"),
                              ("keyring", KR, "Define IKEv2 keyrings"), ("profile", PF, "Define IKEv2 profiles")):
        add(f"crypto ikev2 {kind} <name>", lambda a, k=kind: _enter(con, f"ikev2-{k}", a[0]), help_, CR)
        add(f"no crypto ikev2 {kind} <name>", lambda a, k=kind: _no(con, f"ikev2-{k}:{a[0]}"),
            "Negate a command or set its defaults", C)
    add("crypto ipsec transform-set <name> <line>", lambda a: _tset(con, a[0], a[1]),
        "Define transform and settings", CR)
    add("no crypto ipsec transform-set <name>", lambda a: _no(con, f"ipsec-tset:{a[0]}"),
        "Negate a command or set its defaults", C)
    add("crypto ipsec profile <name>", lambda a: _enter(con, "ipsec-profile", a[0]),
        "Configure an ipsec policy profile", CR)
    add("no crypto ipsec profile <name>", lambda a: _no(con, f"ipsec-profile:{a[0]}"),
        "Negate a command or set its defaults", C)
    # proposal
    for k, help_ in (("encryption", "Set encryption algorithm(s) for proposal"),
                     ("integrity", "Set integrity hash algorithm(s) for proposal"),
                     ("prf", "Set prf algorithm(s) for proposal"), ("group", "Set the Diffie-Hellman group(s)")):
        add(f"{k} <line>", lambda a, x=k: _proposal(con, x, a[0].split(), True), help_, PR)
        add(f"no {k} <line>", lambda a, x=k: _proposal(con, x, a[0].split(), False),
            "Negate a command or set its defaults", PR)
    # policy
    add("proposal <name>", lambda a: _policy(con, "proposal", a[0], True), "Specify Proposal", PO)
    add("no proposal <name>", lambda a: _policy(con, "proposal", a[0], False), "Negate a command or set its defaults", PO)
    add("match address local <ip>", lambda a: _policy(con, "local", a[0], True), "Local address", PO)
    add("no match address local <ip>", lambda a: _policy(con, "local", a[0], False),
        "Negate a command or set its defaults", PO)
    # keyring
    add("peer <name>", lambda a: _peer(con, a[0]), "Configure a Peer and associated keys", KR + KP)
    add("no peer <name>", lambda a: _no_peer(con, a[0]), "Negate a command or set its defaults", KR)
    add("address <ip>", lambda a: _peer_set(con, "address", f"{a[0]} 255.255.255.255"), "IPv4 address", KP)
    add("address <ip> <mask>", lambda a: _peer_set(con, "address", f"{a[0]} {a[1]}"), "IPv4 address", KP)
    add("no address", lambda a: _peer_set(con, "address", None), "Negate a command or set its defaults", KP)
    add("identity address <ip>", lambda a: _peer_set(con, "identity", a[0]), "Peer identity", KP)
    add("no identity", lambda a: _peer_set(con, "identity", None), "Negate a command or set its defaults", KP)
    add("description <line>", lambda a: _peer_set(con, "desc", a[0]), "Specify a description of this peer", KP)
    add("pre-shared-key <line>", lambda a: _psk(con, "psk", a[0]), "Specify pre-shared key", KP)
    add("pre-shared-key local <line>", lambda a: _psk(con, "psk-local", a[0]), "Local signing key", KP)
    add("pre-shared-key remote <line>", lambda a: _psk(con, "psk-remote", a[0]), "Remote verification key", KP)
    add("no pre-shared-key", lambda a: [_peer_set(con, k, None) for k in ("psk", "psk-local", "psk-remote")][-1],
        "Negate a command or set its defaults", KP)
    # profile
    add("match identity remote address <ip>", lambda a: _prof_match(con, f"{a[0]} 255.255.255.255", True),
        "IP address", PF)
    add("match identity remote address <ip> <mask>", lambda a: _prof_match(con, f"{a[0]} {a[1]}", True),
        "IP address", PF)
    add("no match identity remote address <ip> <mask>", lambda a: _prof_match(con, f"{a[0]} {a[1]}", False),
        "Negate a command or set its defaults", PF)
    add("no match identity remote address <ip>", lambda a: _prof_match(con, f"{a[0]} 255.255.255.255", False),
        "Negate a command or set its defaults", PF)
    add("identity local address <ip>", lambda a: _prof_set(con, "identity", a[0]), "Local IKE identity", PF)
    add("no identity local", lambda a: _prof_set(con, "identity", None), "Negate a command or set its defaults", PF)
    add("no identity local address <ip>", lambda a: _prof_set(con, "identity", None),
        "Negate a command or set its defaults", PF)
    for side in ("local", "remote"):
        add(f"authentication {side} pre-share", lambda a, s=side: _prof_set(con, f"auth-{s}", "pre-share"),
            "Pre-Shared Key", PF)
        add(f"authentication {side} <name>", lambda a, s=side: _auth_other(con, a[0]), "Authentication method", PF)
        add(f"no authentication {side}", lambda a, s=side: _prof_set(con, f"auth-{s}", None),
            "Negate a command or set its defaults", PF)
        add(f"no authentication {side} <line>", lambda a, s=side: _prof_set(con, f"auth-{s}", None),
            "Negate a command or set its defaults", PF)
    add("keyring local <name>", lambda a: _prof_set(con, "keyring", a[0]), "Keyring", PF)
    add("no keyring", lambda a: _prof_set(con, "keyring", None), "Negate a command or set its defaults", PF)
    add("no keyring local <name>", lambda a: _prof_set(con, "keyring", None), "Negate a command or set its defaults", PF)
    add("lifetime <num>", lambda a: _prof_num(con, "lifetime", a[0], 120, 86400), "Specify lifetime for IKE SAs", PF)
    add("no lifetime", lambda a: _prof_set(con, "lifetime", None), "Negate a command or set its defaults", PF)
    add("dpd <num> <num> <name>", lambda a: _dpd(con, a), "Enable IKE liveness check for peers", PF)
    add("no dpd", lambda a: _prof_set(con, "dpd", None), "Negate a command or set its defaults", PF)
    # transform-set
    add("mode tunnel", lambda a: _tset_mode(con, "tunnel"), "tunnel (datagram encapsulation) mode", TS)
    add("mode transport", lambda a: _tset_mode(con, "transport"), "transport (payload encapsulation) mode", TS)
    add("no mode", lambda a: _tset_mode(con, "tunnel"), "Negate a command or set its defaults", TS)
    # ipsec profile
    add("set transform-set <line>", lambda a: _ip_set(con, "tsets", a[0].split()), "Specify list of transform sets", IP)
    add("set ikev2-profile <name>", lambda a: _ip_set(con, "ikev2", a[0]), "Specify ikev2 Profile", IP)
    add("set pfs <name>", lambda a: _ip_set(con, "pfs", a[0]), "Specify pfs settings", IP)
    add("set security-association lifetime seconds <num>", lambda a: _ip_set(con, "lifetime", a[0]),
        "Time-based key duration in seconds", IP)
    for k, key in (("transform-set", "tsets"), ("ikev2-profile", "ikev2"), ("pfs", "pfs"),
                   ("security-association lifetime seconds", "lifetime")):
        add(f"no set {k}", lambda a, x=key: _ip_set(con, x, None), "Negate a command or set its defaults", IP)
        add(f"no set {k} <line>", lambda a, x=key: _ip_set(con, x, None), "Negate a command or set its defaults", IP)
    # interface Tunnel
    add("ip address <ip> <mask>", lambda a: _tun_ip(con, a[0], a[1]), "Set the IP address of an interface", T)
    add("no ip address", lambda a: _tun_set(con, "ip", None), "Negate a command or set its defaults", T)
    add("no ip address <line>", lambda a: _tun_set(con, "ip", None), "Negate a command or set its defaults", T)
    add("description <line>", lambda a: _tun_set(con, "desc", a[0]), "Interface specific description", T)
    add("no description", lambda a: _tun_set(con, "desc", None), "Negate a command or set its defaults", T)
    add("shutdown", lambda a: _tun_set(con, "shut", True), "Shutdown the selected interface", T)
    add("no shutdown", lambda a: _tun_set(con, "shut", None), "Negate a command or set its defaults", T)
    add("ip mtu <num>", lambda a: _tun_num(con, "mtu", a[0], 68, 9000), "Set IP Maximum Transmission Unit", T)
    add("no ip mtu", lambda a: _tun_set(con, "mtu", None), "Negate a command or set its defaults", T)
    add("ip tcp adjust-mss <num>", lambda a: _tun_num(con, "mss", a[0], 500, 1460), "Adjust the mss of transit packets", T)
    add("no ip tcp adjust-mss", lambda a: _tun_set(con, "mss", None), "Negate a command or set its defaults", T)
    add("tunnel source <line>", lambda a: _tun_src(con, a[0]), "source of tunnel packets", T)
    add("no tunnel source", lambda a: _tun_set(con, "src", None), "Negate a command or set its defaults", T)
    add("tunnel destination <ip>", lambda a: _tun_dst(con, a[0]), "destination of tunnel", T)
    add("no tunnel destination", lambda a: _tun_set(con, "dst", None), "Negate a command or set its defaults", T)
    add("tunnel mode ipsec ipv4", lambda a: _tun_set(con, "mode", "ipsec"), "over IPv4", T)
    add("tunnel mode gre ip", lambda a: _tun_set(con, "mode", None), "over IP", T)
    add("no tunnel mode", lambda a: _tun_set(con, "mode", None), "Negate a command or set its defaults", T)
    add("tunnel protection ipsec profile <name>", lambda a: _tun_prot(con, a[0]), "Determine the ipsec policy profile to use.", T)
    add("no tunnel protection ipsec profile", lambda a: _tun_set(con, "prot", None), "Negate a command or set its defaults", T)
    add("no tunnel protection ipsec profile <name>", lambda a: _tun_set(con, "prot", None),
        "Negate a command or set its defaults", T)
    # show and clear
    add("show crypto ikev2 sa", lambda a: show_ike_sa(con, False), "Shows ikev2 SAs", U)
    add("show crypto ikev2 sa detailed", lambda a: show_ike_sa(con, True), "detailed output", U)
    add("show crypto ipsec sa", lambda a: show_ipsec_sa(con), "IPSEC SA table", U)
    add("show crypto session", lambda a: show_session(con), "Show crypto sessions currently established", U)
    add("show crypto ikev2 proposal", lambda a: show_conf(con, "ikev2-proposal"), "Show IKEv2 proposals", U)
    add("show crypto ikev2 policy", lambda a: show_conf(con, "ikev2-policy"), "Show IKEv2 policies", U)
    add("show crypto ikev2 profile", lambda a: show_conf(con, "ikev2-profile"), "Shows ikev2 profiles", U)
    add("show crypto ipsec transform-set", lambda a: show_conf(con, "ipsec-tset"), "Crypto transform sets", U)
    add("show crypto ipsec profile", lambda a: show_conf(con, "ipsec-profile"), "ipsec profile information", U)
    add("show interfaces tunnel <num>", lambda a: show_tunnel(con, f"Tunnel{a[0]}"), "Tunnel interface", U)
    add("clear crypto session", lambda a: _clear(con), "Clear crypto session", E)
    add("clear crypto ikev2 sa", lambda a: _clear(con), "Clear IKEv2 SAs", E)


def _own(con) -> dict:
    from . import devcli
    return devcli.settings(con.lab, devcli.ROUTER)


def _err(text: str) -> Exception:
    from . import devcli
    return devcli.CliError(text)


def _done(con) -> str:
    return con._save().strip()


def _name_ok(name: str) -> str:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$", name):
        raise _err("% Invalid input detected at '^' marker.")
    return name


MODES = {"ikev2-proposal": "config-ikev2-proposal", "ikev2-policy": "config-ikev2-policy",
         "ikev2-keyring": "config-ikev2-keyring", "ikev2-profile": "config-ikev2-profile",
         "ipsec-profile": "config-ipsec-profile"}


def _enter(con, kind: str, name: str) -> str:
    _name_ok(name)
    own = _own(con)
    if f"{kind}:{name}" not in own:
        _put(own, f"{kind}:{name}", {})
    con.s.mode, con.s.ctx = MODES[kind], name
    return _done(con)


def _no(con, key: str) -> str:
    own = _own(con)
    kind, name = key.split(":", 1)
    users = {"ikev2-proposal": [n for n in names(own, "ikev2-policy")
                                if name in _j(own, f"ikev2-policy:{n}").get("proposal", [])],
             "ikev2-keyring": [n for n in names(own, "ikev2-profile")
                               if _j(own, f"ikev2-profile:{n}").get("keyring") == name],
             "ikev2-profile": [n for n in names(own, "ipsec-profile")
                               if _j(own, f"ipsec-profile:{n}").get("ikev2") == name],
             "ipsec-tset": [n for n in names(own, "ipsec-profile")
                            if name in _j(own, f"ipsec-profile:{n}").get("tsets", [])],
             "ipsec-profile": [n for n, t in tunnels(own) if t.get("prot") == name]}.get(kind, [])
    if users:
        return f"% {name} is in use by {', '.join(users)}; remove it there first"
    if own.pop(key, None) is None:
        return f"% {name} does not exist"
    return _done(con)


def _proposal(con, what: str, vals: list[str], on: bool) -> str:
    own = _own(con)
    key = f"ikev2-proposal:{con.s.ctx}"
    d = _j(own, key)
    allowed = {"encryption": ENCR, "integrity": INTEG, "prf": INTEG, "group": GROUPS}[what]
    for v in vals:
        if v.lower() not in allowed:
            raise _err("% Invalid input detected at '^' marker.")
    cur = d.get(what, [])
    if on:
        cur += [v.lower() for v in vals if v.lower() not in cur]
    else:
        cur = [v for v in cur if v not in [x.lower() for x in vals]]
    d[what] = cur
    _put(own, key, d)
    return _done(con)


def _policy(con, what: str, val: str, on: bool) -> str:
    own = _own(con)
    if what == "proposal" and on and f"ikev2-proposal:{val}" not in own:
        raise _err(f"% Proposal {val} does not exist")
    key = f"ikev2-policy:{con.s.ctx}"
    d = _j(own, key)
    cur = d.get(what, [])
    if on and val not in cur:
        cur.append(val)
    elif not on:
        cur = [v for v in cur if v != val]
    d[what] = cur
    _put(own, key, d)
    return _done(con)


def _peer(con, peer: str) -> str:
    _name_ok(peer)
    own = _own(con)
    kr_name = con.s.ctx.split("|")[0]
    key = f"ikev2-keyring:{kr_name}"
    kr = _j(own, key)
    kr.setdefault(peer, {})
    _put(own, key, kr)
    con.s.mode, con.s.ctx = "config-ikev2-keyring-peer", f"{kr_name}|{peer}"
    return _done(con)


def _no_peer(con, peer: str) -> str:
    own = _own(con)
    key = f"ikev2-keyring:{con.s.ctx}"
    kr = _j(own, key)
    kr.pop(peer, None)
    _put(own, key, kr)
    return _done(con)


def _peer_set(con, what: str, val) -> str:
    own = _own(con)
    kr_name, peer = con.s.ctx.split("|", 1)
    key = f"ikev2-keyring:{kr_name}"
    kr = _j(own, key)
    p = kr.setdefault(peer, {})
    if val is None:
        p.pop(what, None)
    else:
        if what == "address":
            a, m = val.split()
            try:
                ipaddress.IPv4Network(f"{a}/{m}", strict=False)
            except ValueError:
                raise _err("% Invalid input detected at '^' marker.") from None
        p[what] = val
    _put(own, key, kr)
    return _done(con)


def _psk(con, what: str, text: str) -> str:
    """pre-shared-key [0|6|7] <key>: kept scrambled (type 7), never in clear."""
    from . import iosnv
    w = text.split()
    if len(w) == 2 and w[0] == "7":
        try:
            clear = iosnv.untype7(w[1])
        except ValueError:
            raise _err("% Invalid encrypted key") from None
    elif len(w) == 2 and w[0] == "0":
        clear = w[1]
    elif len(w) == 1:
        clear = w[0]
    else:
        raise _err("% Invalid input detected at '^' marker.")
    if not KEY_RE.match(clear):
        raise _err("% A key here is 1 to 128 printable characters, no spaces, quotes or backslashes")
    return _peer_set(con, what, f"7 {iosnv.type7(clear)}")


def _prof(con) -> tuple[dict, str, dict]:
    own = _own(con)
    key = f"ikev2-profile:{con.s.ctx}"
    return own, key, _j(own, key)


def _prof_set(con, what: str, val) -> str:
    own, key, d = _prof(con)
    if val is None:
        d.pop(what, None)
    else:
        d[what] = val
    _put(own, key, d)
    return _done(con)


def _prof_match(con, val: str, on: bool) -> str:
    own, key, d = _prof(con)
    try:
        a, m = val.split()
        ipaddress.IPv4Network(f"{a}/{m}", strict=False)
    except ValueError:
        raise _err("% Invalid input detected at '^' marker.") from None
    cur = d.get("match", [])
    if on and val not in cur:
        cur.append(val)
    elif not on:
        cur = [v for v in cur if v != val]
    d["match"] = cur
    _put(own, key, d)
    return _done(con)


def _auth_other(con, how: str) -> str:
    if how.lower() in ("rsa-sig", "ecdsa-sig", "eap"):
        raise _err(f"% {how}: only pre-share is built in this lab (certificates are not modelled)")
    raise _err("% Invalid input detected at '^' marker.")


def _prof_num(con, what: str, val: str, lo: int, hi: int) -> str:
    if not lo <= int(val) <= hi:
        raise _err(f"% Value must be {lo} to {hi}")
    return _prof_set(con, what, val)


def _dpd(con, a) -> str:
    interval, retry, mode = a
    if not 10 <= int(interval) <= 3600 or not 2 <= int(retry) <= 60 or mode.lower() not in ("on-demand", "periodic"):
        raise _err("% Invalid input detected at '^' marker.")
    return _prof_set(con, "dpd", f"{int(interval)} {int(retry)} {mode.lower()}")


def _tset(con, name: str, text: str) -> str:
    _name_ok(name)
    w = text.lower().split()
    out, i, have_enc, have_auth = [], 0, False, False
    while i < len(w):
        t = w[i]
        if t in ESP_ENC and not have_enc:
            sizes = ESP_ENC[t]
            if i + 1 < len(w) and w[i + 1] in sizes:
                out.append(f"{t} {w[i + 1]}")
                i += 2
            else:
                out.append(t)
                i += 1
            have_enc = True
            continue
        if t in ESP_AUTH and not have_auth:
            out.append(t)
            have_auth = True
            i += 1
            continue
        if t.startswith("ah-"):
            raise _err("% AH is not built in this lab: ESP gives integrity and encryption both")
        raise _err("% Invalid input detected at '^' marker.")
    if not have_enc:
        raise _err("% A transform set here needs an ESP encryption transform (esp-aes, esp-gcm)")
    if any(x.startswith("esp-gcm") for x in out) and have_auth:
        raise _err("% esp-gcm is an authenticated cipher: it takes no esp-*-hmac")
    own = _own(con)
    key = f"ipsec-tset:{name}"
    d = _j(own, key)
    d["t"] = out
    d.setdefault("mode", "tunnel")
    _put(own, key, d)
    con.s.mode, con.s.ctx = "config-crypto-trans", name
    return _done(con)


def _tset_mode(con, mode: str) -> str:
    own = _own(con)
    key = f"ipsec-tset:{con.s.ctx}"
    d = _j(own, key)
    d["mode"] = mode
    _put(own, key, d)
    return _done(con)


def _ip_set(con, what: str, val) -> str:
    own = _own(con)
    key = f"ipsec-profile:{con.s.ctx}"
    d = _j(own, key)
    if val is None:
        d.pop(what, None)
    else:
        if what == "tsets":
            for ts in val:
                if f"ipsec-tset:{ts}" not in own:
                    raise _err(f"% transform set {ts} does not exist")
        elif what == "ikev2" and f"ikev2-profile:{val}" not in own:
            raise _err(f"% IKEv2 profile {val} does not exist")
        elif what == "pfs":
            m = re.match(r"^group(\d+)$", val.lower())
            if not m or m.group(1) not in GROUPS:
                raise _err("% Invalid input detected at '^' marker.")
            val = m.group(1)
        elif what == "lifetime" and not 120 <= int(val) <= 86400:
            raise _err("% Value must be 120 to 86400")
        d[what] = val
    _put(own, key, d)
    return _done(con)


# ---- interface Tunnel<n>
def enter_tunnel(con, text: str) -> str:
    name = tunnel_name(text)
    own = _own(con)
    key = f"tunnel:{name[6:]}"
    if key not in own:
        _put(own, key, {})
        out = f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {name}, changed state to down"
    else:
        out = ""
    con.s.mode, con.s.ctx = "config-if-tunnel", name
    con._save()
    return out


def no_tunnel(con, text: str) -> str:
    name = tunnel_name(text)
    own = _own(con)
    if own.pop(f"tunnel:{name[6:]}", None) is None:
        return ""
    for k in [k for k in own if k.endswith(f":{name}") and k.startswith(("zone-member:", "qos-out:", "qos-in:",
                                                                          "acl-in:", "acl-out:", "nat:"))]:
        del own[k]
    return _done(con)


def _tun(con) -> tuple[dict, str, dict]:
    own = _own(con)
    key = f"tunnel:{con.s.ctx[6:]}"
    return own, key, _j(own, key)


def _tun_set(con, what: str, val) -> str:
    own, key, d = _tun(con)
    if val is None:
        d.pop(what, None)
    else:
        d[what] = val
    _put(own, key, d)
    return _done(con)


def _tun_ip(con, addr: str, mask: str) -> str:
    try:
        i = ipaddress.IPv4Interface(f"{addr}/{mask}")
    except ValueError:
        raise _err("% Invalid address or mask") from None
    lab = con.lab
    for net in lab.networks.values():
        if net.routed and i.ip in net.net:
            raise _err(f"% {i.network} overlaps with {net.id}'s network")
    return _tun_set(con, "ip", str(i))


def _tun_num(con, what: str, val: str, lo: int, hi: int) -> str:
    if not lo <= int(val) <= hi:
        raise _err("% Invalid input detected at '^' marker.")
    return _tun_set(con, what, int(val))


def _tun_src(con, text: str) -> str:
    from . import devcli
    t = text.strip()
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", t):
        try:
            t = str(ipaddress.IPv4Address(t))
        except ValueError:
            raise _err("% Invalid input detected at '^' marker.") from None
    else:
        t = devcli.parse_if(t, con._if_names(), sub=True)
    return _tun_set(con, "src", t)


def _tun_dst(con, addr: str) -> str:
    try:
        addr = str(ipaddress.IPv4Address(addr))
    except ValueError:
        raise _err("% Invalid input detected at '^' marker.") from None
    return _tun_set(con, "dst", addr)


def _tun_prot(con, prof: str) -> str:
    own, key, d = _tun(con)
    if f"ipsec-profile:{prof}" not in own:
        raise _err(f"% ipsec profile {prof} does not exist")
    if d.get("mode") != "ipsec":
        raise _err("% tunnel protection here protects a VTI: tunnel mode ipsec ipv4 first "
                   "(GRE over IPsec is not built in this lab)")
    return _tun_set(con, "prot", prof)


# ---- show
def _sas(con) -> list[dict]:
    if not con.powered() or not tunnels(con.lab.devices.get("router", {})):
        return []
    try:
        return parse_sas(con._on_router(SAS_CMD, timeout=15))
    except Exception:  # noqa: BLE001 - nothing to show without the router
        return []


def show_ike_sa(con, detailed: bool) -> str:
    out = [" IPv4 Crypto IKEv2  SA ", "",
           f"{'Tunnel-id':<10}{'Local':<22}{'Remote':<22}{'fvrf/ivrf':<21}Status "]
    own = con.lab.devices.get("router", {})
    for n, sa in enumerate(_sas(con), 1):
        st = {"ESTABLISHED": "READY", "CONNECTING": "IN-NEG", "REKEYING": "READY", "DELETING": "DELETE"}.get(
            sa["state"], sa["state"])
        out.append(f"{n:<10}{sa['local'] + '/' + sa['lport']:<22}{sa['remote'] + '/' + sa['rport']:<22}"
                   f"{'none/none':<21}{st}")
        a = _alg_parts(sa["algs"])
        life = 86400
        t = tunnel(own, sa["name"]) if sa["name"].startswith("Tunnel") else {}
        prof = _j(own, f"ipsec-profile:{t.get('prot', '')}")
        ike = _j(own, f"ikev2-profile:{prof.get('ikev2', '')}")
        life = int(ike.get("lifetime", life))
        out.append(f"      Encr: {a['encr']}, keysize: {a['keysize'] or '0'}, PRF: {a['prf']}, Hash: {a['hash'] or 'None'}, "
                   f"DH Grp:{a['group']}, Auth sign: PSK, Auth verify: PSK")
        out.append(f"      Life/Active Time: {life}/{sa['age']} sec")
        if detailed:
            out += [f"      CE id: 0, Session-id: {n}", f"      Local spi: (IKE SA #{sa['id']} on {sa['name']})",
                    f"      Status Description: {'Negotiation done' if st == 'READY' else sa['state']}",
                    "      Local id: " + sa["local"], "      Remote id: " + sa["remote"],
                    "      Local req msg id:  0              Remote req msg id:  0",
                    f"      IPsec SAs: {len(sa['children'])}"]
        out.append("")
    out += ["", " IPv6 Crypto IKEv2  SA ", ""]
    return "\n".join(out)


def _esp_names(alg: str) -> str:
    m = {"AES_CBC-128": "esp-aes", "AES_CBC-192": "esp-192-aes", "AES_CBC-256": "esp-256-aes",
         "AES_GCM_16-128": "esp-gcm", "AES_GCM_16-256": "esp-gcm 256", "3DES_CBC": "esp-3des"}
    h = {"HMAC_SHA1_96": "esp-sha-hmac", "HMAC_SHA2_256_128": "esp-sha256-hmac",
         "HMAC_SHA2_384_192": "esp-sha384-hmac", "HMAC_SHA2_512_256": "esp-sha512-hmac", "HMAC_MD5_96": "esp-md5-hmac"}
    parts = alg.split("/")
    return " ".join([m.get(parts[0], parts[0])] + [h[p] for p in parts[1:] if p in h])


def _mask(cidr: str) -> str:
    n = ipaddress.IPv4Network(cidr or "0.0.0.0/0", strict=False)
    return f"{n.network_address}/{n.netmask}"


def show_ipsec_sa(con) -> str:
    own = con.lab.devices.get("router", {})
    sas = {sa["name"]: sa for sa in _sas(con)}
    out = []
    for name, t in tunnels(own):
        if t.get("mode") != "ipsec":
            continue
        local, _ = _source(con.lab, con.plan, t)
        sa = sas.get(name)
        ch = next((c for c in (sa or {}).get("children", []) if c["state"] == "INSTALLED"), None)
        enc = ch["pkts_out"] if ch else 0
        dec = ch["pkts_in"] if ch else 0
        out += ["", f"interface: {name}", f"    Crypto map tag: {name}-head-0, local addr {local or '0.0.0.0'}", "",
                "   protected vrf: (none)",
                f"   local  ident (addr/mask/prot/port): ({_mask(ch['local_ts'] if ch else '')}/0/0)",
                f"   remote ident (addr/mask/prot/port): ({_mask(ch['remote_ts'] if ch else '')}/0/0)",
                f"   current_peer {t.get('dst', '0.0.0.0')} port 500",
                "     PERMIT, flags={origin_is_acl,}",
                f"    #pkts encaps: {enc}, #pkts encrypt: {enc}, #pkts digest: {enc}",
                f"    #pkts decaps: {dec}, #pkts decrypt: {dec}, #pkts verify: {dec}",
                "    #pkts compressed: 0, #pkts decompressed: 0",
                "    #pkts not compressed: 0, #pkts compr. failed: 0",
                "    #pkts not decompressed: 0, #pkts decompress failed: 0",
                "    #send errors 0, #recv errors 0", "",
                f"     local crypto endpt.: {local or '0.0.0.0'}, remote crypto endpt.: {t.get('dst', '0.0.0.0')}",
                f"     plaintext mtu {t.get('mtu', 1438)}, path mtu 1500, ip mtu 1500, ip mtu idb {t.get('src', '')}"]
        if ch:
            spi_out = int(ch["spi_out"], 16) if ch["spi_out"] else 0
            spi_in = int(ch["spi_in"], 16) if ch["spi_in"] else 0
            prof = _j(own, f"ipsec-profile:{t.get('prot', '')}")
            out += [f"     current outbound spi: {spi_out:#X}({spi_out})".replace("0X", "0x"),
                    f"     PFS (Y/N): {'Y' if prof.get('pfs') else 'N'}, DH group: "
                    + (f"group{prof['pfs']}" if prof.get("pfs") else "none"), "", "     inbound esp sas:",
                    f"      spi: {spi_in:#X}({spi_in})".replace("0X", "0x"),
                    f"        transform: {_esp_names(ch['alg'])} ,", "        in use settings ={Tunnel, }",
                    f"        sa timing: remaining key lifetime (sec): ({ch['expires']})",
                    "        Status: ACTIVE(ACTIVE)", "", "     outbound esp sas:",
                    f"      spi: {spi_out:#X}({spi_out})".replace("0X", "0x"),
                    f"        transform: {_esp_names(ch['alg'])} ,", "        in use settings ={Tunnel, }",
                    f"        sa timing: remaining key lifetime (sec): ({ch['expires']})",
                    "        Status: ACTIVE(ACTIVE)"]
        else:
            out += ["     current outbound spi: 0x0(0)", "     PFS (Y/N): N, DH group: none", "",
                    "     inbound esp sas:", "", "     outbound esp sas:"]
    return "\n".join(out).strip("\n")


def show_session(con) -> str:
    own = con.lab.devices.get("router", {})
    sas = {sa["name"]: sa for sa in _sas(con)}
    out = ["Crypto session current status", ""]
    for name, t in tunnels(own):
        if t.get("mode") != "ipsec":
            continue
        sa = sas.get(name)
        prof = _j(own, f"ipsec-profile:{t.get('prot', '')}")
        up = bool(sa and sa["state"] == "ESTABLISHED" and any(c["state"] == "INSTALLED" for c in sa["children"]))
        out += [f"Interface: {name}", f"Profile: {prof.get('ikev2', '')}",
                f"Session status: {'UP-ACTIVE' if up else 'DOWN'}     ",
                f"Peer: {t.get('dst', '')} port 500 "]
        if sa:
            out += ["  Session ID: 1  ",
                    f"  IKEv2 SA: local {sa['local']}/{sa['lport']} remote {sa['remote']}/{sa['rport']} "
                    + ("Active " if up else sa["state"]),
                    "  IPSEC FLOW: permit ip 0.0.0.0/0.0.0.0 0.0.0.0/0.0.0.0 ",
                    f"        Active SAs: {2 * len(sa['children'])}, origin: crypto map"]
        out.append("")
    return "\n".join(out).rstrip()


def show_conf(con, kind: str) -> str:
    own = con.lab.devices.get("router", {})
    out = []
    for n in names(own, kind):
        d = _j(own, f"{kind}:{n}")
        if kind == "ikev2-proposal":
            s = proposal_string(d)
            out += [f" IKEv2 proposal: {n} ",
                    f"     Encryption : {' '.join(e.upper() for e in d.get('encryption', []))}",
                    f"     Integrity  : {' '.join(i.upper() for i in d.get('integrity', []))}",
                    f"     PRF        : {' '.join(i.upper() for i in (d.get('prf') or d.get('integrity', [])))}",
                    f"     DH Group   : {' '.join('DH_GROUP_' + g for g in d.get('group', []))}"]
            out += ["     % Incomplete: a proposal needs encryption, integrity (or a GCM cipher with prf) and a group"] \
                if not s else []
        elif kind == "ikev2-policy":
            out += [f"IKEv2 policy : {n}", "      Match fvrf : global",
                    f"      Match address local : {', '.join(d.get('local', [])) or 'any'}",
                    f"      Proposal    : {', '.join(d.get('proposal', []))}"]
        elif kind == "ikev2-profile":
            out += [f"IKEv2 profile: {n}", " Ref Count: 0", " Match criteria: ", "  Fvrf: global",
                    "  Local address/interface: none", "  Identities: "]
            out += [f"   address {m}" for m in d.get("match", [])]
            out += [f" Local identifier: address {d.get('identity', '(the tunnel source)')}",
                    f" Local authentication method: {d.get('auth-local', 'none')}",
                    f" Remote authentication method(s): {d.get('auth-remote', 'none')}",
                    f" Keyring: {d.get('keyring', 'none')}",
                    f" Lifetime: {d.get('lifetime', 86400)} seconds",
                    " DPD: " + (f"interval {d['dpd'].split()[0]} retry {d['dpd'].split()[1]} {d['dpd'].split()[2]}"
                                if d.get("dpd") else "disabled")]
        elif kind == "ipsec-tset":
            out += [f"Transform set {n}: {{ {' '.join(d.get('t', []))} }} ",
                    f"   will negotiate = {{ {d.get('mode', 'tunnel').capitalize()},  }}, "]
        else:
            out += [f"IPSEC profile {n}", f"        IKEv2 Profile: {d.get('ikev2', '')}",
                    "        Security association lifetime: 4608000 kilobytes/"
                    f"{d.get('lifetime', 3600)} seconds",
                    "        Responder-Only (Y/N): N", f"        PFS (Y/N): {'Y' if d.get('pfs') else 'N'}"]
            out += [f"        DH group:  group{d['pfs']}"] if d.get("pfs") else []
            out += ["        Mixed-mode : Disabled", "        Transform sets={ "]
            out += [f"                {ts}:  {{ {' '.join(_j(own, f'ipsec-tset:{ts}').get('t', []))} }} ,"
                    for ts in d.get("tsets", [])] + ["        }"]
        out.append("")
    return "\n".join(out).rstrip()


def show_tunnel(con, name: str) -> str:
    own = con.lab.devices.get("router", {})
    t = tunnel(own, name)
    if not t:
        return "% Invalid input detected at '^' marker."
    row = next((r for r in brief_rows(con) if r.startswith(name + " ")), "")
    st = "administratively down" if t.get("shut") else "up"
    pr = row.split()[-1] if row else "down"
    out = [f"{name} is {st}, line protocol is {pr} ", "  Hardware is Tunnel"]
    out += [f"  Description: {t['desc']}"] if t.get("desc") else []
    if t.get("ip"):
        out.append(f"  Internet address is {t['ip']}")
    out += [f"  MTU 9976 bytes, BW 100 Kbit/sec, DLY 50000 usec, ",
            "  Encapsulation TUNNEL, loopback not set",
            f"  Tunnel source {t.get('src', 'UNKNOWN')}, destination {t.get('dst', 'UNKNOWN')}",
            "  Tunnel protocol/transport " + ("IPSEC/IP" if t.get("mode") == "ipsec" else "GRE/IP")]
    if t.get("prot"):
        out.append(f'  Tunnel protection via IPSec (profile "{t["prot"]}")')
    return "\n".join(out)


def _clear(con) -> str:
    own = con.lab.devices.get("router", {})
    names_ = " ".join(n for n, t in tunnels(own) if t.get("mode") == "ipsec")
    if names_:
        con._on_router(f"for c in {names_}; do swanctl --terminate --ike $c --force >/dev/null 2>&1; "
                       "(swanctl --initiate --child $c --timeout 20 >/dev/null 2>&1 &); done; true", timeout=15)
    return ""
