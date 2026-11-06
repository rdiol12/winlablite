"""Secure Boot keys for a lab machine's UEFI firmware, written by winlab
itself into the machine's variable store (NVRAM), the way an OEM's factory
writes them into a new PC's flash.

What a Windows PC with Secure Boot on carries in its firmware, and what this
module enrolls:

* PK, the platform key: the PC maker's own. winlab is the maker here, so each
  installation of winlab makes one of its own (a self-signed RSA-2048
  certificate, "winlab Platform Key", made on this PC the first time a
  machine needs it). The private half is thrown away once the certificate is
  signed: nobody, the student included, can sign a new KEK for these
  machines, exactly as on a PC whose maker keeps its key in a vault.
* KEK, the key exchange keys: Microsoft Corporation KEK CA 2011 and
  Microsoft Corporation KEK 2K CA 2023 (the two Windows Update signs db and
  dbx updates with).
* db, the allowed signatures, by template, named as Hyper-V names them
  (Set-VMFirmware -SecureBootTemplate):
    MicrosoftWindows: Microsoft Windows Production PCA 2011 and Windows UEFI
      CA 2023, the two CAs Windows Boot Manager is signed under.
    MicrosoftUEFICertificateAuthority: Microsoft Corporation UEFI CA 2011 and
      Microsoft UEFI CA 2023, the third-party CAs (Linux shim, option ROMs).
      As on Hyper-V, Windows does not start under it: its boot manager is not
      signed by either.
* dbx, the forbidden signatures: Microsoft's published revocation list (the
  DBXUpdate.bin in microsoft/secureboot_objects), when this PC has it.

The certificates are Microsoft's, published for PC makers to put in their
firmware (https://learn.microsoft.com/windows-hardware/manufacture/desktop/
windows-secure-boot-key-creation-and-management-guidance, and Microsoft's
github.com/microsoft/secureboot_objects). winlab never ships them: `winlab
secureboot fetch` downloads them on the student's PC (each one checked
against its SHA-256 below), or `winlab secureboot import <folder>` picks up
the files the student downloaded themselves. LICENSING.md lists them.

The variable store is edk2's (the firmware QEMU ships): a firmware volume
(EFI_FIRMWARE_VOLUME_HEADER, gEfiSystemNvDataFvGuid), then a variable store
header (gEfiAuthenticatedVariableGuid, formatted, healthy), then variables,
each an AUTHENTICATED_VARIABLE_HEADER (start id 0x55AA, state, attributes,
monotonic count, EFI_TIME, public key index, name size, data size, vendor
GUID), its UTF-16 name and its data, every header on a 4-byte boundary. A
variable is replaced the way the firmware does it: the old copy's state is
marked deleted and a new copy is appended. Everything after the variable
store (the fault-tolerant-write blocks) is left as the firmware wrote it.
"""

from __future__ import annotations

import hashlib
import struct
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import paths

# ------------------------------------------------------------------ GUIDs
NV_DATA_FV = uuid.UUID("fff12b8d-7696-4c8b-a985-2747075b4f50")      # gEfiSystemNvDataFvGuid
AUTH_VAR_STORE = uuid.UUID("aaf32c78-947b-439a-a180-2e144ec37792")  # gEfiAuthenticatedVariableGuid
EFI_GLOBAL = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")      # PK, KEK, SecureBoot, SetupMode
IMAGE_SECURITY_DB = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")  # db, dbx
SECURE_BOOT_ENABLE = uuid.UUID("f0a30bc7-af08-4556-99c4-001009c93a44")  # edk2's own on/off switch
CUSTOM_MODE = uuid.UUID("c076ec0c-7028-4399-a072-71ee5c448b9f")
CERT_X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")       # EFI_CERT_X509_GUID
CERT_SHA256 = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")     # EFI_CERT_SHA256_GUID
CERT_TYPE_PKCS7 = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7")  # EFI_CERT_TYPE_PKCS7_GUID
MICROSOFT = uuid.UUID("77fa9abd-0359-4d32-bd60-28f4e78f784b")       # Microsoft's signature owner
WINLAB = uuid.UUID("5d3a1e0c-9b7f-4c61-8e2a-77b0c1f4a9d2")          # this maker's own, for PK

# ------------------------------------------------------------------ layout
FV_SIGNATURE = b"_FVH"
STORE_HEADER = struct.Struct("<16sIBBHI")          # Signature, Size, Format, State, Reserved, Reserved1
VAR_HEADER = struct.Struct("<HBBIQ16sIII16s")      # 60 bytes
START_ID = 0x55AA
FORMATTED, HEALTHY = 0x5A, 0xFE
VAR_ADDED, VAR_DELETED, VAR_IN_DELETED_TRANSITION = 0x3F, 0xFD, 0xFE
NV, BS, RT, TIME_AUTH = 0x01, 0x02, 0x04, 0x20
AUTH_ATTRS = NV | BS | RT | TIME_AUTH              # PK, KEK, db, dbx
EFI_TIME = struct.Struct("<HBBBBBBIhBB")

TEMPLATES = {
    "MicrosoftWindows": "Microsoft Windows",
    "MicrosoftUEFICertificateAuthority": "Microsoft UEFI Certificate Authority",
}
DEFAULT_TEMPLATE = "MicrosoftWindows"
PK_FILE = "winlab-platform-key.der"
REPO = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/"
GUIDE = ("https://learn.microsoft.com/windows-hardware/manufacture/desktop/"
         "windows-secure-boot-key-creation-and-management-guidance")


@dataclass(frozen=True)
class Cert:
    file: str        # the name it is kept under on this PC
    name: str        # its subject's common name
    store: str       # KEK or db
    templates: tuple[str, ...]
    url: str         # Microsoft's own link (go.microsoft.com)
    mirror: str      # its path in microsoft/secureboot_objects
    sha256: str


CERTS = (
    Cert("MicCorKEKCA2011_2011-06-24.crt", "Microsoft Corporation KEK CA 2011", "KEK",
         tuple(TEMPLATES), "https://go.microsoft.com/fwlink/?LinkId=321185",
         "PreSignedObjects/KEK/Certificates/MicCorKEKCA2011_2011-06-24.der",
         "a1117f516a32cefcba3f2d1ace10a87972fd6bbe8fe0d0b996e09e65d802a503"),
    Cert("microsoft corporation kek 2k ca 2023.crt", "Microsoft Corporation KEK 2K CA 2023", "KEK",
         tuple(TEMPLATES), "https://go.microsoft.com/fwlink/?linkid=2239775",
         "PreSignedObjects/KEK/Certificates/microsoft corporation kek 2k ca 2023.der",
         "3cd3f0309edae228767a976dd40d9f4affc4fbd5218f2e8cc3c9dd97e8ac6f9d"),
    Cert("MicWinProPCA2011_2011-10-19.crt", "Microsoft Windows Production PCA 2011", "db",
         ("MicrosoftWindows",), "https://go.microsoft.com/fwlink/?linkid=321192",
         "PreSignedObjects/DB/Certificates/MicWinProPCA2011_2011-10-19.der",
         "e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"),
    Cert("windows uefi ca 2023.crt", "Windows UEFI CA 2023", "db",
         ("MicrosoftWindows",), "https://go.microsoft.com/fwlink/?linkid=2239776",
         "PreSignedObjects/DB/Certificates/windows uefi ca 2023.der",
         "076f1fea90ac29155ebf77c17682f75f1fdd1be196da302dc8461e350a9ae330"),
    Cert("MicCorUEFCA2011_2011-06-27.crt", "Microsoft Corporation UEFI CA 2011", "db",
         ("MicrosoftUEFICertificateAuthority",), "https://go.microsoft.com/fwlink/?linkid=321194",
         "PreSignedObjects/DB/Certificates/MicCorUEFCA2011_2011-06-27.der",
         "48e99b991f57fc52f76149599bff0a58c47154229b9f8d603ac40d3500248507"),
    Cert("microsoft uefi ca 2023.crt", "Microsoft UEFI CA 2023", "db",
         ("MicrosoftUEFICertificateAuthority",), "https://go.microsoft.com/fwlink/?linkid=2239872",
         "PreSignedObjects/DB/Certificates/microsoft uefi ca 2023.der",
         "f6124e34125bee3fe6d79a574eaa7b91c0e7bd9d929c1a321178efd611dad901"),
)
# The revocation list changes as Microsoft revokes boot managers, so it is
# not pinned: it is checked for its shape (a KEK-signed authenticated
# variable of SHA-256 entries) instead.
DBX_FILE = "DBXUpdate.bin"
DBX_MIRROR = "PostSignedObjects/DBX/amd64/DBXUpdate.bin"


class SecureBootError(Exception):
    pass


# ------------------------------------------------------------------ the store
@dataclass
class Variable:
    offset: int
    state: int
    attributes: int
    name: str
    guid: uuid.UUID
    data: bytes
    timestamp: bytes = b"\0" * 16
    count: int = 0

    @property
    def live(self) -> bool:
        return self.state in (VAR_ADDED, VAR_ADDED & VAR_IN_DELETED_TRANSITION)


def efi_time(t: float | None = None) -> bytes:
    tm = time.gmtime(time.time() if t is None else t)
    return EFI_TIME.pack(tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, 0, 0, 0, 0, 0)


class VarStore:
    """An edk2 variable store file (QEMU's edk2-i386-vars.fd or a machine's
    copy of it), read and changed in place."""

    def __init__(self, data: bytes) -> None:
        self.buf = bytearray(data)
        if len(data) < 0x48 + STORE_HEADER.size or data[0x28:0x2C] != FV_SIGNATURE:
            raise SecureBootError("not a UEFI variable store (no firmware volume header)")
        if uuid.UUID(bytes_le=bytes(data[0x10:0x20])) != NV_DATA_FV:
            raise SecureBootError("the firmware volume is not an NV data volume")
        self.header_len = struct.unpack_from("<H", data, 0x30)[0]
        sig, size, fmt, st, _r, _r1 = STORE_HEADER.unpack_from(data, self.header_len)
        if uuid.UUID(bytes_le=sig) != AUTH_VAR_STORE:
            raise SecureBootError("the variable store is not edk2's authenticated format")
        if fmt != FORMATTED or st != HEALTHY:
            raise SecureBootError("the variable store is not formatted and healthy")
        self.start = _align(self.header_len + STORE_HEADER.size)
        self.end = self.header_len + size
        if self.end > len(data):
            raise SecureBootError("the variable store runs past the end of the file")

    # -- reading
    def variables(self) -> list[Variable]:
        out, p = [], self.start
        while p + VAR_HEADER.size <= self.end:
            sid, st, _r, attrs, count, ts, _pki, nsize, dsize, guid = VAR_HEADER.unpack_from(self.buf, p)
            if sid != START_ID:
                break
            body = p + VAR_HEADER.size
            name = bytes(self.buf[body:body + nsize]).decode("utf-16-le", "replace").rstrip("\0")
            data = bytes(self.buf[body + nsize:body + nsize + dsize])
            out.append(Variable(p, st, attrs, name, uuid.UUID(bytes_le=guid), data, ts, count))
            p = _align(body + nsize + dsize)
        return out

    def free_offset(self) -> int:
        v = self.variables()
        if not v:
            return self.start
        last = v[-1]
        return _align(last.offset + VAR_HEADER.size + (len(last.name) + 1) * 2 + len(last.data))

    def get(self, name: str, guid: uuid.UUID) -> Variable | None:
        found = [v for v in self.variables() if v.live and v.name == name and v.guid == guid]
        return found[-1] if found else None

    # -- writing
    def delete(self, name: str, guid: uuid.UUID) -> bool:
        hit = False
        for v in self.variables():
            if v.live and v.name == name and v.guid == guid:
                self.buf[v.offset + 2] = v.state & VAR_DELETED
                hit = True
        return hit

    def set(self, name: str, guid: uuid.UUID, attributes: int, data: bytes, timestamp: bytes | None = None) -> None:
        """Replace (or add) one variable, as the firmware does: the old copy
        is marked deleted, the new one goes after the last."""
        ts = timestamp if timestamp is not None else (efi_time() if attributes & TIME_AUTH else b"\0" * 16)
        uname = (name + "\0").encode("utf-16-le")
        rec = VAR_HEADER.pack(START_ID, VAR_ADDED, 0, attributes, 0, ts, 0, len(uname), len(data),
                              guid.bytes_le) + uname + data
        at = self.free_offset()
        if at + len(rec) > self.end:
            raise SecureBootError(f"the machine's NVRAM is full: {name} ({len(data)} bytes) does not fit")
        self.delete(name, guid)
        self.buf[at:at + len(rec)] = rec

    def to_bytes(self) -> bytes:
        return bytes(self.buf)


def _align(n: int) -> int:
    return (n + 3) & ~3


FTW_SIGNATURE = uuid.UUID("9e58292b-7c68-497d-a0ce-6500fd9f1b95")  # gEdkiiWorkingBlockSignatureGuid


def blank_store() -> bytes:
    """edk2's empty variable store of a 4 MB OVMF build (OVMF_VARS.fd,
    QEMU's edk2-i386-vars.fd): 0x84000 bytes, 132 blocks of 4 KiB; the
    variable store in the first 256 KiB, the fault-tolerant-write working
    block at 0x41000, its spare area after. The tests build stores from it."""
    size, block = 0x84000, 0x1000
    hdr = bytearray(struct.pack("<16s16sQ4sIHHHBB", b"\0" * 16, NV_DATA_FV.bytes_le, size, FV_SIGNATURE,
                                0x0004FEFF, 0x48, 0, 0, 0, 2) + struct.pack("<IIII", size // block, block, 0, 0))
    csum = (-sum(struct.unpack("<36H", hdr))) & 0xFFFF
    struct.pack_into("<H", hdr, 0x32, csum)
    buf = bytearray(b"\xff" * size)
    buf[:0x48] = hdr
    buf[0x48:0x64] = STORE_HEADER.pack(AUTH_VAR_STORE.bytes_le, 0x40000 - 0x48, FORMATTED, HEALTHY, 0, 0)
    buf[0x41000:0x41020] = (FTW_SIGNATURE.bytes_le + struct.pack("<I", 0x642CAF2C) + b"\xfe\xff\xff\xff"
                            + struct.pack("<Q", block - 0x20))
    return bytes(buf)


# ------------------------------------------------------------------ signature lists
def esl_x509(der: bytes, owner: uuid.UUID = MICROSOFT) -> bytes:
    """One EFI_SIGNATURE_LIST holding one X.509 certificate."""
    sig_size = 16 + len(der)
    return CERT_X509.bytes_le + struct.pack("<III", 28 + sig_size, 0, sig_size) + owner.bytes_le + der


def parse_esl(data: bytes) -> list[tuple[uuid.UUID, uuid.UUID, bytes]]:
    """(type, owner, signature data) for every entry of a list of lists."""
    out, p = [], 0
    while p + 28 <= len(data):
        typ = uuid.UUID(bytes_le=data[p:p + 16])
        lsize, hsize, ssize = struct.unpack_from("<III", data, p + 16)
        if lsize < 28 or ssize < 16 or p + lsize > len(data):
            raise SecureBootError("a malformed EFI_SIGNATURE_LIST")
        q = p + 28 + hsize
        while q + ssize <= p + lsize:
            out.append((typ, uuid.UUID(bytes_le=data[q:q + 16]), data[q + 16:q + ssize]))
            q += ssize
        p += lsize
    if p != len(data):
        raise SecureBootError("trailing bytes after the signature lists")
    return out


def dbx_lists(update: bytes) -> bytes:
    """The signature lists inside a signed dbx update: EFI_TIME, then the
    WIN_CERTIFICATE_UEFI_GUID (PKCS#7, signed with a KEK), then the lists."""
    if len(update) < 16 + 24:
        raise SecureBootError("the dbx update is too short")
    length, rev, ctype = struct.unpack_from("<IHH", update, 16)
    if rev != 0x0200 or ctype != 0x0EF1 or uuid.UUID(bytes_le=update[24:40]) != CERT_TYPE_PKCS7:
        raise SecureBootError("the dbx update is not a signed authenticated variable")
    lists = update[16 + length:]
    entries = parse_esl(lists)
    if not entries or any(t != CERT_SHA256 for t, _o, _d in entries):
        raise SecureBootError("the dbx update holds no SHA-256 entries")
    return lists


def subject_cn(der: bytes) -> str:
    """The certificate's subject common name (enough DER to read it)."""
    try:
        tbs = _children(_children(der)[0][1])[0][1]
        parts = _children(tbs)
        if parts and parts[0][0] == 0xA0:       # [0] version
            parts = parts[1:]
        subject = parts[4][1]                   # serial, sigalg, issuer, validity, subject
        for _t, rdn in _children(subject):
            for _t2, atv in _children(rdn):
                kids = _children(atv)
                if kids[0][1] == bytes.fromhex("550403"):
                    return kids[1][1].decode("utf-8", "replace")
    except (IndexError, ValueError):
        pass
    return ""


def _children(der: bytes) -> list[tuple[int, bytes]]:
    out, p = [], 0
    while p < len(der):
        tag, n = der[p], der[p + 1]
        p += 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(der[p:p + k], "big")
            p += k
        out.append((tag, der[p:p + n]))
        p += n
    return out


# ------------------------------------------------------------------ the platform key
def make_pk(common_name: str = "winlab Platform Key", years: int = 30, bits: int = 2048) -> bytes:
    """A self-signed RSA-2048 certificate for PK, its private key discarded
    once signed (sha256WithRSAEncryption, PKCS#1 v1.5)."""
    from .iosssh import _der, _der_int, generate, spki
    key = generate(bits)
    sha256_rsa = _der(0x30, _der(0x06, bytes.fromhex("2A864886F70D01010B")) + b"\x05\x00")

    def name(cn: str) -> bytes:
        def rdn(oid: str, val: str) -> bytes:
            return _der(0x31, _der(0x30, _der(0x06, bytes.fromhex(oid)) + _der(0x0C, val.encode())))
        return _der(0x30, rdn("550406", "US") + rdn("55040A", "winlab") + rdn("550403", cn))

    def utc(t: float) -> bytes:
        tm = time.gmtime(t)
        if tm.tm_year >= 2050:
            return _der(0x18, time.strftime("%Y%m%d%H%M%SZ", tm).encode())
        return _der(0x17, time.strftime("%y%m%d%H%M%SZ", tm).encode())

    now = time.time()
    k = bits // 8
    serial = int.from_bytes(hashlib.sha256(key["n"].to_bytes(k, "big")).digest()[:16], "big") >> 1
    ski = hashlib.sha1(key["n"].to_bytes(k, "big")).digest()
    exts = _der(0xA3, _der(0x30,
        _der(0x30, _der(0x06, bytes.fromhex("551D13")) + _der(0x01, b"\xff")
             + _der(0x04, _der(0x30, _der(0x01, b"\xff"))))                    # basicConstraints CA
        + _der(0x30, _der(0x06, bytes.fromhex("551D0E")) + _der(0x04, _der(0x04, ski)))))
    tbs = _der(0x30, _der(0xA0, _der_int(2)) + _der_int(serial) + sha256_rsa + name(common_name)
               + _der(0x30, utc(now - 86400) + utc(now + years * 365.25 * 86400)) + name(common_name)
               + spki(key) + exts)
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(tbs).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    sig = pow(int.from_bytes(em, "big"), key["d"], key["n"]).to_bytes(k, "big")
    del key
    return _der(0x30, tbs + sha256_rsa + _der(0x03, b"\x00" + sig))


def verify_self_signed(der: bytes) -> bool:
    """Checks a PK certificate's signature against its own key (the tests,
    and a corrupted file on disk)."""
    try:
        outer = _children(der)[0][1]
        tbs_t, sigalg, sigbits = _children(outer)
        tbs = bytes([0x30]) + _len(len(tbs_t[1])) + tbs_t[1]
        parts = _children(tbs_t[1])[1:]
        spki_seq = _children(parts[5][1])
        rsa = _children(spki_seq[1][1][1:])[0][1]
        n_b, e_b = (v for _t, v in _children(rsa))
        n, e = int.from_bytes(n_b, "big"), int.from_bytes(e_b, "big")
        em = pow(int.from_bytes(sigbits[1][1:], "big"), e, n).to_bytes((n.bit_length() + 7) // 8, "big")
        return em.endswith(hashlib.sha256(tbs).digest()) and em.startswith(b"\x00\x01\xff")
    except (ValueError, IndexError):
        return False


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


# ------------------------------------------------------------------ this PC's copies
def der_of(data: bytes) -> bytes:
    """A certificate as DER, whether it came as DER or as PEM text."""
    head = data.lstrip()[:30]
    if head.startswith(b"-----BEGIN"):
        import base64
        body = b"".join(line for line in data.strip().splitlines() if not line.startswith(b"-----"))
        try:
            return base64.b64decode(body)
        except ValueError:
            return data
    return data


def store_dir() -> Path:
    return paths.images_dir() / "secureboot"


def cert_path(c: Cert) -> Path:
    return store_dir() / c.file


def have(c: Cert) -> bool:
    p = cert_path(c)
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest() == c.sha256
    except OSError:
        return False


def missing(template: str = DEFAULT_TEMPLATE) -> list[Cert]:
    return [c for c in CERTS if template in c.templates and not have(c)]


def ready(template: str = DEFAULT_TEMPLATE) -> bool:
    return not missing(template)


def dbx_path() -> Path:
    return store_dir() / DBX_FILE


def platform_key() -> bytes:
    """This installation's PK certificate, made the first time it is asked for."""
    p = store_dir() / PK_FILE
    try:
        der = p.read_bytes()
        if verify_self_signed(der):
            return der
    except OSError:
        pass
    der = make_pk()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(der)
    return der


def fetch(say=print, get=None) -> list[str]:
    """Downloads every certificate (and the dbx list) from Microsoft onto
    this PC: Microsoft's go.microsoft.com link first, then the same file in
    microsoft/secureboot_objects. Returns what it could not get."""
    from urllib.parse import quote
    if get is None:
        from .bootstrap import _get as get
    failed = []
    store_dir().mkdir(parents=True, exist_ok=True)
    for c in CERTS:
        if have(c):
            say(f"  {c.name}: already on this PC")
            continue
        for url in (c.url, REPO + quote(c.mirror)):
            try:
                data = get(url)
            except Exception as exc:  # noqa: BLE001 - the next source, then a sentence
                say(f"  {c.name}: {url}: {exc}")
                continue
            data = der_of(data)
            if hashlib.sha256(data).hexdigest() == c.sha256:
                cert_path(c).write_bytes(data)
                say(f"  {c.name}: downloaded from {url.split('/')[2]}")
                break
            say(f"  {c.name}: {url} did not give the certificate winlab expects (SHA-256 differs)")
        else:
            failed.append(c.name)
    try:
        data = get(REPO + DBX_MIRROR)
        dbx_lists(data)
        dbx_path().write_bytes(data)
        say("  dbx (Microsoft's revocation list): downloaded")
    except Exception as exc:  # noqa: BLE001 - dbx is optional
        say(f"  dbx (Microsoft's revocation list): not downloaded ({exc}); machines start with an empty dbx")
    return failed


def import_from(folders: list[Path], depth: int = 2) -> list[str]:
    """Picks the certificates (and DBXUpdate.bin) out of folders the student
    downloaded them into, by their SHA-256, whatever their file names."""
    want = {c.sha256: c for c in CERTS if not have(c)}
    got: list[str] = []
    store_dir().mkdir(parents=True, exist_ok=True)

    def walk(d: Path, left: int):
        try:
            kids = sorted(d.iterdir())
        except OSError:
            return
        for k in kids:
            if k.is_dir() and left > 0:
                yield from walk(k, left - 1)
            elif k.is_file():
                yield k

    for root in folders:
        for f in walk(root, depth):
            try:
                if f.stat().st_size > 1 << 20:
                    continue
                data = der_of(f.read_bytes())
            except OSError:
                continue
            c = want.pop(hashlib.sha256(data).hexdigest(), None)
            if c is not None:
                cert_path(c).write_bytes(data)
                got.append(c.name)
            elif f.name.lower() == DBX_FILE.lower():
                try:
                    dbx_lists(data)
                except SecureBootError:
                    continue
                dbx_path().write_bytes(data)
                got.append("dbx (DBXUpdate.bin)")
    return got


# ------------------------------------------------------------------ enrolling
def enrolled(store: VarStore) -> bool:
    return store.get("PK", EFI_GLOBAL) is not None


def template_of(store: VarStore) -> str:
    """Which template's CAs are in db, or '' when none matches."""
    db = store.get("db", IMAGE_SECURITY_DB)
    if db is None:
        return ""
    try:
        names = {subject_cn(d) for t, _o, d in parse_esl(db.data) if t == CERT_X509}
    except SecureBootError:
        return ""
    for tpl in TEMPLATES:
        if names == {c.name for c in CERTS if c.store == "db" and tpl in c.templates}:
            return tpl
    return ""


def _lists(store: str, template: str, certs: dict[str, bytes] | None) -> bytes:
    out = b""
    for c in CERTS:
        if c.store == store and template in c.templates:
            der = certs[c.file] if certs is not None else cert_path(c).read_bytes()
            out += esl_x509(der)
    return out


def enroll(data: bytes, template: str = DEFAULT_TEMPLATE, pk: bytes | None = None,
           certs: dict[str, bytes] | None = None, dbx: bytes | None = None,
           when: float | None = None) -> bytes:
    """The variable store with Secure Boot's keys in it: db (by template),
    dbx, KEK, then PK last, as an OEM enrolls them (PK leaves Setup Mode).
    certs and pk default to this PC's copies; certs maps Cert.file to DER."""
    if template not in TEMPLATES:
        raise SecureBootError(f"no Secure Boot template {template!r}: {', '.join(TEMPLATES)}")
    if certs is None:
        gone = missing(template)
        if gone:
            raise SecureBootError("Microsoft's Secure Boot certificates are not on this PC ("
                                  + ", ".join(c.name for c in gone) + "): winlab secureboot fetch")
    if dbx is None and certs is None and dbx_path().exists():
        try:
            dbx = dbx_lists(dbx_path().read_bytes())
        except (OSError, SecureBootError):
            dbx = None
    store = VarStore(data)
    ts = efi_time(when)
    store.set("db", IMAGE_SECURITY_DB, AUTH_ATTRS, _lists("db", template, certs), ts)
    if dbx:
        store.set("dbx", IMAGE_SECURITY_DB, AUTH_ATTRS, dbx, ts)
    store.set("KEK", EFI_GLOBAL, AUTH_ATTRS, _lists("KEK", template, certs), ts)
    store.set("PK", EFI_GLOBAL, AUTH_ATTRS, esl_x509(pk if pk is not None else platform_key(), WINLAB), ts)
    store.set("SecureBootEnable", SECURE_BOOT_ENABLE, NV | BS, b"\x01")
    store.set("CustomMode", CUSTOM_MODE, NV | BS, b"\x00")
    return store.to_bytes()


def set_template(data: bytes, template: str, certs: dict[str, bytes] | None = None,
                 when: float | None = None) -> bytes:
    """db replaced with another template's CAs (the keys stay)."""
    if certs is None and missing(template):
        raise SecureBootError("Microsoft's Secure Boot certificates are not on this PC: winlab secureboot fetch")
    store = VarStore(data)
    store.set("db", IMAGE_SECURITY_DB, AUTH_ATTRS, _lists("db", template, certs), efi_time(when))
    return store.to_bytes()


def describe(data: bytes) -> dict:
    """What the firmware's Secure Boot page shows: mode, PK owner, template."""
    try:
        store = VarStore(data)
    except SecureBootError as exc:
        return {"ok": False, "why": str(exc)}
    pk = store.get("PK", EFI_GLOBAL)
    pk_cn = ""
    if pk is not None:
        try:
            pk_cn = next((subject_cn(d) for t, _o, d in parse_esl(pk.data) if t == CERT_X509), "")
        except SecureBootError:
            pk_cn = ""
    dbx = store.get("dbx", IMAGE_SECURITY_DB)
    try:
        dbx_n = len(parse_esl(dbx.data)) if dbx is not None else 0
    except SecureBootError:
        dbx_n = 0
    return {"ok": True, "mode": "User" if pk is not None else "Setup", "pk": pk_cn,
            "template": template_of(store), "dbx": dbx_n}


# ------------------------------------------------------------------ command line
def cli(args: list[str], say=print) -> int:
    """winlab secureboot [status | fetch | import <folder>...]"""
    op = args[0] if args else "status"
    if op == "fetch":
        say(f"Fetching Microsoft's Secure Boot certificates into {store_dir()}")
        failed = fetch(say)
        if failed:
            say("Could not get: " + ", ".join(failed) + f". Download them yourself from {GUIDE} "
                "and run: winlab secureboot import <the folder>")
            return 1
        platform_key()
        say("Ready: machines set to UEFI with Secure Boot get these keys at their next start.")
        return 0
    if op == "import":
        folders = [Path(a) for a in args[1:]] or [Path.home() / "Downloads"]
        got = import_from(folders)
        say("Imported: " + (", ".join(got) if got else "nothing new"))
        return 0 if ready() else 1
    if op == "status":
        for c in CERTS:
            say(f"  {'ready  ' if have(c) else 'missing'}  {c.store:<3}  {c.name}  ({c.url})")
        say(f"  {'ready  ' if dbx_path().exists() else 'missing'}  dbx  Microsoft's revocation list (optional)")
        pk = store_dir() / PK_FILE
        say(f"  {'ready  ' if pk.exists() else 'not yet'}  PK   winlab Platform Key (made on this PC)")
        return 0 if ready() else 1
    say("usage: winlab secureboot [status | fetch | import <folder>...]")
    return 2
