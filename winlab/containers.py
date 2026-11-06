"""Containers inside the lab: Docker on Ubuntu and on Windows Server 2025,
a registry of the student's own, and a three-node Kubernetes cluster (k3s),
all built by hand in a lab that never sees the internet.

What is fetched, on this PC, never inside the lab:

- Docker on Ubuntu: the 'docker' pack (winlab/debpacks.py): docker.io,
  containerd, runc, docker-compose-v2 and docker-buildx from the Ubuntu
  archive, installed by hand from the pack stick.
- Container images: pulled here straight from the registry's own HTTP API
  (the OCI distribution protocol), with no Docker on this PC. Docker Hub
  (registry-1.docker.io, an anonymous pull token from auth.docker.io) for
  the Linux images, Microsoft's registry (mcr.microsoft.com, anonymous) for
  the Windows ones. A tag's manifest list picks linux/amd64, or for Windows
  windows/amd64 with the Windows Server 2025 build (10.0.26100); the image
  manifest, its config and every layer are checked against their sha256
  digests and written as one tar that both `docker load` and containerd's
  import read (the docker-save layout with an OCI index beside it). A short
  catalog (CATALOG) is always fetched; `winlab containers add <image>` puts
  more on the list, still fetched here. The media shelf writes them onto an
  "images" stick.
- k3s (Apache-2.0), from its GitHub release: the k3s binary, the air-gap
  image bundle (k3s-airgap-images-amd64.tar.zst), both checked against the
  release's sha256sum-amd64.txt, and install.sh from the same tag (k3s
  publishes no checksum for it; winlab records the SHA-256 it got). Written
  onto a "k3s" stick and installed by hand following k3s's air-gap steps.
- Docker for Windows: the static Docker CE binaries (docker.exe, dockerd.exe)
  from download.docker.com/win/static/stable/x86_64/, onto a "Docker for
  Windows" stick. download.docker.com publishes no checksum for them; winlab
  records the SHA-256 it got. The student turns on the Containers feature
  (on the evaluation media already) and registers dockerd as a service.

What is not supported, and why:

- Kubernetes on Windows nodes: k3s runs its server and agents on Linux only.
  Windows containers in this lab run under Docker on the Windows host.
- Hyper-V isolation for Windows containers: it needs nested virtualization
  inside the lab's VM. Process isolation (the Server default) is used, which
  is why the Windows image must match the host's build (ltsc2025).
- Pulling from the internet inside the lab, ever: the lab has no route out.
  Every image a machine runs comes from the images stick or from the
  registry the student runs inside the lab. Docker Desktop is not used
  (a Windows 11 desktop product with its own VM and licence terms).
- Logging in to a registry: winlab pulls anonymously only. Docker Hub limits
  anonymous pulls per address (about 100 manifests in six hours).
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import paths
from .bootstrap import USER_AGENT, BootstrapError, _download_to, _get


class ContainerError(Exception):
    pass


# --------------------------------------------------------------- catalog
@dataclass(frozen=True)
class CatalogImage:
    ref: str
    os: str          # linux | windows
    what: str
    license: str


CATALOG: tuple[CatalogImage, ...] = (
    CatalogImage("nginx:stable-alpine", "linux", "nginx on Alpine: the web server the lessons run, deploy and scale",
                 "nginx BSD-2-Clause; Alpine packages under their own licences"),
    CatalogImage("httpd:2.4-alpine", "linux", "Apache httpd on Alpine: the second web service in the compose stack",
                 "Apache-2.0; Alpine packages under their own licences"),
    CatalogImage("redis:7.2-alpine", "linux", "Redis 7.2 (the last BSD release) on Alpine: the stack's cache, with a volume",
                 "BSD-3-Clause; Alpine packages under their own licences"),
    CatalogImage("registry:2", "linux", "the CNCF Distribution registry: your own registry inside the lab",
                 "Apache-2.0"),
    CatalogImage("alpine:3", "linux", "Alpine Linux: a small shell to look around a network from inside a container",
                 "MIT (alpine-baselayout) and each package's own licence"),
    CatalogImage("mcr.microsoft.com/windows/nanoserver:ltsc2025", "windows",
                 "Nano Server for Windows Server 2025: Windows containers on the Windows host",
                 "Microsoft's container OS image licence terms (use with a licensed Windows host)"),
)
# Windows Server 2025: process isolation runs only an image of the host's build.
WINDOWS_BUILD = "10.0.26100"
DOCKER_HUB = "registry-1.docker.io"
IMAGES_SIZE_TEXT = "about 260 MB for the catalog (Nano Server is 190 MB of it)"

ACCEPT_INDEX = ("application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json")
ACCEPT_MANIFEST = ("application/vnd.oci.image.manifest.v1+json",
                   "application/vnd.docker.distribution.manifest.v2+json")
JOBS = {"images": "ctrimages-fetch", "k3s": "k3s-fetch", "docker-win": "dockerwin-fetch"}
STICK_LABELS = {"images": "IMAGES", "k3s": "K3S", "docker-win": "DOCKERWIN"}


def store() -> Path:
    return paths.RUNTIME / "containers"


# -------------------------------------------------------------- references
@dataclass(frozen=True)
class Ref:
    registry: str   # docker.io, mcr.microsoft.com, ...
    repo: str       # library/nginx, windows/nanoserver
    tag: str = "latest"
    digest: str = ""

    @property
    def host(self) -> str:
        """Where the API answers."""
        return DOCKER_HUB if self.registry == "docker.io" else self.registry

    @property
    def reference(self) -> str:
        return self.digest or self.tag

    @property
    def familiar(self) -> str:
        """The name `docker images` shows: nginx:stable-alpine,
        mcr.microsoft.com/windows/nanoserver:ltsc2025."""
        repo = self.repo
        if self.registry == "docker.io":
            repo = repo[len("library/"):] if repo.startswith("library/") else repo
        else:
            repo = f"{self.registry}/{repo}"
        return f"{repo}:{self.tag}" if self.tag else f"{repo}@{self.digest}"

    @property
    def full(self) -> str:
        return f"{self.registry}/{self.repo}:{self.tag}" if self.tag else f"{self.registry}/{self.repo}@{self.digest}"

    @property
    def file_stem(self) -> str:
        """A file name for the image's tar: nginx_stable-alpine,
        windows_nanoserver_ltsc2025; other registries keep their host."""
        base = self.repo[len("library/"):] if self.repo.startswith("library/") else self.repo
        if self.registry not in ("docker.io", "mcr.microsoft.com"):
            base = f"{self.registry}/{base}"
        tail = self.tag or self.digest.split(":", 1)[-1][:12]
        return re.sub(r"[^A-Za-z0-9._-]+", "_", f"{base}_{tail}")


_REF = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$")


def parse_ref(text: str) -> Ref:
    """An image name the way docker pull takes it: nginx, nginx:1.27,
    bitnami/redis, mcr.microsoft.com/windows/nanoserver:ltsc2025,
    ghcr.io/org/app@sha256:..."""
    s = text.strip()
    digest = ""
    if "@" in s:
        s, digest = s.split("@", 1)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ContainerError(f"{text!r}: a digest is sha256: and 64 hex digits")
    tag = ""
    last = s.rsplit("/", 1)[-1]
    if ":" in last:
        s, tag = s.rsplit(":", 1)
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag):
            raise ContainerError(f"{text!r}: {tag!r} is not a valid tag")
    if not digest and not tag:
        tag = "latest"
    parts = s.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = "docker.io", s
    if registry in ("index.docker.io", "registry-1.docker.io"):
        registry = "docker.io"
    if registry == "docker.io" and "/" not in repo:
        repo = f"library/{repo}"
    if not repo or not _REF.match(repo):
        raise ContainerError(f"{text!r} is not an image name (try nginx:stable-alpine or "
                             f"mcr.microsoft.com/windows/nanoserver:ltsc2025)")
    return Ref(registry=registry, repo=repo, tag=tag, digest=digest)


# ------------------------------------------------------------ HTTP client
class _Resp:
    def __init__(self, status: int, headers: dict[str, str], fp):
        self.status, self.headers, self.fp = status, headers, fp

    def read(self, n: int = -1) -> bytes:
        return self.fp.read(n) if self.fp is not None else b""

    def close(self) -> None:
        if self.fp is not None:
            try:
                self.fp.close()
            except OSError:
                pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_open(url: str, headers: dict[str, str], timeout: int = 120) -> _Resp:
    """One request, redirects not followed (the client follows them itself
    and drops the registry's token on the way to a CDN)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    try:
        r = _OPENER.open(req, timeout=timeout)
        return _Resp(r.status, {k.lower(): v for k, v in r.headers.items()}, r)
    except urllib.error.HTTPError as exc:
        return _Resp(exc.code, {k.lower(): v for k, v in (exc.headers or {}).items()}, exc)
    except (urllib.error.URLError, OSError) as exc:
        raise ContainerError(f"cannot reach {url.split('/v2/')[0]}: {exc}") from exc


def _challenge(header: str) -> dict[str, str]:
    """WWW-Authenticate: Bearer realm="...",service="...",scope="..." -> its fields."""
    if not header.lower().startswith("bearer "):
        return {}
    return {k.lower(): v for k, v in re.findall(r'(\w+)="([^"]*)"', header[7:])}


class Registry:
    """A registry's HTTP API, read anonymously: the token dance Docker Hub
    asks for, redirects to blob storage, digests checked."""

    def __init__(self, transport=http_open):
        self.transport = transport
        self.tokens: dict[tuple[str, str], str] = {}

    def _token(self, chal: dict[str, str], repo: str) -> str:
        realm = chal.get("realm", "")
        if not realm.startswith("https://"):
            raise ContainerError(f"the registry asks for a login at {realm or 'nowhere'}; winlab pulls anonymously only")
        scope = chal.get("scope") or f"repository:{repo}:pull"
        key = (realm, scope)
        if key not in self.tokens:
            q = {"scope": scope}
            if chal.get("service"):
                q["service"] = chal["service"]
            r = self.transport(f"{realm}?{urllib.parse.urlencode(q)}", {})
            try:
                body = r.read()
            finally:
                r.close()
            if r.status != 200:
                raise ContainerError(f"no pull token for {repo} from {realm} (HTTP {r.status}): "
                                     "a private image, or a name that does not exist")
            try:
                d = json.loads(body.decode("utf-8"))
            except ValueError as exc:
                raise ContainerError(f"{realm} answered with something that is not a token") from exc
            tok = d.get("token") or d.get("access_token") or ""
            if not tok:
                raise ContainerError(f"{realm} gave no token for {repo}")
            self.tokens[key] = tok
        return self.tokens[key]

    def open(self, ref: Ref, url: str, accept: tuple[str, ...] = ()) -> _Resp:
        """GET url on ref's registry: a token when it asks for one, redirects
        followed (without the token once the host changes)."""
        headers = {"Accept": ", ".join(accept)} if accept else {}
        host = urllib.parse.urlsplit(url).netloc
        authed = False
        for _ in range(8):
            h = dict(headers)
            if urllib.parse.urlsplit(url).netloc == host:
                tok = next((t for (_realm, scope), t in self.tokens.items() if scope.split(":")[1:2] == [ref.repo]), "")
                if tok:
                    h["Authorization"] = f"Bearer {tok}"
            r = self.transport(url, h)
            if r.status == 401 and not authed:
                chal = _challenge(r.headers.get("www-authenticate", ""))
                r.close()
                if not chal:
                    raise ContainerError(f"{ref.registry} wants a login for {ref.repo}; winlab pulls anonymously only")
                # A token we hold has expired (Docker Hub's last five minutes): ask again.
                self.tokens = {k: t for k, t in self.tokens.items() if k[1].split(":")[1:2] != [ref.repo]}
                self._token(chal, ref.repo)
                authed = True
                continue
            if r.status in (301, 302, 303, 307, 308):
                loc = r.headers.get("location", "")
                r.close()
                if not loc:
                    raise ContainerError(f"{url}: a redirect to nowhere")
                url = urllib.parse.urljoin(url, loc)
                continue
            if r.status == 200:
                return r
            body = r.read(2000)
            r.close()
            if r.status == 404:
                raise ContainerError(f"{ref.familiar}: not found on {ref.registry} (check the name and the tag)")
            if r.status == 429:
                raise ContainerError(f"{ref.registry} says too many requests: Docker Hub limits anonymous pulls "
                                     "per address (about 100 in six hours); try again later")
            if r.status == 401:
                raise ContainerError(f"{ref.familiar}: {ref.registry} refuses an anonymous pull (a private image?)")
            raise ContainerError(f"{url}: HTTP {r.status} {body[:200].decode('utf-8', 'replace')}")
        raise ContainerError(f"{url}: too many redirects")

    def get(self, ref: Ref, url: str, accept: tuple[str, ...] = ()) -> tuple[bytes, dict[str, str]]:
        r = self.open(ref, url, accept)
        try:
            return r.read(), r.headers
        finally:
            r.close()

    def download(self, ref: Ref, digest: str, dest: Path, urls: tuple[str, ...] = (), say=None) -> Path:
        """A blob into dest, its sha256 checked; a foreign layer falls back to
        the URLs its descriptor names."""
        want = digest.split(":", 1)[1] if digest.startswith("sha256:") else ""
        if not want:
            raise ContainerError(f"{digest}: only sha256 digests are supported")
        if dest.exists() and _sha256_file(dest) == want:
            return dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        tried = []
        for src in [f"https://{ref.host}/v2/{ref.repo}/blobs/{digest}", *urls]:
            try:
                r = self.open(ref, src) if src.startswith(f"https://{ref.host}/") else self._plain(src)
            except ContainerError as exc:
                tried.append(str(exc))
                continue
            h = hashlib.sha256()
            got = 0
            try:
                with tmp.open("wb") as fh:
                    while True:
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        fh.write(chunk)
                        h.update(chunk)
                        got += len(chunk)
            finally:
                r.close()
            if h.hexdigest() == want:
                tmp.replace(dest)
                return dest
            tmp.unlink(missing_ok=True)
            tried.append(f"{src}: checksum mismatch after {got} bytes")
        raise ContainerError(f"{ref.familiar}: blob {digest[:19]} failed: {'; '.join(tried)}")

    def _plain(self, url: str) -> _Resp:
        for _ in range(8):
            r = self.transport(url, {})
            if r.status in (301, 302, 303, 307, 308) and r.headers.get("location"):
                url = urllib.parse.urljoin(url, r.headers["location"])
                r.close()
                continue
            if r.status != 200:
                r.close()
                raise ContainerError(f"{url}: HTTP {r.status}")
            return r
        raise ContainerError(f"{url}: too many redirects")


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def choose(index: dict, os_name: str) -> dict:
    """The manifest list's entry for this lab: linux/amd64, or windows/amd64
    of the Windows Server 2025 build (the newest revision of it)."""
    entries = [m for m in index.get("manifests", []) if isinstance(m, dict)]
    fits = [m for m in entries
            if (m.get("platform") or {}).get("os") == os_name
            and (m.get("platform") or {}).get("architecture") == "amd64"]
    if os_name == "windows":
        fits = [m for m in fits if str(m["platform"].get("os.version", "")).startswith(WINDOWS_BUILD + ".")]
        fits.sort(key=lambda m: _version_key(m["platform"].get("os.version", "")), reverse=True)
        if not fits:
            have = sorted({str((m.get("platform") or {}).get("os.version", "?")) for m in entries})
            raise ContainerError(f"no windows/amd64 image for Windows Server 2025 (build {WINDOWS_BUILD}) in this tag; "
                                 f"it has {', '.join(have) or 'none'}. Process isolation needs the host's build: "
                                 "use an ltsc2025 tag")
    if not fits:
        have = sorted({f"{(m.get('platform') or {}).get('os')}/{(m.get('platform') or {}).get('architecture')}"
                       for m in entries})
        raise ContainerError(f"no {os_name}/amd64 image in this tag (it has {', '.join(have) or 'nothing'})")
    return fits[0]


# ----------------------------------------------------------------- images
def images_dir() -> Path:
    return store() / "images"


def _wanted_file() -> Path:
    return store() / "wanted.json"


def extra_images() -> list[dict]:
    try:
        d = json.loads(_wanted_file().read_text(encoding="utf-8"))
        return [e for e in d.get("extra", []) if isinstance(e, dict) and e.get("ref")]
    except (OSError, ValueError, AttributeError):
        return []


def wanted() -> list[dict]:
    """Every image to fetch: the catalog, then what the student added."""
    out = [{"ref": c.ref, "os": c.os, "what": c.what, "license": c.license, "catalog": True} for c in CATALOG]
    have = {parse_ref(e["ref"]).full for e in out}
    for e in extra_images():
        if parse_ref(e["ref"]).full not in have:
            out.append({"ref": e["ref"], "os": e.get("os", "linux"), "what": "added by you",
                        "license": "the image's own licences (check its page)", "catalog": False})
    return out


def add_image(text: str, os_name: str = "linux") -> dict:
    """Puts an image on the fetch list (fetched on this PC by the next fetch)."""
    if os_name not in ("linux", "windows"):
        raise ContainerError("an image is for linux or windows")
    ref = parse_ref(text)
    if any(parse_ref(w["ref"]).full == ref.full for w in wanted()):
        raise ContainerError(f"{ref.familiar} is already on the list")
    extra = extra_images() + [{"ref": ref.familiar, "os": os_name}]
    store().mkdir(parents=True, exist_ok=True)
    _wanted_file().write_text(json.dumps({"extra": extra}, indent=1), encoding="utf-8")
    return {"ref": ref.familiar, "os": os_name}


def remove_image(text: str) -> bool:
    ref = parse_ref(text)
    if any(parse_ref(c.ref).full == ref.full for c in CATALOG):
        raise ContainerError(f"{ref.familiar} is in winlab's catalog: the lessons use it")
    extra = [e for e in extra_images() if parse_ref(e["ref"]).full != ref.full]
    gone = len(extra) != len(extra_images())
    if gone:
        _wanted_file().write_text(json.dumps({"extra": extra}, indent=1), encoding="utf-8")
        rec = images_meta().pop(ref.full, None)
        if rec:
            (images_dir() / rec["file"]).unlink(missing_ok=True)
            _save_images_meta({k: v for k, v in images_meta().items() if k != ref.full})
    return gone


def images_meta() -> dict[str, dict]:
    try:
        return json.loads((images_dir() / "images.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_images_meta(m: dict) -> None:
    images_dir().mkdir(parents=True, exist_ok=True)
    (images_dir() / "images.json").write_text(json.dumps(m, indent=1, sort_keys=True), encoding="utf-8")


def image_ready(full: str) -> bool:
    rec = images_meta().get(full)
    return bool(rec) and (images_dir() / rec["file"]).is_file()


def images_ready() -> bool:
    return all(image_ready(parse_ref(w["ref"]).full) for w in wanted())


def write_image_tar(dest: Path, ref: Ref, manifest_raw: bytes, manifest_type: str, manifest: dict,
                    blobs: Path) -> None:
    """One tar that `docker load`, `ctr images import` and k3s's image
    directory all read: the blobs under blobs/sha256 as the registry served
    them, the docker-save manifest.json naming them, and an OCI index."""
    cfg = manifest["config"]["digest"]
    layers = [l["digest"] for l in manifest.get("layers", [])]
    mdig = _digest(manifest_raw)
    path = lambda d: f"blobs/sha256/{d.split(':', 1)[1]}"
    docker_manifest = [{"Config": path(cfg), "RepoTags": [ref.familiar] if ref.tag else [],
                        "Layers": [path(d) for d in layers]}]
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
             "manifests": [{"mediaType": manifest_type, "digest": mdig, "size": len(manifest_raw),
                            "annotations": {"io.containerd.image.name": ref.full,
                                            "org.opencontainers.image.ref.name": ref.tag or ref.digest}}]}
    tmp = dest.with_name(dest.name + ".part")
    dest.parent.mkdir(parents=True, exist_ok=True)

    def add_bytes(tf: tarfile.TarFile, name: str, data: bytes) -> None:
        ti = tarfile.TarInfo(name)
        ti.size, ti.mtime, ti.mode = len(data), 0, 0o644
        tf.addfile(ti, io.BytesIO(data))

    with tarfile.open(tmp, "w", format=tarfile.PAX_FORMAT) as tf:
        for d in ("blobs", "blobs/sha256"):
            ti = tarfile.TarInfo(d)
            ti.type, ti.mode, ti.mtime = tarfile.DIRTYPE, 0o755, 0
            tf.addfile(ti)
        add_bytes(tf, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        add_bytes(tf, path(mdig), manifest_raw)
        done = set()
        for d in [cfg, *layers]:
            if d in done:
                continue
            done.add(d)
            src = blobs / d.split(":", 1)[1]
            ti = tarfile.TarInfo(path(d))
            ti.size, ti.mtime, ti.mode = src.stat().st_size, 0, 0o644
            with src.open("rb") as fh:
                tf.addfile(ti, fh)
        add_bytes(tf, "index.json", json.dumps(index, separators=(",", ":")).encode())
        add_bytes(tf, "manifest.json", json.dumps(docker_manifest, separators=(",", ":")).encode())
    tmp.replace(dest)


def fetch_image(entry: dict, client: Registry, say=None) -> dict:
    """One image from its registry onto this PC, as a loadable tar."""
    say = say or (lambda _m: None)
    ref = parse_ref(entry["ref"])
    os_name = entry.get("os", "linux")
    base = f"https://{ref.host}/v2/{ref.repo}/manifests/"
    raw, headers = client.get(ref, base + ref.reference, ACCEPT_INDEX + ACCEPT_MANIFEST)
    if ref.digest and _digest(raw) != ref.digest:
        raise ContainerError(f"{ref.familiar}: the manifest does not match its digest")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise ContainerError(f"{ref.familiar}: the registry sent a manifest that is not JSON") from exc
    mtype = doc.get("mediaType") or headers.get("content-type", "").split(";")[0]
    platform = {"os": os_name, "architecture": "amd64"}
    if mtype in ACCEPT_INDEX or "manifests" in doc:
        pick = choose(doc, os_name)
        platform = pick.get("platform") or platform
        raw, headers = client.get(ref, base + pick["digest"], ACCEPT_MANIFEST)
        if _digest(raw) != pick["digest"]:
            raise ContainerError(f"{ref.familiar}: the image manifest does not match the digest its list gives")
        doc = json.loads(raw.decode("utf-8"))
        mtype = doc.get("mediaType") or pick.get("mediaType") or headers.get("content-type", "").split(";")[0]
    if mtype not in ACCEPT_MANIFEST or "config" not in doc:
        raise ContainerError(f"{ref.familiar}: an old or unknown manifest format ({mtype or 'none'})")
    blobs = store() / "cache" / "blobs"
    descs = [doc["config"], *doc.get("layers", [])]
    total = sum(int(d.get("size", 0)) for d in descs)
    say(f"{ref.familiar} ({platform.get('os')}/{platform.get('architecture')}"
        f"{' ' + platform['os.version'] if platform.get('os.version') else ''}): "
        f"{len(descs) - 1} layers, {total >> 20} MB")
    for d in descs:
        client.download(ref, d["digest"], blobs / d["digest"].split(":", 1)[1], tuple(d.get("urls") or ()), say)
    cfg = json.loads((blobs / doc["config"]["digest"].split(":", 1)[1]).read_bytes().decode("utf-8"))
    if os_name and cfg.get("os") and cfg["os"] != os_name:
        raise ContainerError(f"{ref.familiar}: the image is for {cfg['os']}, not {os_name}")
    name = f"{ref.file_stem}.tar"
    write_image_tar(images_dir() / name, ref, raw, mtype, doc, blobs)
    return {"ref": ref.familiar, "full": ref.full, "os": os_name, "file": name,
            "digest": _digest(raw), "os_version": platform.get("os.version", ""),
            "size": (images_dir() / name).stat().st_size, "fetched": time.strftime("%Y-%m-%d"),
            "source": f"https://{ref.host}/v2/{ref.repo}"}


def fetch_images(progress=None, transport=http_open, only: list[str] | None = None) -> dict:
    say = progress or (lambda _m: None)
    client = Registry(transport)
    meta = images_meta()
    todo = wanted()
    if only:
        names = {parse_ref(o).full for o in only}
        todo = [w for w in todo if parse_ref(w["ref"]).full in names]
    failed = []
    for i, w in enumerate(todo, 1):
        say(f"{i}/{len(todo)} {w['ref']}")
        try:
            rec = fetch_image(w, client, say)
        except ContainerError as exc:
            failed.append(str(exc))
            say(f"  failed: {exc}")
            continue
        meta[rec["full"]] = rec
        _save_images_meta(meta)
    # Layers are kept only while a fetch runs: the tars hold them.
    cache = store() / "cache" / "blobs"
    if cache.is_dir():
        for f in cache.iterdir():
            f.unlink(missing_ok=True)
    keep = {r["file"] for r in meta.values()} | {"images.json"}
    if images_dir().is_dir():
        for f in images_dir().iterdir():
            if f.name not in keep:
                f.unlink(missing_ok=True)
    if failed:
        raise ContainerError("; ".join(failed))
    say(f"images ready: {images_dir()}")
    return meta


# -------------------------------------------------------------------- k3s
K3S_CHANNELS = "https://update.k3s.io/v1-release/channels"
K3S_LATEST_API = "https://api.github.com/repos/k3s-io/k3s/releases/latest"
K3S_RELEASES = "https://github.com/k3s-io/k3s/releases/download"
K3S_RAW = "https://raw.githubusercontent.com/k3s-io/k3s"
K3S_PAGE = "https://docs.k3s.io/installation/airgap"
K3S_PINNED = "v1.33.4+k3s1"
K3S_FILES = ("k3s", "k3s-airgap-images-amd64.tar.zst")
K3S_SIZE_TEXT = "about 250 MB"


def k3s_dir() -> Path:
    return store() / "k3s"


def _meta(d: Path) -> dict:
    try:
        return json.loads((d / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def k3s_meta() -> dict:
    return _meta(k3s_dir())


def k3s_ready() -> bool:
    m = k3s_meta()
    return bool(m.get("version")) and all((k3s_dir() / f).is_file() for f in (*K3S_FILES, "install.sh"))


def discover_k3s(get=_get) -> str:
    """The stable channel's release (what k3s's own installer picks), then
    GitHub's latest release, then the pinned one."""
    ok = lambda v: bool(re.fullmatch(r"v\d+\.\d+\.\d+\+k3s\d+", v or ""))
    try:
        d = json.loads(get(K3S_CHANNELS, timeout=30).decode("utf-8"))
        v = next((c.get("latest", "") for c in d.get("data", []) if c.get("id") == "stable"), "")
        if ok(v):
            return v
    except (BootstrapError, ValueError, AttributeError):
        pass
    try:
        v = json.loads(get(K3S_LATEST_API, timeout=30).decode("utf-8")).get("tag_name", "")
        if ok(v):
            return v
    except (BootstrapError, ValueError, AttributeError):
        pass
    return K3S_PINNED


def parse_sums(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        sha, _, name = line.strip().partition(" ")
        name = name.strip().lstrip("*")
        if len(sha) == 64 and name:
            out[name] = sha.lower()
    return out


def fetch_k3s(progress=None, get=_get, download=_download_to) -> dict:
    say = progress or (lambda _m: None)
    version = discover_k3s(get)
    base = f"{K3S_RELEASES}/{urllib.parse.quote(version)}"
    say(f"k3s {version} from {base}/")
    try:
        sums = parse_sums(get(f"{base}/sha256sum-amd64.txt", timeout=60).decode("utf-8", "replace"))
    except BootstrapError as exc:
        raise ContainerError(str(exc)) from exc
    missing = [f for f in K3S_FILES if f not in sums]
    if missing:
        raise ContainerError(f"k3s {version}: {', '.join(missing)} not in the release's sha256sum-amd64.txt")
    d = k3s_dir()
    d.mkdir(parents=True, exist_ok=True)
    files = {}
    try:
        for f in K3S_FILES:
            say(f"{f}")
            download(f"{base}/{f}", d / f, expect_sha=sums[f], label=f)
            files[f] = {"sha256": sums[f], "source": f"{base}/{f}", "checked": True}
        say("install.sh (from the same tag; k3s publishes no checksum for it)")
        src = f"{K3S_RAW}/{urllib.parse.quote(version)}/install.sh"
        body = get(src, timeout=60)
    except BootstrapError as exc:
        raise ContainerError(str(exc)) from exc
    if not body.startswith(b"#!/bin/sh"):
        raise ContainerError(f"{src} is not the k3s install script")
    (d / "install.sh").write_bytes(body)
    files["install.sh"] = {"sha256": hashlib.sha256(body).hexdigest(), "source": src, "checked": False}
    m = {"name": "k3s", "version": version, "license": "Apache-2.0", "fetched": time.strftime("%Y-%m-%d"),
         "files": files}
    (d / "meta.json").write_text(json.dumps(m, indent=1), encoding="utf-8")
    say(f"k3s {version} ready: {d}")
    return m


# ------------------------------------------------------ Docker for Windows
DOCKERWIN_INDEX = "https://download.docker.com/win/static/stable/x86_64/"
DOCKERWIN_PINNED = "28.3.3"
DOCKERWIN_SIZE_TEXT = "about 50 MB"
DOCKERWIN_PAGE = "https://docs.docker.com/engine/install/binaries/#install-server-and-client-binaries-on-windows"


def dockerwin_dir() -> Path:
    return store() / "docker-windows"


def dockerwin_meta() -> dict:
    return _meta(dockerwin_dir())


def dockerwin_ready() -> bool:
    m = dockerwin_meta()
    return bool(m.get("file")) and (dockerwin_dir() / m["file"]).is_file()


def discover_dockerwin(get=_get) -> str:
    """The newest docker-X.Y.Z.zip download.docker.com lists."""
    try:
        html = get(DOCKERWIN_INDEX, timeout=30).decode("utf-8", "replace")
        vs = set(re.findall(r'href="docker-(\d+\.\d+\.\d+)\.zip"', html))
        if vs:
            return max(vs, key=_version_key)
    except BootstrapError:
        pass
    return DOCKERWIN_PINNED


def fetch_dockerwin(progress=None, get=_get, download=_download_to) -> dict:
    say = progress or (lambda _m: None)
    version = discover_dockerwin(get)
    name = f"docker-{version}.zip"
    src = DOCKERWIN_INDEX + name
    say(f"Docker CE {version} for Windows from {src}")
    d = dockerwin_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        download(src, d / name, label=name)
    except BootstrapError as exc:
        raise ContainerError(str(exc)) from exc
    with (d / name).open("rb") as fh:
        if fh.read(2) != b"PK":
            (d / name).unlink(missing_ok=True)
            raise ContainerError(f"{src} is not a zip file")
    m = {"name": "Docker CE (static binaries for Windows)", "version": version, "license": "Apache-2.0",
         "file": name, "sha256": _sha256_file(d / name), "source": src, "fetched": time.strftime("%Y-%m-%d")}
    (d / "meta.json").write_text(json.dumps(m, indent=1), encoding="utf-8")
    for f in d.iterdir():
        if f.name not in (name, "meta.json"):
            f.unlink()
    say(f"Docker {version} for Windows ready: {d}")
    return m


# ---------------------------------------------------------------- fetching
KINDS = ("images", "k3s", "docker-win")


def ready(kind: str) -> bool:
    return {"images": images_ready, "k3s": k3s_ready, "docker-win": dockerwin_ready}[kind]()


def fetch(kind: str = "all", progress=None) -> None:
    kinds = KINDS if kind == "all" else (kind,)
    if any(k not in KINDS for k in kinds):
        raise ContainerError(f"fetch what? {', '.join(KINDS)} or all")
    for k in kinds:
        if k == "images":
            fetch_images(progress)
        elif k == "k3s":
            fetch_k3s(progress)
        else:
            fetch_dockerwin(progress)


# ------------------------------------------------------------------ sticks
def _readme_images(recs: list[dict]) -> str:
    lines = ["Container images, pulled from their registries on the winlab PC (never inside the lab),",
             "each layer checked against its sha256 digest. One tar per image: docker load reads it,",
             "and so do containerd (ctr images import) and k3s.", ""]
    for r in recs:
        folder = "Windows" if r["os"] == "windows" else "Linux"
        lines.append(f"  {folder}/{r['file']:<44} {r['ref']}  ({r['size'] >> 20} MB, {r['digest'][:19]})")
    lines += ["", "Ubuntu with Docker:",
              "  sudo mkdir -p /mnt/images; sudo mount LABEL=IMAGES /mnt/images",
              "  docker load -i /mnt/images/Linux/nginx_stable-alpine.tar   then docker images", "",
              "A k3s node (the images go into containerd's k8s.io namespace):",
              "  sudo k3s ctr images import /mnt/images/Linux/nginx_stable-alpine.tar", "",
              "Windows Server 2025 with Docker (the stick is a drive letter, say E:):",
              "  docker load -i E:\\Windows\\windows_nanoserver_ltsc2025.tar", "",
              "Better than carrying sticks around: load once on the Docker host, run the registry:2",
              "image there and docker push to it; every other machine pulls from that registry."]
    return "\r\n".join(lines) + "\r\n"


def _readme_k3s(m: dict) -> str:
    v = m.get("version", "")
    return "\r\n".join([
        f"k3s {v} (Apache-2.0) for an air-gapped install, from github.com/k3s-io/k3s releases.",
        "k3s and the image bundle were checked against the release's sha256sum-amd64.txt;",
        f"install.sh came from the same tag (sha256 {m.get('files', {}).get('install.sh', {}).get('sha256', '?')}).", "",
        "On every node (k3s's air-gap steps, https://docs.k3s.io/installation/airgap):",
        "  sudo mkdir -p /mnt/k3s; sudo mount LABEL=K3S /mnt/k3s",
        "  sudo mkdir -p /var/lib/rancher/k3s/agent/images",
        "  sudo cp /mnt/k3s/k3s-airgap-images-amd64.tar.zst /var/lib/rancher/k3s/agent/images/",
        "  sudo install -m 755 /mnt/k3s/k3s /usr/local/bin/k3s",
        "  cp /mnt/k3s/install.sh ~/ && chmod +x ~/install.sh", "",
        "The server:  sudo INSTALL_K3S_SKIP_DOWNLOAD=true ~/install.sh",
        "             the join token is in /var/lib/rancher/k3s/server/node-token",
        "An agent:    sudo INSTALL_K3S_SKIP_DOWNLOAD=true K3S_URL=https://<server address>:6443 \\",
        "                  K3S_TOKEN=\"$(cat ~/node-token)\" ~/install.sh",
        "             (copy node-token from the server first, with scp)", "",
        "k3s needs a default route even with no internet: ip route must show 'default via'.",
        "Kubernetes on Windows nodes is not part of k3s: Windows containers run under Docker.",
    ]) + "\r\n"


def _readme_dockerwin(m: dict) -> str:
    return "\r\n".join([
        f"Docker CE {m.get('version', '')} static binaries for Windows (Apache-2.0), from download.docker.com",
        f"(no checksum is published there; the file's SHA-256 on the winlab PC was {m.get('sha256', '?')}).", "",
        "On Windows Server 2025, in an elevated PowerShell (the stick is a drive letter, say E:):",
        "  Install-WindowsFeature -Name Containers; Restart-Computer",
        f"  Expand-Archive E:\\{m.get('file', 'docker.zip')} -DestinationPath $env:ProgramFiles",
        "  [Environment]::SetEnvironmentVariable('Path', $env:Path + \";$env:ProgramFiles\\docker\", 'Machine')",
        "  & \"$env:ProgramFiles\\docker\\dockerd.exe\" --register-service; Start-Service docker",
        "  docker version   (both Client and Server answer: OS/Arch windows/amd64)", "",
        "Containers run with process isolation: the image must be built for this host's Windows build",
        "(nanoserver:ltsc2025 for Windows Server 2025). Hyper-V isolation would need nested",
        "virtualization and is not used in the lab.",
    ]) + "\r\n"


def stick_files(kind: str, only: list[str] | None = None) -> dict[str, bytes]:
    if kind == "images":
        meta = images_meta()
        recs = [r for r in meta.values() if (images_dir() / r["file"]).is_file()]
        if only:
            names = {parse_ref(o).full for o in only}
            recs = [r for r in recs if r["full"] in names]
        if not recs:
            raise ContainerError("no container images on this PC yet: winlab containers fetch images "
                                 "(or Images, Container images)")
        recs.sort(key=lambda r: (r["os"], r["ref"]))
        out = {f"{'Windows' if r['os'] == 'windows' else 'Linux'}/{r['file']}": (images_dir() / r["file"]).read_bytes()
               for r in recs}
        out["README.txt"] = _readme_images(recs).encode("utf-8")
        return out
    if kind == "k3s":
        if not k3s_ready():
            raise ContainerError("k3s is not on this PC yet: winlab containers fetch k3s")
        out = {f: (k3s_dir() / f).read_bytes() for f in (*K3S_FILES, "install.sh")}
        out["README.txt"] = _readme_k3s(k3s_meta()).encode("utf-8")
        return out
    if kind == "docker-win":
        if not dockerwin_ready():
            raise ContainerError("Docker for Windows is not on this PC yet: winlab containers fetch docker-win")
        m = dockerwin_meta()
        return {m["file"]: (dockerwin_dir() / m["file"]).read_bytes(),
                "README.txt": _readme_dockerwin(m).encode("utf-8")}
    raise ContainerError(f"which stick? {', '.join(KINDS)}")


STICK_TITLES = {"images": "Container images", "k3s": "k3s air-gap", "docker-win": "Docker for Windows"}


def to_stick(lab_name: str, kind: str, only: list[str] | None = None) -> dict:
    """A new stick on the lab's media shelf."""
    from . import media, mediashelf
    files = stick_files(kind, only)
    title = STICK_TITLES[kind]
    if kind == "k3s":
        title += f" ({k3s_meta().get('version', '')})"
    elif kind == "docker-win":
        title += f" ({dockerwin_meta().get('version', '')})"
    else:
        title += f" ({len(files) - 1})"
    sid = mediashelf._new_id(lab_name, {"images": "container-images", "k3s": "k3s", "docker-win": "docker-windows"}[kind])
    d = mediashelf.shelf_dir(lab_name, "sticks")
    try:
        media.write_stick(files, d / f"{sid}.img", STICK_LABELS[kind])
    except media.MediaError as exc:
        raise ContainerError(f"{exc}" + (": write fewer images (winlab containers stick <lab> images "
                                         "--image <name> ...)" if kind == "images" else "")) from exc
    (d / f"{sid}.json").write_text(json.dumps({"id": sid, "title": title}) + "\n", encoding="utf-8")
    return {"id": sid, "title": title, "files": len(files), "mb": sum(len(b) for b in files.values()) >> 20}


# ------------------------------------------------------------------ status
def summary() -> dict:
    meta = images_meta()
    imgs = []
    for w in wanted():
        full = parse_ref(w["ref"]).full
        rec = meta.get(full) or {}
        imgs.append({"ref": parse_ref(w["ref"]).familiar, "os": w["os"], "what": w["what"], "license": w["license"],
                     "catalog": w["catalog"], "ready": image_ready(full),
                     "size_mb": round(rec.get("size", 0) / 1048576, 1), "fetched": rec.get("fetched", "")})
    km, dm = k3s_meta(), dockerwin_meta()
    return {"images": imgs, "images_ready": images_ready(),
            "k3s": {"ready": k3s_ready(), "version": km.get("version", ""), "fetched": km.get("fetched", ""),
                    "page": K3S_PAGE},
            "docker_win": {"ready": dockerwin_ready(), "version": dm.get("version", ""),
                           "fetched": dm.get("fetched", ""), "page": DOCKERWIN_PAGE},
            "store": str(store())}


def render_status() -> str:
    s = summary()
    lines = [f"container store: {s['store']}", "", "  images (pulled from their registries onto this PC):"]
    for i in s["images"]:
        state = f"ready, {i['size_mb']} MB, fetched {i['fetched']}" if i["ready"] else "not fetched"
        lines.append(f"    {i['ref']:<48} {i['os']:<8} {state}{'' if i['catalog'] else '  (added by you)'}")
    k, d = s["k3s"], s["docker_win"]
    lines += ["", f"  k3s         {'ready ' + k['version'] + ', fetched ' + k['fetched'] if k['ready'] else 'not fetched (' + K3S_SIZE_TEXT + ')'}",
              f"  docker-win  {'ready ' + d['version'] + ', fetched ' + d['fetched'] if d['ready'] else 'not fetched (' + DOCKERWIN_SIZE_TEXT + ')'}",
              "", "  onto a stick: winlab containers stick <lab> images|k3s|docker-win, or the media shelf",
              "  more images:  winlab containers add <name> [--windows], then winlab containers fetch images", ""]
    return "\n".join(lines)


# ----------------------------------------------------------------- the lab
def downloads(node) -> list[str]:
    v = node.vars.get("downloads") or []
    return [x for x in (v if isinstance(v, list) else [v]) if x in ("container-images", "k3s", "docker-windows")]


SETUP = {
    "container-images": ("images", "Fetch the container images (Docker Hub, Microsoft's registry)", IMAGES_SIZE_TEXT,
                         "pulled from the registries' HTTP API onto this PC, every layer checked against its digest"),
    "k3s": ("k3s", "Fetch k3s for an air-gapped install (GitHub release)", K3S_SIZE_TEXT,
            "the binary and the air-gap image bundle, checked against the release's sha256sum-amd64.txt"),
    "docker-windows": ("docker-win", "Fetch Docker for Windows (download.docker.com)", DOCKERWIN_SIZE_TEXT,
                       "the static Docker CE binaries for Windows Server"),
}


def setup_steps(lab, have: set[str] | None = None) -> list[dict]:
    have = set(have or ())
    steps = []
    for key, (kind, label, size, how) in SETUP.items():
        who = [n.id for n in lab.node_list() if key in downloads(n)]
        if not who or f"ctr-{kind}" in have:
            continue
        steps.append({"id": f"ctr-{kind}", "label": label, "done": ready(kind), "blocked": False,
                      "hint": f"{', '.join(who)} use it from the {STICK_TITLES[kind].lower()} stick: {how}, {size} once",
                      "job": JOBS[kind]})
    return steps


def act(dash, action: str, params: dict) -> dict:
    """wb-ctr-stick writes one of the three sticks onto the shelf."""
    if action == "wb-ctr-stick":
        kind = str(params.get("kind", ""))
        if kind not in KINDS:
            return {"ok": False, "message": f"which stick? {', '.join(KINDS)}"}
        try:
            r = to_stick(dash.lab.name, kind)
        except ContainerError as exc:
            return {"ok": False, "message": str(exc), "fetch": not ready(kind), "job": JOBS[kind]}
        return {"ok": True, "message": f"{r['title']} is on the shelf: drag it onto a machine", "stick": r["id"]}
    return {"ok": False, "message": f"unknown containers action {action!r}"}


def node_of(lab, role: str):
    """The machine a lab names for a part (node vars container = docker,
    k3s-server, k3s-agent, windows), or None."""
    return next((n for n in lab.node_list() if n.vars.get("container") == role), None)


def fault_params(lab) -> dict[str, str]:
    d, k = node_of(lab, "docker"), node_of(lab, "k3s-server")
    ip = lambda n: (n.primary_nic.ip if n is not None and n.primary_nic and n.primary_nic.ip else "")
    return {"registry": f"{ip(d)}:5000" if ip(d) else "the registry", "k3sserver": ip(k) or "the k3s server"}


# --------------------------------------------------------------- the drills
def _faults():
    from .guestfaults import LINUX, GuestFault
    need_docker = ("command -v docker >/dev/null 2>&1 && docker inspect web >/dev/null 2>&1 || { echo 'no container "
                   "named web on this machine: run it first (lesson docker-basics)'; exit 1; }; ")
    need_server = ("[ -f /etc/rancher/k3s/k3s.yaml ] && k3s kubectl get deploy web >/dev/null 2>&1 || { echo 'no "
                   "deployment web on this k3s server: build it first (lesson k3s-deploy-scale)'; exit 1; }; ")
    need_agent = ("[ -f /etc/systemd/system/k3s-agent.service.env ] || { echo 'this is not a k3s agent: break it on "
                  "an agent node (lesson k3s-air-gapped)'; exit 1; }; ")
    run_web = ('img=$(docker inspect -f "{{.Config.Image}}" web); '
               'vols=$(docker inspect -f "{{range .Mounts}}-v {{.Source}}:{{.Destination}}{{if not .RW}}:ro{{end}} {{end}}" web); ')
    return [
        GuestFault(
            id="ctr-wrong-port",
            images=("ubuntu",),
            title="The web container runs, and nothing answers on its port",
            os=LINUX,
            teaches="port publishing (-p host:container), what docker ps and docker port show, and that the "
                    "container side must be the port the process inside listens on",
            symptom="curl http://localhost:8080 fails with 'Connection reset by peer' (or an empty reply), yet "
                    "docker ps shows web Up with 0.0.0.0:8080 published",
            apply=(need_docker + run_web + "docker rm -f web >/dev/null && docker run -d --name web --restart unless-stopped -p 8080:8080 $vols "
                   "$img >/dev/null && echo broken"),
            clear=(need_docker + run_web + "docker rm -f web >/dev/null && docker run -d --name web --restart "
                   "unless-stopped -p 8080:80 $vols $img >/dev/null; echo ok"),
            shell="sh",
            hints=(
                "Is it the container or the mapping? docker ps shows the PORTS column; docker port web lists "
                "each mapping as container-port -> host address. Then ask from inside: docker exec web wget -qO- "
                "http://127.0.0.1:80 | head -3.",
                "nginx inside listens on 80 (docker exec web netstat -ltn, or the EXPOSE line in docker image "
                "inspect). The mapping sends host 8080 to container 8080, where nothing listens: docker answers the "
                "connection, finds no one behind it, and resets it.",
                "A container's port mapping cannot be changed in place: docker rm -f web, then docker run -d --name "
                "web --restart unless-stopped -p 8080:80 with the same -v as before (docker inspect web showed "
                "them under Mounts). curl -I http://localhost:8080 answers 200 OK.",
            ),
            verify=("docker port web 80/tcp 2>/dev/null | grep -q ':8080$' && curl -fsS -m 5 -o /dev/null "
                    "http://127.0.0.1:8080/ && echo True || echo False"),
        ),
        GuestFault(
            id="ctr-image-pull-backoff",
            images=("ubuntu",),
            title="A rollout hangs: new pods sit in ImagePullBackOff",
            os=LINUX,
            teaches="where a node gets an image in a sealed lab (its own containerd store or the lab registry, "
                    "never the internet), reading kubectl describe pod events, and kubectl rollout undo",
            symptom="kubectl get pods shows new web pods in ErrImagePull and then ImagePullBackOff while the "
                    "old ones keep running; kubectl rollout status deployment/web never finishes",
            apply=(need_server + "k3s kubectl get deploy web -o jsonpath='{.spec.template.spec.containers[0].image}' "
                   "> /root/.winlab-web-image; k3s kubectl set image deployment/web '*=nginx:latest' >/dev/null && "
                   "echo broken"),
            clear=(need_server + "[ -s /root/.winlab-web-image ] && k3s kubectl set image deployment/web "
                   "\"*=$(cat /root/.winlab-web-image)\" >/dev/null; rm -f /root/.winlab-web-image; echo ok"),
            shell="sh",
            hints=(
                "Ask the pod, not the deployment: k3s kubectl get pods -l app=web, then k3s kubectl describe pod "
                "<one in ImagePullBackOff>. The Events at the bottom say which image it tried and why it failed.",
                "The image is nginx:latest, and the lab has no internet: docker.io resolves to nothing (or to "
                "your mirror, {registry}, which only has the tags you pushed). curl http://{registry}/v2/"
                "library/nginx/tags/list shows which tags the lab really has. k3s kubectl rollout history "
                "deployment/web shows the change.",
                "Either go back: k3s kubectl rollout undo deployment/web, or bring the image into the lab: on the "
                "Docker host, docker tag and docker push the tag to {registry} first. Then k3s kubectl rollout "
                "status deployment/web finishes and every pod is Running.",
            ),
            verify=("k3s kubectl get pods -l app=web --no-headers 2>/dev/null | grep -qE 'ImagePull|ErrImage' && "
                    "{ echo False; exit 0; }; r=$(k3s kubectl get deploy web -o jsonpath='{.status.replicas}/"
                    "{.status.readyReplicas}/{.status.updatedReplicas}' 2>/dev/null); "
                    "a=${r%%/*}; [ -n \"$a\" ] && [ \"$a\" != 0 ] && [ \"$r\" = \"$a/$a/$a\" ] && echo True || echo False"),
        ),
        GuestFault(
            id="ctr-node-notready",
            images=("ubuntu",),
            title="A k3s node goes NotReady after a change on it",
            os=LINUX,
            teaches="how an agent joins (K3S_URL and the token in the service's env file), reading the agent's "
                    "journal, and what NotReady means to the pods on that node",
            symptom="on the server, k3s kubectl get nodes shows this node NotReady; pods on it go Terminating "
                    "after a few minutes and new ones are scheduled elsewhere",
            apply=(need_agent + "f=/etc/systemd/system/k3s-agent.service.env; [ -f $f.winlab ] || cp $f $f.winlab; "
                   "sed -i -E \"s#^(K3S_URL=['\\\"]?https://[^:/'\\\"]+):6443#\\1:6444#\" $f && systemctl restart "
                   "--no-block k3s-agent && echo broken"),
            clear=("f=/etc/systemd/system/k3s-agent.service.env; [ -f $f.winlab ] && mv $f.winlab $f; "
                   "systemctl restart --no-block k3s-agent; echo ok"),
            shell="sh",
            hints=(
                "Start on the server: k3s kubectl get nodes, then k3s kubectl describe node <this node>: under "
                "Conditions, 'Kubelet stopped posting node status'. The node itself is up, so look at its agent: "
                "systemctl status k3s-agent and journalctl -u k3s-agent -n 30.",
                "The journal keeps failing to connect to {k3sserver}:6444. The server listens on 6443 (ss -ltn on "
                "{k3sserver}). Where does the agent get its server address? systemctl cat k3s-agent names the "
                "env file: /etc/systemd/system/k3s-agent.service.env.",
                "Put K3S_URL back to https://{k3sserver}:6443 in that file (sudo nano), then sudo systemctl "
                "restart k3s-agent. Within a minute k3s kubectl get nodes shows it Ready again.",
            ),
            verify=("f=/etc/systemd/system/k3s-agent.service.env; grep -qE '^K3S_URL=.*:6443' $f && "
                    "systemctl is-active -q k3s-agent && ss -Htn state established '( dport = :6443 )' | grep -q . "
                    "&& echo True || echo False"),
        ),
    ]


FAULT_IDS = ("ctr-wrong-port", "ctr-image-pull-backoff", "ctr-node-notready")


def register_faults(reg) -> None:
    for f in _faults():
        reg(f)
