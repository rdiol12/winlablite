"""Write winlab's version (winlab/__init__.py): what the release workflow does
with the release's tag, so no release needs the version raised by hand.

    python tools/set_version.py 1.2.1
        writes it in this checkout (the build then names its files for it)
    python tools/set_version.py 1.2.1 --push owner/repo main
        commits the same change to that branch on GitHub (gh, GH_TOKEN) when
        the branch says something else
"""
from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path

FILE = "winlab/__init__.py"
LINE = re.compile(r'^__version__ = "[^"]*"$', re.M)
VERSION = re.compile(r"^\d+(\.\d+){1,3}$")


def stamped(text: str, version: str) -> str:
    if not VERSION.match(version):
        raise SystemExit(f"{version!r} is not a version (1.2 or 1.2.3)")
    if len(LINE.findall(text)) != 1:
        raise SystemExit(f"{FILE} has no single __version__ line")
    return LINE.sub(f'__version__ = "{version}"', text)


def main(argv: list[str]) -> int:
    version = argv[0]
    if "--push" not in argv:
        path = Path(__file__).resolve().parent.parent / FILE
        path.write_text(stamped(path.read_text(encoding="utf-8"), version), encoding="utf-8", newline="\n")
        print(f"{FILE}: {version}")
        return 0
    repo, branch = argv[argv.index("--push") + 1:argv.index("--push") + 3]
    got = json.loads(subprocess.run(["gh", "api", f"repos/{repo}/contents/{FILE}?ref={branch}"],
                                    check=True, capture_output=True).stdout)
    old = base64.b64decode(got["content"]).decode("utf-8")
    new = stamped(old, version)
    if new == old:
        print(f"{branch} already says {version}")
        return 0
    body = {"message": f"Version {version}", "branch": branch, "sha": got["sha"],
            "content": base64.b64encode(new.encode("utf-8")).decode()}
    subprocess.run(["gh", "api", "-X", "PUT", f"repos/{repo}/contents/{FILE}", "--input", "-"],
                   input=json.dumps(body).encode(), check=True, capture_output=True)
    print(f"{branch}: Version {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
