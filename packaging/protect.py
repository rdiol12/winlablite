"""Compile the winlab trial's code to native extension modules before
PyInstaller packs the exe.

PyInstaller stores modules as .pyc bytecode, which tools turn back into
near-source in minutes. Every module in PROTECTED (the whole package, with
the pack decryption and the trial's pack key) is compiled with Cython into a
C extension module (.pyd on Windows), which has no bytecode to decompile.
This raises the cost of reading or patching it; it does not make the program
impossible to take apart.

    python packaging/protect.py <out-dir>

copies the winlab package to <out-dir>/winlab, compiles the protected
modules in place, deletes their .py sources there, checks that every one
imports as an extension, and prints the standard-library modules they import
(one per line, prefixed "hidden-import: ") for PyInstaller, which cannot see
inside a compiled module. Cython (Apache 2.0) and a C compiler are needed on
the build machine only; nothing of Cython ships except the generated code.
"""

from __future__ import annotations

import ast
import importlib.machinery
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The winlab trial compiles its whole package: every module but the package
# files themselves (__init__.py, __main__.py), which PyInstaller must see as
# Python. The trial's pack key (licensing/trialkey.py) is among them when the
# build wrote it (packaging/trialpack.py).
PROTECTED = sorted(
    p.relative_to(ROOT).as_posix() for p in (ROOT / "winlab").rglob("*.py")
    if p.name not in ("__init__.py", "__main__.py") and "__pycache__" not in p.parts)


def stdlib_imports(paths: list[Path]) -> list[str]:
    """Top-level and dotted standard-library imports of the given modules."""
    names: set[str] = set()
    for p in paths:
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module)
    std = set(sys.stdlib_module_names)
    return sorted(n for n in names if n.split(".")[0] in std and n != "__future__")


def compile_modules(pkg_root: Path, rels: list[str]) -> None:
    setup = pkg_root / "_protect_setup.py"
    setup.write_text(
        "from setuptools import setup\n"
        "from Cython.Build import cythonize\n"
        "import os\n"
        "# Every core at once: the trial compiles its whole package. The guard\n"
        "# keeps Windows' spawned workers from running the setup again.\n"
        "if __name__ == '__main__':\n"
        f"    setup(ext_modules=cythonize({rels!r}, language_level=3, quiet=True, nthreads=os.cpu_count() or 1,\n"
        "          compiler_directives={'binding': True, 'embedsignature': False, 'emit_code_comments': False,\n"
        "                                               'annotation_typing': False}),\n"
        "          script_args=['build_ext', '--inplace', '--parallel', str(os.cpu_count() or 1)])\n",
        encoding="utf-8")
    try:
        subprocess.run([sys.executable, str(setup)], cwd=pkg_root, check=True)
    finally:
        setup.unlink(missing_ok=True)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[0])
        print("usage: python packaging/protect.py <out-dir>")
        return 2
    out = Path(argv[0]).resolve()
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(ROOT / "winlab", out / "winlab",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.so", "*.pyd"))
    hidden = stdlib_imports([out / r for r in PROTECTED])
    compile_modules(out, PROTECTED)
    for rel in PROTECTED:
        src = out / rel
        for gen in (src.with_suffix(".c"),):
            gen.unlink(missing_ok=True)
        src.unlink()
    shutil.rmtree(out / "build", ignore_errors=True)
    # Every protected module must now load from an extension, not a .py.
    probe = ("import importlib, sys\n"
             f"mods = {[r[:-3].replace('/', '.') for r in PROTECTED]!r}\n"
             "bad = [m for m in mods if not importlib.import_module(m).__file__.endswith(tuple(importlib.machinery.EXTENSION_SUFFIXES))]\n"
             "print('not compiled:', bad) if bad else None\n"
             "sys.exit(1 if bad else 0)\n")
    env = {**os.environ, "PYTHONPATH": str(out), "WINLAB_HOME": str(ROOT)}
    r = subprocess.run([sys.executable, "-c", "import importlib.machinery\n" + probe], cwd=out, env=env)
    if r.returncode != 0:
        print("protect: a protected module did not import as native code", file=sys.stderr)
        return 1
    for name in hidden:
        print(f"hidden-import: {name}")
    print(f"protect: {len(PROTECTED)} modules compiled to native code in {out / 'winlab'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
