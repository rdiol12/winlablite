"""PyInstaller entry point for winlab.exe. Equivalent to `python -m winlab`.

Kept as a file in the repository (not generated at build time) so the exe is
reproducible from a checkout and the build script has nothing to template."""

import sys

from winlab.cli import main

if __name__ == "__main__":
    sys.exit(main())
