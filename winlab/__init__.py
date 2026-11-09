"""winlab -- a portable, isolated Windows Server lab.

No host footprint, stdlib only, isolated by construction, one lab definition
across two runtimes (portable QEMU and a bootable KVM appliance).
"""

__version__ = "0.3.0"

# The trial's source has only its own parts; the rest of winlab is named by
# the engine but not shipped (winlab/trialparts.py).
from . import trialparts as _trialparts  # noqa: E402

_trialparts.install()
