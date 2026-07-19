"""Temporary compatibility layer.

Real implementation: acme2certifier.tools
Do not add logic here.
"""

import runpy
import sys

from acme2certifier.compat import warn_legacy_import

_PREFERRED = "acme2certifier.tools.eab_chk"

if __name__ == "__main__":
    warn_legacy_import("tools.eab_chk", _PREFERRED)
    runpy.run_module("acme2certifier.tools.eab_chk", run_name="__main__")
else:
    warn_legacy_import("tools.eab_chk", _PREFERRED)
    from acme2certifier.tools import eab_chk as _impl

    sys.modules[__name__] = _impl
