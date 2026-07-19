"""Temporary compatibility layer.

Real implementation: acme2certifier.tools
Do not add logic here.
"""

import runpy
import sys

from acme2certifier.compat import warn_legacy_import

_PREFERRED = "acme2certifier.tools.django_secret_keygen"

if __name__ == "__main__":
    warn_legacy_import("tools.django_secret_keygen", _PREFERRED)
    runpy.run_module("acme2certifier.tools.django_secret_keygen", run_name="__main__")
else:
    warn_legacy_import("tools.django_secret_keygen", _PREFERRED)
    from acme2certifier.tools import django_secret_keygen as _impl

    sys.modules[__name__] = _impl
