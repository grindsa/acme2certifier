"""Temporary compatibility layer.

Real implementation: the acme2certifier package
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.cahandlers import certsrv as _impl

warn_legacy_import("examples.ca_handler.certsrv", "acme2certifier.cahandlers.certsrv")
sys.modules[__name__] = _impl
