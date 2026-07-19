"""Temporary compatibility layer.

Real implementation: the acme2certifier package
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.cahandlers.ms_wcce import rpc as _impl

warn_legacy_import("examples.ca_handler.ms_wcce.rpc", "acme2certifier.cahandlers.ms_wcce.rpc")
sys.modules[__name__] = _impl
