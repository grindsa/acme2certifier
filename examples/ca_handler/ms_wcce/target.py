"""Temporary compatibility layer.

Real implementation: the acme2certifier package
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.cahandlers.ms_wcce import target as _impl

warn_legacy_import("examples.ca_handler.ms_wcce.target", "acme2certifier.cahandlers.ms_wcce.target")
sys.modules[__name__] = _impl
