"""Temporary compatibility layer.

Real implementation: the acme2certifier package
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.cahandlers.ms_wcce import errors as _impl

warn_legacy_import("examples.ca_handler.ms_wcce.errors", "acme2certifier.cahandlers.ms_wcce.errors")
sys.modules[__name__] = _impl
