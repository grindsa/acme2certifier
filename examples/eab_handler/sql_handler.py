"""Temporary compatibility layer.

Real implementation: the acme2certifier package
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.eabhandlers import sql_handler as _impl

warn_legacy_import("examples.eab_handler.sql_handler", "acme2certifier.eabhandlers.sql_handler")
sys.modules[__name__] = _impl
