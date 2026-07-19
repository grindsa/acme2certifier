"""Temporary compatibility layer.

Real implementation: acme2certifier.acme_srv
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.acme_srv import order as _impl

warn_legacy_import("acme_srv.order", "acme2certifier.acme_srv.order")
sys.modules[__name__] = _impl
