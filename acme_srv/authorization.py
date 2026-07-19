"""Temporary compatibility layer.

Real implementation: acme2certifier.acme_srv
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.acme_srv import authorization as _impl

warn_legacy_import("acme_srv.authorization", "acme2certifier.acme_srv.authorization")
sys.modules[__name__] = _impl
