"""Temporary compatibility layer.

Real implementation: acme2certifier.acme_srv
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.acme_srv import directory as _impl

warn_legacy_import("acme_srv.directory", "acme2certifier.acme_srv.directory")
sys.modules[__name__] = _impl
