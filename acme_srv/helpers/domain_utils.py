"""Temporary compatibility layer.

Real implementation: acme2certifier.acme_srv
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.acme_srv.helpers import domain_utils as _impl

warn_legacy_import("acme_srv.helpers.domain_utils", "acme2certifier.acme_srv.helpers.domain_utils")
sys.modules[__name__] = _impl
