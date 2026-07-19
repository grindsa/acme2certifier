"""Temporary compatibility layer.

Real implementation: acme2certifier.acme_srv
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.acme_srv.helpers import plugin_loader as _impl

warn_legacy_import("acme_srv.helpers.plugin_loader", "acme2certifier.acme_srv.helpers.plugin_loader")
sys.modules[__name__] = _impl
