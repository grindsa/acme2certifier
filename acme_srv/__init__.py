"""Temporary compatibility layer.

Real implementation: acme2certifier.acme_srv
Do not add logic here.
"""

from acme2certifier.compat import warn_legacy_import
from acme2certifier.acme_srv.version import __version__

warn_legacy_import("acme_srv", "acme2certifier.acme_srv")

__all__ = ["__version__"]
