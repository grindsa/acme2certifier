"""Temporary compatibility layer.

Real implementation: acme2certifier.cahandlers
Do not add logic here.
"""

from acme2certifier.compat import warn_legacy_import

warn_legacy_import("examples.ca_handler", "acme2certifier.cahandlers")
