"""Temporary compatibility layer.

Real implementation: acme2certifier.eabhandlers
Do not add logic here.
"""

from acme2certifier.compat import warn_legacy_import

warn_legacy_import("examples.eab_handler", "acme2certifier.eabhandlers")
