"""Temporary compatibility layer.

Real implementation: acme2certifier.hookhandlers
Do not add logic here.
"""

from acme2certifier.compat import warn_legacy_import

warn_legacy_import("examples.hooks", "acme2certifier.hookhandlers")
