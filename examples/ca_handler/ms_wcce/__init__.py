"""Temporary compatibility layer.

Real implementation: acme2certifier.cahandlers.ms_wcce
Do not add logic here.
"""

from acme2certifier.compat import warn_legacy_import

warn_legacy_import("examples.ca_handler.ms_wcce", "acme2certifier.cahandlers.ms_wcce")
from acme2certifier.cahandlers.ms_wcce import *  # noqa: F401, F403
