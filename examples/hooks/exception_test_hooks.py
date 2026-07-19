"""Temporary compatibility layer.

Real implementation: the acme2certifier package
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.hookhandlers import exception_test_hooks as _impl

warn_legacy_import("examples.hooks.exception_test_hooks", "acme2certifier.hookhandlers.exception_test_hooks")
sys.modules[__name__] = _impl
