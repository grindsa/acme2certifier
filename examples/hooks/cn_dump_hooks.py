"""Temporary compatibility layer.

Real implementation: the acme2certifier package
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.hookhandlers import cn_dump_hooks as _impl

warn_legacy_import("examples.hooks.cn_dump_hooks", "acme2certifier.hookhandlers.cn_dump_hooks")
sys.modules[__name__] = _impl
