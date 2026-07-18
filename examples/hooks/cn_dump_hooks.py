"""Temporary compatibility layer.

Real implementation lives under the acme2certifier package.
Do not add logic here.
"""
import sys
from acme2certifier.hookhandlers import cn_dump_hooks as _impl
sys.modules[__name__] = _impl
