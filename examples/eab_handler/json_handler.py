"""Temporary compatibility layer.

Real implementation lives under the acme2certifier package.
Do not add logic here.
"""
import sys
from acme2certifier.eabhandlers import json_handler as _impl
sys.modules[__name__] = _impl
