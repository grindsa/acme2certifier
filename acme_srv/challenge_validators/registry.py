"""Temporary compatibility layer.

Real implementation: acme2certifier.acme_srv
Do not add logic here.
"""
import sys
from acme2certifier.acme_srv.challenge_validators import registry as _impl
sys.modules[__name__] = _impl
