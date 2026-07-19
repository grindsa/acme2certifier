"""Temporary compatibility layer.

Real implementation: acme2certifier.acme_srv
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.acme_srv.challenge_validators import dns_validator as _impl

warn_legacy_import("acme_srv.challenge_validators.dns_validator", "acme2certifier.acme_srv.challenge_validators.dns_validator")
sys.modules[__name__] = _impl
