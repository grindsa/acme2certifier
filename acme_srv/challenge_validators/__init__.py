"""Temporary compatibility layer.

Real implementation: acme2certifier.acme_srv.challenge_validators
Do not add logic here.
"""

from acme2certifier.compat import warn_legacy_import

warn_legacy_import("acme_srv.challenge_validators", "acme2certifier.acme_srv.challenge_validators")
from acme2certifier.acme_srv.challenge_validators import *  # noqa: F401, F403
