"""Temporary compatibility layer.

Real implementation lives under the acme2certifier package.
Do not add logic here.
"""

import sys
from acme2certifier.cahandlers import freeipa_ca_handler as _impl

sys.modules[__name__] = _impl
