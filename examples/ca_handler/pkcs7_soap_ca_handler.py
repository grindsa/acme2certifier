"""Temporary compatibility layer.

Real implementation: the acme2certifier package
Do not add logic here.
"""

import sys
from acme2certifier.compat import warn_legacy_import
from acme2certifier.cahandlers import pkcs7_soap_ca_handler as _impl

warn_legacy_import("examples.ca_handler.pkcs7_soap_ca_handler", "acme2certifier.cahandlers.pkcs7_soap_ca_handler")
sys.modules[__name__] = _impl
