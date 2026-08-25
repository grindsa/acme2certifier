# -*- coding: utf-8 -*-
"""Deprecated alias for acme2certifier.cahandlers.msicpr_ca_handler.

Historically named MS-WCCE; enrollment uses the MS-ICPR RPC interface.
Prefer ``handler_module: acme2certifier.cahandlers.msicpr_ca_handler``.
"""

import warnings

from acme2certifier.cahandlers.msicpr_ca_handler import CAhandler

warnings.warn(
    "acme2certifier.cahandlers.mswcce_ca_handler is deprecated; "
    "use acme2certifier.cahandlers.msicpr_ca_handler instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["CAhandler"]
