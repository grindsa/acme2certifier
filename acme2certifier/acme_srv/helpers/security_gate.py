# -*- coding: utf-8 -*-
"""Break-glass gate for options that disable security controls.

Kept free of DB/message imports so low-level modules (challenge validators,
registry setup) can import it without pulling in those layers.
"""

from __future__ import annotations

import logging
import os
from typing import Any, List, Optional, Sequence

# Break-glass acknowledgment for options that disable security checks (testing only).
SECURITY_DISABLE_ACK_ENV = "ACME2CERTIFIER_I_KNOW_THE_RISK"
_SECURITY_DISABLE_ACK_VALUES = frozenset({"1", "true", "yes", "on"})


def security_disable_acknowledged() -> bool:
    """Return True when the break-glass env var acknowledges security-disable flags."""
    return (
        os.environ.get(SECURITY_DISABLE_ACK_ENV, "").strip().lower()
        in _SECURITY_DISABLE_ACK_VALUES
    )


def client_header_parameter_decide(
    logger: logging.Logger,
    field: str,
    client_value: Optional[str],
    allowlist: Optional[Sequence[str]],
    default_value: Any,
) -> Any:
    """Decide whether a client-supplied header enrollment parameter may be applied.

    - No client value → keep ``default_value``.
    - Non-empty ``allowlist`` → apply ``client_value`` only if listed; otherwise
      ignore and keep ``default_value``.
    - Empty / missing allowlist → apply only when ``ACME2CERTIFIER_I_KNOW_THE_RISK``
      is set; otherwise ignore and keep ``default_value``.
    """
    if not client_value:
        return default_value

    allowlist_list: List[str] = [str(item) for item in allowlist] if allowlist else []
    if allowlist_list:
        if client_value in allowlist_list:
            return client_value
        logger.warning(
            "Ignoring client-selected %s=%s; value is not in the allowlist",
            field,
            client_value,
        )
        return default_value

    if security_disable_acknowledged():
        logger.critical(
            "Client-selected %s=%s permitted with empty allowlist because %s is set",
            field,
            client_value,
            SECURITY_DISABLE_ACK_ENV,
        )
        return client_value

    logger.warning(
        "Ignoring client-selected %s=%s; empty allowlist requires %s "
        "or a non-empty [Order] allowed_header_values list",
        field,
        client_value,
        SECURITY_DISABLE_ACK_ENV,
    )
    return default_value
