# -*- coding: utf-8 -*-
"""Break-glass gate for options that disable security controls.

Kept free of DB/message imports so low-level modules (challenge validators,
registry setup) can import it without pulling in those layers.
"""

import logging
import os
from typing import Any, List, Optional, Sequence

# Break-glass acknowledgment for options that disable security checks (testing only).
SECURITY_DISABLE_ACK_ENV = "ACME2CERTIFIER_I_KNOW_THE_RISK"
_SECURITY_DISABLE_ACK_VALUES = frozenset({"1", "true", "yes", "on"})

# EAB profile cahandler keys that must not be overridden from kid_profiles (exact match).
# acme_url is intentionally allowed: acme_ca_handler EAB profiling selects upstream
_EAB_PROFILE_DENY_EXACT = frozenset(
    {
        "acme_keypath",
        "ca_bundle",
        "config_dic",
        "dbstore",
        "debug",
        "error",
        "handler_module",
        "logger",
        "openssl_bin",
        "rpc_path",
        "ssl_verify",
        "verify",
        "eab_handler",
        "eab_profiling",
        "err_msg_dic",
    }
)

# Handler implementation attrs (suffix match); not network endpoint patterns.
_EAB_PROFILE_DENY_SUFFIXES = (
    "_handler",
    "_module",
    "_bin",
    "_dic",
    "_store",
)


def eab_profile_attr_denied(key: str) -> bool:
    """Return True if *key* must not be set from an EAB cahandler profile."""
    if key in _EAB_PROFILE_DENY_EXACT:
        return True
    return any(key.endswith(suffix) for suffix in _EAB_PROFILE_DENY_SUFFIXES)


def eab_profile_warn_if_denied(logger: logging.Logger, key: str) -> bool:
    """Log and return True when profile application of *key* is blocked."""
    if not eab_profile_attr_denied(key):
        return False
    logger.warning(
        "EAB profile: ignoring denied attribute: key: %s",
        key,
    )
    return True


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
