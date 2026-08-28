# -*- coding: utf-8 -*-
"""Break-glass gate for options that disable security controls.

Kept dependency-free so low-level modules (challenge validators, registry
setup) can import it without pulling in the database or message layer.
"""

import os

# Break-glass acknowledgment for options that disable security checks (testing only).
SECURITY_DISABLE_ACK_ENV = "ACME2CERTIFIER_I_KNOW_THE_RISK"
_SECURITY_DISABLE_ACK_VALUES = frozenset({"1", "true", "yes", "on"})

# EAB profile cahandler keys that must not be overridden from kid_profiles (exact match).
_EAB_PROFILE_DENY_EXACT = frozenset(
    {
        "acme_keypath",
        "acme_url",
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
