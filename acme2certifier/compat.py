# -*- coding: utf-8 -*-
"""Deprecation helpers for handler config migration.

Warns when deprecated ``*_file`` keys or legacy default CA-handler loading
are used. Prefer ``handler_module`` / ``eab_handler_module`` / ``hooks_module``.
"""

from __future__ import annotations

import logging
import warnings
from typing import Optional, Set

# Target major release for removing ``*_file`` keys and default ca_handler fallback.
REMOVAL_VERSION = "1.0"

_WARNED: Set[str] = set()


def warn_once(
    key: str,
    message: str,
    *,
    logger: Optional[logging.Logger] = None,
    stacklevel: int = 2,
) -> None:
    """Emit a DeprecationWarning (and optional log) at most once per ``key``."""
    if key in _WARNED:
        return
    _WARNED.add(key)
    warnings.warn(message, DeprecationWarning, stacklevel=stacklevel)
    if logger is not None:
        logger.warning(message)


def warn_default_ca_handler(logger: logging.Logger, *, stacklevel: int = 3) -> None:
    """Warn when falling back to ``acme_srv.ca_handler``."""
    warn_once(
        "default:acme_srv.ca_handler",
        (
            "Loading default CA handler via 'acme_srv.ca_handler' is deprecated; "
            "set handler_module (e.g. acme2certifier.cahandlers.openssl_ca_handler). "
            f"This fallback will be removed in acme2certifier {REMOVAL_VERSION}."
        ),
        logger=logger,
        stacklevel=stacklevel,
    )


def warn_file_config_deprecated(
    logger: logging.Logger,
    file_key: str,
    module_key: str,
    example_module: str,
    *,
    stacklevel: int = 3,
) -> None:
    """Warn when deprecated ``*_file`` config keys are used."""
    message = (
        f"{file_key} is deprecated; use {module_key} "
        f"(e.g. {example_module}). "
        f"File-based handler loading will be removed in "
        f"acme2certifier {REMOVAL_VERSION}."
    )
    warnings.warn(message, DeprecationWarning, stacklevel=stacklevel)
    logger.warning(message)
