# -*- coding: utf-8 -*-
"""Compatibility helpers for the package-layout migration.

Runtime deprecation warnings guide users from legacy imports and config
keys toward ``acme2certifier.*`` modules. Shims and ``*_file`` keys remain
supported until the removal version documented below.
"""

from __future__ import annotations

import logging
import warnings
from typing import Optional, Set

# Target major release for removing compatibility shims and ``*_file`` keys.
REMOVAL_VERSION = "1.0"

_WARNED: Set[str] = set()

_LEGACY_HANDLER_PREFIXES = (
    ("examples.ca_handler.", "acme2certifier.cahandlers."),
    ("examples.eab_handler.", "acme2certifier.eabhandlers."),
    ("examples.hooks.", "acme2certifier.hookhandlers."),
)


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


def warn_legacy_import(legacy_name: str, preferred_name: str, stacklevel: int = 3) -> None:
    """Warn when a compatibility shim module is imported."""
    warn_once(
        f"import:{legacy_name}",
        (
            f"Importing '{legacy_name}' is deprecated; use '{preferred_name}' instead. "
            f"Compatibility shims will be removed in acme2certifier {REMOVAL_VERSION}."
        ),
        stacklevel=stacklevel,
    )


def warn_legacy_handler_module(
    logger: logging.Logger,
    module_path: str,
    *,
    stacklevel: int = 3,
) -> None:
    """Warn when ``*_module`` still points at ``examples.*`` shim paths."""
    for legacy_prefix, preferred_prefix in _LEGACY_HANDLER_PREFIXES:
        if module_path.startswith(legacy_prefix):
            preferred = preferred_prefix + module_path[len(legacy_prefix) :]
            warn_once(
                f"handler_module:{module_path}",
                (
                    f"handler module path '{module_path}' is deprecated; "
                    f"use '{preferred}' instead. "
                    f"Legacy examples.* module paths will be removed in "
                    f"acme2certifier {REMOVAL_VERSION}."
                ),
                logger=logger,
                stacklevel=stacklevel,
            )
            return


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
    """Warn when deprecated ``*_file`` config keys are used.

    Always emitted (not once-per-process): config is typically loaded at
    startup, and tests assert on the warning text.
    """
    message = (
        f"{file_key} is deprecated; use {module_key} "
        f"(e.g. {example_module}). "
        f"File-based handler loading will be removed in "
        f"acme2certifier {REMOVAL_VERSION}."
    )
    warnings.warn(message, DeprecationWarning, stacklevel=stacklevel)
    logger.warning(message)
