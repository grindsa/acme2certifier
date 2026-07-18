# -*- coding: utf-8 -*-
"""Plugin loading utilities for acme2certifier"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import warnings
from typing import Any, Dict, Optional


def _warn_file_deprecated(
    logger: logging.Logger,
    file_key: str,
    module_key: str,
    example_module: str,
) -> None:
    """Emit structured deprecation warnings for file-based handler loading."""
    message = (
        f"{file_key} is deprecated; use {module_key} "
        f"(e.g. {example_module})"
    )
    warnings.warn(message, DeprecationWarning, stacklevel=3)
    logger.warning(message)


def _load_from_file(
    logger: logging.Logger,
    module_name: str,
    file_path: str,
    error_prefix: str,
) -> Optional[Any]:
    """Load a handler module from a filesystem path."""
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    except Exception as err_:
        logger.critical("%s failed with err: %s", error_prefix, err_)
        return None


def _load_from_module(
    logger: logging.Logger,
    module_path: str,
    error_prefix: str,
) -> Optional[Any]:
    """Load a handler module by dotted import path."""
    try:
        return importlib.import_module(module_path)
    except Exception as err_:
        logger.critical("%s failed with err: %s", error_prefix, err_)
        return None


def _section_option(section: Any, key: str) -> Optional[str]:
    """Return option value if present (ConfigParser- and dict-safe)."""
    if key in section:
        return section[key]
    return None


def ca_handler_load(
    logger: logging.Logger, config_dic: Dict
) -> importlib.import_module:
    """load and return ca_handler"""
    logger.debug("Helper.ca_handler_load()")

    if "CAhandler" not in config_dic:
        logger.error("CAhandler configuration missing in config file")
        return None

    section = config_dic["CAhandler"]
    handler_module = _section_option(section, "handler_module")
    handler_file = _section_option(section, "handler_file")

    if handler_module and handler_file:
        logger.warning(
            "Both handler_module and handler_file set; using handler_module, "
            "ignoring handler_file"
        )

    if handler_module:
        loaded = _load_from_module(
            logger,
            handler_module,
            "Loading CAhandler via handler_module",
        )
        if loaded is not None:
            return loaded
    elif handler_file:
        _warn_file_deprecated(
            logger,
            "handler_file",
            "handler_module",
            "acme2certifier.cahandlers.openssl_ca_handler",
        )
        loaded = _load_from_file(
            logger,
            "CAhandler",
            handler_file,
            "Loading CAhandler configured in cfg",
        )
        if loaded is not None:
            return loaded

    # if no module/file provided or loading was unsuccessful, try default handler
    try:
        return importlib.import_module("acme_srv.ca_handler")
    except Exception as err_:
        logger.critical("Loading default CAhandler failed with err: %s", err_)
        return None


def eab_handler_load(
    logger: logging.Logger, config_dic: Dict
) -> importlib.import_module:
    """load and return eab_handler"""
    logger.debug("Helper.eab_handler_load()")
    # pylint: disable=w0621
    if "EABhandler" not in config_dic:
        logger.error("EABhandler configuration missing in config file")
        return None

    section = config_dic["EABhandler"]
    eab_module = _section_option(section, "eab_handler_module")
    eab_file = _section_option(section, "eab_handler_file")

    if eab_module and eab_file:
        logger.warning(
            "Both eab_handler_module and eab_handler_file set; using "
            "eab_handler_module, ignoring eab_handler_file"
        )

    if eab_module:
        loaded = _load_from_module(
            logger,
            eab_module,
            "Loading EABhandler via eab_handler_module",
        )
        if loaded is not None:
            return loaded
        return None

    if eab_file:
        _warn_file_deprecated(
            logger,
            "eab_handler_file",
            "eab_handler_module",
            "acme2certifier.eabhandlers.file_handler",
        )
        loaded = _load_from_file(
            logger,
            "EABhandler",
            eab_file,
            "Loading EABhandler configured in cfg",
        )
        if loaded is not None:
            return loaded
        # fall back to default on file load failure (legacy behavior)
        try:
            return importlib.import_module("acme_srv.eab_handler")
        except Exception as err_:
            logger.critical("Loading default EABhandler failed with err: %s", err_)
            return None

    # EABhandler section present but no explicit file/module → default
    try:
        return importlib.import_module("acme_srv.eab_handler")
    except Exception as err_:
        logger.critical("Loading default EABhandler failed with err: %s", err_)
        return None


def hooks_load(logger: logging.Logger, config_dic: Dict) -> importlib.import_module:
    """load and return hooks"""
    logger.debug("Helper.hooks_load()")

    if "Hooks" not in config_dic:
        return None

    section = config_dic["Hooks"]
    hooks_module_name = _section_option(section, "hooks_module")
    hooks_file = _section_option(section, "hooks_file")

    if hooks_module_name and hooks_file:
        logger.warning(
            "Both hooks_module and hooks_file set; using hooks_module, "
            "ignoring hooks_file"
        )

    if hooks_module_name:
        return _load_from_module(
            logger,
            hooks_module_name,
            "Loading Hooks via hooks_module",
        )

    if hooks_file:
        _warn_file_deprecated(
            logger,
            "hooks_file",
            "hooks_module",
            "acme2certifier.hookhandlers.skeleton_hooks",
        )
        return _load_from_file(
            logger,
            "Hooks",
            hooks_file,
            "Loading Hooks configured in cfg",
        )

    return None
