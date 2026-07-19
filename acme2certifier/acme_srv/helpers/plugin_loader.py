# -*- coding: utf-8 -*-
"""Plugin loading utilities for acme2certifier"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from typing import Any, Dict, Optional

from acme2certifier.compat import (
    warn_default_ca_handler,
    warn_file_config_deprecated,
)


def _load_from_file(
    logger: logging.Logger,
    module_name: str,
    file_path: str,
    error_prefix: str,
) -> Optional[Any]:
    """Load a handler module from a filesystem path."""
    logger.debug(
        "Helper.plugin_loader._load_from_file() start module_name=%s file_path=%s",
        module_name,
        file_path,
    )
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        # Register before exec so compatibility shims can replace this entry.
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        # Shims at legacy paths may replace sys.modules[module_name] with the
        # real implementation; return that object so callers see CAhandler/etc.
        loaded = sys.modules.get(module_name, module)
        logger.debug(
            "Helper.plugin_loader._load_from_file() ended ok file=%s resolved=%s",
            getattr(loaded, "__file__", None),
            getattr(loaded, "__name__", None),
        )
        return loaded
    except Exception as err_:
        logger.critical("%s failed with err: %s", error_prefix, err_)
        logger.debug("Helper.plugin_loader._load_from_file() ended with failure")
        return None


def _load_from_module(
    logger: logging.Logger,
    module_path: str,
    error_prefix: str,
) -> Optional[Any]:
    """Load a handler module by dotted import path."""
    logger.debug(
        "Helper.plugin_loader._load_from_module() start module_path=%s", module_path
    )
    try:
        loaded = importlib.import_module(module_path)
        logger.debug(
            "Helper.plugin_loader._load_from_module() ended ok file=%s",
            getattr(loaded, "__file__", None),
        )
        return loaded
    except Exception as err_:
        logger.critical("%s failed with err: %s", error_prefix, err_)
        logger.debug("Helper.plugin_loader._load_from_module() ended with failure")
        return None


def _section_option(section: Any, key: str) -> Optional[str]:
    """Return option value if present (ConfigParser- and dict-safe)."""
    if key in section:
        return section[key]
    return None


def _loaded_identity(loaded: Any) -> str:
    """Short identity string for a loaded module."""
    name = getattr(loaded, "__name__", None)
    path = getattr(loaded, "__file__", None)
    if name and path:
        return f"{name} ({path})"
    return str(path or name or loaded)


def ca_handler_load(
    logger: logging.Logger, config_dic: Dict
) -> importlib.import_module:
    """load and return ca_handler"""
    logger.debug("Helper.plugin_loader.ca_handler_load() start")

    if "CAhandler" not in config_dic:
        logger.error("CAhandler configuration missing in config file")
        return None

    section = config_dic["CAhandler"]
    handler_module = _section_option(section, "handler_module")
    handler_file = _section_option(section, "handler_file")
    logger.info(
        "CA handler configuration: handler_module=%r handler_file=%r",
        handler_module,
        handler_file,
    )

    if handler_module and handler_file:
        logger.warning(
            "Both handler_module and handler_file set; using handler_module, "
            "ignoring handler_file"
        )

    if handler_module:
        logger.info("Loading CA handler via handler_module=%s", handler_module)
        loaded = _load_from_module(
            logger,
            handler_module,
            "Loading CAhandler via handler_module",
        )
        if loaded is not None:
            logger.info("Loaded CA handler %s", _loaded_identity(loaded))
            return loaded
        logger.warning(
            "CA handler_module load failed; falling back to default CAhandler"
        )
    elif handler_file:
        warn_file_config_deprecated(
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
            logger.info("Loaded CA handler %s", _loaded_identity(loaded))
            return loaded
        logger.warning("CA handler_file load failed; falling back to default CAhandler")
    else:
        logger.info(
            "Neither handler_module nor handler_file set; using default CAhandler"
        )

    logger.info("Attempting default CA handler acme_srv.ca_handler")
    warn_default_ca_handler(logger)
    try:
        loaded = importlib.import_module("acme_srv.ca_handler")
        logger.info("Loaded default CA handler %s", _loaded_identity(loaded))
        return loaded
    except Exception as err_:
        logger.critical("Loading default CAhandler failed with err: %s", err_)
        return None


def eab_handler_load(
    logger: logging.Logger, config_dic: Dict
) -> importlib.import_module:
    """load and return eab_handler"""
    logger.debug("Helper.plugin_loader.eab_handler_load() start")
    # pylint: disable=w0621
    if "EABhandler" not in config_dic:
        logger.debug("Helper.plugin_loader.eab_handler_load() ended with None")
        return None

    section = config_dic["EABhandler"]
    eab_module = _section_option(section, "eab_handler_module")
    eab_file = _section_option(section, "eab_handler_file")
    logger.info(
        "EAB handler configuration: eab_handler_module=%r eab_handler_file=%r",
        eab_module,
        eab_file,
    )

    if eab_module and eab_file:
        logger.warning(
            "Both eab_handler_module and eab_handler_file set; using "
            "eab_handler_module, ignoring eab_handler_file"
        )

    if eab_module:
        logger.info("Loading EAB handler via eab_handler_module=%s", eab_module)
        loaded = _load_from_module(
            logger,
            eab_module,
            "Loading EABhandler via eab_handler_module",
        )
        if loaded is not None:
            logger.info("Loaded EAB handler %s", _loaded_identity(loaded))
            return loaded
        logger.debug("Helper.plugin_loader.eab_handler_load() ended with None")
        return None

    if eab_file:
        warn_file_config_deprecated(
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
            logger.info("Loaded EAB handler %s", _loaded_identity(loaded))
            return loaded
        logger.warning("EAB handler_file load failed")
        return None

    logger.warning(
        "EABhandler section present but neither eab_handler_module nor "
        "eab_handler_file is set"
    )
    logger.debug("Helper.plugin_loader.eab_handler_load() ended with None")
    return None


def hooks_load(logger: logging.Logger, config_dic: Dict) -> importlib.import_module:
    """load and return hooks"""
    logger.debug("Helper.plugin_loader.hooks_load() start")

    if "Hooks" not in config_dic:
        logger.debug("Helper.plugin_loader.hooks_load() ended with None")
        return None

    section = config_dic["Hooks"]
    hooks_module_name = _section_option(section, "hooks_module")
    hooks_file = _section_option(section, "hooks_file")
    logger.info(
        "Hooks configuration: hooks_module=%r hooks_file=%r",
        hooks_module_name,
        hooks_file,
    )

    if hooks_module_name and hooks_file:
        logger.warning(
            "Both hooks_module and hooks_file set; using hooks_module, "
            "ignoring hooks_file"
        )

    if hooks_module_name:
        logger.info("Loading hooks via hooks_module=%s", hooks_module_name)
        loaded = _load_from_module(
            logger,
            hooks_module_name,
            "Loading Hooks via hooks_module",
        )
        if loaded is not None:
            logger.info("Loaded hooks %s", _loaded_identity(loaded))
            return loaded
        logger.warning("Hooks module load failed")
        return None

    if hooks_file:
        warn_file_config_deprecated(
            logger,
            "hooks_file",
            "hooks_module",
            "acme2certifier.hookhandlers.skeleton_hooks",
        )
        loaded = _load_from_file(
            logger,
            "Hooks",
            hooks_file,
            "Loading Hooks configured in cfg",
        )
        if loaded is not None:
            logger.info("Loaded hooks %s", _loaded_identity(loaded))
            logger.debug("Helper.plugin_loader.hooks_load() ended with module")
            return loaded
        logger.warning("Hooks file load failed")
        return None

    logger.info("Neither hooks_module nor hooks_file set; hooks disabled")
    logger.debug("Helper.plugin_loader.hooks_load() ended with None")
    return None
