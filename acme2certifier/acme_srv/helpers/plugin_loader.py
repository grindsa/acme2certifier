# -*- coding: utf-8 -*-
"""Plugin loading utilities for acme2certifier"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
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
    logger.debug(
        "Helper._load_from_file() start module_name=%s file_path=%s",
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
            "Helper._load_from_file() ended ok file=%s resolved=%s",
            getattr(loaded, "__file__", None),
            getattr(loaded, "__name__", None),
        )
        return loaded
    except Exception as err_:
        logger.critical("%s failed with err: %s", error_prefix, err_)
        logger.debug("Helper._load_from_file() ended with failure")
        return None


def _load_from_module(
    logger: logging.Logger,
    module_path: str,
    error_prefix: str,
) -> Optional[Any]:
    """Load a handler module by dotted import path."""
    logger.debug("Helper._load_from_module() start module_path=%s", module_path)
    try:
        loaded = importlib.import_module(module_path)
        logger.debug(
            "Helper._load_from_module() ended ok file=%s",
            getattr(loaded, "__file__", None),
        )
        return loaded
    except Exception as err_:
        logger.critical("%s failed with err: %s", error_prefix, err_)
        logger.debug("Helper._load_from_module() ended with failure")
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
    logger.debug("Helper.ca_handler_load() start")

    if "CAhandler" not in config_dic:
        logger.info("Helper.ca_handler_load(): CAhandler section missing")
        logger.error("CAhandler configuration missing in config file")
        logger.debug("Helper.ca_handler_load() ended with None")
        return None

    logger.info("Helper.ca_handler_load(): CAhandler section found")
    section = config_dic["CAhandler"]
    handler_module = _section_option(section, "handler_module")
    handler_file = _section_option(section, "handler_file")
    logger.info(
        "Helper.ca_handler_load(): handler_module=%r handler_file=%r",
        handler_module,
        handler_file,
    )

    if handler_module and handler_file:
        logger.info(
            "Helper.ca_handler_load(): both handler_module and handler_file set; "
            "preferring handler_module"
        )
        logger.warning(
            "Both handler_module and handler_file set; using handler_module, "
            "ignoring handler_file"
        )
    else:
        logger.info(
            "Helper.ca_handler_load(): not both keys set "
            "(module=%s file=%s)",
            bool(handler_module),
            bool(handler_file),
        )

    if handler_module:
        logger.info(
            "Helper.ca_handler_load(): loading via handler_module=%s",
            handler_module,
        )
        loaded = _load_from_module(
            logger,
            handler_module,
            "Loading CAhandler via handler_module",
        )
        if loaded is not None:
            logger.info(
                "Helper.ca_handler_load(): handler_module load succeeded (%s)",
                getattr(loaded, "__file__", loaded),
            )
            logger.debug("Helper.ca_handler_load() ended with module")
            return loaded
        logger.info(
            "Helper.ca_handler_load(): handler_module load failed; "
            "falling back to default CAhandler"
        )
    elif handler_file:
        logger.info(
            "Helper.ca_handler_load(): loading via deprecated handler_file=%s",
            handler_file,
        )
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
            logger.info(
                "Helper.ca_handler_load(): handler_file load succeeded (%s)",
                getattr(loaded, "__file__", loaded),
            )
            logger.debug("Helper.ca_handler_load() ended with module")
            return loaded
        logger.info(
            "Helper.ca_handler_load(): handler_file load failed; "
            "falling back to default CAhandler"
        )
    else:
        logger.info(
            "Helper.ca_handler_load(): neither handler_module nor handler_file "
            "set; using default CAhandler"
        )

    # if no module/file provided or loading was unsuccessful, try default handler
    logger.info("Helper.ca_handler_load(): attempting default acme_srv.ca_handler")
    try:
        loaded = importlib.import_module("acme_srv.ca_handler")
        logger.info(
            "Helper.ca_handler_load(): default CAhandler load succeeded (%s)",
            getattr(loaded, "__file__", loaded),
        )
        logger.debug("Helper.ca_handler_load() ended with default module")
        return loaded
    except Exception as err_:
        logger.info("Helper.ca_handler_load(): default CAhandler load failed")
        logger.critical("Loading default CAhandler failed with err: %s", err_)
        logger.debug("Helper.ca_handler_load() ended with None")
        return None


def eab_handler_load(
    logger: logging.Logger, config_dic: Dict
) -> importlib.import_module:
    """load and return eab_handler"""
    logger.debug("Helper.eab_handler_load() start")
    # pylint: disable=w0621
    if "EABhandler" not in config_dic:
        logger.info("Helper.eab_handler_load(): EABhandler section missing")
        logger.error("EABhandler configuration missing in config file")
        logger.debug("Helper.eab_handler_load() ended with None")
        return None

    logger.info("Helper.eab_handler_load(): EABhandler section found")
    section = config_dic["EABhandler"]
    eab_module = _section_option(section, "eab_handler_module")
    eab_file = _section_option(section, "eab_handler_file")
    logger.info(
        "Helper.eab_handler_load(): eab_handler_module=%r eab_handler_file=%r",
        eab_module,
        eab_file,
    )

    if eab_module and eab_file:
        logger.info(
            "Helper.eab_handler_load(): both eab_handler_module and "
            "eab_handler_file set; preferring eab_handler_module"
        )
        logger.warning(
            "Both eab_handler_module and eab_handler_file set; using "
            "eab_handler_module, ignoring eab_handler_file"
        )
    else:
        logger.info(
            "Helper.eab_handler_load(): not both keys set "
            "(module=%s file=%s)",
            bool(eab_module),
            bool(eab_file),
        )

    if eab_module:
        logger.info(
            "Helper.eab_handler_load(): loading via eab_handler_module=%s",
            eab_module,
        )
        loaded = _load_from_module(
            logger,
            eab_module,
            "Loading EABhandler via eab_handler_module",
        )
        if loaded is not None:
            logger.info(
                "Helper.eab_handler_load(): eab_handler_module load succeeded (%s)",
                getattr(loaded, "__file__", loaded),
            )
            logger.debug("Helper.eab_handler_load() ended with module")
            return loaded
        logger.info(
            "Helper.eab_handler_load(): eab_handler_module load failed; "
            "returning None (no default fallback)"
        )
        logger.debug("Helper.eab_handler_load() ended with None")
        return None

    if eab_file:
        logger.info(
            "Helper.eab_handler_load(): loading via deprecated eab_handler_file=%s",
            eab_file,
        )
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
            logger.info(
                "Helper.eab_handler_load(): eab_handler_file load succeeded (%s)",
                getattr(loaded, "__file__", loaded),
            )
            logger.debug("Helper.eab_handler_load() ended with module")
            return loaded
        # fall back to default on file load failure (legacy behavior)
        logger.info(
            "Helper.eab_handler_load(): eab_handler_file load failed; "
            "falling back to default acme_srv.eab_handler"
        )
        try:
            loaded = importlib.import_module("acme_srv.eab_handler")
            logger.info(
                "Helper.eab_handler_load(): default EABhandler load succeeded (%s)",
                getattr(loaded, "__file__", loaded),
            )
            logger.debug("Helper.eab_handler_load() ended with default module")
            return loaded
        except Exception as err_:
            logger.info("Helper.eab_handler_load(): default EABhandler load failed")
            logger.critical("Loading default EABhandler failed with err: %s", err_)
            logger.debug("Helper.eab_handler_load() ended with None")
            return None

    # EABhandler section present but no explicit file/module → default
    logger.info(
        "Helper.eab_handler_load(): neither eab_handler_module nor "
        "eab_handler_file set; using default acme_srv.eab_handler"
    )
    try:
        loaded = importlib.import_module("acme_srv.eab_handler")
        logger.info(
            "Helper.eab_handler_load(): default EABhandler load succeeded (%s)",
            getattr(loaded, "__file__", loaded),
        )
        logger.debug("Helper.eab_handler_load() ended with default module")
        return loaded
    except Exception as err_:
        logger.info("Helper.eab_handler_load(): default EABhandler load failed")
        logger.critical("Loading default EABhandler failed with err: %s", err_)
        logger.debug("Helper.eab_handler_load() ended with None")
        return None


def hooks_load(logger: logging.Logger, config_dic: Dict) -> importlib.import_module:
    """load and return hooks"""
    logger.debug("Helper.hooks_load() start")

    if "Hooks" not in config_dic:
        logger.info("Helper.hooks_load(): Hooks section missing; hooks disabled")
        logger.debug("Helper.hooks_load() ended with None")
        return None

    logger.info("Helper.hooks_load(): Hooks section found")
    section = config_dic["Hooks"]
    hooks_module_name = _section_option(section, "hooks_module")
    hooks_file = _section_option(section, "hooks_file")
    logger.info(
        "Helper.hooks_load(): hooks_module=%r hooks_file=%r",
        hooks_module_name,
        hooks_file,
    )

    if hooks_module_name and hooks_file:
        logger.info(
            "Helper.hooks_load(): both hooks_module and hooks_file set; "
            "preferring hooks_module"
        )
        logger.warning(
            "Both hooks_module and hooks_file set; using hooks_module, "
            "ignoring hooks_file"
        )
    else:
        logger.info(
            "Helper.hooks_load(): not both keys set (module=%s file=%s)",
            bool(hooks_module_name),
            bool(hooks_file),
        )

    if hooks_module_name:
        logger.info(
            "Helper.hooks_load(): loading via hooks_module=%s",
            hooks_module_name,
        )
        loaded = _load_from_module(
            logger,
            hooks_module_name,
            "Loading Hooks via hooks_module",
        )
        if loaded is not None:
            logger.info(
                "Helper.hooks_load(): hooks_module load succeeded (%s)",
                getattr(loaded, "__file__", loaded),
            )
        else:
            logger.info("Helper.hooks_load(): hooks_module load failed")
        logger.debug(
            "Helper.hooks_load() ended with %s",
            "module" if loaded is not None else "None",
        )
        return loaded

    if hooks_file:
        logger.info(
            "Helper.hooks_load(): loading via deprecated hooks_file=%s",
            hooks_file,
        )
        _warn_file_deprecated(
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
            logger.info(
                "Helper.hooks_load(): hooks_file load succeeded (%s)",
                getattr(loaded, "__file__", loaded),
            )
        else:
            logger.info("Helper.hooks_load(): hooks_file load failed")
        logger.debug(
            "Helper.hooks_load() ended with %s",
            "module" if loaded is not None else "None",
        )
        return loaded

    logger.info(
        "Helper.hooks_load(): neither hooks_module nor hooks_file set; "
        "hooks disabled"
    )
    logger.debug("Helper.hooks_load() ended with None")
    return None
