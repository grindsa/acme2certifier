# -*- coding: utf-8 -*-
"""Plugin loading utilities for acme2certifier"""

import importlib
import importlib.util
import logging
import os
import sys
from typing import Any, Dict, Optional, Set

from acme2certifier.compat import (
    warn_default_ca_handler,
    warn_file_config_deprecated,
)

# Emit routine handler-load INFO at most once per key per process.
_HANDLER_LOAD_LOGGED: Set[str] = set()
_EAB_HANDLER_LOAD_ENDED_NONE = (
    "Helper.plugin_loader.eab_handler_load() ended with None"
)


def _log_once_info(
    logger: logging.Logger, key: str, msg: str, *args: Any
) -> None:
    """Log *msg* at INFO once per *key*; subsequent calls use DEBUG."""
    if key not in _HANDLER_LOAD_LOGGED:
        _HANDLER_LOAD_LOGGED.add(key)
        logger.info(msg, *args)
    else:
        logger.debug(msg, *args)


def _is_filesystem_path(value: str) -> bool:
    """True if *value* is a filesystem path rather than a dotted module name.

    Path form is preferred for out-of-tree customer handlers (no packaging,
    no ``PYTHONPATH`` / ``__init__.py``). Detection: absolute path, ``.py``
    suffix, or path separator.
    """
    if not value:
        return False
    if os.path.isabs(value):
        return True
    if value.endswith(".py"):
        return True
    if os.sep in value or (os.altsep and os.altsep in value) or "/" in value:
        return True
    return False


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
        if spec is None or spec.loader is None:
            raise ImportError(
                f"Cannot load module {module_name!r} from {file_path!r}"
            )
        module = importlib.util.module_from_spec(spec)
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


def _load_plugin_ref(
    logger: logging.Logger,
    ref: str,
    *,
    sys_module_name: str,
    error_prefix: str,
) -> Optional[Any]:
    """Load a plugin from a dotted module name or a filesystem path."""
    if _is_filesystem_path(ref):
        logger.debug("Loading plugin from filesystem path=%s", ref)
        return _load_from_file(logger, sys_module_name, ref, error_prefix)
    logger.debug("Loading plugin via import_module=%s", ref)
    return _load_from_module(logger, ref, error_prefix)


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
    logger.debug(
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
        logger.debug("Loading CA handler via handler_module=%s", handler_module)
        loaded = _load_plugin_ref(
            logger,
            handler_module,
            sys_module_name="CAhandler",
            error_prefix="Loading CAhandler via handler_module",
        )
        if loaded is not None:
            _log_once_info(
                logger, "ca_handler", "Loaded CA handler %s", _loaded_identity(loaded)
            )
            return loaded
        logger.warning(
            "CA handler_module load failed; falling back to default CAhandler"
        )
    elif handler_file:
        warn_file_config_deprecated(
            logger,
            "handler_file",
            "handler_module",
            "acme2certifier.cahandlers.openssl_ca_handler or /path/to/handler.py",
        )
        loaded = _load_from_file(
            logger,
            "CAhandler",
            handler_file,
            "Loading CAhandler configured in cfg",
        )
        if loaded is not None:
            _log_once_info(
                logger, "ca_handler", "Loaded CA handler %s", _loaded_identity(loaded)
            )
            return loaded
        logger.warning("CA handler_file load failed; falling back to default CAhandler")
    else:
        logger.debug(
            "Neither handler_module nor handler_file set; using default CAhandler"
        )

    logger.debug("Attempting default CA handler acme_srv.ca_handler")
    warn_default_ca_handler(logger)
    try:
        loaded = importlib.import_module("acme_srv.ca_handler")
        _log_once_info(
            logger,
            "ca_handler",
            "Loaded default CA handler %s",
            _loaded_identity(loaded),
        )
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
        logger.debug(_EAB_HANDLER_LOAD_ENDED_NONE)
        return None

    section = config_dic["EABhandler"]
    eab_module = _section_option(section, "eab_handler_module")
    eab_file = _section_option(section, "eab_handler_file")
    logger.debug(
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
        logger.debug("Loading EAB handler via eab_handler_module=%s", eab_module)
        loaded = _load_plugin_ref(
            logger,
            eab_module,
            sys_module_name="EABhandler",
            error_prefix="Loading EABhandler via eab_handler_module",
        )
        if loaded is not None:
            _log_once_info(
                logger, "eab_handler", "Loaded EAB handler %s", _loaded_identity(loaded)
            )
            return loaded
        logger.debug(_EAB_HANDLER_LOAD_ENDED_NONE)
        return None

    if eab_file:
        warn_file_config_deprecated(
            logger,
            "eab_handler_file",
            "eab_handler_module",
            "acme2certifier.eabhandlers.file_handler or /path/to/eab_handler.py",
        )
        loaded = _load_from_file(
            logger,
            "EABhandler",
            eab_file,
            "Loading EABhandler configured in cfg",
        )
        if loaded is not None:
            _log_once_info(
                logger, "eab_handler", "Loaded EAB handler %s", _loaded_identity(loaded)
            )
            return loaded
        logger.warning("EAB handler_file load failed")
        return None

    logger.warning(
        "EABhandler section present but neither eab_handler_module nor "
        "eab_handler_file is set"
    )
    logger.debug(_EAB_HANDLER_LOAD_ENDED_NONE)
    return None


def db_handler_load(
    logger: logging.Logger, config_dic: Optional[Dict] = None
) -> importlib.import_module:
    """Load and return the configured DB handler module.

    Precedence matches password loading elsewhere (cfg over env):

    1. ``[DBhandler] handler_module`` / ``handler`` in config
    2. ``ACME_SRV_DB_HANDLER``
    3. default ``wsgi``

    ``config_dic`` is accepted for API symmetry with other loaders; selection is
    performed by ``acme2certifier.acme_srv.db_handler``.
    """
    logger.debug("Helper.plugin_loader.db_handler_load() start")
    from acme2certifier.acme_srv.db_handler import (  # pylint: disable=c0415
        load_db_handler_module,
    )

    _ = config_dic
    loaded = load_db_handler_module()
    _log_once_info(
        logger, "db_handler", "Loaded DB handler %s", _loaded_identity(loaded)
    )
    logger.debug("Helper.plugin_loader.db_handler_load() ended")
    return loaded


def hooks_load(logger: logging.Logger, config_dic: Dict) -> importlib.import_module:
    """load and return hooks"""
    logger.debug("Helper.plugin_loader.hooks_load() start")

    if "Hooks" not in config_dic:
        logger.debug("Helper.plugin_loader.hooks_load() ended with None")
        return None

    section = config_dic["Hooks"]
    hooks_module_name = _section_option(section, "hooks_module")
    hooks_file = _section_option(section, "hooks_file")
    logger.debug(
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
        logger.debug("Loading hooks via hooks_module=%s", hooks_module_name)
        loaded = _load_plugin_ref(
            logger,
            hooks_module_name,
            sys_module_name="Hooks",
            error_prefix="Loading Hooks via hooks_module",
        )
        if loaded is not None:
            _log_once_info(
                logger, "hooks", "Loaded hooks %s", _loaded_identity(loaded)
            )
            return loaded
        logger.warning("Hooks module load failed")
        return None

    if hooks_file:
        warn_file_config_deprecated(
            logger,
            "hooks_file",
            "hooks_module",
            "acme2certifier.hookhandlers.skeleton_hooks or /path/to/hooks.py",
        )
        loaded = _load_from_file(
            logger,
            "Hooks",
            hooks_file,
            "Loading Hooks configured in cfg",
        )
        if loaded is not None:
            _log_once_info(
                logger, "hooks", "Loaded hooks %s", _loaded_identity(loaded)
            )
            logger.debug("Helper.plugin_loader.hooks_load() ended with module")
            return loaded
        logger.warning("Hooks file load failed")
        return None

    logger.debug("Neither hooks_module nor hooks_file set; hooks disabled")
    logger.debug("Helper.plugin_loader.hooks_load() ended with None")
    return None
