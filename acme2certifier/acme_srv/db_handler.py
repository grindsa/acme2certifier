# -*- coding: utf-8 -*-
"""Selectable DB handler loader.

Resolves the active database backend and re-exports ``DBstore`` / ``initialize``
so callers can keep importing ``acme2certifier.acme_srv.db_handler``.

Precedence (cfg wins over env, matching CAhandler password loading):

1. ``[DBhandler] handler_module`` or ``handler`` in ``acme_srv.cfg``
2. ``ACME_SRV_DB_HANDLER`` environment variable
3. default ``wsgi``
"""

import importlib
import logging
import os
from typing import Any, Dict, Mapping, Optional, Tuple, Union

_LOGGER = logging.getLogger("acme2certifier.db_handler")

_ENV_NAME = "ACME_SRV_DB_HANDLER"
_DEFAULT_HANDLER = "wsgi"

_SHORT_NAMES: Dict[str, str] = {
    "wsgi": "acme2certifier.dbhandlers.wsgi_handler",
    "django": "acme2certifier.dbhandlers.django_handler",
}

_MODULE_TO_SHORT = {module: name for name, module in _SHORT_NAMES.items()}

ConfigLike = Union[Mapping[str, Any], Any]

# Emit [DBhandler] handler missing/invalid warning at most once per process.
_DBHANDLER_CFG_WARNED = False


def _env_selection_hint() -> str:
    """Suffix for warnings when handler falls back to env or default."""
    env_value = os.environ.get(_ENV_NAME, "").strip()
    if env_value:
        return f" (currently selected via {_ENV_NAME}={env_value})"
    return " (default: wsgi)"


def _normalize_handler(value: str) -> str:
    """Map short names to dotted modules; pass through other module paths."""
    key = value.strip()
    if not key:
        return _SHORT_NAMES[_DEFAULT_HANDLER]
    short = key.lower()
    if short in _SHORT_NAMES:
        return _SHORT_NAMES[short]
    return key


def _section_get(section: Any, key: str) -> str:
    """Read an option from a ConfigParser section or mapping."""
    if key not in section:
        return ""
    value = section.get(key) if hasattr(section, "get") else section[key]
    return (value or "").strip()


def _cfg_handler_name(config_dic: Optional[ConfigLike] = None) -> Optional[str]:
    """Return handler selection from config, if any."""
    if config_dic is None:
        try:
            from acme2certifier.acme_srv.helpers.config import (  # pylint: disable=c0415
                load_config,
            )

            config_dic = load_config()
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.debug("DB handler cfg lookup failed: %s", err)
            return None

    if "DBhandler" not in config_dic:
        return None

    section = config_dic["DBhandler"]
    handler_module = _section_get(section, "handler_module")
    handler = _section_get(section, "handler")

    if handler_module and handler:
        _LOGGER.info(
            "Both handler_module and handler set; using handler_module, "
            "ignoring handler"
        )

    if handler_module:
        return handler_module
    if handler:
        return handler
    return None


def _resolve_db_handler(
    config_dic: Optional[ConfigLike] = None,
) -> Tuple[str, str]:
    """Resolve ``(module_path, source)`` with ``source`` in cfg|env|default."""
    cfg_value = _cfg_handler_name(config_dic)
    if cfg_value:
        return _normalize_handler(cfg_value), "cfg"

    env_value = os.environ.get(_ENV_NAME, "").strip()
    if env_value:
        return _normalize_handler(env_value), "env"

    return _SHORT_NAMES[_DEFAULT_HANDLER], "default"


def resolve_db_handler_module(config_dic: Optional[ConfigLike] = None) -> str:
    """Resolve dotted module path for the active DB handler."""
    module_path, _source = _resolve_db_handler(config_dic)
    return module_path


def load_db_handler_module(config_dic: Optional[ConfigLike] = None) -> Any:
    """Import and return the configured DB handler module."""
    module_path, source = _resolve_db_handler(config_dic)
    try:
        loaded = importlib.import_module(module_path)
    except Exception as err:
        _LOGGER.critical("Loading DB handler %s failed: %s", module_path, err)
        raise
    short = _MODULE_TO_SHORT.get(module_path, module_path)
    _LOGGER.debug(
        "Loaded DB handler %s (%s) via %s from %s",
        short,
        module_path,
        source,
        getattr(loaded, "__file__", None),
    )
    return loaded


def active_db_handler_label() -> str:
    """Human-readable label for the loaded DB handler (e.g. ``wsgi``)."""
    module_name = getattr(_handler_module, "__name__", "")
    return _MODULE_TO_SHORT.get(module_name, module_name or "unknown")


def warn_dbhandler_cfg_missing(
    logger: logging.Logger, config_dic: Optional[ConfigLike] = None
) -> None:
    """Warn when ``[DBhandler] handler`` is unset or not ``wsgi``/``django``.

    ``handler_module`` alone suppresses the warning. Called once per process.
    """
    global _DBHANDLER_CFG_WARNED  # pylint: disable=global-statement

    if _DBHANDLER_CFG_WARNED or config_dic is None:
        return

    if "DBhandler" not in config_dic:
        _DBHANDLER_CFG_WARNED = True
        logger.warning(
            "[DBhandler] section missing in acme_srv.cfg; "
            "set handler: wsgi or handler: django%s",
            _env_selection_hint(),
        )
        return

    section = config_dic["DBhandler"]
    handler_module = _section_get(section, "handler_module")
    if handler_module:
        return

    handler = _section_get(section, "handler")
    if handler:
        if handler.lower() in _SHORT_NAMES:
            return
        _DBHANDLER_CFG_WARNED = True
        logger.warning(
            "[DBhandler] handler=%r is not wsgi or django",
            handler,
        )
        return

    _DBHANDLER_CFG_WARNED = True
    logger.warning(
        "[DBhandler] handler not set in acme_srv.cfg; "
        "set handler: wsgi or handler: django%s",
        _env_selection_hint(),
    )


def log_active_db_handler(
    logger: logging.Logger, config_dic: Optional[ConfigLike] = None
) -> None:
    """Log which DB handler is active (call after ``logger_setup``)."""
    warn_dbhandler_cfg_missing(logger, config_dic)
    module_name = getattr(_handler_module, "__name__", "unknown")
    module_file = getattr(_handler_module, "__file__", None)
    short = _MODULE_TO_SHORT.get(module_name, module_name)
    logger.info(
        "Using DB handler '%s' (%s) selected via %s%s",
        short,
        module_name,
        _handler_source,
        f" from {module_file}" if module_file else "",
    )


_handler_module_path, _handler_source = _resolve_db_handler()
_handler_module = importlib.import_module(_handler_module_path)

DBstore = _handler_module.DBstore
initialize = getattr(_handler_module, "initialize", lambda: None)

# Optional helpers some backends expose (WSGI).
dict_from_row = getattr(_handler_module, "dict_from_row", None)
