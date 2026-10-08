# -*- coding: utf-8 -*-
"""Selectable DB handler loader.

Resolves the active database backend and re-exports ``DBstore`` / ``initialize``
so callers can keep importing ``acme2certifier.acme_srv.db_handler``.

Precedence (cfg wins over env, matching CAhandler password loading):

1. ``[DBhandler] handler_module`` or ``handler`` in ``acme_srv.cfg``
2. ``ACME_SRV_DB_HANDLER`` environment variable
3. default ``wsgi``

Resolution logic lives in ``acme_srv.helpers.db_handler_select``.
"""

import importlib
import logging
from typing import Any, Optional

from acme2certifier.acme_srv.helpers.db_handler_select import (
    ConfigLike,
    MODULE_TO_SHORT,
    resolve_db_handler,
    warn_dbhandler_cfg_missing,
)

_LOGGER = logging.getLogger("acme2certifier.db_handler")


def load_db_handler_module(config_dic: Optional[ConfigLike] = None) -> Any:
    """Import and return the configured DB handler module."""
    _LOGGER.debug("Loading DB handler module from config: %s", config_dic)
    module_path, source = resolve_db_handler(config_dic)
    try:
        loaded = importlib.import_module(module_path)
    except Exception as err:
        _LOGGER.critical("Loading DB handler %s failed: %s", module_path, err)
        raise
    short = MODULE_TO_SHORT.get(module_path, module_path)
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
    return MODULE_TO_SHORT.get(module_name, module_name or "unknown")


def log_active_db_handler(
    logger: logging.Logger, config_dic: Optional[ConfigLike] = None
) -> None:
    """Log which DB handler is active (call after ``logger_setup``)."""
    warn_dbhandler_cfg_missing(logger, config_dic)
    module_name = getattr(_handler_module, "__name__", "unknown")
    module_file = getattr(_handler_module, "__file__", None)
    short = MODULE_TO_SHORT.get(module_name, module_name)
    logger.info(
        "Using DB handler '%s' (%s) selected via %s%s",
        short,
        module_name,
        _handler_source,
        f" from {module_file}" if module_file else "",
    )


_handler_module_path, _handler_source = resolve_db_handler()
_handler_module = importlib.import_module(_handler_module_path)

DBstore = _handler_module.DBstore
initialize = getattr(_handler_module, "initialize", lambda: None)
