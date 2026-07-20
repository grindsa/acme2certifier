# -*- coding: utf-8 -*-
"""Selectable DB handler loader.

Resolves the active database backend and re-exports ``DBstore`` / ``initialize``
so callers can keep importing ``acme2certifier.acme_srv.db_handler``.

Precedence (cfg wins over env, matching CAhandler password loading):

1. ``[DBhandler] handler_module`` or ``handler`` in ``acme_srv.cfg``
2. ``ACME_SRV_DB_HANDLER`` environment variable
3. default ``wsgi``
"""

from __future__ import annotations

import importlib
import logging
import os
from typing import Any, Dict, Mapping, Optional, Union

_LOGGER = logging.getLogger("acme2certifier.db_handler")

_ENV_NAME = "ACME_SRV_DB_HANDLER"
_DEFAULT_HANDLER = "wsgi"

_SHORT_NAMES: Dict[str, str] = {
    "wsgi": "acme2certifier.dbhandlers.wsgi_handler",
    "django": "acme2certifier.dbhandlers.django_handler",
}

ConfigLike = Union[Mapping[str, Any], Any]


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


def resolve_db_handler_module(config_dic: Optional[ConfigLike] = None) -> str:
    """Resolve dotted module path for the active DB handler.

    Args:
        config_dic: Optional config mapping/parser. When omitted, ``load_config()``
            is used. Pass an explicit dict in tests to avoid filesystem config.
    """
    cfg_value = _cfg_handler_name(config_dic)
    if cfg_value:
        module_path = _normalize_handler(cfg_value)
        _LOGGER.info("DB handler from acme_srv.cfg: %s", module_path)
        return module_path

    # Only consult env when no explicit config_dic was supplied for testing, or
    # when that config had no handler selection.
    env_value = os.environ.get(_ENV_NAME, "").strip()
    if env_value:
        module_path = _normalize_handler(env_value)
        _LOGGER.info("DB handler from %s: %s", _ENV_NAME, module_path)
        return module_path

    module_path = _SHORT_NAMES[_DEFAULT_HANDLER]
    _LOGGER.info("DB handler default: %s", module_path)
    return module_path


def load_db_handler_module(config_dic: Optional[ConfigLike] = None) -> Any:
    """Import and return the configured DB handler module."""
    module_path = resolve_db_handler_module(config_dic)
    try:
        loaded = importlib.import_module(module_path)
    except Exception as err:
        _LOGGER.critical("Loading DB handler %s failed: %s", module_path, err)
        raise
    _LOGGER.info(
        "Loaded DB handler %s (%s)",
        getattr(loaded, "__name__", module_path),
        getattr(loaded, "__file__", None),
    )
    return loaded


_handler_module = load_db_handler_module()

DBstore = _handler_module.DBstore
initialize = getattr(_handler_module, "initialize", lambda: None)

# Optional helpers some backends expose (WSGI).
dict_from_row = getattr(_handler_module, "dict_from_row", None)
