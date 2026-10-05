# -*- coding: utf-8 -*-
"""Pure DB handler resolution (no backend import).

Precedence matches ``acme_srv.db_handler`` / Docker ``resolve_db_handler.sh``:

1. ``[DBhandler] handler_module`` or ``handler`` in ``acme_srv.cfg``
2. ``ACME_SRV_DB_HANDLER`` environment variable
3. default ``wsgi``
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Mapping, Optional, Tuple, Union

_LOGGER = logging.getLogger("acme2certifier.db_handler_select")

ENV_NAME = "ACME_SRV_DB_HANDLER"
DEFAULT_HANDLER = "wsgi"

SHORT_NAMES: Dict[str, str] = {
    "wsgi": "acme2certifier.dbhandlers.wsgi_handler",
    "django": "acme2certifier.dbhandlers.django_handler",
}

MODULE_TO_SHORT = {module: name for name, module in SHORT_NAMES.items()}

ConfigLike = Union[Mapping[str, Any], Any]

# Emit [DBhandler] handler missing/invalid warning at most once per process.
_DBHANDLER_CFG_WARNED = False


def _env_selection_hint() -> str:
    """Suffix for warnings when handler falls back to env or default."""
    env_value = os.environ.get(ENV_NAME, "").strip()
    if env_value:
        return f" (currently selected via {ENV_NAME}={env_value})"
    return " (default: wsgi)"


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


def _normalize_handler(value: str) -> str:
    """Map short names to dotted modules; pass through other module paths."""
    key = value.strip()
    if not key:
        return SHORT_NAMES[DEFAULT_HANDLER]
    short = key.lower()
    if short in SHORT_NAMES:
        return SHORT_NAMES[short]
    return key


def resolve_db_handler(
    config_dic: Optional[ConfigLike] = None,
) -> Tuple[str, str]:
    """Resolve ``(module_path, source)`` with ``source`` in cfg|env|default."""
    cfg_value = _cfg_handler_name(config_dic)
    if cfg_value:
        return _normalize_handler(cfg_value), "cfg"

    env_value = os.environ.get(ENV_NAME, "").strip()
    if env_value:
        return _normalize_handler(env_value), "env"

    return SHORT_NAMES[DEFAULT_HANDLER], "default"


def resolve_db_handler_module(config_dic: Optional[ConfigLike] = None) -> str:
    """Resolve dotted module path for the active DB handler."""
    module_path, _source = resolve_db_handler(config_dic)
    return module_path


def resolve_db_handler_short(config_dic: Optional[ConfigLike] = None) -> str:
    """Resolve ``wsgi`` or ``django`` for schema/bootstrap tools.

    Unknown / custom module paths map to ``wsgi`` (Docker entrypoint default).
    """
    module_path = resolve_db_handler_module(config_dic)
    return MODULE_TO_SHORT.get(module_path, DEFAULT_HANDLER)


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
        if handler.lower() in SHORT_NAMES:
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
