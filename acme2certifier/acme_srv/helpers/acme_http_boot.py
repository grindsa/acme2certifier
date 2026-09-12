# -*- coding: utf-8 -*-
"""Shared ACME HTTP adapter bootstrap for Django views and the WSGI app."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from acme2certifier.acme_srv import helper as helper_mod
from acme2certifier.acme_srv import housekeeping as housekeeping_mod
from acme2certifier.acme_srv import trigger as trigger_mod
from acme2certifier.acme_srv import db_handler as db_handler_mod
from acme2certifier.acme_srv.version import __dbversion__, __version__

CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_PROBLEM_JSON = "application/problem+json"


def acme_response_content_type(status_code: Optional[Any] = None) -> str:
    """JSON content type for success; RFC 7807 problem+json for ACME errors."""
    if status_code is not None:
        try:
            if int(status_code) > 201:
                return CONTENT_TYPE_PROBLEM_JSON
        except (TypeError, ValueError):
            pass
    return CONTENT_TYPE_JSON


@dataclass
class AcmeHttpStack:
    """Runtime objects shared by Django and WSGI ACME HTTP adapters."""

    config: Any
    debug: bool
    logger: Any
    legacy_acme_get: bool
    trigger_endpoint_enabled: bool
    housekeeping_cli_enabled: bool


def boot_acme_http_stack(*, log_startup_version: bool = False) -> AcmeHttpStack:
    """Load config, logging, validations, and housekeeping for an HTTP adapter."""
    helper_mod.apply_log_levels(False)
    config = helper_mod.load_config()
    debug = helper_mod.config_debug_get(config)
    logger = helper_mod.logger_setup(debug)
    if log_startup_version:
        logger.info("starting acme2certifier version %s", __version__)
    helper_mod.log_loaded_acme_srv_cfg(logger)
    db_handler_mod.log_active_db_handler(logger, config)
    helper_mod.config_check(logger, config)
    helper_mod.server_name_configuration_validate(logger, config)
    helper_mod.tnauthlist_configuration_validate(logger, config)
    helper_mod.challenge_type_configuration_validate(logger, config)
    legacy_acme_get = helper_mod.legacy_acme_get_load(logger, config)
    trigger_endpoint_enabled = trigger_mod.resolve_trigger_endpoint(
        logger, config, log_status=True
    )
    housekeeping_cli_enabled = housekeeping_mod.resolve_housekeeping_cli_endpoint(
        logger, config, log_status=True
    )
    with housekeeping_mod.Housekeeping(
        debug, logger, config_dic=config
    ) as housekeeping:
        housekeeping.dbversion_check(__dbversion__)
        housekeeping.nonce_cleanup()
    return AcmeHttpStack(
        config=config,
        debug=debug,
        logger=logger,
        legacy_acme_get=legacy_acme_get,
        trigger_endpoint_enabled=trigger_endpoint_enabled,
        housekeeping_cli_enabled=housekeeping_cli_enabled,
    )
