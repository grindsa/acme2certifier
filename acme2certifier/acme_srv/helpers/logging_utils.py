# -*- coding: utf-8 -*-
"""Logging utilities for acme2certifier"""

import logging
import logging.handlers
import os
import sys
import copy
from typing import Any, Dict, Optional, Union
import datetime
from .config import load_config


def _logger_nonce_modify(data_dic: Dict[str, str]) -> Dict[str, str]:
    """remove nonce from log entry"""
    if "header" in data_dic and "Replay-Nonce" in data_dic["header"]:
        data_dic["header"]["Replay-Nonce"] = "- modified -"
    return data_dic


def _logger_certificate_modify(
    data_dic: Dict[str, Any], locator: str
) -> Dict[str, Any]:
    """Redact certificate / chain from log entry.

    Cert downloads put a PEM string (often a full chain) in ``data``.
    Match on ``/acme/cert`` path, or on PEM content for custom cert paths.
    """
    if "/acme/cert" in locator:
        data_dic["data"] = " - certificate - "
        return data_dic
    data = data_dic.get("data")
    if isinstance(data, str) and "BEGIN CERTIFICATE" in data:
        data_dic["data"] = " - certificate - "
    return data_dic


def _logger_token_modify(data_dic: Dict[str, str]) -> Dict[str, str]:
    """remove token from challenge"""
    if "token" in data_dic["data"]:
        data_dic["data"]["token"] = "- modified -"
    return data_dic


def _logger_challenges_modify(data_dic: Dict[str, str]) -> Dict[str, str]:
    """remove token from challenge"""
    if "challenges" in data_dic["data"]:
        for challenge in data_dic["data"]["challenges"]:
            if "token" in challenge:
                challenge.update(
                    (k, "- modified - ") for k, v in challenge.items() if k == "token"
                )
    return data_dic


def _response_http_code(data_dic: Any) -> Optional[int]:
    """Extract HTTP status code from an ACME response dict."""
    if not isinstance(data_dic, dict):
        return None
    code = data_dic.get("code")
    try:
        if code is not None:
            return int(code)
    except (TypeError, ValueError):
        pass
    return None


def _response_log_level(code: Optional[int]) -> int:
    """Return WARNING for 4xx, ERROR for 5xx, INFO otherwise."""
    if code is None:
        return logging.INFO
    if code >= 500:
        return logging.ERROR
    if code >= 400:
        return logging.WARNING
    return logging.INFO


def _sanitize_response_for_log(dat_dic: Any, locator: str) -> Any:
    """Deep-copy response and redact secrets for logging."""
    data_dic = copy.deepcopy(dat_dic)
    if isinstance(data_dic, dict):
        data_dic = _logger_nonce_modify(data_dic)
        if "data" in data_dic:
            # PEM string bodies (cert download) must be redacted too — not only dicts
            data_dic = _logger_certificate_modify(data_dic, locator)
            if isinstance(data_dic["data"], dict):
                data_dic = _logger_token_modify(data_dic)
                data_dic = _logger_challenges_modify(data_dic)
    return data_dic


def log_response(
    logger: logging.Logger, addr: str, locator: str, dat_dic: Dict[str, str]
) -> None:
    """Log ACME HTTP responses at the edge.

    Success: INFO with redacted response dump.
    Failures (4xx/5xx): DEBUG dump only — concise ACME problem lines are
    emitted by Message.prepare_response to avoid duplicate operator noise.
    """
    code = _response_http_code(dat_dic)
    level = _response_log_level(code)
    data_dic = _sanitize_response_for_log(dat_dic, locator)

    if level >= logging.WARNING:
        logger.debug("%s %s %s", addr, locator, str(data_dic))
    else:
        logger.info("%s %s %s", addr, locator, str(data_dic))


_SYSLOG_FACILITY_MAP = {
    name[4:].lower(): getattr(logging.handlers.SysLogHandler, name)
    for name in dir(logging.handlers.SysLogHandler)
    if name.startswith("LOG_")
}


def _syslog_facility(facility_name: str) -> int:
    """Map facility name to SysLogHandler constant."""
    return _SYSLOG_FACILITY_MAP.get(
        facility_name.lower(), logging.handlers.SysLogHandler.LOG_USER
    )


def _syslog_address(address: str) -> Union[str, tuple]:
    """Parse syslog address as Unix socket path or host:port."""
    if address.startswith("/"):
        return address
    if ":" in address:
        host, port_str = address.rsplit(":", 1)
        try:
            return (host, int(port_str))
        except ValueError:
            return address
    return address


def _attach_syslog_handler(
    logger: logging.Logger, config_dic, formatter: logging.Formatter
) -> None:
    """Attach SysLogHandler when Helper.syslog_address is set."""
    if "Helper" not in config_dic or "syslog_address" not in config_dic["Helper"]:
        return

    address_cfg = config_dic["Helper"]["syslog_address"].strip()
    if not address_cfg:
        return

    for handler in logger.handlers:
        if isinstance(handler, logging.handlers.SysLogHandler):
            return

    facility_name = "user"
    if "syslog_facility" in config_dic["Helper"]:
        facility_name = config_dic["Helper"]["syslog_facility"]

    try:
        handler = logging.handlers.SysLogHandler(
            address=_syslog_address(address_cfg),
            facility=_syslog_facility(facility_name),
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.debug(
            "SysLogHandler attached (address=%s, facility=%s)",
            address_cfg,
            facility_name,
        )
    except OSError as err:
        logger.error("Failed to attach SysLogHandler: %s", err)


def _attach_file_handler(
    logger: logging.Logger, config_dic, formatter: logging.Formatter
) -> None:
    """Attach FileHandler when Helper.log_file is set."""
    if "Helper" not in config_dic or "log_file" not in config_dic["Helper"]:
        return

    log_file = config_dic["Helper"]["log_file"].strip()
    if not log_file:
        return

    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler) and getattr(
            handler, "baseFilename", None
        ) == os.path.abspath(log_file):
            return

    try:
        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.debug("FileHandler attached (log_file=%s)", log_file)
    except OSError as err:
        logger.error("Failed to attach FileHandler for %s: %s", log_file, err)


def logger_setup(debug: bool) -> logging.Logger:
    """setup logger; optional syslog/file handlers via Helper config"""
    if debug:
        log_mode = logging.DEBUG
    else:
        log_mode = logging.INFO

    config_dic = load_config()

    # define standard log format
    log_format = "%(message)s"
    if "Helper" in config_dic and "log_format" in config_dic["Helper"]:
        log_format = config_dic["Helper"]["log_format"]

    logging.basicConfig(format=log_format, datefmt="%Y-%m-%d %H:%M:%S", level=log_mode)
    logger = logging.getLogger("acme2certifier")
    logger.setLevel(log_mode)

    formatter = logging.Formatter(fmt=log_format, datefmt="%Y-%m-%d %H:%M:%S")
    _attach_syslog_handler(logger, config_dic, formatter)
    _attach_file_handler(logger, config_dic, formatter)
    return logger


def print_debug(debug: bool, text: str):
    """little helper to print debug messages"""
    if debug:
        print(f"{datetime.datetime.now()}: {text}")


def handle_exception(exc_type, exc_value, exc_traceback):  # pragma: no cover
    """exception handler"""
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    logging.exception(
        "Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback)
    )
