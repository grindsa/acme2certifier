# -*- coding: utf-8 -*-
"""Logging utilities for acme2certifier"""

import logging
import sys
import copy
from typing import Dict
import datetime
from .config import load_config


def _logger_nonce_modify(data_dic: Dict[str, str]) -> Dict[str, str]:
    """remove nonce from log entry"""
    if "header" in data_dic and "Replay-Nonce" in data_dic["header"]:
        data_dic["header"]["Replay-Nonce"] = "- modified -"
    return data_dic


def _logger_certificate_modify(
    data_dic: Dict[str, str], locator: str
) -> Dict[str, str]:
    """remove cert from log entry"""
    if "/acme/cert" in locator:
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
            if not _log_cert_content_enabled():
                # PEM string bodies (cert download) must be redacted too — not only dicts
                data_dic = _logger_certificate_modify(data_dic, locator)
            if isinstance(data_dic.get("data"), dict):
                data_dic = _logger_token_modify(data_dic)
                data_dic = _logger_challenges_modify(data_dic)
    return data_dic


def log_response(
    logger: logging.Logger, addr: str, locator: str, dat_dic: Dict[str, str]
):
    """log responses"""
    # create a copy of the dictionary
    data_dic = copy.deepcopy(dat_dic)

    data_dic = _logger_nonce_modify(data_dic)
    if "data" in data_dic:
        # remove cert from log entry
        data_dic = _logger_certificate_modify(data_dic, locator)

        # remove token
        data_dic = _logger_token_modify(data_dic)

        # remove token from challenge
        data_dic = _logger_challenges_modify(data_dic)

    logger.info("%s %s %s", addr, locator, str(data_dic))


def logger_setup(debug: bool) -> logging.Logger:
    """setup logger"""
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
