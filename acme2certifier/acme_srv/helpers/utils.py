# -*- coding: utf-8 -*-
"""General utilities for acme2certifier"""

import os
import secrets
import logging
from typing import Dict, List, Optional
from .global_variables import PARSING_ERR_MSG, CONFIGURATION_ERROR_DETAIL


def error_dic_get(logger: logging.Logger) -> Dict[str, str]:
    """load acme error messages"""
    logger.debug("Helper.error_dict_get()")
    # this is the main dictionary
    error_dic = {
        "accountdoesnotexist": "urn:ietf:params:acme:error:accountDoesNotExist",
        "alreadyrevoked": "urn:ietf:params:acme:error:alreadyRevoked",
        "badcsr": "urn:ietf:params:acme:error:badCSR",
        "badpubkey": "urn:ietf:params:acme:error:badPublicKey",
        "badrevocationreason": "urn:ietf:params:acme:error:badRevocationReason",
        "externalaccountrequired": "urn:ietf:params:acme:error:externalAccountRequired",
        "invalidcontact": "urn:ietf:params:acme:error:invalidContact",
        "invalidprofile": "urn:ietf:params:acme:error:invalidProfile",
        "malformed": "urn:ietf:params:acme:error:malformed",
        "ordernotready": "urn:ietf:params:acme:error:orderNotReady",
        "ratelimited": "urn:ietf:params:acme:error:rateLimited",
        "rejectedidentifier": "urn:ietf:params:acme:error:rejectedIdentifier",
        "serverinternal": "urn:ietf:params:acme:error:serverInternal",
        "unauthorized": "urn:ietf:params:acme:error:unauthorized",
        "unsupportedidentifier": "urn:ietf:params:acme:error:unsupportedIdentifier",
        "useractionrequired": "urn:ietf:params:acme:error:userActionRequired",
    }
    return error_dic


# Debian/Ubuntu kerberos alternatives install ``kinit`` as a symlink to
# ``kinit.mit`` / ``kinit.heimdal``. Allow those resolved basenames only when
# the configured path itself ends with ``kinit``.
_KRB5_KINIT_RESOLVED_BASENAMES = frozenset({"kinit", "kinit.mit", "kinit.heimdal"})


def kerberos_kinit_command_resolve(
    logger: logging.Logger, kinit_path: Optional[str]
) -> Optional[str]:
    """Resolve argv0 for a kinit subprocess.

    Default / bare ``kinit`` is resolved from PATH at exec time.
    Any other configured value must be an absolute path whose basename is
    exactly ``kinit``. After symlink resolution the basename must be one of
    ``kinit``, ``kinit.mit``, or ``kinit.heimdal`` (Debian/Ubuntu alternatives).
    """
    logger.debug("Helper.kerberos_kinit_command_resolve()")
    if not isinstance(kinit_path, str) or not kinit_path.strip():
        return "kinit"

    configured = kinit_path.strip()
    if configured == "kinit":
        return "kinit"

    if "\x00" in configured:
        logger.error("Rejected krb5_kinit_path: null byte in path")
        return None

    if not os.path.isabs(configured):
        logger.error(
            "Rejected krb5_kinit_path '%s': path must be absolute "
            "(or the bare name 'kinit' for PATH lookup)",
            configured,
        )
        return None

    if os.path.basename(configured) != "kinit":
        logger.error(
            "Rejected krb5_kinit_path '%s': basename must be 'kinit'",
            configured,
        )
        return None

    resolved = os.path.realpath(configured)
    resolved_basename = os.path.basename(resolved)
    if resolved_basename not in _KRB5_KINIT_RESOLVED_BASENAMES:
        logger.error(
            "Rejected krb5_kinit_path '%s': resolved basename must be one of "
            "%s (resolved to '%s')",
            configured,
            sorted(_KRB5_KINIT_RESOLVED_BASENAMES),
            resolved,
        )
        return None

    logger.debug("Helper.kerberos_kinit_command_resolve() ended with: %s", resolved)
    return resolved


_ENROLLMENT_CONFIG_LOG_DEFAULT_SKIPLIST = [
    "logger",
    "session",
    "password",
    "api_key",
    "api_password",
    "key",
    "secret",
    "token",
    "err_msg_dic",
    "dbstore",
    "cert_passphrase",
    "passphrase",
    "client_passphrase",
    "client_key",
    "auth",
    "vault_token",
    "eab_mac_key",
    "credential_dic",
    "headers",
]

_SECRET_NAME_FRAGMENTS = (
    "passphrase",
    "password",
    "secret",
    "credential",
    "private_key",
)


def _enrollment_key_is_sensitive(key: str, skiplist: set) -> bool:
    """Return True when an attribute name should not be logged."""
    if key.startswith("__") or key in skiplist:
        return True
    lowered = key.lower()
    return any(fragment in lowered for fragment in _SECRET_NAME_FRAGMENTS)


def enrollment_config_log(
    logger: logging.Logger, obj: object, handler_skiplist: List[str] = None
):
    """log enrollment configuration"""
    logger.debug("Helper.enrollment_config_log()")

    skiplist = set(_ENROLLMENT_CONFIG_LOG_DEFAULT_SKIPLIST)

    if handler_skiplist and isinstance(handler_skiplist, list):
        skiplist.update(handler_skiplist)

    if handler_skiplist and PARSING_ERR_MSG in handler_skiplist:
        logger.error(
            "Enrollment configuration won't get logged due to: %s",
            CONFIGURATION_ERROR_DETAIL,
        )
    else:
        enroll_parameter_list = []
        for key, value in obj.__dict__.items():
            if _enrollment_key_is_sensitive(key, skiplist):
                continue
            enroll_parameter_list.append(f"{key}: {value}")
        logger.info("Enrollment configuration: %s", enroll_parameter_list)


def radomize_parameter_list(
    logger: logging.Logger, ca_handler: object, parameter_list: List[str] = None
):
    """randomize parameter list"""
    logger.debug("Helper.radomize_parameter_list()")

    tmp_dic = {}
    for parameter in parameter_list:
        if hasattr(ca_handler, parameter):
            value = getattr(ca_handler, parameter)
            if value and "," in value:
                values_list = value.split(",")
                tmp_dic[parameter] = []
                for ele in values_list:
                    tmp_dic[parameter].append(ele.strip())

    if tmp_dic:
        # Find the list with the minimum length in tmp_dic values
        min_length_list = min(tmp_dic.values(), key=len)
        # Get the length of that list
        min_len = len(min_length_list)

        # Calculate random number as index for the parameter list
        index = secrets.randbelow(min_len)
        # set parameter values
        for parameter, value_list in tmp_dic.items():
            setattr(ca_handler, parameter, value_list[index])


def handler_config_check(logger, handler, parameterlist) -> str:
    """check if handler config is valid"""
    logger.debug("Helper.handler_config_check()")
    error = None

    error = None
    for ele in parameterlist:
        if not getattr(handler, ele):
            error = f"{ele} parameter is missing in config file"
            logger.error("%s: %s", CONFIGURATION_ERROR_DETAIL, error)
            break

    logger.debug("Helper.handler_config_check() ended with %s", error)
    return error
