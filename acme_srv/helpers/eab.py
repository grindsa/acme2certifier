# -*- coding: utf-8 -*-
"""EAB (External Account Binding) utilities for acme2certifier"""
import logging
from typing import Optional
from .csr import csr_subject_get
from .encoding import b64_url_recode
from .config import client_parameter_validate, profile_lookup, header_info_lookup
from .validation import cn_validate
from .domain_utils import allowed_domainlist_check


def _handle_eab_profiling(
    logger: logging.Logger, cahandler, csr: str, handler_hifield: str
) -> Optional[str]:
    """Handle EAB profiling logic"""
    logger.debug("Helper._handle_eab_profiling()")

    if not (hasattr(cahandler, "eab_handler") and cahandler.eab_handler):
        logger.error("EAB profiling enabled but no handler defined")
        return "Eab_profiling enabled but no handler defined"

    # profiling enabled - check profile
    return eab_profile_check(logger, cahandler, csr, handler_hifield)


def _handle_acme_profiling(
    logger: logging.Logger, cahandler, csr: str, handler_hifield: str
) -> None:
    """Handle ACME profiling logic"""
    logger.debug("Helper._handle_acme_profiling()")

    profile = profile_lookup(logger, csr)
    if profile:
        logger.debug(
            "Helper.profile_lookup(): setting %s to %s",
            handler_hifield,
            profile,
        )
        setattr(cahandler, handler_hifield, profile)


def _handle_header_info_profiling(
    logger: logging.Logger, cahandler, csr: str, handler_hifield: str
) -> None:
    """Handle header info profiling logic"""
    logger.debug("Helper._handle_header_info_profiling()")

    hil_value = header_info_lookup(
        logger, csr, cahandler.header_info_field, handler_hifield
    )
    if hil_value:
        logger.debug(
            "Helper.eab_profile_header_info_check(): setting %s to %s",
            handler_hifield,
            hil_value,
        )
        logger.info(
            "Received enrollment parameter: %s value: %s via headerinfo field",
            handler_hifield,
            hil_value,
        )
        setattr(cahandler, handler_hifield, hil_value)
    else:
        logger.debug("eab_profile_header_info_check(): no header_info field found")


def eab_profile_header_info_check(
    logger: logging.Logger,
    cahandler,
    csr: str,
    handler_hifield: str = "profile_name",
) -> Optional[str]:
    """check profile"""
    logger.debug("Helper.eab_profile_header_info_check()")

    # Priority 1: EAB profiling - returns error string or None
    if hasattr(cahandler, "eab_profiling") and cahandler.eab_profiling:
        error = _handle_eab_profiling(logger, cahandler, csr, handler_hifield)

    # Priority 2: ACME profiling (preferred over header info) - no errors
    elif hasattr(cahandler, "profiles") and cahandler.profiles:
        _handle_acme_profiling(logger, cahandler, csr, handler_hifield)
        error = None

    # Priority 3: Header info profiling - no errors
    elif hasattr(cahandler, "header_info_field") and cahandler.header_info_field:
        _handle_header_info_profiling(logger, cahandler, csr, handler_hifield)
        error = None

    # Priority 4: No profiling
    else:
        error = None

    logger.debug("Helper.eab_profile_header_info_check() ended with %s", error)
    return error


def eab_profile_subject_string_check(
    logger: logging.Logger, profile_subject_dic, key: str, value: str
) -> str:
    """check if a for a string value taken from profile if its a variable inside a class and apply value"""
    logger.debug(
        "Helper.eab_profile_subject_string_check(): string: key: %s, value: %s",
        key,
        value,
    )

    error = False
    if key == "commonName":
        # check if CN is a valid IP address or fqdn
        error = cn_validate(logger, value)
    elif key in profile_subject_dic:
        if isinstance(profile_subject_dic[key], str) and (
            value == profile_subject_dic[key] or profile_subject_dic[key] == "*"
        ):
            logger.debug(
                "Helper.eab_profile_subject_check() successul for string : %s", key
            )
            del profile_subject_dic[key]
        elif (
            isinstance(profile_subject_dic[key], list)
            and value in profile_subject_dic[key]
        ):
            logger.debug(
                "Helper.eab_profile_subject_check() successul for list : %s", key
            )
            del profile_subject_dic[key]
        else:
            logger.error(
                "EAB profile subject check failed for: %s: value: %s expected: %s",
                key,
                value,
                profile_subject_dic[key],
            )
            error = f"Profile subject check failed for {key}"
    else:
        logger.error("EAB profile subject failed for: %s", key)
        error = f"Profile subject check failed for {key}"

    logger.debug("Helper.eab_profile_subject_string_check() ended")
    return error


def eab_profile_subject_check(
    logger: logging.Logger, csr: str, profile_subject_dic: str
) -> str:
    """check subject against profile information"""
    logger.debug("Helper.eab_profile_subject_check()")
    error = None

    # get subject from csr
    subject_dic = csr_subject_get(logger, csr)

    # check if all profile subject entries are in csr
    for key, value in subject_dic.items():
        error = eab_profile_subject_string_check(
            logger, profile_subject_dic, key, value
        )
        if error:
            break

    # check if we have any entries left in the profile_subject_dic
    if not error and profile_subject_dic:
        logger.error(
            "EAB profile subject check failed for: %s",
            list(profile_subject_dic.keys()),
        )
        error = "Profile subject check failed"

    logger.debug("Helper.eab_profile_subject_check() ended with: %s", error)
    return error


def eab_profile_revocation_check(
    logger: logging.Logger, cahandler, certificate_raw: str
):
    """check eab profile for revocation"""
    logger.debug("Helper.eab_profile_revocation_check()")
    with cahandler.eab_handler(logger) as eab_handler:
        eab_profile_dic = eab_handler.eab_profile_get(
            b64_url_recode(logger, certificate_raw), revocation=True
        )
        for key, value in eab_profile_dic.items():
            if key in ["subject", "allowed_domainlist"]:
                continue
            elif isinstance(value, str):
                eab_profile_string_check(logger, cahandler, key, value)
            elif isinstance(value, list):
                # check if we need to execute a function from the handler
                if "eab_profile_list_check" in dir(cahandler):
                    _result = cahandler.eab_profile_list_check(
                        eab_handler, certificate_raw, key, value
                    )
                else:
                    _result = eab_profile_list_check(
                        logger, cahandler, eab_handler, certificate_raw, key, value
                    )

    logger.debug("Helper.eab_profile_revocation_check() ended")


def eab_profile_check(
    logger: logging.Logger, cahandler, csr: str, handler_hifield: str
) -> str:
    """check eab profile"""
    logger.debug("Helper.eab_profile_check()")

    result = None
    with cahandler.eab_handler(logger) as eab_handler:
        eab_profile_dic = eab_handler.eab_profile_get(csr)
        for key, value in eab_profile_dic.items():
            if key == "subject":
                result = eab_profile_subject_check(logger, csr, value)
            elif isinstance(value, str):
                eab_profile_string_check(logger, cahandler, key, value)
            elif isinstance(value, list):
                # check if we need to execute a function from the handler
                if "eab_profile_list_check" in dir(cahandler):
                    result = cahandler.eab_profile_list_check(
                        eab_handler, csr, key, value
                    )
                else:
                    result = eab_profile_list_check(
                        logger, cahandler, eab_handler, csr, key, value
                    )
            if result:
                break

        # we need to reject situations where profiling is enabled but the header_hifiled is not defined in json
        if cahandler.header_info_field and handler_hifield not in eab_profile_dic:
            hil_value = header_info_lookup(
                logger, csr, cahandler.header_info_field, handler_hifield
            )
            if hil_value:
                # setattr(self, handler_hifield, hil_value)
                result = (
                    f'header_info field "{handler_hifield}" is not allowed by profile'
                )

    logger.debug("Helper.eab_profile_check() ended with: %s", result)
    return result


def eab_profile_list_check(logger, cahandler, eab_handler, csr, key, value):
    """check if a for a list value taken from profile if its a variable inside a class and apply value"""
    logger.debug(
        "Helper.eab_profile_list_check(): list: key: %s, value: %s", key, value
    )

    result = None
    if hasattr(cahandler, key) and key != "allowed_domainlist":
        new_value, error = client_parameter_validate(logger, csr, cahandler, key, value)
        if new_value:
            logger.debug(
                "Helper.eab_profile_list_check(): setting attribute: %s to %s",
                key,
                new_value,
            )
            setattr(cahandler, key, new_value)
        else:
            result = error
    elif key == "allowed_domainlist":
        # check if csr contains allowed domains
        if "allowed_domains_check" in dir(eab_handler):
            # execute a function from eab_handler
            logger.info("Execute allowed_domains_check() from eab handler")
            error = eab_handler.allowed_domains_check(csr, value)
        else:
            # execute default adl function from helper
            logger.debug(
                "Helper.eab_profile_list_check(): execute default allowed_domainlist_check()"
            )
            error = allowed_domainlist_check(logger, csr, value)
        if error:
            result = error
    else:
        logger.warning(
            "EAP profile list checking: ignoring unrecognized list attribute: key: %s value: %s",
            key,
            value,
        )

    logger.debug("Helper.eab_profile_list_check() ended with: %s", result)
    return result


def eab_profile_string_check(logger, cahandler, key, value):
    """check if a for a string value taken from profile if its a variable inside a class and apply value"""
    logger.debug(
        "Helper.eab_profile_string_check(): string: key: %s, value: %s", key, value
    )

    if hasattr(cahandler, key):
        logger.debug(
            "Helper.eab_profile_string_check(): setting attribute: %s to %s", key, value
        )
        setattr(cahandler, key, value)
    else:
        logger.warning(
            "EAB profile string checking: ignoring unrecognized string attribute: key: %s value: %s",
            key,
            value,
        )

    logger.debug("Helper.eab_profile_string_check() ended")
