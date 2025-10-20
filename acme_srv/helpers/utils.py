# -*- coding: utf-8 -*-
"""General utilities for acme2certifier"""
import random
import logging
from typing import Dict, List


PARSING_ERR_MSG = "failed to parse"

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



def enrollment_config_log(
    logger: logging.Logger, obj: object, handler_skiplist: List[str] = None
):
    """log enrollment configuration"""
    logger.debug("Helper.enrollment_config_log()")

    skiplist = [
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
    ]

    if handler_skiplist and isinstance(handler_skiplist, list):
        skiplist.extend(handler_skiplist)

    if handler_skiplist and PARSING_ERR_MSG in handler_skiplist:
        logger.error(
            "Enrollment configuration won't get logged due to a configuration error."
        )
    else:
        enroll_parameter_list = []
        for key, value in obj.__dict__.items():
            if key.startswith("__") or key in skiplist:
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
        index = random.randint(0, min_len - 1)
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
            logger.error("Configuration check ended with error: %s", error)
            break

    logger.debug("Helper.handler_config_check() ended with %s", error)
    return error


