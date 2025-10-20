# -*- coding: utf-8 -*-
"""Configuration utilities for acme2certifier"""
import configparser
import json
import logging
import os
from typing import Dict, List, Tuple
from .plugin_loader import eab_handler_load


PARSING_ERR_MSG = "failed to parse"


def config_check(logger: logging.Logger, config_dic: Dict):
    """check configuration"""
    logger.debug("Helper.config_check()")

    for section, section_dic in config_dic.items():
        for key, value in section_dic.items():
            if value.startswith('"') or value.endswith('"'):
                logger.warning(
                    'Section %s option: %s contains " characters. Please check if this is required!',
                    section,
                    key,
                )


def config_profile_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_profile_load()")

    # load profiles
    profiles = {}
    if "Order" in config_dic and "profiles" in config_dic["Order"]:
        try:
            profiles = json.loads(config_dic["Order"]["profiles"])
        except Exception as err_:
            logger.warning("Failed to load profiles from configuration: %s", err_)

    logger.debug("Helper.config_profile_load() ended")
    return profiles


def config_eab_profile_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_eab_profile_load()")

    eab_profiling = False
    eab_handler = None

    try:
        eab_profiling = config_dic.getboolean(
            "CAhandler", "eab_profiling", fallback=False
        )
    except Exception as err:
        logger.warning("Failed to load eabprofile from configuration: %s", err)
        eab_profiling = False

    if eab_profiling:
        if (
            "EABhandler" in config_dic
            and "eab_handler_file" in config_dic["EABhandler"]
        ):
            # load eab_handler according to configuration
            eab_handler_module = eab_handler_load(logger, config_dic)
            if not eab_handler_module:
                logger.critical("EABHandler could not get loaded")
            else:
                eab_handler = eab_handler_module.EABhandler
        else:
            logger.critical("EABHandler configuration incomplete")

    logger.debug("_config_profile_load() ended")
    return eab_profiling, eab_handler


def config_headerinfo_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_headerinfo_load()")

    header_info_field = None
    if (
        "Order" in config_dic
        and "header_info_list" in config_dic["Order"]
        and config_dic["Order"]["header_info_list"]
    ):
        try:
            header_info_field = json.loads(config_dic["Order"]["header_info_list"])[0]
        except Exception as err_:
            logger.warning(
                "Failed to parse header_info_list from configuration: %s", err_
            )
    #
    logger.debug("Helper.config_headerinfo_load() ended")
    return header_info_field


def config_enroll_config_log_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_enroll_config_log_load()")

    enrollment_cfg_log = False
    enrollment_cfg_log_skip_list = []

    if "CAhandler" in config_dic:
        try:
            enrollment_cfg_log = config_dic.getboolean(
                "CAhandler", "enrollment_config_log", fallback=False
            )
        except Exception as err_:
            logger.warning(
                "Failed to load enrollment_config_log from configuration: %s", err_
            )

        if "enrollment_config_log_skip_list" in config_dic["CAhandler"]:
            try:
                enrollment_cfg_log_skip_list = json.loads(
                    config_dic["CAhandler"]["enrollment_config_log_skip_list"]
                )
            except Exception as err_:
                logger.warning(
                    "Failed to parse enrollment_config_log_skip_list from configuration: %s",
                    err_,
                )
                enrollment_cfg_log_skip_list = PARSING_ERR_MSG

    logger.debug(
        "Helper.config_enroll_config_log_load() ended with: %s", enrollment_cfg_log
    )
    return enrollment_cfg_log, enrollment_cfg_log_skip_list


def config_allowed_domainlist_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_allowed_domainlist_load()")

    allowed_domainlist = []

    if "CAhandler" in config_dic and "allowed_domainlist" in config_dic["CAhandler"]:
        try:
            allowed_domainlist = json.loads(
                config_dic["CAhandler"]["allowed_domainlist"]
            )
        except Exception as err_:
            logger.warning(
                "Failed to load allowed_domainlist from configuration: %s", err_
            )
            allowed_domainlist = PARSING_ERR_MSG

    logger.debug(
        "Helper.config_allowed_domainlist_load() ended with: %s", allowed_domainlist
    )
    return allowed_domainlist


def config_proxy_load(logger, config_dic: Dict[str, str], host_name: str):
    """load parameters"""
    logger.debug("_config_proxy_load()")

    # Lazy import to avoid circular dependency
    from .network import parse_url, proxy_check  # pylint: disable=C0415

    proxy = {}
    if "DEFAULT" in config_dic and "proxy_server_list" in config_dic["DEFAULT"]:
        try:
            proxy_list = json.loads(config_dic["DEFAULT"]["proxy_server_list"])
            url_dic = parse_url(logger, host_name)
            if "host" in url_dic:
                # check if we need to set the proxy
                (fqdn, _port) = url_dic["host"].split(":")
                proxy_server = proxy_check(logger, fqdn, proxy_list)
                proxy = {"http": proxy_server, "https": proxy_server}
        except Exception as err_:
            logger.warning(
                "Failed to parse proxy_server_list from configuration: %s",
                err_,
            )

    logger.debug("config_proxy_load() ended with: %s", proxy)
    return proxy


def load_config(
    logger: logging.Logger = None, mfilter: str = None, cfg_file: str = None
) -> configparser.ConfigParser:
    """small configparser wrappter to load a config file"""
    if not cfg_file:
        if "ACME_SRV_CONFIGFILE" in os.environ:
            cfg_file = os.environ["ACME_SRV_CONFIGFILE"]
        else:
            # go up one directory from helpers/ to acme_srv/ to find config file
            cfg_file = os.path.dirname(os.path.dirname(__file__)) + "/" + "acme_srv.cfg"
            print(cfg_file)
    if logger:
        logger.debug("load_config(%s:%s)", mfilter, cfg_file)
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    config.read(cfg_file, encoding="utf8")
    return config


def header_info_jsonify(logger: logging.Logger, header_info: str) -> Dict[str, str]:
    """jsonify header info"""
    logger.debug("Helper.header_info_json_parse()")

    header_info_dic = {}
    try:
        if isinstance(header_info, list) and "header_info" in header_info[-1]:
            header_info_dic = json.loads(header_info[-1]["header_info"])
    except Exception as err:
        logger.error("Could not parse header_info_field: %s", err)

    logger.debug(
        "Helper.header_info_json_parse() ended with: %s", bool(header_info_dic)
    )
    return header_info_dic


def header_info_lookup(logger, csr: str, header_info_field, key: str) -> str:
    """lookup header info"""
    logger.debug("Helper.header_info_lookup(%s)", key)

    # Lazy import to avoid circular dependency
    from .network import header_info_get  # pylint: disable=C0415

    result = None
    header_info = header_info_get(logger, csr=csr)

    if header_info:
        header_info_dic = header_info_jsonify(logger, header_info)
        if header_info_field in header_info_dic:
            for ele in header_info_dic[header_info_field].split(" "):
                if key in ele.lower():
                    result = ele.split("=", 1)[1]
                    break
        else:
            logger.warning(
                "Header_info_field not found in header info: %s", header_info_field
            )
    logger.debug("Helper.header_info_lookup(%s) ended with: %s", key, result)
    return result


def profile_lookup(logger: logging.Logger, csr: str) -> str:
    """get profile name from csr"""
    logger.debug("Helper.profile_lookup()")

    from acme_srv.db_handler import DBstore  # pylint: disable=c0415

    dbstore = DBstore(logger=logger)

    try:
        result = dbstore.certificates_search(
            "csr", csr, ["id", "order_id", "order__profile"]
        )
    except Exception as err:
        logger.warning("Profile lookup failed with: %s", err)
        result = None
    if result and "order__profile" in result[0]:
        # we have a match - get profile name
        profile_name = result[0]["order__profile"]
    else:
        profile_name = None

    logger.debug("Helper.profile_lookup() ended with: %s", profile_name)
    return profile_name


def client_parameter_validate(
    logger, csr: str, cahandler, value: str, value_list: List[str]
) -> Tuple[str, str]:
    """select value from list"""
    logger.debug("Helper.client_parameter_validate(%s)", value)

    value_to_set = None
    error = None
    if cahandler.profiles:
        logger.debug("Helper.client_parameter_validate(): using profile")
        # get profile info
        client_parameter = profile_lookup(logger, csr)
    else:
        logger.debug("Helper.client_parameter_validate(): using header info")
        # get header info
        client_parameter = header_info_lookup(
            logger, csr, cahandler.header_info_field, value
        )
    if client_parameter:
        if client_parameter in value_list:
            value_to_set = client_parameter
        else:
            error = f'{value} "{client_parameter}" is not allowed'
    else:
        # header not set, use first value from list
        value_to_set = value_list[0]

    logger.debug(
        "Helper.client_parameter_validate(%s) ended with %s/%s",
        value,
        value_to_set,
        error,
    )
    return value_to_set, error
