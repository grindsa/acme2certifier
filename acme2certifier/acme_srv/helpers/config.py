# -*- coding: utf-8 -*-
"""Configuration utilities for acme2certifier"""

import configparser
import json
import logging
import os
import warnings
from typing import Dict, List, Optional, Tuple
from .plugin_loader import eab_handler_load
from .global_variables import PARSING_ERR_MSG

# Emit legacy acme_srv.cfg path deprecation at most once per process.
_LEGACY_ACME_SRV_CFG_WARNED = False


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
        # load eab_profiling from eabhandler section
        eab_profiling = config_dic.getboolean(
            "EABhandler", "eab_profiling", fallback=False
        )
    except Exception as err:
        logger.error("Failed to load eabprofile from configuration: %s", err)
        eab_profiling = False

    if (
        not eab_profiling
        and "CAhandler" in config_dic
        and "eab_profiling" in config_dic["CAhandler"]
    ):
        # load eab_profiling from CAHandler section - deprecated
        logger.warning(
            "eab_profiling found in CAhandler section - this is deprecated, please use EABhandler section"
        )
        try:
            eab_profiling = config_dic.getboolean(
                "CAhandler", "eab_profiling", fallback=False
            )
        except Exception as err:
            logger.error("Failed to load eabprofile from configuration: %s", err)
            eab_profiling = False

    if eab_profiling:
        if "EABhandler" in config_dic and (
            "eab_handler_file" in config_dic["EABhandler"]
            or "eab_handler_module" in config_dic["EABhandler"]
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


def config_dns_server_list_load(
    logger: logging.Logger, config_dic: Dict[str, str]
) -> Tuple[List[str], int]:
    """load parameters"""
    logger.debug("Helper.config_dns_server_list_load()")

    dns_server_list = []
    dns_validation_pause_timer = 0.5

    if "DEFAULT" in config_dic and "dns_server_list" in config_dic["DEFAULT"]:
        try:
            dns_server_list = json.loads(config_dic["DEFAULT"]["dns_server_list"])
        except Exception as err_:
            logger.warning(
                "Failed to load dns_server_list from configuration: %s", err_
            )
    elif "Challenge" in config_dic and "dns_server_list" in config_dic["Challenge"]:
        logger.warning(
            "dns_server_list parameter found in Challenge section - this is deprecated, please use DEFAULT section"
        )
        try:
            dns_server_list = json.loads(config_dic["Challenge"]["dns_server_list"])
        except Exception as err_:
            logger.warning(
                "Failed to load dns_server_list from configuration: %s", err_
            )

        if (
            "Challenge" in config_dic
            and "dns_validation_pause_timer" in config_dic["Challenge"]
        ):
            try:
                dns_validation_pause_timer = int(
                    config_dic["Challenge"]["dns_validation_pause_timer"]
                )
            except Exception as err_:
                logger.warning(
                    "Failed to parse dns_validation_pause_timer from configuration: %s",
                    err_,
                )

    logger.debug("Helper.config_dns_server_list_load() ended with: %s", dns_server_list)
    return dns_server_list, dns_validation_pause_timer


def config_allowed_domainlist_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_allowed_domainlist_load()")

    allowed_domainlist = []

    if "Order" in config_dic and "allowed_domainlist" in config_dic["Order"]:
        try:
            allowed_domainlist = json.loads(config_dic["Order"]["allowed_domainlist"])
        except Exception as err_:
            logger.warning(
                "Failed to load allowed_domainlist from configuration: %s", err_
            )
            allowed_domainlist = PARSING_ERR_MSG

    if (
        not allowed_domainlist
        and "CAhandler" in config_dic
        and "allowed_domainlist" in config_dic["CAhandler"]
    ):
        logger.warning(
            "allowed_domainlist parameter found in CAhandler section - this is deprecated, please use Order section"
        )
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


def config_allowed_iplist_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load parameters"""
    logger.debug("Helper.config_allowed_iplist_load()")

    allowed_iplist = []

    if "Order" in config_dic and "allowed_iplist" in config_dic["Order"]:
        try:
            allowed_iplist = json.loads(config_dic["Order"]["allowed_iplist"])
        except Exception as err_:
            logger.warning("Failed to load allowed_iplist from configuration: %s", err_)
            allowed_iplist = PARSING_ERR_MSG

    logger.debug("Helper.config_allowed_iplist_load() ended with: %s", allowed_iplist)
    return allowed_iplist


def config_async_mode_load(
    logger: logging.Logger, config_dic: Dict[str, str], db_type: str
):
    """load parameters"""
    logger.debug("Helper.config_async_mode_load()")

    async_mode = False

    async_cfg = config_dic.getboolean("DEFAULT", "async_mode", fallback=False)
    if async_cfg:
        if db_type == "django":
            async_mode = True
        else:
            logger.info(
                "asynchronous Challenge validation disabled, requires django db handler"
            )
    logger.debug("Helper.config_async_mode_load() ended with: %s", async_mode)
    return async_mode


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
                fqdn, _port = url_dic["host"].split(":")
                proxy_server = proxy_check(logger, fqdn, proxy_list)
                proxy = {"http": proxy_server, "https": proxy_server}
        except Exception as err_:
            logger.warning(
                "Failed to parse proxy_server_list from configuration: %s",
                err_,
            )

    logger.debug("config_proxy_load() ended with: %s", proxy)
    return proxy


def _default_acme_srv_cfg_file(
    logger: Optional[logging.Logger] = None,
) -> str:
    """Resolve default acme_srv.cfg after the package move.

    Candidates (first existing file wins):
    1. Next to the real package: ``acme2certifier/acme_srv/acme_srv.cfg``
    2. Legacy layout: ``<repo>/acme_srv/acme_srv.cfg``
    """
    log = logger or logging.getLogger(__name__)
    log.debug("Helper._default_acme_srv_cfg_file() start")

    helpers_dir = os.path.dirname(os.path.abspath(__file__))
    pkg_dir = os.path.dirname(helpers_dir)  # .../acme_srv (new or install tree)
    install_or_repo_root = os.path.dirname(os.path.dirname(pkg_dir))

    packaged_cfg = os.path.join(pkg_dir, "acme_srv.cfg")
    legacy_cfg = os.path.join(install_or_repo_root, "acme_srv", "acme_srv.cfg")
    log.debug(
        "Helper._default_acme_srv_cfg_file(): candidates packaged=%s legacy=%s",
        packaged_cfg,
        legacy_cfg,
    )

    if os.path.isfile(packaged_cfg):
        log.debug(
            "Helper._default_acme_srv_cfg_file() ended with packaged %s",
            packaged_cfg,
        )
        return packaged_cfg

    if os.path.isfile(legacy_cfg):
        global _LEGACY_ACME_SRV_CFG_WARNED  # pylint: disable=global-statement
        if not _LEGACY_ACME_SRV_CFG_WARNED:
            message = (
                f"Loading acme_srv.cfg from legacy path {legacy_cfg}; "
                f"prefer placing it next to the package ({packaged_cfg}) "
                "or set ACME_SRV_CONFIGFILE. "
                "Legacy default cfg discovery will change in acme2certifier 1.0."
            )
            warnings.warn(message, DeprecationWarning, stacklevel=3)
            log.warning(message)
            _LEGACY_ACME_SRV_CFG_WARNED = True
        log.debug(
            "Helper._default_acme_srv_cfg_file() ended with legacy %s",
            legacy_cfg,
        )
        return legacy_cfg

    log.debug(
        "Helper._default_acme_srv_cfg_file() ended with fallback %s",
        packaged_cfg,
    )
    return packaged_cfg


def load_config(
    logger: logging.Logger = None, mfilter: str = None, cfg_file: str = None
) -> configparser.ConfigParser:
    """small configparser wrappter to load a config file"""
    log = logger or logging.getLogger(__name__)
    log.debug(
        "Helper.load_config() start mfilter=%r cfg_file=%r",
        mfilter,
        cfg_file,
    )

    if not cfg_file:
        if "ACME_SRV_CONFIGFILE" in os.environ:
            cfg_file = os.environ["ACME_SRV_CONFIGFILE"]
            log.debug(
                "Helper.load_config(): using ACME_SRV_CONFIGFILE=%s",
                cfg_file,
            )
        else:
            cfg_file = _default_acme_srv_cfg_file(log)
    else:
        log.debug("Helper.load_config(): using explicit cfg_file=%s", cfg_file)

    log.debug("load_config(%s:%s)", mfilter, cfg_file)
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    read_ok = config.read(cfg_file, encoding="utf8")
    if not read_ok:
        log.warning(
            "Helper.load_config(): could not read config file %s",
            cfg_file,
        )
    log.debug(
        "Helper.load_config() ended sections=%s",
        list(config.sections()),
    )
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

    from acme2certifier.acme_srv.db_handler import DBstore  # pylint: disable=c0415

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


def config_dryrun_load(logger: logging.Logger, config_dic: Dict[str, str]):
    """load dryrun configuration"""
    logger.debug("Helper.config_dryrun_load()")

    dryrun = False
    dryrun_profilename = None

    if "DEFAULT" in config_dic and "dryrun" in config_dic["DEFAULT"]:
        if config_dic["DEFAULT"]["dryrun"].lower() in ["true", "false"]:
            dryrun = config_dic.getboolean("DEFAULT", "dryrun", fallback=False)
        elif config_dic["DEFAULT"]["dryrun"].lower() == "profile":
            if config_dic.get("DEFAULT", "dryrun_profile", fallback=None):
                dryrun_profilename = config_dic["DEFAULT"]["dryrun_profile"]
            else:
                logger.warning(
                    "Dryrun profile name not set in configuration, please set dryrun_profile parameter"
                )

    logger.debug(
        "Helper.config_dryrun_load() ended with: %s/%s", dryrun, dryrun_profilename
    )
    return dryrun, dryrun_profilename
