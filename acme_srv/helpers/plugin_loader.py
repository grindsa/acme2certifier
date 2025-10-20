# -*- coding: utf-8 -*-
"""Plugin loading utilities for acme2certifier"""
import importlib
import importlib.util
import logging
from typing import Dict
def ca_handler_load(
    logger: logging.Logger, config_dic: Dict
) -> importlib.import_module:
    """load and return ca_handler"""
    logger.debug("Helper.ca_handler_load()")

    if "CAhandler" not in config_dic:
        logger.error("CAhandler configuration missing in config file")
        return None

    if "handler_file" in config_dic["CAhandler"]:
        # try to load handler from file
        try:
            spec = importlib.util.spec_from_file_location(
                "CAhandler", config_dic["CAhandler"]["handler_file"]
            )
            ca_handler_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ca_handler_module)
            return ca_handler_module
        except Exception as err_:
            logger.critical(
                "Loading CAhandler configured in cfg failed with err: %s", err_
            )

    # if no 'handler_file' provided or loading was unsuccessful, try to load default handler
    try:
        ca_handler_module = importlib.import_module("acme_srv.ca_handler")
    except Exception as err_:
        logger.critical("Loading default CAhandler failed with err: %s", err_)
        ca_handler_module = None

    return ca_handler_module



def eab_handler_load(
    logger: logging.Logger, config_dic: Dict
) -> importlib.import_module:
    """load and return eab_handler"""
    logger.debug("Helper.eab_handler_load()")
    # pylint: disable=w0621
    if "EABhandler" in config_dic and "eab_handler_file" in config_dic["EABhandler"]:
        # try to load handler from file
        try:
            spec = importlib.util.spec_from_file_location(
                "EABhandler", config_dic["EABhandler"]["eab_handler_file"]
            )
            eab_handler_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(eab_handler_module)
        except Exception as err_:
            logger.critical(
                "Loading EABhandler configured in cfg failed with err: %s", err_
            )
            try:
                eab_handler_module = importlib.import_module("acme_srv.eab_handler")
            except Exception as err_:
                eab_handler_module = None
                logger.critical("Loading default EABhandler failed with err: %s", err_)
    else:
        if "EABhandler" in config_dic:
            try:
                eab_handler_module = importlib.import_module("acme_srv.eab_handler")
            except Exception as err_:
                logger.critical("Loading default EABhandler failed with err: %s", err_)
                eab_handler_module = None
        else:
            logger.error("EABhandler configuration missing in config file")
            eab_handler_module = None

    return eab_handler_module



def hooks_load(logger: logging.Logger, config_dic: Dict) -> importlib.import_module:
    """load and return hooks"""
    logger.debug("Helper.hooks_load()")

    hooks_module = None
    if "Hooks" in config_dic and "hooks_file" in config_dic["Hooks"]:
        # try to load hooks from file
        try:
            spec = importlib.util.spec_from_file_location(
                "Hooks", config_dic["Hooks"]["hooks_file"]
            )
            hooks_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(hooks_module)
        except Exception as err_:
            logger.critical(
                "Loading Hooks configured in cfg failed with err: %s",
                err_,
            )

    return hooks_module



