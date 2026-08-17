#!/usr/bin/python3
"""Verify and list EAB keyfile entries."""

import argparse
import os.path
from typing import Dict, Tuple

import yaml

from acme2certifier.acme_srv.db_handler import initialize
from acme2certifier.acme_srv.helper import (
    config_eab_profile_load,
    eab_handler_load,
    load_config,
    logger_setup,
    print_debug,
)


def _eab_dic_print(logger, eab_dic: Dict[str, str], config_dic: Dict[str, str]) -> None:
    """print eab dic"""
    logger.debug("eab_print_dic()")

    if config_dic["summary"] or config_dic["verbose"] or config_dic["veryverbose"]:
        _summary_print(logger, eab_dic)

    if config_dic["verbose"]:
        for key, value in eab_dic.items():
            if "hmac" in value:
                print(f'{key}: {value["hmac"]}')
            else:
                print(f"{key}: {value}")
    elif config_dic["veryverbose"]:
        print(yaml.dump(eab_dic, default_flow_style=False, default_style=""))


def _summary_print(logger, eab_dic: Dict[str, str]) -> None:
    """print summary of eab dic"""
    logger.debug("summary_print()")
    print(f"Summary: {len(eab_dic.keys())} entries in kid_file")


def _filter_eab_dic(logger, eab_dic: Dict[str, str], keyid: str) -> Dict[str, str]:
    """filter eab dic"""
    logger.debug("_filter_eab_dic(%s)", keyid)
    return {k: v for k, v in eab_dic.items() if k == keyid}


def arg_parse() -> Tuple[bool, Dict[str, str]]:
    """simple argparser"""
    parser = argparse.ArgumentParser(description="a2c-eab-chk - verify eab keyfile")
    parser.add_argument("-c", "--configfile", help="configfile", required=True)
    parser.add_argument(
        "-d", "--debug", help="debug mode", action="store_true", default=False
    )
    parser.add_argument(
        "-v", "--verbose", help="verbose", action="store_true", default=False
    )
    parser.add_argument(
        "-vv",
        "--veryverbose",
        help="show enrollment profile",
        action="store_true",
        default=False,
    )
    clist = parser.add_mutually_exclusive_group()
    clist.add_argument("-k", "--keyid", help="keyid to filter", default=None)
    clist.add_argument(
        "-s", "--summary", help="summary", default=False, action="store_true"
    )

    args = parser.parse_args()

    debug = args.debug
    config_dic = {
        "debug": args.debug,
        "verbose": args.verbose,
        "veryverbose": args.veryverbose,
        "keyid": args.keyid,
        "summary": args.summary,
        "configfile": args.configfile,
    }

    if not config_dic["summary"] and not config_dic["keyid"]:
        config_dic["summary"] = True

    return (debug, config_dic)


def eab_dic_load(logger, acme_srv_dic: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    """load eabhandler"""
    logger.debug("eab_dic_load()")

    eab_profiling, eab_module = config_eab_profile_load(logger, acme_srv_dic)
    if not eab_profiling:
        eab_handler_module = eab_handler_load(logger, acme_srv_dic)
        eab_module = eab_handler_module.EABhandler

    with eab_module(logger) as eab_handler:
        eab_dic = eab_handler.key_file_load()

    return eab_dic


def main() -> None:
    """Load and print EAB keyfile contents according to CLI flags."""
    initialize()
    debug, config_dic = arg_parse()
    logger = logger_setup(debug)

    if os.path.exists(config_dic["configfile"]):
        acme_srv_dic = load_config(cfg_file=config_dic["configfile"])
    else:
        acme_srv_dic = {}
        error_text = f'Configfile {config_dic["configfile"]} not found.'
        logger.debug(error_text)
        print_debug(True, error_text)

    if "EABhandler" in acme_srv_dic:
        eab_dic = eab_dic_load(logger, acme_srv_dic)
        if config_dic.get("keyid"):
            eab_dic = _filter_eab_dic(logger, eab_dic, config_dic["keyid"])
    else:
        eab_dic = None
        print_debug(True, "No EABhandler section in configfile")

    if eab_dic:
        _eab_dic_print(logger, eab_dic, config_dic)


if __name__ == "__main__":
    main()
