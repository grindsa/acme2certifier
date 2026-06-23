#!/usr/bin/python
"""database updater"""

# pylint: disable=E0401, C0413
import sys
import json
import argparse
import os.path

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))
)
sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir)
    )
)
from acme_srv.helper import logger_setup  # nopep8
from acme_srv.housekeeping import Housekeeping  # nopep8


def arg_parse():
    """simple argparser"""
    parser = argparse.ArgumentParser(
        description="match_import.py - update matches in database"
    )
    parser.add_argument(
        "-d", "--debug", help="debug mode", action="store_true", default=False
    )
    parser.add_argument(
        "-c",
        "--certificateadmin",
        help="grant permissions to manage certificates",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-r",
        "--reportadmin",
        help="grant permissions to download reports",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-u",
        "--useradmin",
        help="grant permissions to manage cli users",
        action="store_true",
        default=False,
    )
    parser.add_argument("-e", "--email", help="email address", default=None)
    parser.add_argument("-k", "--keyfile", help="file containing JWK")
    parser.add_argument("-n", "--jwkname", help="name of the key")
    clist = parser.add_mutually_exclusive_group()
    clist.add_argument("--list", help="list users", action="store_true", default=False)
    clist.add_argument(
        "--delete", help="delete user", action="store_true", default=False
    )

    args = parser.parse_args()

    debug = args.debug
    config_dic = {
        "debug": args.debug,
        "permissions": {
            "certificateadmin": args.certificateadmin,
            "reportadmin": args.reportadmin,
            "cliadmin": args.useradmin,
        },
    }

    if args.jwkname:
        config_dic["jwkname"] = args.jwkname
    if args.delete:
        config_dic["delete"] = args.delete
    if args.list:
        config_dic["list"] = args.list
    if args.email:
        config_dic["email"] = args.email
    if args.keyfile:
        try:
            keyfile = validate_keyfile_path(args.keyfile)
            config_dic["jwk"] = json.loads(file_load(keyfile))
        except ValueError as err:
            print(f"Error: {err}")

    return (debug, config_dic)


def validate_keyfile_path(filename):
    """validate keyfile path before reading from disk"""
    if not filename:
        raise ValueError("keyfile path is empty")

    base_dir = os.path.realpath(os.getcwd())
    candidate = os.path.realpath(os.path.abspath(filename))

    if candidate != base_dir and not candidate.startswith(base_dir + os.sep):
        raise ValueError(
            f'Invalid keyfile path "{filename}". Path must be within "{base_dir}".'
        )

    if not os.path.isfile(candidate):
        raise ValueError(f'keyfile "{filename}" does not exist')

    return candidate


def file_load(filename):
    """load file at once"""
    safe_filename = validate_keyfile_path(filename)
    with open(safe_filename, encoding="utf8") as _file:
        lines = _file.read()
    return lines


if __name__ == "__main__":

    DEBUG, CONFIG_DIC = arg_parse()

    # the cli program needs ot be chatty
    CONFIG_DIC["silent"] = False

    # initialize logger
    LOGGER = logger_setup(DEBUG)

    with Housekeeping(DEBUG, LOGGER) as housekeeping:
        # cli usermgr
        result = housekeeping.cli_usermgr(CONFIG_DIC)
