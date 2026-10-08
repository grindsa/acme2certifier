#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Print current HARICA CertManager TOTP code from acme_srv.cfg."""

import argparse
import logging
import os
import sys
import time
from typing import Optional, Tuple

from acme2certifier.acme_srv.helper import (
    config_option_load,
    load_config,
    logger_setup,
)
from acme2certifier.cahandlers.harica_ca_handler import totp_generate

ROLE_USER = "user"
ROLE_APPROVER = "approver"
TOTP_PERIOD = 30


def _arg_parse() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Generate a HARICA CertManager TOTP code from [CAhandler] seeds "
            "in acme_srv.cfg (for portal login / troubleshooting)."
        )
    )
    parser.add_argument(
        "-c",
        "--configfile",
        help="Path to acme_srv.cfg (default: auto-detect)",
        default=None,
    )
    role = parser.add_mutually_exclusive_group()
    role.add_argument(
        "-u",
        "--user",
        dest="role",
        action="store_const",
        const=ROLE_USER,
        help="Use requester_totp_seed. Default.",
    )
    role.add_argument(
        "-a",
        "--approver",
        dest="role",
        action="store_const",
        const=ROLE_APPROVER,
        help="Use approver_totp_seed",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Print email and seconds remaining (stderr)",
    )
    parser.set_defaults(role=ROLE_USER)
    return parser.parse_args()


def _seed_from_config(
    cfg_file: Optional[str],
    role: str,
    logger: Optional[logging.Logger] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Load TOTP seed and account email for the selected role.

    Returns:
        (seed, email, error)
    """
    if logger is None:
        logger = logging.getLogger("a2c_harica_totp")

    config_dic = load_config(cfg_file=cfg_file) if cfg_file else load_config()
    if "CAhandler" not in config_dic:
        return None, None, "No [CAhandler] section in config file"

    if role == ROLE_APPROVER:
        seed = config_option_load(logger, config_dic, "approver_totp_seed")
        email = config_option_load(logger, config_dic, "approver_email")
        missing = "approver_totp_seed / approver_totp_seed_variable"
    else:
        seed = config_option_load(logger, config_dic, "requester_totp_seed")
        email = config_option_load(logger, config_dic, "requester_email")
        missing = "requester_totp_seed / requester_totp_seed_variable"

    if seed:
        seed = seed.strip() or None
    if email:
        email = email.strip() or None

    if not seed:
        return None, email, f"{missing} is missing in [CAhandler]"
    return seed, email, None


def main() -> int:
    """Print current TOTP to STDOUT; metadata to STDERR when verbose."""
    args = _arg_parse()
    logger = logger_setup(False)

    if args.configfile and not os.path.exists(args.configfile):
        print(f"Configfile {args.configfile} not found.", file=sys.stderr)
        return 1

    seed, email, error = _seed_from_config(args.configfile, args.role, logger)
    if error:
        logger.error(error)
        print(error, file=sys.stderr)
        return 1

    try:
        code = totp_generate(seed)
    except Exception as err:
        print(f"Failed to generate TOTP: {err}", file=sys.stderr)
        return 1

    if args.verbose:
        remaining = TOTP_PERIOD - (int(time.time()) % TOTP_PERIOD)
        account = email or "(no email in config)"
        print(
            f"role={args.role} account={account} remaining={remaining}s",
            file=sys.stderr,
        )

    print(code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
