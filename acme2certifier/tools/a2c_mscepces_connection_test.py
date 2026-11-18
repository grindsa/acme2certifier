#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Test Microsoft CEP/CES CA handler connectivity."""

from acme2certifier.acme_srv.helper import logger_setup
from acme2certifier.cahandlers.mscepces_ca_handler import CAhandler


def main() -> None:
    """Check configured CEP/CES endpoints via handler_check()."""
    logger = logger_setup(True)
    with CAhandler(True, logger) as ca_handler:
        error = ca_handler.handler_check()
        if error:
            raise SystemExit(f"mscepces connection check failed: {error}")
        print("mscepces connection check OK")


if __name__ == "__main__":
    main()
