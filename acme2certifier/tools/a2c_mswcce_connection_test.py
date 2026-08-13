#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Test MS-WCCE CA handler connectivity."""

from acme2certifier.acme_srv.helper import logger_setup
from acme2certifier.cahandlers.mswcce_ca_handler import CAhandler


def main() -> None:
    """Create a test MS-WCCE request against the configured CA."""
    logger = logger_setup(True)
    with CAhandler(True, logger) as ca_handler:
        ca_handler.request_create()


if __name__ == "__main__":
    main()
