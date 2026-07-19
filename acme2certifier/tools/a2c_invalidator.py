#!/usr/bin/python
"""Invalidate expired orders/authorizations and refresh certificate dates."""

from __future__ import annotations

import time

from acme2certifier.acme_srv.helper import logger_setup, uts_to_date_utc
from acme2certifier.acme_srv.housekeeping import Housekeeping


def main() -> None:
    """Run housekeeping invalidation tasks."""
    debug = True
    logger = logger_setup(debug)
    suffix = uts_to_date_utc(int(time.time()), "%Y-%m-%d-%H%M%S")

    with Housekeeping(debug, logger) as housekeeping:
        housekeeping.orders_invalidate(
            report_format="csv", report_name=f"orders_invalidate_{suffix}"
        )
        housekeeping.authorizations_invalidate(
            report_format="csv", report_name=f"authorization_expire_{suffix}"
        )
        housekeeping.certificate_dates_update()


if __name__ == "__main__":
    main()
