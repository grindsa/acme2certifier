#!/usr/bin/python
"""Generate housekeeping reports (certificates, accounts, cleanup)."""

import time

from acme2certifier.acme_srv.helper import logger_setup, uts_to_date_utc
from acme2certifier.acme_srv.housekeeping import Housekeeping


def main() -> None:
    """Generate certificate/account/cleanup reports."""
    debug = True
    logger = logger_setup(debug)
    suffix = uts_to_date_utc(int(time.time()), "%Y-%m-%d-%H%M%S")

    with Housekeeping(debug, logger) as housekeeping:
        housekeeping.certreport_get(
            report_name=f"certificate_report_{suffix}", report_format="json"
        )
        housekeeping.certreport_get(report_name=f"certificate_report_{suffix}")
        housekeeping.accountreport_get(
            report_name=f"account_report_{suffix}", report_format="json", nested=True
        )
        housekeeping.accountreport_get(report_name=f"account_report_{suffix}")
        housekeeping.certificates_cleanup(
            report_format="json", report_name=f"certificate_cleanup_{suffix}"
        )
        housekeeping.orders_invalidate(
            report_format="csv", report_name=f"orders_invalidate_{suffix}"
        )
        housekeeping.authorizations_invalidate(
            report_format="csv", report_name=f"authorization_expire_{suffix}"
        )


if __name__ == "__main__":
    main()
