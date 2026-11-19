#!/usr/bin/python
"""Poll certificates stuck in processing status."""

from acme2certifier.acme_srv.certificate import Certificate
from acme2certifier.acme_srv.db_handler import initialize
from acme2certifier.acme_srv.helper import logger_setup


def main() -> None:
    """Poll CA for certificates in status processing."""
    initialize()
    debug = True
    logger = logger_setup(debug)

    with Certificate(debug, "foo", logger) as certificate:
        cert_list = certificate.certlist_search(
            "order__status_id", 4, ("name", "poll_identifier", "csr", "order__name")
        )
        for cert in cert_list:
            poll_identifier = cert.get("poll_identifier")
            if not poll_identifier:
                logger.warning(
                    "Skipping certificate %s (order=%s): missing poll_identifier; "
                    "not eligible for CA polling",
                    cert.get("name"),
                    cert.get("order__name"),
                )
                continue
            certificate.poll(
                cert["name"],
                poll_identifier,
                cert["csr"],
                cert["order__name"],
            )


if __name__ == "__main__":
    main()
