#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
One-off auth check for google_cas_ca_handler (not wired into CI).

Uses a disposable venv with google-auth, e.g.:

  d=$(mktemp -d)
  python3 -m venv "$d"
  "$d/bin/pip" install google-auth requests
  "$d/bin/python" check_auth.py --endpoint-url http://127.0.0.1:8080 \\
      --project demo --location europe-west1 --pool demo-pool
  rm -rf "$d"

Modes:
  * With --endpoint-url: proves google-auth (ADC / SA JSON) can mint a Bearer
    and the handler attaches it; the mock only requires a non-empty token.
  * Without --endpoint-url: hits real privateca.googleapis.com (needs IAM).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

# Allow running from this directory or repo root
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


def _parse_args(argv: list) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manual google-auth / Private CAS Bearer check"
    )
    parser.add_argument("--project", default="demo")
    parser.add_argument("--location", default="europe-west1")
    parser.add_argument("--pool", default="demo-pool")
    parser.add_argument(
        "--issuing-ca-id",
        default="mock-issuing-ca",
        help="Used for handler_check GET certificateAuthorities/{id}",
    )
    parser.add_argument(
        "--endpoint-url",
        default=None,
        help="Mock base URL (e.g. http://127.0.0.1:8080). Omit for real GCP.",
    )
    parser.add_argument(
        "--credentials-file",
        default=None,
        help="Service account JSON (else ADC / GOOGLE_APPLICATION_CREDENTIALS)",
    )
    parser.add_argument(
        "--access-token",
        default=None,
        help="Skip google-auth and use this Bearer token",
    )
    parser.add_argument(
        "--verify",
        default="true",
        help="TLS verify for requests (true/false or path to ca_bundle)",
    )
    return parser.parse_args(argv)


def main(argv: list = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logger = logging.getLogger("check_auth")

    from acme2certifier.cahandlers.google_cas_ca_handler import CAhandler

    handler = CAhandler(False, logger)
    handler.project = args.project
    handler.location = args.location
    handler.ca_pool = args.pool
    handler.issuing_certificate_authority_id = args.issuing_ca_id
    handler.endpoint_url = args.endpoint_url
    handler.credentials_file = args.credentials_file
    handler.access_token = args.access_token

    verify = args.verify.strip().lower()
    if verify in ("0", "false", "no"):
        handler.verify = False
        handler.ca_bundle = False
    elif verify not in ("1", "true", "yes"):
        handler.ca_bundle = args.verify
        handler.verify = True

    # Force real google-auth path when checking against mock: clear placeholder path
    # by requiring credentials unless access_token is set.
    if args.endpoint_url and not args.access_token and not args.credentials_file:
        if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            logger.warning(
                "No credentials_file / GOOGLE_APPLICATION_CREDENTIALS / "
                "access_token — handler will use mock placeholder Bearer. "
                "Pass --credentials-file or --access-token to exercise google-auth."
            )

    try:
        token = handler._credentials_resolve()  # noqa: W0212
    except RuntimeError as err:
        logger.error("%s", err)
        return 2

    logger.info("Resolved Bearer token length=%s prefix=%s…", len(token), token[:8])

    try:
        error = handler.handler_check()
    except Exception as err:  # noqa: BLE001
        logger.error("handler_check raised: %s", err)
        return 3

    if error:
        logger.error("handler_check failed: %s", error)
        return 4

    logger.info("handler_check ok against %s", handler._service_url())  # noqa: W0212
    return 0


if __name__ == "__main__":
    sys.exit(main())
