#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seed a processing order + CSR for /trigger CI (run inside a2c container)."""

import argparse
import base64
import logging
import os
import sys
import time


def _validate_csr_path(path_value: str) -> str:
    """Resolve ``path_value`` and require it stays under the process CWD (S8707)."""
    if not path_value:
        raise ValueError("CSR path is empty")

    base_dir = os.path.realpath(os.getcwd())
    candidate = os.path.realpath(os.path.abspath(path_value))

    if candidate != base_dir and not candidate.startswith(base_dir + os.sep):
        raise ValueError(
            f"Invalid CSR path '{path_value}'. Path must be within '{base_dir}'."
        )

    if not os.path.isfile(candidate):
        raise ValueError(f"Invalid CSR path '{path_value}'. File does not exist.")

    return candidate


def _b64url_der_from_pem(pem_path: str) -> str:
    with open(pem_path, "rb") as handle:
        data = handle.read()
    # Strip PEM headers if present; accept raw DER too
    text = data.decode("ascii", errors="ignore")
    if "BEGIN" in text:
        lines = [
            line.strip()
            for line in text.splitlines()
            if line and not line.startswith("-----")
        ]
        der = base64.b64decode("".join(lines))
    else:
        der = data
    return base64.urlsafe_b64encode(der).rstrip(b"=").decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csr", required=True, help="CSR PEM path")
    parser.add_argument("--account-name", default="triggertstacct")
    parser.add_argument("--order-name", default="triggertstorder")
    parser.add_argument("--cert-name", default="triggertstcert")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("trigger_ci_seed")

    try:
        csr_path = _validate_csr_path(args.csr)
    except ValueError as err:
        logger.error("%s", err)
        return 1

    from acme2certifier.acme_srv.db_handler import DBstore

    csr = _b64url_der_from_pem(csr_path)
    dbstore = DBstore(False, logger)

    jwk = '{"kty":"RSA","n":"trigger-ci-n-%s","e":"AQAB"}' % args.account_name
    dbstore.account_add(
        {
            "name": args.account_name,
            "alg": "RS256",
            "jwk": jwk,
            "contact": '["mailto:trigger-ci@example.local"]',
            "eab_kid": "",
        }
    )
    # status id 4 = processing (wsgi); django handler accepts id via _status_getinstance
    expires = int(time.time()) + 86400
    rid = dbstore.order_add(
        {
            "name": args.order_name,
            "identifiers": '[{"type":"dns","value":"trigger.ci.example"}]',
            "account": args.account_name,
            "status": 4,
            "expires": expires,
            "notbefore": 0,
            "notafter": 0,
            "profile": "",
        }
    )
    if not rid:
        logger.error("order_add failed")
        return 1
    dbstore.certificate_add(
        {
            "name": args.cert_name,
            "csr": csr,
            "order": args.order_name,
            "header_info": "",
        }
    )
    # Ensure order is processing (django may have interpreted status differently)
    try:
        dbstore.order_update({"name": args.order_name, "status": "processing"})
    except Exception as err:
        logger.warning("order_update to processing: %s", err)

    print(
        f"seeded account={args.account_name} order={args.order_name} "
        f"cert={args.cert_name} order_id={rid}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
