#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate a 2-level mini-PKI for the Google Private CAS REST mock.

Runnable on a test client (no CI required):

  python3 bootstrap_ca.py --output-dir ./ca
  python3 bootstrap_ca.py --output-dir ./ca --force \\
      --root-cn "Dev Root" --issuing-cn "Dev Issuing"

Depends only on the ``cryptography`` package (already used by acme2certifier).
"""

from __future__ import annotations

import argparse
import os
import sys

from pki import create_hierarchy, write_hierarchy


def _parse_args(argv: list) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bootstrap root + issuing CA PEMs for the Private CAS mock"
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        required=True,
        help="Directory to write PEM files into",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite existing PEM files in --output-dir",
    )
    parser.add_argument("--root-cn", default="Mock Private CAS Root")
    parser.add_argument("--issuing-cn", default="Mock Private CAS Issuing")
    parser.add_argument(
        "--issuing-ca-id",
        default="mock-issuing-ca",
        help="Resource id used as issuingCertificateAuthorityId",
    )
    parser.add_argument("--root-days", type=int, default=3650)
    parser.add_argument("--issuing-days", type=int, default=1825)
    parser.add_argument("--key-size", type=int, default=2048)
    return parser.parse_args(argv)


def main(argv: list = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    output_dir = os.path.abspath(args.output_dir)
    marker = os.path.join(output_dir, "issuing-cert.pem")
    if os.path.exists(marker) and not args.force:
        print(
            f"Refusing to overwrite existing hierarchy in {output_dir} "
            "(pass --force).",
            file=sys.stderr,
        )
        return 1

    material = create_hierarchy(
        root_cn=args.root_cn,
        issuing_cn=args.issuing_cn,
        root_days=args.root_days,
        issuing_days=args.issuing_days,
        key_size=args.key_size,
        issuing_ca_id=args.issuing_ca_id,
    )
    paths = write_hierarchy(material, output_dir)

    print(f"Wrote Private CAS mock PKI to {output_dir}")
    for key in (
        "root_cert",
        "root_key",
        "issuing_cert",
        "issuing_key",
        "trust_bundle",
        "issuing_ca_id",
    ):
        print(f"  {key}: {paths[key]}")

    print()
    print("Suggested mock server start:")
    print(
        f"  python3 server.py --listen 0.0.0.0:8080 --ca-dir {output_dir} "
        f"--project demo --location europe-west1 --pool demo-pool"
    )
    print()
    print("Suggested acme_srv.cfg TLS trust for HTTPS mock / chain checks:")
    print(f"  ca_bundle: {paths['trust_bundle']}")
    print()
    print(f"issuing_certificate_authority_id: {args.issuing_ca_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
