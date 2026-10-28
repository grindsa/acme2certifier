#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal Google Cloud Private CAS (privateca.googleapis.com/v1) REST mock.

Implements the enrollment/revoke subset used by acme2certifier:

  POST /v1/{parent}/certificates
  GET  /v1/{name}
  GET  /v1/{parent}/certificates
  POST /v1/{name}:revoke
  GET  /v1/.../certificateAuthorities/{caId}
  GET  /healthz

Based on:
  https://cloud.google.com/certificate-authority-service/docs/reference/rest
  https://cloud.google.com/certificate-authority-service/docs/reference/rest/v1/projects.locations.caPools.certificates

Auth: requires ``Authorization: Bearer <any-non-empty>`` (not verified).

Examples:

  python3 bootstrap_ca.py -o ./ca
  python3 server.py --listen 127.0.0.1:8080 --ca-dir ./ca \\
      --project demo --location europe-west1 --pool demo-pool
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse
from wsgiref.simple_server import WSGIRequestHandler, make_server

from pki import CaMaterial, create_hierarchy, load_hierarchy, sign_csr

# Resource path fragments
_RE_CERTS_COLLECTION = re.compile(
    r"^/v1/(projects/[^/]+/locations/[^/]+/caPools/[^/]+)/certificates$"
)
_RE_CERT = re.compile(
    r"^/v1/(projects/[^/]+/locations/[^/]+/caPools/[^/]+/certificates/[^/]+)$"
)
_RE_CERT_REVOKE = re.compile(
    r"^/v1/(projects/[^/]+/locations/[^/]+/caPools/[^/]+/certificates/[^/]+):revoke$"
)
_RE_CA = re.compile(
    r"^/v1/(projects/[^/]+/locations/[^/]+/caPools/[^/]+)/certificateAuthorities/([^/]+)$"
)


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def _rfc3339_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_lifetime(value: Any) -> int:
    """Parse Google Duration (e.g. ``2592000s``) to seconds."""
    if value is None:
        return 365 * 24 * 3600
    text = str(value).strip()
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)s", text)
    if not match:
        raise ValueError(f"Invalid lifetime duration: {value!r}")
    return max(int(float(match.group(1))), 60)


def _serial_from_filter(filter_expr: str) -> Optional[str]:
    """
    Extract a serial from a CAS-style filter string.

    Accepts forms like:
      certificate_description.subject_description.serial_number="abc"
      serial_number="abc"
      serial="abc"
    """
    if not filter_expr:
        return None
    match = re.search(
        r'(?:serial_number|serial)\s*=\s*"?([0-9a-fA-Fx]+)"?',
        filter_expr,
    )
    if not match:
        return None
    serial = match.group(1).lower()
    if serial.startswith("0x"):
        serial = serial[2:]
    return serial


class MockPrivateCaApp:
    """WSGI application implementing the Private CAS mock."""

    def __init__(
        self,
        *,
        material: CaMaterial,
        project: str,
        location: str,
        pool: str,
        require_bearer: bool = True,
    ) -> None:
        self.material = material
        self.project = project
        self.location = location
        self.pool = pool
        self.require_bearer = require_bearer
        self.parent = f"projects/{project}/locations/{location}/caPools/{pool}"
        self._certs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def __call__(self, environ: dict, start_response: Callable) -> List[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "") or "/"
        query = parse_qs(environ.get("QUERY_STRING", "") or "")

        if path in ("/healthz", "/"):
            return self._json(
                start_response, 200, {"status": "ok", "parent": self.parent}
            )

        auth_err = self._check_auth(environ)
        if auth_err is not None:
            return self._api_error(start_response, 401, "UNAUTHENTICATED", auth_err)

        try:
            body = self._read_json(environ)
        except ValueError as err:
            return self._api_error(start_response, 400, "INVALID_ARGUMENT", str(err))

        if method == "POST" and _RE_CERTS_COLLECTION.match(path):
            return self._create_certificate(start_response, path, query, body)
        if method == "GET" and _RE_CERTS_COLLECTION.match(path):
            return self._list_certificates(start_response, path, query)
        if method == "POST" and _RE_CERT_REVOKE.match(path):
            return self._revoke_certificate(start_response, path, body)
        if method == "GET" and _RE_CERT.match(path):
            return self._get_certificate(start_response, path)
        if method == "GET" and _RE_CA.match(path):
            return self._get_certificate_authority(start_response, path)

        return self._api_error(
            start_response,
            404,
            "NOT_FOUND",
            f"No mock handler for {method} {path}",
        )

    def _check_auth(self, environ: dict) -> Optional[str]:
        if not self.require_bearer:
            return None
        header = environ.get("HTTP_AUTHORIZATION") or ""
        parts = header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
            return "Authorization: Bearer <token> required"
        return None

    @staticmethod
    def _read_json(environ: dict) -> Dict[str, Any]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = environ["wsgi.input"].read(length)
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as err:
            raise ValueError(f"Invalid JSON body: {err}") from err
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _json(
        self, start_response: Callable, status: int, payload: Dict[str, Any]
    ) -> List[bytes]:
        body = json.dumps(payload).encode("utf-8")
        start_response(
            f"{status} OK" if status < 400 else f"{status} Error",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]

    def _api_error(
        self, start_response: Callable, http_status: int, status: str, message: str
    ) -> List[bytes]:
        return self._json(
            start_response,
            http_status,
            {
                "error": {
                    "code": http_status,
                    "message": message,
                    "status": status,
                }
            },
        )

    def _create_certificate(
        self,
        start_response: Callable,
        path: str,
        query: Dict[str, List[str]],
        body: Dict[str, Any],
    ) -> List[bytes]:
        match = _RE_CERTS_COLLECTION.match(path)
        assert match is not None
        parent = match.group(1)
        if parent != self.parent:
            return self._api_error(
                start_response,
                404,
                "NOT_FOUND",
                f"Unknown caPool parent {parent} (mock serves {self.parent})",
            )

        pem_csr = body.get("pemCsr")
        if not pem_csr or not isinstance(pem_csr, str):
            return self._api_error(
                start_response,
                400,
                "INVALID_ARGUMENT",
                "pemCsr is required",
            )
        try:
            lifetime_s = _parse_lifetime(body.get("lifetime"))
        except ValueError as err:
            return self._api_error(start_response, 400, "INVALID_ARGUMENT", str(err))

        cert_id = (query.get("certificateId") or [None])[0] or uuid.uuid4().hex[:16]
        issuing_id = (query.get("issuingCertificateAuthorityId") or [None])[0]
        if issuing_id and issuing_id != self.material.issuing_ca_id:
            return self._api_error(
                start_response,
                404,
                "NOT_FOUND",
                f"Unknown issuingCertificateAuthorityId {issuing_id}",
            )

        try:
            leaf_pem, serial_hex, _not_after = sign_csr(
                self.material, pem_csr, lifetime_seconds=lifetime_s
            )
        except Exception as err:  # noqa: BLE001 — surface as API error
            return self._api_error(
                start_response, 400, "INVALID_ARGUMENT", f"Failed to sign CSR: {err}"
            )

        name = f"{parent}/certificates/{cert_id}"
        now = _rfc3339_now()
        certificate: Dict[str, Any] = {
            "name": name,
            "pemCsr": pem_csr,
            "lifetime": f"{lifetime_s}s",
            "pemCertificate": leaf_pem,
            "pemCertificateChain": self.material.chain_pems,
            "issuerCertificateAuthority": (
                f"{parent}/certificateAuthorities/{self.material.issuing_ca_id}"
            ),
            "createTime": now,
            "updateTime": now,
            "certificateDescription": {
                "subjectDescription": {
                    "serialNumber": serial_hex,
                }
            },
        }
        if body.get("certificateTemplate"):
            certificate["certificateTemplate"] = body["certificateTemplate"]

        with self._lock:
            self._certs[name] = certificate

        return self._json(start_response, 200, certificate)

    def _get_certificate(self, start_response: Callable, path: str) -> List[bytes]:
        match = _RE_CERT.match(path)
        assert match is not None
        name = match.group(1)
        with self._lock:
            cert = self._certs.get(name)
        if not cert:
            return self._api_error(
                start_response, 404, "NOT_FOUND", f"Certificate {name} not found"
            )
        return self._json(start_response, 200, cert)

    def _list_certificates(
        self,
        start_response: Callable,
        path: str,
        query: Dict[str, List[str]],
    ) -> List[bytes]:
        match = _RE_CERTS_COLLECTION.match(path)
        assert match is not None
        parent = match.group(1)
        if parent != self.parent:
            return self._api_error(
                start_response,
                404,
                "NOT_FOUND",
                f"Unknown caPool parent {parent}",
            )
        filter_expr = (query.get("filter") or [""])[0]
        want_serial = _serial_from_filter(filter_expr)
        with self._lock:
            items = list(self._certs.values())
        if want_serial:
            items = [
                item
                for item in items
                if item.get("certificateDescription", {})
                .get("subjectDescription", {})
                .get("serialNumber", "")
                .lower()
                == want_serial
            ]
        return self._json(start_response, 200, {"certificates": items})

    def _revoke_certificate(
        self,
        start_response: Callable,
        path: str,
        body: Dict[str, Any],
    ) -> List[bytes]:
        match = _RE_CERT_REVOKE.match(path)
        assert match is not None
        name = match.group(1)
        reason = body.get("reason") or "REVOCATION_REASON_UNSPECIFIED"
        with self._lock:
            cert = self._certs.get(name)
            if not cert:
                return self._api_error(
                    start_response, 404, "NOT_FOUND", f"Certificate {name} not found"
                )
            if cert.get("revocationDetails"):
                return self._api_error(
                    start_response,
                    400,
                    "FAILED_PRECONDITION",
                    f"Certificate {name} is already revoked",
                )
            cert = dict(cert)
            cert["revocationDetails"] = {
                "revocationState": "REVOKED",
                "revocationTime": _rfc3339_now(),
                "revocationReason": reason,
            }
            cert["updateTime"] = _rfc3339_now()
            self._certs[name] = cert
        return self._json(start_response, 200, cert)

    def _get_certificate_authority(
        self, start_response: Callable, path: str
    ) -> List[bytes]:
        match = _RE_CA.match(path)
        assert match is not None
        parent, ca_id = match.group(1), match.group(2)
        if parent != self.parent:
            return self._api_error(
                start_response, 404, "NOT_FOUND", f"Unknown caPool parent {parent}"
            )
        if ca_id != self.material.issuing_ca_id:
            return self._api_error(
                start_response,
                404,
                "NOT_FOUND",
                f"CertificateAuthority {ca_id} not found",
            )
        name = f"{parent}/certificateAuthorities/{ca_id}"
        return self._json(
            start_response,
            200,
            {
                "name": name,
                "state": "ENABLED",
                "tier": "DEVOPS",
                "pemCaCertificates": [
                    self.material.issuing_pem,
                    self.material.root_pem,
                ],
            },
        )


def _parse_listen(value: str) -> Tuple[str, int]:
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8080
        return host, port
    if ":" in value:
        host, port_s = value.rsplit(":", 1)
        return host or "0.0.0.0", int(port_s)
    return "0.0.0.0", int(value)


def _parse_args(argv: list) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Google Private CAS REST mock server")
    parser.add_argument(
        "--listen",
        default="0.0.0.0:8080",
        help="host:port (default 0.0.0.0:8080)",
    )
    parser.add_argument(
        "--ca-dir",
        default=None,
        help="Directory from bootstrap_ca.py; omit to generate ephemeral PKI",
    )
    parser.add_argument("--project", default="demo")
    parser.add_argument("--location", default="europe-west1")
    parser.add_argument("--pool", default="demo-pool")
    parser.add_argument(
        "--issuing-ca-id",
        default="mock-issuing-ca",
        help="Used when --ca-dir is omitted (ephemeral PKI)",
    )
    parser.add_argument(
        "--tls-cert",
        default=None,
        help="PEM server certificate for HTTPS",
    )
    parser.add_argument(
        "--tls-key",
        default=None,
        help="PEM server private key for HTTPS",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable Bearer requirement (debug only)",
    )
    return parser.parse_args(argv)


def main(argv: list = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    if args.ca_dir:
        material = load_hierarchy(args.ca_dir, issuing_ca_id=args.issuing_ca_id)
    else:
        material = create_hierarchy(issuing_ca_id=args.issuing_ca_id)
        sys.stderr.write(
            "No --ca-dir given; using ephemeral in-memory root+issuing CA\n"
        )

    host, port = _parse_listen(args.listen)
    app = MockPrivateCaApp(
        material=material,
        project=args.project,
        location=args.location,
        pool=args.pool,
        require_bearer=not args.no_auth,
    )
    httpd = make_server(host, port, app, handler_class=_QuietHandler)

    if args.tls_cert or args.tls_key:
        if not (args.tls_cert and args.tls_key):
            sys.stderr.write("--tls-cert and --tls-key must be set together\n")
            return 2
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"

    parent = app.parent
    sys.stderr.write(
        f"Private CAS mock listening on {scheme}://{host}:{port}\n"
        f"  parent={parent}\n"
        f"  issuing_ca_id={material.issuing_ca_id}\n"
        f"  bearer_required={app.require_bearer}\n"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nShutting down\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
