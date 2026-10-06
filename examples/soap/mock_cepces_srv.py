# -*- coding: utf-8 -*-
"""Minimal WSGI mock for Microsoft CEP (MS-XCEP) and CES (MS-WSTEP)."""

from __future__ import annotations

import argparse
import os
from typing import Callable, Dict, Iterable, List, Tuple
from wsgiref.simple_server import make_server
from xml.etree import ElementTree as ET

FIXTURE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "test",
        "fixtures",
        "mscepces",
    )
)


def _load_fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURE_DIR, name), "rb") as handle:
        return handle.read()


def _local_name(tag: str) -> str:
    if tag and "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag or ""


def _request_type(body: bytes) -> str:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return "unknown"
    for element in root.iter():
        if _local_name(element.tag) == "GetPolicies":
            return "GetPolicies"
        if _local_name(element.tag) == "RequestType" and element.text:
            text = element.text.strip()
            if text.endswith("QueryTokenStatus"):
                return "QueryTokenStatus"
            if text.endswith("Issue"):
                return "Issue"
    return "unknown"


class MockCepCesApp:
    """WSGI application returning canned CEP/CES SOAP responses."""

    def __init__(self, pending_polls: int = 1) -> None:
        self.pending_polls = pending_polls
        self._poll_counts: Dict[str, int] = {}

    def __call__(
        self, environ: Dict[str, str], start_response: Callable
    ) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length) if length else b""

        if method != "POST":
            start_response("405 Method Not Allowed", [("Content-Type", "text/plain")])
            return [b"POST required"]

        req_type = _request_type(body)
        if "CEP" in path.upper() or req_type == "GetPolicies":
            payload = _load_fixture("xcep_get_policies_response.xml")
        elif req_type == "QueryTokenStatus":
            key = path
            self._poll_counts[key] = self._poll_counts.get(key, 0) + 1
            if self._poll_counts[key] <= self.pending_polls:
                payload = _load_fixture("wstep_poll_still_pending.xml")
            else:
                payload = _load_fixture("wstep_poll_issued.xml")
        elif req_type == "Issue":
            if self.pending_polls > 0:
                payload = _load_fixture("wstep_issue_pending.xml")
            else:
                payload = _load_fixture("wstep_issue_issued.xml")
        else:
            start_response("400 Bad Request", [("Content-Type", "text/plain")])
            return [b"Unrecognized SOAP body"]

        headers: List[Tuple[str, str]] = [
            ("Content-Type", "application/soap+xml; charset=utf-8"),
            ("Content-Length", str(len(payload))),
        ]
        start_response("200 OK", headers)
        return [payload]


def main() -> None:
    """Run mock CEP/CES HTTP server."""
    parser = argparse.ArgumentParser(description="Mock Microsoft CEP/CES SOAP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument(
        "--pending-polls",
        type=int,
        default=0,
        help="Number of poll responses that stay pending before issuing",
    )
    args = parser.parse_args()
    app = MockCepCesApp(pending_polls=args.pending_polls)
    httpd = make_server(args.host, args.port, app)
    print(
        f"Mock CEP/CES listening on http://{args.host}:{args.port}/ "
        f"(pending_polls={args.pending_polls})"
    )
    print("Example CEP path: /ADPolicyProvider_CEP_Kerberos/service.svc/CEP")
    print("Example CES path: /TestCA_CES_Kerberos/service.svc/CES")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
