# -*- coding: utf-8 -*-
"""tests for google_cas_ca_handler"""

# pylint: disable=C0415, R0904, W0212
from __future__ import annotations

import logging
import os
import socket
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, ".")
sys.path.insert(1, "..")

MOCK_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "examples",
        "Docker",
        "google_privateca",
    )
)


@pytest.fixture
def logger():
    logging.basicConfig(level=logging.CRITICAL)
    return logging.getLogger("test_a2c")


@pytest.fixture
def handler(logger):
    from acme2certifier.cahandlers.google_cas_ca_handler import CAhandler

    return CAhandler(False, logger)


def _ready(handler, *, endpoint: str = "http://127.0.0.1:9"):
    handler.project = "demo"
    handler.location = "europe-west1"
    handler.ca_pool = "demo-pool"
    handler.endpoint_url = endpoint
    handler.access_token = "unit-test-token"
    handler.issuing_certificate_authority_id = "mock-issuing-ca"
    return handler


def test_trigger_not_implemented(handler):
    error, cert_bundle, cert_raw = handler.trigger("payload")
    assert error == "Method not implemented."
    assert cert_bundle is None
    assert cert_raw is None


def test_config_check_missing_params(handler):
    err = handler._config_check()
    assert err
    assert "project" in err or "ca_pool" in err or "required" in err.lower()


def test_config_check_ok_with_endpoint_placeholder(handler):
    handler.project = "demo"
    handler.location = "europe-west1"
    handler.ca_pool = "demo-pool"
    handler.endpoint_url = "http://127.0.0.1:8080"
    assert handler._config_check() is None
    assert handler._credentials_resolve() == "mock-token"


def test_config_check_full_pool_name(handler):
    handler.ca_pool = "projects/demo/locations/europe-west1/caPools/demo-pool"
    handler.endpoint_url = "http://127.0.0.1:8080"
    assert handler._parent_resource().endswith("/caPools/demo-pool")
    assert handler._config_check() is None


def test_revocation_reason_mapping(handler):
    assert handler._revocation_reason("keyCompromise") == "KEY_COMPROMISE"
    assert handler._revocation_reason("unspecified") == "REVOCATION_REASON_UNSPECIFIED"


def test_lifetime_duration(handler):
    handler.lifetime_days = 30
    assert handler._lifetime_duration() == "2592000s"


def test_service_url(handler):
    assert handler._service_url() == "https://privateca.googleapis.com"
    handler.endpoint_url = "http://localhost:8080/"
    assert handler._service_url() == "http://localhost:8080"


def test_access_token_precedence(handler):
    _ready(handler)
    handler.credentials_file = "/nonexistent.json"
    assert handler._credentials_resolve() == "unit-test-token"


@patch("acme2certifier.cahandlers.google_cas_ca_handler.requests.request")
def test_api_call_sends_bearer(mock_request, handler):
    _ready(handler)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"ok":true}'
    mock_resp.json.return_value = {"ok": True}
    mock_request.return_value = mock_resp

    out = handler._api_call("GET", "v1/projects/demo/locations/europe-west1/caPools/demo-pool/certificates")
    assert out == {"ok": True}
    headers = mock_request.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer unit-test-token"
    assert mock_request.call_args.kwargs["verify"] is True


@patch("acme2certifier.cahandlers.google_cas_ca_handler.requests.request")
def test_api_call_error(mock_request, handler):
    _ready(handler)
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.text = '{"error":{"status":"INVALID_ARGUMENT","message":"bad"}}'
    mock_resp.json.return_value = {
        "error": {"status": "INVALID_ARGUMENT", "message": "bad"}
    }
    mock_request.return_value = mock_resp
    with pytest.raises(RuntimeError) as ctx:
        handler._api_call("POST", "v1/x/certificates", payload={})
    assert "INVALID_ARGUMENT" in str(ctx.value)


@patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
def test_enroll(mock_api, handler):
    _ready(handler)
    leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"
    ica = "-----BEGIN CERTIFICATE-----\nICA\n-----END CERTIFICATE-----"
    root = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----"
    mock_api.return_value = {
        "name": "projects/demo/locations/europe-west1/caPools/demo-pool/certificates/c1",
        "pemCertificate": leaf,
        "pemCertificateChain": [ica, root],
    }

    with (
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.build_pem_file",
            return_value="-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
        ),
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.b64_url_recode",
            return_value="csr",
        ),
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.cert_pem2der",
            return_value=b"der",
        ),
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.b64_encode",
            return_value="Y2VydA==",
        ),
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ),
    ):
        error, bundle, cert_raw, poll_id = handler.enroll("csr-b64")

    assert error is None
    assert "LEAF" in bundle
    assert "ICA" in bundle
    assert cert_raw == "Y2VydA=="
    assert poll_id.endswith("/certificates/c1")
    assert mock_api.call_args[0][0] == "POST"
    assert "pemCsr" in mock_api.call_args.kwargs["payload"]


@patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
def test_handler_check(mock_api, handler):
    _ready(handler)
    mock_api.return_value = {"name": "…/certificateAuthorities/mock-issuing-ca"}
    assert handler.handler_check() is None
    assert mock_api.call_args[0][0] == "GET"
    assert "certificateAuthorities/mock-issuing-ca" in mock_api.call_args[0][1]


@patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
@patch("acme2certifier.cahandlers.google_cas_ca_handler.cert_serial_get")
def test_revoke(mock_serial, mock_api, handler):
    _ready(handler)
    mock_serial.return_value = "abcd"
    name = "projects/demo/locations/europe-west1/caPools/demo-pool/certificates/c1"
    mock_api.side_effect = [
        {"certificates": [{"name": name}]},
        {"name": name, "revocationDetails": {"revocationState": "REVOKED"}},
    ]
    code, message, detail = handler.revoke("certraw", "keyCompromise")
    assert code == 200
    assert message is None
    assert detail is None
    assert mock_api.call_args_list[0][0][0] == "GET"
    assert mock_api.call_args_list[1][0][0] == "POST"
    assert mock_api.call_args_list[1][0][1].endswith(":revoke")
    assert mock_api.call_args_list[1][1]["payload"]["reason"] == "KEY_COMPROMISE"


@patch("acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._api_call")
def test_poll(mock_api, handler):
    _ready(handler)
    name = "projects/demo/locations/europe-west1/caPools/demo-pool/certificates/c1"
    leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"
    mock_api.return_value = {
        "name": name,
        "pemCertificate": leaf,
        "pemCertificateChain": [],
    }
    with (
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.cert_pem2der",
            return_value=b"der",
        ),
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.b64_encode",
            return_value="Y2VydA==",
        ),
    ):
        error, bundle, cert_raw, poll_id, rejected = handler.poll("n", name, "csr")
    assert error is None
    assert "LEAF" in bundle
    assert cert_raw == "Y2VydA=="
    assert poll_id == name
    assert rejected is False


def test_missing_google_auth_on_real_endpoint(handler):
    handler.project = "demo"
    handler.location = "europe-west1"
    handler.ca_pool = "demo-pool"
    handler.endpoint_url = None
    handler.access_token = None
    handler.credentials_file = None
    with patch.dict(sys.modules, {"google.auth": None}):
        with patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.CAhandler._google_auth_import",
            side_effect=RuntimeError(
                "google-auth is required for Google Private CAS authentication"
            ),
        ):
            with pytest.raises(RuntimeError) as ctx:
                handler._credentials_resolve()
            assert "google-auth" in str(ctx.value)


def test_tls_verify_false(handler):
    handler.verify = False
    assert handler._tls_verify() is False
    handler.verify = True
    handler.ca_bundle = "/tmp/trust.pem"
    assert handler._tls_verify() == "/tmp/trust.pem"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def mock_privateca_server():
    """Start examples/Docker/google_privateca/server.py on an ephemeral port."""
    if not os.path.isdir(MOCK_DIR):
        pytest.skip("google_privateca mock not present")

    sys.path.insert(0, MOCK_DIR)
    from server import MockPrivateCaApp  # noqa: WPS433
    from pki import create_hierarchy  # noqa: WPS433
    from wsgiref.simple_server import make_server

    port = _free_port()
    material = create_hierarchy(issuing_ca_id="mock-issuing-ca")
    app = MockPrivateCaApp(
        material=material,
        project="demo",
        location="europe-west1",
        pool="demo-pool",
        require_bearer=True,
    )
    httpd = make_server("127.0.0.1", port, app)

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            requests.get(f"http://127.0.0.1:{port}/healthz", timeout=0.5)
            break
        except requests.RequestException:
            time.sleep(0.05)
    else:
        httpd.shutdown()
        pytest.fail("mock Private CAS server did not start")

    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_mock_server_rejects_missing_bearer(mock_privateca_server):
    url = (
        f"{mock_privateca_server}/v1/projects/demo/locations/europe-west1/"
        "caPools/demo-pool/certificates"
    )
    resp = requests.get(url, timeout=5)
    assert resp.status_code == 401


def test_mock_server_enroll_and_revoke(mock_privateca_server, handler, tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _ready(handler, endpoint=mock_privateca_server)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "smoke.acme")])
        )
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

    # enroll expects ACME-style CSR input; feed via build_pem_file bypass
    with (
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.build_pem_file",
            return_value=csr_pem,
        ),
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.b64_url_recode",
            return_value="ignored",
        ),
        patch(
            "acme2certifier.cahandlers.google_cas_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ),
    ):
        error, bundle, cert_raw, poll_id = handler.enroll("dummy")

    assert error is None, error
    assert bundle and "BEGIN CERTIFICATE" in bundle
    assert cert_raw
    assert poll_id and "/certificates/" in poll_id

    # Revoke using real leaf DER/b64 path: parse leaf from bundle
    leaf_pem = bundle.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----"
    leaf_der = x509.load_pem_x509_certificate(leaf_pem.encode("ascii")).public_bytes(
        serialization.Encoding.DER
    )
    import base64

    cert_b64 = base64.b64encode(leaf_der).decode("ascii")
    code, message, detail = handler.revoke(cert_b64, "keyCompromise")
    assert code == 200, (message, detail)
