# -*- coding: utf-8 -*-
"""unittests for aws_pca_ca_handler"""

# pylint: disable=C0415, R0904, W0212
import base64
import datetime
import hashlib
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestAWSPCAHandler(unittest.TestCase):
    """unit tests for REST/SigV4 ACM PCA handler"""

    def setUp(self):
        import logging
        from acme2certifier.cahandlers.aws_pca_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.region = "eu-central-1"
        self.ca_arn = (
            "arn:aws:acm-pca:eu-central-1:123456789012:certificate-authority/x"
        )

    def _ready(self):
        self.cahandler.aws_region = self.region
        self.cahandler.certificate_authority_arn = self.ca_arn
        self.cahandler.aws_access_key_id = "AKIATEST"
        self.cahandler.aws_secret_access_key = "secret"

    def test_001_trigger_not_implemented(self):
        error, cert_bundle, cert_raw = self.cahandler.trigger("payload")
        self.assertEqual(error, "Method not implemented.")
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)

    def test_002_config_check_missing_params(self):
        err = self.cahandler._config_check()
        self.assertIn("aws_region", err)

    def test_003_config_check_missing_credentials(self):
        self.cahandler.aws_region = self.region
        self.cahandler.certificate_authority_arn = self.ca_arn
        err = self.cahandler._config_check()
        self.assertIn("aws_access_key_id", err)

    def test_004_config_check_ok(self):
        self._ready()
        self.assertIsNone(self.cahandler._config_check())

    def test_005_config_check_localstack_placeholder(self):
        self.cahandler.aws_region = self.region
        self.cahandler.certificate_authority_arn = self.ca_arn
        self.cahandler.endpoint_url = "http://localhost:4566"
        self.assertIsNone(self.cahandler._config_check())

    def test_006_revocation_reason_mapping(self):
        self.assertEqual(
            self.cahandler._revocation_reason("keyCompromise"), "KEY_COMPROMISE"
        )
        self.assertEqual(
            self.cahandler._revocation_reason("unspecified"), "UNSPECIFIED"
        )

    def test_007_service_url(self):
        self.cahandler.aws_region = "us-east-1"
        self.assertEqual(
            self.cahandler._service_url(), "https://acm-pca.us-east-1.amazonaws.com"
        )
        self.cahandler.endpoint_url = "http://localhost:4566/"
        self.assertEqual(self.cahandler._service_url(), "http://localhost:4566")

    def test_008_sigv4_stable_hash(self):
        from acme2certifier.cahandlers.aws_pca_ca_handler import _sigv4_sign

        now = datetime.datetime(2024, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
        body = b'{"Foo":"Bar"}'
        headers = _sigv4_sign(
            method="POST",
            url="https://acm-pca.eu-central-1.amazonaws.com/",
            body=body,
            amz_target="ACMPrivateCA.DescribeCertificateAuthority",
            region="eu-central-1",
            access_key="AKIATEST",
            secret_key="secret",
            now=now,
        )
        self.assertEqual(headers["X-Amz-Date"], "20240102T030405Z")
        self.assertIn("Signature=", headers["Authorization"])
        self.assertEqual(
            headers["X-Amz-Content-Sha256"], hashlib.sha256(body).hexdigest()
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.requests.post")
    def test_009_api_call_success(self, mock_post):
        self._ready()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"CertificateArn":"arn:aws:acm-pca:eu-central-1:1:certificate/x"}'
        mock_resp.json.return_value = {
            "CertificateArn": "arn:aws:acm-pca:eu-central-1:1:certificate/x"
        }
        mock_post.return_value = mock_resp

        out = self.cahandler._api_call(
            "IssueCertificate", {"CertificateAuthorityArn": self.ca_arn}
        )
        self.assertEqual(
            out["CertificateArn"], "arn:aws:acm-pca:eu-central-1:1:certificate/x"
        )
        self.assertEqual(mock_post.call_args.kwargs["headers"]["X-Amz-Target"],
                         "ACMPrivateCA.IssueCertificate")
        self.assertIn("Authorization", mock_post.call_args.kwargs["headers"])

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.requests.post")
    def test_010_api_call_error(self, mock_post):
        self._ready()
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = '{"__type":"ValidationException","message":"bad"}'
        mock_resp.json.return_value = {
            "__type": "ValidationException",
            "message": "bad",
        }
        mock_post.return_value = mock_resp
        with self.assertRaises(RuntimeError) as ctx:
            self.cahandler._api_call("IssueCertificate", {})
        self.assertIn("ValidationException", str(ctx.exception))

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    def test_011_enroll(self, mock_api):
        self._ready()
        leaf = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBkTCB+wIJAKHBf6Xt9x7cMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl\n"
            "c3QuZXhhbXBsZTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQ\n"
            "BgNVBAMMCXRlc3QuZXhhbXBsZTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7\n"
            "-----END CERTIFICATE-----"
        )
        # Use a minimal valid-looking PEM is hard; mock cert_pem2der/b64 path via real helpers
        # Prefer mocking lower layers for enroll return path
        mock_api.side_effect = [
            {"CertificateArn": "arn:aws:acm-pca:eu-central-1:1:certificate/y"},
            {"Certificate": leaf, "CertificateChain": leaf},
        ]

        with patch(
            "acme2certifier.cahandlers.aws_pca_ca_handler.build_pem_file",
            return_value="-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
        ), patch(
            "acme2certifier.cahandlers.aws_pca_ca_handler.b64_url_recode",
            return_value="csr",
        ), patch(
            "acme2certifier.cahandlers.aws_pca_ca_handler.cert_pem2der",
            return_value=b"der",
        ), patch(
            "acme2certifier.cahandlers.aws_pca_ca_handler.b64_encode",
            return_value="Y2VydA==",
        ), patch(
            "acme2certifier.cahandlers.aws_pca_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ):
            error, bundle, cert_raw, poll_id = self.cahandler.enroll("csr-b64")

        self.assertIsNone(error)
        self.assertIn("BEGIN CERTIFICATE", bundle)
        self.assertEqual(cert_raw, "Y2VydA==")
        self.assertTrue(poll_id.startswith("arn:aws:acm-pca:"))
        self.assertEqual(mock_api.call_args_list[0][0][0], "IssueCertificate")
        issue_payload = mock_api.call_args_list[0][0][1]
        self.assertIn("Csr", issue_payload)
        # CSR is base64 of PEM bytes
        self.assertEqual(
            base64.b64decode(issue_payload["Csr"]).decode("utf-8").splitlines()[0],
            "-----BEGIN CERTIFICATE REQUEST-----",
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    def test_012_get_certificate_polls_in_progress(self, mock_api):
        self._ready()
        self.cahandler.poll_timeout = 5
        self.cahandler.poll_interval = 0.01
        leaf = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"
        mock_api.side_effect = [
            RuntimeError("RequestInProgressException: pending"),
            {"Certificate": leaf, "CertificateChain": ""},
            {"Certificate": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"},
        ]
        cert_pem, chain_pem = self.cahandler._get_certificate("arn:cert")
        self.assertEqual(cert_pem, leaf)
        self.assertIn("BEGIN CERTIFICATE", chain_pem)
        self.assertEqual(mock_api.call_count, 3)

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    def test_013_handler_check(self, mock_api):
        self._ready()
        mock_api.return_value = {"CertificateAuthority": {"Status": "ACTIVE"}}
        self.assertIsNone(self.cahandler.handler_check())
        self.assertEqual(mock_api.call_args[0][0], "DescribeCertificateAuthority")

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.cert_serial_get")
    def test_014_revoke(self, mock_serial, mock_api):
        self._ready()
        mock_serial.return_value = "ABCD"
        mock_api.return_value = {}
        code, message, detail = self.cahandler.revoke("certraw", "keyCompromise")
        self.assertEqual(code, 200)
        self.assertIsNone(message)
        self.assertIsNone(detail)
        self.assertEqual(mock_api.call_args[0][0], "RevokeCertificate")
        self.assertEqual(mock_api.call_args[0][1]["RevocationReason"], "KEY_COMPROMISE")
        self.assertEqual(mock_api.call_args[0][1]["CertificateSerial"], "abcd")


if __name__ == "__main__":
    unittest.main()
