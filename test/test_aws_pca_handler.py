# -*- coding: utf-8 -*-
"""unittests for aws_pca_ca_handler"""

# pylint: disable=C0415, R0904, W0212
import base64
import configparser
import datetime
import hashlib
import sys
import unittest
from unittest.mock import MagicMock, patch

import requests

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
        mock_resp.text = (
            '{"CertificateArn":"arn:aws:acm-pca:eu-central-1:1:certificate/x"}'
        )
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
        self.assertEqual(
            mock_post.call_args.kwargs["headers"]["X-Amz-Target"],
            "ACMPrivateCA.IssueCertificate",
        )
        self.assertIn("Authorization", mock_post.call_args.kwargs["headers"])
        self.assertTrue(mock_post.call_args.kwargs["verify"])

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
            {
                "Certificate": "-----BEGIN CERTIFICATE-----\nICA\n-----END CERTIFICATE-----",
                "CertificateChain": "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----",
            },
        ]

        with (
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.build_pem_file",
                return_value="-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.b64_url_recode",
                return_value="csr",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.cert_pem2der",
                return_value=b"der",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.b64_encode",
                return_value="Y2VydA==",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.eab_profile_header_info_check",
                return_value=None,
            ),
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
        ica = "-----BEGIN CERTIFICATE-----\nICA\n-----END CERTIFICATE-----"
        root = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----"
        mock_api.side_effect = [
            RuntimeError("RequestInProgressException: pending"),
            {"Certificate": leaf, "CertificateChain": ""},
            {"Certificate": ica, "CertificateChain": root},
        ]
        cert_pem, chain_pem = self.cahandler._get_certificate("arn:cert")
        self.assertEqual(cert_pem, leaf)
        self.assertIn("ICA", chain_pem)
        self.assertIn("ROOT", chain_pem)
        self.assertEqual(mock_api.call_count, 3)

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    def test_012b_get_certificate_merges_partial_pca_chain(self, mock_api):
        """GetCertificate returns only ICA; CA API supplies ICA+root (deduped)."""
        self._ready()
        leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"
        ica = "-----BEGIN CERTIFICATE-----\nICA\n-----END CERTIFICATE-----"
        root = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----"
        mock_api.side_effect = [
            {"Certificate": leaf, "CertificateChain": ica},
            {"Certificate": ica, "CertificateChain": root},
        ]
        cert_pem, chain_pem = self.cahandler._get_certificate("arn:cert")
        self.assertEqual(cert_pem, leaf)
        self.assertEqual(chain_pem.count("BEGIN CERTIFICATE"), 2)
        self.assertIn("ICA", chain_pem)
        self.assertIn("ROOT", chain_pem)
        self.assertEqual(
            mock_api.call_args_list[1][0][0], "GetCertificateAuthorityCertificate"
        )

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

    def test_015_sigv4_with_session_token(self):
        """session token is included in SigV4 signed headers"""
        from acme2certifier.cahandlers.aws_pca_ca_handler import _sigv4_sign

        now = datetime.datetime(2024, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
        headers = _sigv4_sign(
            method="POST",
            url="https://acm-pca.eu-central-1.amazonaws.com/",
            body=b"{}",
            amz_target="ACMPrivateCA.IssueCertificate",
            region="eu-central-1",
            access_key="AKIATEST",
            secret_key="secret",
            session_token="session-token",
            now=now,
        )
        self.assertEqual(headers["X-Amz-Security-Token"], "session-token")
        self.assertIn("x-amz-security-token", headers["Authorization"].lower())

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._config_load")
    def test_016_enter_loads_config_when_arn_missing(self, mock_load):
        """__enter__ loads config when certificate_authority_arn is unset"""
        with self.cahandler as handler:
            self.assertIs(handler, self.cahandler)
        mock_load.assert_called_once_with()

    def test_017_enter_skips_load_when_arn_set(self):
        """__enter__ skips config load when ARN is already set"""
        self.cahandler.certificate_authority_arn = self.ca_arn
        with patch.object(self.cahandler, "_config_load") as mock_load:
            with self.cahandler:
                pass
            mock_load.assert_not_called()

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.config_proxy_load", return_value={})
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_enroll_config_log_load",
        return_value=(False, []),
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_headerinfo_load",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_profile_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_eab_profile_load",
        return_value=(False, None),
    )
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.config_option_load")
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.load_config")
    def test_018_config_load_full(
        self,
        mock_load_cfg,
        mock_option,
        mock_eab,
        mock_profiles,
        mock_header,
        mock_enroll,
        mock_proxy,
    ):
        """_config_load applies CAhandler options and helpers"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "aws_region": "eu-west-1",
            "certificate_authority_arn": self.ca_arn,
            "signing_algorithm": "SHA384WITHRSA",
            "template_arn": "arn:aws:acm-pca:::template/EndEntity/1",
            "endpoint_url": "http://localhost:4566",
            "validity_days": "90",
            "poll_timeout": "30",
            "request_timeout": "15",
            "request_retries": "2",
            "poll_interval": "0.5",
        }
        mock_load_cfg.return_value = parser
        mock_option.side_effect = ["AKIATEST", "secret", "tok"]
        self.cahandler._config_load()
        self.assertEqual(self.cahandler.aws_region, "eu-west-1")
        self.assertEqual(self.cahandler.certificate_authority_arn, self.ca_arn)
        self.assertEqual(self.cahandler.signing_algorithm, "SHA384WITHRSA")
        self.assertEqual(
            self.cahandler.template_arn, "arn:aws:acm-pca:::template/EndEntity/1"
        )
        self.assertEqual(self.cahandler.endpoint_url, "http://localhost:4566")
        self.assertEqual(self.cahandler.aws_access_key_id, "AKIATEST")
        self.assertEqual(self.cahandler.aws_secret_access_key, "secret")
        self.assertEqual(self.cahandler.aws_session_token, "tok")
        self.assertEqual(self.cahandler.validity_days, 90)
        self.assertEqual(self.cahandler.poll_timeout, 30)
        self.assertEqual(self.cahandler.request_timeout, 15)
        self.assertEqual(self.cahandler.request_retries, 2)
        self.assertEqual(self.cahandler.poll_interval, 0.5)
        mock_eab.assert_called_once()
        mock_profiles.assert_called_once()
        mock_header.assert_called_once()
        mock_enroll.assert_called_once()
        mock_proxy.assert_called_once()

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.config_proxy_load", return_value={})
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_enroll_config_log_load",
        return_value=(False, []),
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_headerinfo_load",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_profile_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_eab_profile_load",
        return_value=(False, None),
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_option_load",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.load_config")
    def test_019_config_load_bad_ints_and_env(
        self,
        mock_load_cfg,
        _mock_option,
        _mock_eab,
        _mock_profiles,
        _mock_header,
        _mock_enroll,
        _mock_proxy,
    ):
        """invalid numeric options log errors; AWS env vars fill credentials"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "aws_region": "eu-central-1",
            "certificate_authority_arn": self.ca_arn,
            "validity_days": "nope",
            "poll_interval": "bad",
        }
        mock_load_cfg.return_value = parser
        with (
            patch.dict(
                "os.environ",
                {
                    "AWS_ACCESS_KEY_ID": "env-key",
                    "AWS_SECRET_ACCESS_KEY": "env-secret",
                    "AWS_SESSION_TOKEN": "env-token",
                },
                clear=False,
            ),
            self.assertLogs("test_a2c", level="INFO") as lcm,
        ):
            self.cahandler._config_load()
        self.assertEqual(self.cahandler.aws_access_key_id, "env-key")
        self.assertEqual(self.cahandler.aws_secret_access_key, "env-secret")
        self.assertEqual(self.cahandler.aws_session_token, "env-token")
        self.assertTrue(
            any("Failed to parse validity_days parameter" in line for line in lcm.output)
        )
        self.assertTrue(
            any("Failed to parse poll_interval parameter" in line for line in lcm.output)
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.config_proxy_load", return_value={})
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_enroll_config_log_load",
        return_value=(False, []),
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_headerinfo_load",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_profile_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_eab_profile_load",
        return_value=(False, None),
    )
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.load_config")
    def test_020_config_load_without_cahandler_section(
        self,
        mock_load_cfg,
        _mock_eab,
        _mock_profiles,
        _mock_header,
        _mock_enroll,
        _mock_proxy,
    ):
        """_config_load tolerates missing CAhandler section"""
        mock_load_cfg.return_value = configparser.ConfigParser()
        self.cahandler._config_load()
        self.assertIsNone(self.cahandler.aws_region)

    def test_021_api_error_message_fallback(self):
        """non-dict / empty error bodies fall back to HTTP status text"""
        self.assertEqual(
            self.cahandler._api_error_message(502, "gateway"),
            "HTTP 502: gateway",
        )
        self.assertEqual(
            self.cahandler._api_error_message(400, {}),
            "HTTP 400: {}",
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.time.sleep")
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.requests.post")
    def test_022_api_call_json_error_retry_and_non_dict(self, mock_post, mock_sleep):
        """API call retries transient HTTP, handles bad JSON, rejects non-dict"""
        self._ready()
        self.cahandler.request_retries = 1

        bad_json = MagicMock()
        bad_json.status_code = 200
        bad_json.text = "not-json"
        bad_json.json.side_effect = ValueError("nope")

        transient = MagicMock()
        transient.status_code = 503
        transient.text = '{"message":"busy"}'
        transient.json.return_value = {"message": "busy"}

        ok = MagicMock()
        ok.status_code = 200
        ok.text = '{"ok":true}'
        ok.json.return_value = {"ok": True}

        mock_post.side_effect = [transient, ok]
        self.assertEqual(self.cahandler._api_call("DescribeCertificateAuthority", {}), {"ok": True})
        mock_sleep.assert_called()

        mock_post.side_effect = [bad_json]
        self.cahandler.request_retries = 0
        with self.assertRaises(RuntimeError) as ctx:
            self.cahandler._api_call("DescribeCertificateAuthority", {})
        self.assertIn("Unexpected ACM PCA response", str(ctx.exception))

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.time.sleep")
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.requests.post")
    def test_023_api_call_request_exception_retries(self, mock_post, mock_sleep):
        """RequestException retries then raises RuntimeError"""
        self._ready()
        self.cahandler.request_retries = 1
        mock_post.side_effect = [
            requests.RequestException("net1"),
            requests.RequestException("net2"),
        ]
        with self.assertRaises(RuntimeError) as ctx:
            self.cahandler._api_call("DescribeCertificateAuthority", {})
        self.assertIn("net2", str(ctx.exception))
        mock_sleep.assert_called()

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    def test_024_issue_certificate_with_template(self, mock_api):
        """template_arn is forwarded to IssueCertificate"""
        self._ready()
        self.cahandler.template_arn = "arn:aws:acm-pca:::template/EndEntity/1"
        mock_api.return_value = {"CertificateArn": "arn:cert"}
        with patch.object(self.cahandler, "_csr_pem", return_value="CSR"):
            arn = self.cahandler._issue_certificate("CSR")
        self.assertEqual(arn, "arn:cert")
        self.assertEqual(
            mock_api.call_args[0][1]["TemplateArn"],
            "arn:aws:acm-pca:::template/EndEntity/1",
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.time.sleep")
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.time.time")
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    def test_025_get_certificate_timeout(self, mock_api, mock_time, mock_sleep):
        """poll timeout raises TimeoutError after RequestInProgress"""
        self._ready()
        self.cahandler.poll_timeout = 1
        self.cahandler.poll_interval = 0.01
        mock_api.side_effect = RuntimeError("RequestInProgressException")
        mock_time.side_effect = [100.0, 100.5, 101.5]
        with self.assertRaises(TimeoutError) as ctx:
            self.cahandler._get_certificate("arn:cert")
        self.assertIn("Timed out waiting for certificate", str(ctx.exception))
        mock_sleep.assert_called()

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.enrollment_config_log")
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    def test_026_enroll_logs_config_and_errors(self, mock_api, mock_enroll_log):
        """enrollment_config_log runs; enroll errors are returned"""
        self._ready()
        self.cahandler.enrollment_config_log = True
        leaf = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"
        mock_api.side_effect = [
            {"CertificateArn": "arn:cert"},
            {"Certificate": leaf, "CertificateChain": ""},
            {
                "Certificate": "-----BEGIN CERTIFICATE-----\nICA\n-----END CERTIFICATE-----",
                "CertificateChain": "",
            },
        ]
        with (
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.build_pem_file",
                return_value="-----BEGIN CERTIFICATE REQUEST-----\nx\n-----END CERTIFICATE REQUEST-----\n",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.b64_url_recode",
                return_value="csr",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.cert_pem2der",
                return_value=b"der",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.b64_encode",
                return_value="Y2VydA==",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.eab_profile_header_info_check",
                return_value=None,
            ),
        ):
            error, bundle, cert_raw, poll_id = self.cahandler.enroll("csr")
        self.assertIsNone(error)
        self.assertIsNotNone(bundle)
        self.assertEqual(cert_raw, "Y2VydA==")
        self.assertEqual(poll_id, "arn:cert")
        mock_enroll_log.assert_called_once()

        mock_api.side_effect = RuntimeError("issue failed")
        with (
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.build_pem_file",
                return_value="CSR",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.b64_url_recode",
                return_value="csr",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.eab_profile_header_info_check",
                return_value=None,
            ),
            self.assertLogs("test_a2c", level="INFO") as lcm,
        ):
            error, bundle, cert_raw, poll_id = self.cahandler.enroll("csr")
        self.assertEqual(error, "issue failed")
        self.assertIsNone(bundle)
        self.assertTrue(
            any("Failed to enroll certificate: issue failed" in line for line in lcm.output)
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    def test_027_handler_check_api_error(self, mock_api):
        """handler_check surfaces DescribeCertificateAuthority failures"""
        self._ready()
        mock_api.side_effect = RuntimeError("denied")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            err = self.cahandler.handler_check()
        self.assertEqual(err, "denied")
        self.assertTrue(
            any("AWS PCA handler_check failed: denied" in line for line in lcm.output)
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._get_certificate")
    def test_028_poll_success_and_errors(self, mock_get):
        """poll downloads by ARN and maps missing/failure cases"""
        self._ready()
        leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"
        mock_get.return_value = (leaf, "")
        with (
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.cert_pem2der",
                return_value=b"der",
            ),
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.b64_encode",
                return_value="raw",
            ),
        ):
            error, bundle, cert_raw, poll_id, rejected = self.cahandler.poll(
                "cert", "arn:cert", "csr"
            )
        self.assertIsNone(error)
        self.assertEqual(bundle, leaf)
        self.assertEqual(cert_raw, "raw")
        self.assertEqual(poll_id, "arn:cert")
        self.assertFalse(rejected)

        error, *_rest = self.cahandler.poll("cert", "", "csr")
        self.assertEqual(error, "Missing poll_identifier (certificate ARN).")

        mock_get.side_effect = TimeoutError("slow")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            error, bundle, cert_raw, poll_id, rejected = self.cahandler.poll(
                "cert", "arn:cert", "csr"
            )
        self.assertEqual(error, "slow")
        self.assertTrue(
            any("Failed to poll certificate: slow" in line for line in lcm.output)
        )

    def test_029_revoke_config_and_serial_errors(self):
        """revoke returns ACME serverInternal on config/serial failures"""
        code, message, detail = self.cahandler.revoke("certraw")
        self.assertEqual(code, 500)
        self.assertEqual(message, "urn:ietf:params:acme:error:serverInternal")
        self.assertIn("aws_region", detail)

        self._ready()
        with (
            patch(
                "acme2certifier.cahandlers.aws_pca_ca_handler.cert_serial_get",
                return_value=None,
            ),
            self.assertLogs("test_a2c", level="INFO") as lcm,
        ):
            code, message, detail = self.cahandler.revoke("certraw")
        self.assertEqual(code, 500)
        self.assertEqual(detail, "Failed to parse certificate serial")
        self.assertTrue(
            any("Failed to get certificate serial number" in line for line in lcm.output)
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.eab_profile_revocation_check")
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.cert_serial_get")
    def test_030_revoke_eab_and_api_error(self, mock_serial, mock_api, mock_eab):
        """revoke runs EAB profiling check and maps API failures"""
        self._ready()
        self.cahandler.eab_profiling = True
        mock_serial.return_value = "ABCD"
        mock_api.side_effect = RuntimeError("revoke denied")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            code, message, detail = self.cahandler.revoke("certraw", "keyCompromise")
        self.assertEqual(code, 500)
        self.assertEqual(message, "urn:ietf:params:acme:error:serverInternal")
        self.assertEqual(detail, "revoke denied")
        mock_eab.assert_called_once()
        self.assertTrue(
            any("Failed to revoke certificate: revoke denied" in line for line in lcm.output)
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.CAhandler._api_call")
    def test_031_get_certificate_non_progress_error(self, mock_api):
        """non-RequestInProgress errors are re-raised immediately"""
        self._ready()
        mock_api.side_effect = RuntimeError("ValidationException: bad arn")
        with self.assertRaises(RuntimeError) as ctx:
            self.cahandler._get_certificate("arn:cert")
        self.assertIn("ValidationException", str(ctx.exception))

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.requests.post")
    def test_032_api_call_defensive_empty_attempts(self, mock_post):
        """defensive final raise when the retry loop never runs"""
        self._ready()
        with patch("builtins.max", return_value=-1):
            with self.assertRaises(RuntimeError) as ctx:
                self.cahandler._api_call("DescribeCertificateAuthority", {})
        self.assertEqual(str(ctx.exception), "ACM PCA request failed")
        mock_post.assert_not_called()

    def test_033_tls_verify_defaults_and_options(self):
        """_tls_verify maps verify / ca_bundle like mscepces"""
        self.assertTrue(self.cahandler._tls_verify())
        self.cahandler.ca_bundle = "/tmp/custom-ca.pem"
        self.assertEqual(self.cahandler._tls_verify(), "/tmp/custom-ca.pem")
        self.cahandler.ca_bundle = False
        self.assertFalse(self.cahandler._tls_verify())
        self.cahandler.ca_bundle = True
        self.cahandler.verify = False
        self.assertFalse(self.cahandler._tls_verify())

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.config_proxy_load", return_value={})
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_enroll_config_log_load",
        return_value=(False, []),
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_headerinfo_load",
        return_value=False,
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_profile_load",
        return_value={},
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_eab_profile_load",
        return_value=(False, None),
    )
    @patch(
        "acme2certifier.cahandlers.aws_pca_ca_handler.config_option_load",
        return_value=None,
    )
    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.load_config")
    def test_034_config_load_ca_bundle_and_verify(
        self,
        mock_load_cfg,
        _mock_option,
        _mock_eab,
        _mock_profiles,
        _mock_header,
        _mock_enroll,
        _mock_proxy,
    ):
        """ca_bundle path and verify=False load with MITM warning"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "aws_region": "eu-central-1",
            "certificate_authority_arn": self.ca_arn,
            "ca_bundle": "/etc/ssl/private-ca.pem",
            "verify": "False",
        }
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            self.cahandler._config_load()
        self.assertEqual(self.cahandler.ca_bundle, "/etc/ssl/private-ca.pem")
        self.assertFalse(self.cahandler.verify)
        self.assertFalse(self.cahandler._tls_verify())
        self.assertTrue(
            any(
                "TLS certificate verification is disabled" in line
                for line in lcm.output
            )
        )

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.requests.post")
    def test_035_api_call_passes_ca_bundle_verify(self, mock_post):
        """API calls forward ca_bundle path as requests verify= argument"""
        self._ready()
        self.cahandler.ca_bundle = "/tmp/ca.pem"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"ok":true}'
        mock_resp.json.return_value = {"ok": True}
        mock_post.return_value = mock_resp
        self.cahandler._api_call("DescribeCertificateAuthority", {})
        self.assertEqual(mock_post.call_args.kwargs["verify"], "/tmp/ca.pem")


if __name__ == "__main__":
    unittest.main()
