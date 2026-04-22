# -*- coding: utf-8 -*-
"""unittests for dogtag rest handler"""
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, Mock
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestCAhandler(unittest.TestCase):
    def setUp(self):
        """setup unittest"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from examples.ca_handler.dogtag_ca_handler import (
            CAhandler,
            update_validity_attributes,
            approve_profile_get,
        )

        self.cahandler = CAhandler(False, self.logger)
        self.update_validity_attributes = update_validity_attributes
        self.approve_profile_get = approve_profile_get

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    def test_002_config_load_missing_keys(self):
        # Should not raise even if config is missing keys
        parser = configparser.ConfigParser()
        parser["foo"] = {"foo": "bar"}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            with self.assertLogs("test_a2c", level="DEBUG") as lcm:
                self.cahandler._config_load()
                self.assertIn(
                    "DEBUG:test_a2c:CAhandler._config_load()",
                    lcm.output,
                )
                self.assertIn(
                    "DEBUG:test_a2c:CAhandler._config_load() ended",
                    lcm.output,
                )

    def test_003_config_load_api_host(self):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"api_host": "https://example.com"}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.api_host = None
            self.cahandler._config_load()
            self.assertEqual(self.cahandler.api_host, "https://example.com")

    def test_004_config_load_client_cert(self):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"client_cert": "/tmp/cert.pem"}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.client_cert = None
            self.cahandler._config_load()
            self.assertEqual(self.cahandler.client_cert, "/tmp/cert.pem")

    def test_005_config_load_client_key(self):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"client_key": "/tmp/key.pem"}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.client_key = None
            self.cahandler._config_load()
            self.assertEqual(self.cahandler.client_key, "/tmp/key.pem")

    def test_006_config_load_profile(self):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"profile": "testprofile"}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.profile = None
            self.cahandler._config_load()
            self.assertEqual(self.cahandler.profile, "testprofile")

    def test_007_config_load_ca_bundle_str(self):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_bundle": "some_bundle.pem"}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.ca_bundle = None
            self.cahandler._config_load()
            self.assertEqual(self.cahandler.ca_bundle, "some_bundle.pem")

    def test_008_config_load_ca_bundle_bool(self):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_bundle": "true"}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.ca_bundle = None
            self.cahandler._config_load()
            self.assertTrue(self.cahandler.ca_bundle)

    def test_009_config_load_certrequest_approve(self):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"certrequest_approve": "yes"}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.certrequest_approve = False
            self.cahandler._config_load()
            self.assertTrue(self.cahandler.certrequest_approve)

    @patch(
        "examples.ca_handler.dogtag_ca_handler.config_eab_profile_load",
        return_value=(True, "handler"),
    )
    def test_config_load_eab_profile(self, mock_eab):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.eab_profiling = False
            self.cahandler.eab_handler = None
            self.cahandler._config_load()
            self.assertTrue(self.cahandler.eab_profiling)
            self.assertEqual(self.cahandler.eab_handler, "handler")

    @patch("examples.ca_handler.dogtag_ca_handler.CAhandler._config_passphrase_load")
    def test_010_config_load_cert_passphrase(self, mock_passphrase):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler._config_load()
            mock_passphrase.assert_called()

    @patch(
        "examples.ca_handler.dogtag_ca_handler.config_profile_load",
        return_value={"p": 1},
    )
    def test_011_config_load_profiles(self, mock_profile):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.profiles = {}
            self.cahandler._config_load()
            self.assertEqual(self.cahandler.profiles, {"p": 1})

    @patch(
        "examples.ca_handler.dogtag_ca_handler.config_headerinfo_load",
        return_value=True,
    )
    def test_012_config_load_header_info(self, mock_header):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.header_info_field = False
            self.cahandler._config_load()
            self.assertTrue(self.cahandler.header_info_field)

    @patch(
        "examples.ca_handler.dogtag_ca_handler.config_enroll_config_log_load",
        return_value=("log", ["skip"]),
    )
    def test_013_config_load_enrollment_config_log(self, mock_enroll):
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {}
        with patch(
            "examples.ca_handler.dogtag_ca_handler.load_config", return_value=parser
        ):
            self.cahandler.enrollment_config_log = False
            self.cahandler.enrollment_config_log_skip_list = []
            self.cahandler._config_load()
            self.assertEqual(self.cahandler.enrollment_config_log, "log")
            self.assertEqual(self.cahandler.enrollment_config_log_skip_list, ["skip"])

    def test_014_api_post_success(self):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "ok"}
        self.cahandler.session = Mock()
        self.cahandler.api_host = "https://api.example.com"
        self.cahandler.proxy = None
        self.cahandler.ca_bundle = True
        self.cahandler.request_timeout = 5
        self.cahandler.session.post.return_value = mock_response
        code, content = self.cahandler._api_post("/test", {"foo": "bar"})
        self.assertEqual(code, 200)
        self.assertEqual(content, {"result": "ok"})

    def test_015_api_post_error(self):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = Exception("bad json")
        self.cahandler.session = Mock()
        self.cahandler.api_host = "https://api.example.com"
        self.cahandler.proxy = None
        self.cahandler.ca_bundle = True
        self.cahandler.request_timeout = 5
        self.cahandler.session.post.return_value = mock_response
        with patch.object(self.cahandler.logger, "error") as mock_log:
            code, content = self.cahandler._api_post("/test", {"foo": "bar"})
            self.assertEqual(code, 200)
            self.assertIn("error", content)
            mock_log.assert_called()

    def test_016_api_post_exception(self):
        self.cahandler.session = Mock()
        self.cahandler.api_host = "https://api.example.com"
        self.cahandler.proxy = None
        self.cahandler.ca_bundle = True
        self.cahandler.request_timeout = 5
        self.cahandler.session.post.side_effect = Exception("network error")
        with patch.object(self.cahandler.logger, "error") as mock_log:
            code, content = self.cahandler._api_post("/test", {"foo": "bar"})
            self.assertEqual(code, 500)
            self.assertIn("error", content)
            mock_log.assert_called()

    def test_017_api_post_creates_session(self):
        # Remove session to force _login call
        self.cahandler.session = None
        self.cahandler.api_host = "https://api.example.com"
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "ok"}
        mock_session.post.return_value = mock_response

        def fake_login():
            self.cahandler.session = mock_session

        with patch.object(
            self.cahandler, "_login", side_effect=fake_login
        ) as mock_login:
            code, content = self.cahandler._api_post("/test", {"foo": "bar"})
            mock_login.assert_called()
            self.assertEqual(code, 200)
            self.assertEqual(content, {"result": "ok"})

    def test_018_api_get_success(self):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "ok"}
        self.cahandler.session = Mock()
        self.cahandler.api_host = "https://api.example.com"
        self.cahandler.proxy = None
        self.cahandler.ca_bundle = True
        self.cahandler.request_timeout = 5
        self.cahandler.session.get.return_value = mock_response
        code, content = self.cahandler._api_get("/test")
        self.assertEqual(code, 200)
        self.assertEqual(content, {"result": "ok"})

    def test_019_api_get_json_error(self):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = Exception("bad json")
        self.cahandler.session = Mock()
        self.cahandler.api_host = "https://api.example.com"
        self.cahandler.proxy = None
        self.cahandler.ca_bundle = True
        self.cahandler.request_timeout = 5
        self.cahandler.session.get.return_value = mock_response
        with patch.object(self.cahandler.logger, "error") as mock_log:
            code, content = self.cahandler._api_get("/test")
            self.assertEqual(code, 200)
            self.assertIn("error", content)
            mock_log.assert_called()

    def test_020_api_get_exception(self):
        self.cahandler.session = Mock()
        self.cahandler.api_host = "https://api.example.com"
        self.cahandler.proxy = None
        self.cahandler.ca_bundle = True
        self.cahandler.request_timeout = 5
        self.cahandler.session.get.side_effect = Exception("network error")
        with patch.object(self.cahandler.logger, "error") as mock_log:
            code, content = self.cahandler._api_get("/test")
            self.assertEqual(code, 500)
            self.assertIn("error", content)
            mock_log.assert_called()

    def test_021_api_get_creates_session(self):
        self.cahandler.session = None
        self.cahandler.api_host = "https://api.example.com"
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "ok"}
        mock_session.get.return_value = mock_response

        def fake_login():
            self.cahandler.session = mock_session

        with patch.object(
            self.cahandler, "_login", side_effect=fake_login
        ) as mock_login:
            code, content = self.cahandler._api_get("/test")
            mock_login.assert_called()
            self.assertEqual(code, 200)
            self.assertEqual(content, {"result": "ok"})

    def test_022_api_version_get_success(self):
        self.cahandler.api_version = None
        self.cahandler.REST_INFO = "/info"
        version_dict = {"version": "1.2.3", "other": "x"}
        with patch.object(
            self.cahandler, "_api_get", return_value=(200, version_dict)
        ) as mock_get:
            with patch.object(self.cahandler.logger, "info") as mock_log:
                self.cahandler._api_version_get()
                mock_get.assert_called_with("/info")
                self.assertEqual(self.cahandler.api_version, "1.2.3")
                mock_log.assert_called()

    def test_023_api_version_get_success_case_insensitive(self):
        self.cahandler.api_version = None
        self.cahandler.REST_INFO = "/info"
        version_dict = {"Version": "2.0.0"}
        with patch.object(self.cahandler, "_api_get", return_value=(200, version_dict)):
            self.cahandler._api_version_get()
            self.assertEqual(self.cahandler.api_version, "2.0.0")

    def test_024_api_version_get_failure(self):
        self.cahandler.api_version = None
        self.cahandler.REST_INFO = "/info"
        with patch.object(
            self.cahandler, "_api_get", return_value=(404, {"error": "not found"})
        ) as mock_get:
            with patch.object(self.cahandler.logger, "error") as mock_log:
                self.cahandler._api_version_get()
                mock_get.assert_called_with("/info")
                self.assertEqual(self.cahandler.api_version, "unknown")
                mock_log.assert_called()

    def test_025_api_version_get_non_dict_content(self):
        self.cahandler.api_version = None
        self.cahandler.REST_INFO = "/info"
        with patch.object(self.cahandler, "_api_get", return_value=(200, "notadict")):
            self.cahandler._api_version_get()
            self.assertEqual(self.cahandler.api_version, "unknown")

    def test_026_get_approval_nonce_success(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        with patch.object(
            self.cahandler, "_api_get", return_value=(200, {"nonce": "abc123"})
        ) as mock_get:
            with patch.object(self.cahandler.logger, "debug") as mock_log:
                error, nonce = self.cahandler._get_approval_nonce("reqid")
                mock_get.assert_called_with("/agent/reqid")
                self.assertIsNone(error)
                self.assertEqual(nonce, "abc123")
                # Check that the nonce logging statement was called
                calls = [c[0][0] for c in mock_log.call_args_list]
                self.assertTrue(
                    any("Received nonce for approval" in msg for msg in calls)
                )

    def test_027_get_approval_nonce_status_logging(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        response = {"requestStatus": "pending", "nonce": "abc123"}
        with patch.object(
            self.cahandler, "_api_get", return_value=(200, response)
        ) as mock_get:
            with patch.object(self.cahandler.logger, "debug") as mock_log:
                error, nonce = self.cahandler._get_approval_nonce("reqid")
                mock_get.assert_called_with("/agent/reqid")
                # Check that the status logging statement was called
                calls = [c[0][0] for c in mock_log.call_args_list]
                self.assertTrue(any("Certificate request" in msg for msg in calls))

    def test_028_get_approval_nonce_failure(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        with patch.object(
            self.cahandler, "_api_get", return_value=(404, {"error": "not found"})
        ) as mock_get:
            with patch.object(self.cahandler.logger, "error") as mock_log:
                error, nonce = self.cahandler._get_approval_nonce("reqid")
                mock_get.assert_called_with("/agent/reqid")
                self.assertEqual(
                    error, "Failed to get nonce for certificate request approval."
                )
                self.assertIsNone(nonce)
                mock_log.assert_called()

    def test_029_get_approval_nonce_no_nonce(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        # 200 but no nonce in response
        with patch.object(
            self.cahandler, "_api_get", return_value=(200, {"foo": "bar"})
        ):
            with patch.object(self.cahandler.logger, "error") as mock_log:
                error, nonce = self.cahandler._get_approval_nonce("reqid")
                self.assertEqual(
                    error, "Failed to get nonce for certificate request approval."
                )
                self.assertIsNone(nonce)
                mock_log.assert_called()

    def test_030_certrequest_approve_nonce_error(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        with patch.object(
            self.cahandler, "_get_approval_nonce", return_value=("nonce error", None)
        ) as mock_nonce:
            with patch.object(self.cahandler.logger, "error") as mock_log:
                error, cert_bundle, cert_raw = self.cahandler._certrequest_approve(
                    "reqid"
                )
                mock_nonce.assert_called_with("reqid")
                self.assertEqual(error, "nonce error")
                self.assertIsNone(cert_bundle)
                self.assertIsNone(cert_raw)
                # Check log message for nonce error (line 406)
                calls = [c[0][0] for c in mock_log.call_args_list]
                self.assertTrue(
                    any("Cannot approve certificate request" in msg for msg in calls)
                )

    def test_031_certrequest_approve_missing_certId(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        self.cahandler.REST_CERTREQUESTS = "/certreqs"
        with patch.object(
            self.cahandler, "_get_approval_nonce", return_value=(None, "nonce")
        ):
            with patch(
                "examples.ca_handler.dogtag_ca_handler.approve_profile_get",
                return_value={},
            ):
                with patch.object(self.cahandler, "_api_post", return_value=(200, {})):
                    with patch.object(
                        self.cahandler,
                        "_api_get",
                        return_value=(200, {"requestStatus": "approved"}),
                    ):
                        (
                            error,
                            cert_bundle,
                            cert_raw,
                        ) = self.cahandler._certrequest_approve("reqid")
                        self.assertIn("certId is missing", error)
                        self.assertIsNone(cert_bundle)
                        self.assertIsNone(cert_raw)

    def test_032_certrequest_approve_no_request_status(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        self.cahandler.REST_CERTREQUESTS = "/certreqs"
        with patch.object(
            self.cahandler, "_get_approval_nonce", return_value=(None, "nonce")
        ):
            with patch(
                "examples.ca_handler.dogtag_ca_handler.approve_profile_get",
                return_value={},
            ):
                with patch.object(self.cahandler, "_api_post", return_value=(200, {})):
                    with patch.object(
                        self.cahandler, "_api_get", return_value=(200, {})
                    ):
                        with patch.object(self.cahandler.logger, "error") as mock_log:
                            (
                                error,
                                cert_bundle,
                                cert_raw,
                            ) = self.cahandler._certrequest_approve("reqid")
                            self.assertIn(
                                "Failed to approve certificate request", error
                            )
                            self.assertIsNone(cert_bundle)
                            self.assertIsNone(cert_raw)
                            # Check log message for no requestStatus (line 417)
                            calls = [c[0][0] for c in mock_log.call_args_list]
                            self.assertTrue(
                                any(
                                    "Failed to get certificate request status after approval attempt"
                                    in msg
                                    for msg in calls
                                )
                            )

    def test_033_certrequest_approve_cert_fetch_raw_error(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        self.cahandler.REST_CERTREQUESTS = "/certreqs"
        self.cahandler.REST_CERTS = "/certs/"
        with patch.object(
            self.cahandler, "_get_approval_nonce", return_value=(None, "nonce")
        ):
            with patch(
                "examples.ca_handler.dogtag_ca_handler.approve_profile_get",
                return_value={},
            ):
                with patch.object(self.cahandler, "_api_post", return_value=(200, {})):
                    # First _api_get returns requestStatus+certId, second returns missing Encoded
                    with patch.object(
                        self.cahandler,
                        "_api_get",
                        side_effect=[
                            (200, {"requestStatus": "approved", "certId": "cid"}),
                            (200, {"PKCS7CertChain": "chaindata"}),
                        ],
                    ):
                        with patch(
                            "examples.ca_handler.dogtag_ca_handler.pkcs7_to_pem",
                            return_value="pemchain",
                        ):
                            with patch(
                                "examples.ca_handler.dogtag_ca_handler.b64_decode",
                                return_value=b"bytes",
                            ):
                                with patch(
                                    "examples.ca_handler.dogtag_ca_handler.cert_pem2der",
                                    return_value=b"der",
                                ):
                                    with patch(
                                        "examples.ca_handler.dogtag_ca_handler.b64_encode",
                                        return_value="rawcert",
                                    ):
                                        with patch.object(
                                            self.cahandler.logger, "error"
                                        ) as mock_log:
                                            (
                                                error,
                                                cert_bundle,
                                                cert_raw,
                                            ) = self.cahandler._certrequest_approve(
                                                "reqid"
                                            )
                                            self.assertIn("raw certificate data", error)
                                            self.assertEqual(cert_bundle, "pemchain")
                                            self.assertIsNone(cert_raw)
                                            # Check log message for raw cert error (line 412)
                                            calls = [
                                                c[0][0] for c in mock_log.call_args_list
                                            ]
                                            self.assertTrue(
                                                any(
                                                    "failed to fetch raw certificate data"
                                                    in msg
                                                    for msg in calls
                                                )
                                            )

    def test_034_certrequest_approve_cert_fetch_chain_error(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        self.cahandler.REST_CERTREQUESTS = "/certreqs"
        self.cahandler.REST_CERTS = "/certs/"
        with patch.object(
            self.cahandler, "_get_approval_nonce", return_value=(None, "nonce")
        ):
            with patch(
                "examples.ca_handler.dogtag_ca_handler.approve_profile_get",
                return_value={},
            ):
                with patch.object(self.cahandler, "_api_post", return_value=(200, {})):
                    # First _api_get returns requestStatus+certId, second returns Encoded but missing PKCS7CertChain
                    with patch.object(
                        self.cahandler,
                        "_api_get",
                        side_effect=[
                            (200, {"requestStatus": "approved", "certId": "cid"}),
                            (200, {"Encoded": "encodeddata"}),
                        ],
                    ):
                        with patch(
                            "examples.ca_handler.dogtag_ca_handler.pkcs7_to_pem",
                            return_value=None,
                        ):
                            with patch(
                                "examples.ca_handler.dogtag_ca_handler.b64_decode",
                                return_value=b"bytes",
                            ):
                                with patch(
                                    "examples.ca_handler.dogtag_ca_handler.cert_pem2der",
                                    return_value=b"der",
                                ):
                                    with patch(
                                        "examples.ca_handler.dogtag_ca_handler.b64_encode",
                                        return_value="rawcert",
                                    ):
                                        with patch.object(
                                            self.cahandler.logger, "error"
                                        ) as mock_log:
                                            (
                                                error,
                                                cert_bundle,
                                                cert_raw,
                                            ) = self.cahandler._certrequest_approve(
                                                "reqid"
                                            )
                                            self.assertIn(
                                                "certificate chain data", error
                                            )
                                            self.assertIsNone(cert_bundle)
                                            self.assertEqual(cert_raw, "rawcert")
                                            # Check log message for chain error (line 415)
                                            calls = [
                                                c[0][0] for c in mock_log.call_args_list
                                            ]
                                            self.assertTrue(
                                                any(
                                                    "failed to fetch certificate chain data"
                                                    in msg
                                                    for msg in calls
                                                )
                                            )

    def test_035_certrequest_approve_cert_fetch_fail(self):
        self.cahandler.REST_AGENT_CERTREQUESTS = "/agent/"
        self.cahandler.REST_CERTREQUESTS = "/certreqs"
        self.cahandler.REST_CERTS = "/certs/"
        with patch.object(
            self.cahandler, "_get_approval_nonce", return_value=(None, "nonce")
        ):
            with patch(
                "examples.ca_handler.dogtag_ca_handler.approve_profile_get",
                return_value={},
            ):
                with patch.object(self.cahandler, "_api_post", return_value=(200, {})):
                    # First _api_get returns requestStatus+certId, second returns code!=200
                    with patch.object(
                        self.cahandler,
                        "_api_get",
                        side_effect=[
                            (200, {"requestStatus": "approved", "certId": "cid"}),
                            (500, {"error": "fail"}),
                        ],
                    ):
                        (
                            error,
                            cert_bundle,
                            cert_raw,
                        ) = self.cahandler._certrequest_approve("reqid")
                        self.assertIn("failed to fetch certificate data", error)
                        self.assertIsNone(cert_bundle)
                        self.assertIsNone(cert_raw)

    def test_036_parse_cert_key_usage_and_eku(self):
        # Mock the certificate and its extensions to ensure print is called
        class DummyKU:
            digital_signature = True
            content_commitment = False
            key_encipherment = False
            data_encipherment = False
            key_agreement = False
            key_cert_sign = False
            crl_sign = False

        class DummyEKU:
            _name = "serverAuth"
            dotted_string = "1.3.6.1.5.5.7.3.1"

        class DummyExt:
            def __init__(self, value):
                self.value = value

        class DummyCert:
            class extensions:
                @staticmethod
                def get_extension_for_class(cls):
                    if cls.__name__ == "KeyUsage":
                        return DummyExt(DummyKU())
                    if cls.__name__ == "ExtendedKeyUsage":
                        return DummyExt([DummyEKU()])
                    raise Exception("ExtensionNotFound")

        with patch(
            "cryptography.x509.load_pem_x509_certificate", return_value=DummyCert()
        ):
            with patch("builtins.print") as mock_print:
                self.cahandler._parse_cert("dummy")
                mock_print.assert_any_call("\nKey Usage:")

    def test_037_parse_cert_no_key_usage(self):
        # Simulate missing KeyUsage extension using the real ExtensionNotFound exception
        from cryptography import x509

        class DummyCert:
            class extensions:
                @staticmethod
                def get_extension_for_class(cls):
                    raise x509.ExtensionNotFound("not found", cls)

        with patch(
            "cryptography.x509.load_pem_x509_certificate", return_value=DummyCert()
        ):
            with patch("builtins.print") as mock_print:
                self.cahandler._parse_cert("dummy")
                mock_print.assert_any_call("No Key Usage extension found.")

    def test_038_parse_cert_no_eku(self):
        # Simulate KeyUsage present, ExtendedKeyUsage missing using real ExtensionNotFound
        from cryptography import x509

        class KU:
            digital_signature = True
            content_commitment = False
            key_encipherment = False
            data_encipherment = False
            key_agreement = False
            key_cert_sign = False
            crl_sign = False

        class Ext:
            value = KU()

        class DummyCert:
            class extensions:
                @staticmethod
                def get_extension_for_class(cls):
                    if cls.__name__ == "KeyUsage":
                        return Ext()
                    raise x509.ExtensionNotFound("not found", cls)

        with patch(
            "cryptography.x509.load_pem_x509_certificate", return_value=DummyCert()
        ):
            with patch("builtins.print") as mock_print:
                self.cahandler._parse_cert("dummy")
                mock_print.assert_any_call("No Extended Key Usage extension found.")

    def test_039_certrequest_send_success(self):
        self.cahandler.REST_CERTREQUESTS = "/certreqs"
        mock_response = {
            "entries": [{"requestId": "req123", "requestStatus": "pending"}]
        }
        with patch.object(
            self.cahandler, "_api_post", return_value=(200, mock_response)
        ):
            with patch.object(self.cahandler.logger, "info") as mock_log:
                req_id, req_status = self.cahandler._certrequest_send("csrdata")
                self.assertEqual(req_id, "req123")
                self.assertEqual(req_status, "pending")
                mock_log.assert_any_call("Certificate request sent successfully")
                mock_log.assert_any_call(
                    "Request ID: %s, Request Status: %s", "req123", "pending"
                )

    def test_040_certrequest_send_unexpected_response_format_logs_error(self):
        self.cahandler.REST_CERTREQUESTS = "/certreqs"
        # Simulate code 200 but response missing 'entries'
        mock_response = {"foo": "bar"}
        with patch.object(
            self.cahandler, "_api_post", return_value=(200, mock_response)
        ):
            with patch.object(self.cahandler.logger, "error") as mock_log:
                req_id, req_status = self.cahandler._certrequest_send("csrdata")
                self.assertIsNone(req_id)
                self.assertIsNone(req_status)
                mock_log.assert_any_call(
                    "Unexpected response format for certificate request. Response: %s",
                    mock_response,
                )

    def test_041_certrequest_send_failed_logs_error(self):
        self.cahandler.REST_CERTREQUESTS = "/certreqs"
        # Simulate non-200 code
        mock_response = {"error": "fail"}
        with patch.object(
            self.cahandler, "_api_post", return_value=(500, mock_response)
        ):
            with patch.object(self.cahandler.logger, "error") as mock_log:
                req_id, req_status = self.cahandler._certrequest_send("csrdata")
                self.assertIsNone(req_id)
                self.assertIsNone(req_status)
                mock_log.assert_any_call(
                    "Failed to send certificate request. Status code: %s, Response: %s",
                    500,
                    mock_response,
                )

    def test_042_config_passphrase_load_env_error_logs(self):
        # Simulate missing env var, should log error
        config_dic = {"CAhandler": {"cert_passphrase_variable": "MISSING_ENV_VAR"}}
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(self.cahandler.logger, "error") as mock_log:
                self.cahandler._config_passphrase_load(config_dic)
                mock_log.assert_any_call(
                    "Could not load cert_passphrase_variable:%s",
                    unittest.mock.ANY,
                )

    def test_043_config_passphrase_load_overwrite_logs_info(self):
        # Simulate env var present, then config value overwrites, should log info
        config_dic = {
            "CAhandler": {
                "cert_passphrase_variable": "EXISTING_ENV_VAR",
                "cert_passphrase": "from_config",
            }
        }
        with patch.dict(os.environ, {"EXISTING_ENV_VAR": "from_env"}):
            with patch.object(self.cahandler.logger, "info") as mock_log:
                self.cahandler._config_passphrase_load(config_dic)
                self.assertEqual(self.cahandler.cert_passphrase, "from_config")
                mock_log.assert_any_call(
                    "CAhandler._config_load() overwrite cert_passphrase"
                )

    def test_044_config_passphrase_load_direct(self):
        # Only cert_passphrase in config, should set directly
        config_dic = {"CAhandler": {"cert_passphrase": "direct_value"}}
        self.cahandler.cert_passphrase = None
        self.cahandler._config_passphrase_load(config_dic)
        self.assertEqual(self.cahandler.cert_passphrase, "direct_value")

    def test_045_login_pkcs12_auth(self):
        """Test _login with PKCS12 client authentication (client_cert and cert_passphrase set)"""
        self.cahandler.session = None
        self.cahandler.client_cert = "dummy_cert.p12"
        self.cahandler.cert_passphrase = "dummy_pass"
        self.cahandler.api_host = "https://dummyhost"
        with patch("requests.Session") as mock_session, patch(
            "examples.ca_handler.dogtag_ca_handler.Pkcs12Adapter"
        ) as mock_adapter, patch.object(self.cahandler.logger, "debug") as mock_log:
            mock_sess_instance = Mock()
            mock_session.return_value = mock_sess_instance
            self.cahandler._login()
            mock_session.assert_called_once()
            mock_adapter.assert_called_once_with(
                pkcs12_filename="dummy_cert.p12", pkcs12_password="dummy_pass"
            )
            mock_sess_instance.mount.assert_called_once_with(
                "https://dummyhost", mock_adapter.return_value
            )
            mock_sess_instance.headers.update.assert_called_once_with(
                {"Accept": "application/json"}
            )
            mock_log.assert_any_call("CAhandler._login()")
            mock_log.assert_any_call(
                "CAhandler._login() using PKCS12 client authentication"
            )

    def test_046_login_pem_auth(self):
        """Test _login with PEM client authentication (client_cert and client_key set, no passphrase)"""
        self.cahandler.session = None
        self.cahandler.client_cert = "dummy_cert.pem"
        self.cahandler.client_key = "dummy_key.pem"
        self.cahandler.cert_passphrase = None
        self.cahandler.api_host = "https://dummyhost"
        with patch("requests.Session") as mock_session, patch.object(
            self.cahandler.logger, "debug"
        ) as mock_log:
            mock_sess_instance = Mock()
            mock_session.return_value = mock_sess_instance
            self.cahandler._login()
            mock_session.assert_called_once()
            self.assertEqual(
                mock_sess_instance.cert, ("dummy_cert.pem", "dummy_key.pem")
            )
            mock_sess_instance.headers.update.assert_called_once_with(
                {"Accept": "application/json"}
            )
            mock_log.assert_any_call("CAhandler._login()")

    def test_047_login_session_already_set(self):
        """Test _login does nothing if session is already set"""
        mock_session = Mock()
        self.cahandler.session = mock_session
        with patch("requests.Session") as mock_requests_session, patch.object(
            self.cahandler.logger, "debug"
        ) as mock_log:
            self.cahandler._login()
            mock_requests_session.assert_not_called()
            mock_log.assert_any_call("CAhandler._login()")

    def test_048_revoke_success_logs_info(self):
        """Test _revoke logs info on successful revocation (line 673)"""
        serial = "0x1234"
        response = {"Nonce": "nonce", "Status": "valid"}
        with patch.object(
            self.cahandler, "_api_get", return_value=(200, response)
        ), patch.object(
            self.cahandler, "_api_post", return_value=(200, {})
        ), patch.object(
            self.cahandler.logger, "info"
        ) as mock_info:
            code, msg, detail = self.cahandler._revoke(serial)
            self.assertEqual(code, 200)
            self.assertEqual(msg, "Certificate revoked successfully")
            mock_info.assert_any_call(
                "Certificate with serial %s revoked successfully", serial
            )

    def test_049_revoke_failed_revoke_logs_error(self):
        """Test _revoke logs error on failed revocation (line 676)"""
        serial = "0x1234"
        response = {"Nonce": "nonce", "Status": "valid"}
        with patch.object(
            self.cahandler, "_api_get", return_value=(200, response)
        ), patch.object(
            self.cahandler, "_api_post", return_value=(500, {"error": "fail"})
        ), patch.object(
            self.cahandler.logger, "error"
        ) as mock_error:
            code, msg, detail = self.cahandler._revoke(serial)
            self.assertEqual(code, 500)
            self.assertEqual(msg, "Failed to revoke certificate")
            mock_error.assert_any_call(
                "Failed to revoke certificate with serial %s. Status code: %s, Response: %s",
                serial,
                500,
                {"error": "fail"},
            )

    def test_050_revoke_already_revoked_logs_info(self):
        """Test _revoke logs info if already revoked (line 684)"""
        serial = "0x1234"
        response = {"Nonce": "nonce", "Status": "revoked"}
        with patch.object(
            self.cahandler, "_api_get", return_value=(200, response)
        ), patch.object(self.cahandler.logger, "info") as mock_info:
            code, msg, detail = self.cahandler._revoke(serial)
            self.assertEqual(code, 200)
            self.assertEqual(msg, "Certificate is already revoked")
            mock_info.assert_any_call(
                "Certificate with serial %s is already revoked", serial
            )

    def test_051_revoke_status_fail_logs_error(self):
        """Test _revoke logs error if status fetch fails (line 687)"""
        serial = "0x1234"
        with patch.object(
            self.cahandler, "_api_get", return_value=(500, {"error": "fail"})
        ), patch.object(self.cahandler.logger, "error") as mock_error:
            code, msg, detail = self.cahandler._revoke(serial)
            self.assertEqual(code, 500)
            self.assertEqual(
                msg, "Failed to get certificate status before revocation attempt"
            )
            mock_error.assert_any_call(
                "Failed to get certificate status for serial %s before revocation attempt. Status code: %s, Response: %s",
                serial,
                500,
                {"error": "fail"},
            )

    def test_052_revoke_prepends_0x_to_serial(self):
        """Test _revoke prepends '0x' to serial if missing (lines 654-655)"""
        serial = "1234"  # No '0x' prefix
        expected_serial = "0x1234"
        response = {"Nonce": "nonce", "Status": "valid"}
        with patch.object(
            self.cahandler, "_api_get", return_value=(200, response)
        ) as mock_get, patch.object(
            self.cahandler, "_api_post", return_value=(200, {})
        ) as mock_post, patch.object(
            self.cahandler.logger, "info"
        ) as mock_info:
            code, msg, detail = self.cahandler._revoke(serial)
            self.assertEqual(code, 200)
            self.assertEqual(msg, "Certificate revoked successfully")
            # Ensure _api_get was called with the serial prefixed by '0x'
            mock_get.assert_called_once_with(
                f"{self.cahandler.REST_AGENT_CERTS}{expected_serial}"
            )
            mock_info.assert_any_call(
                "Certificate with serial %s revoked successfully", expected_serial
            )

    def test_053_enroll_error_from_eab_profile_header_info_check(self):
        """Test enroll returns error from eab_profile_header_info_check and does not proceed"""
        with patch(
            "examples.ca_handler.dogtag_ca_handler.eab_profile_header_info_check",
            return_value="some error",
        ) as mock_eab, patch.object(
            self.cahandler, "_api_version_get"
        ) as mock_ver, patch.object(
            self.cahandler, "_certrequest_send"
        ) as mock_send:
            error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll("csr")
            self.assertEqual(error, "some error")
            self.assertIsNone(cert_bundle)
            self.assertIsNone(cert_raw)
            self.assertIsNone(poll_identifier)
            mock_ver.assert_not_called()
            mock_send.assert_not_called()

    def test_054_enroll_success_pending_certrequest_approve(self):
        """Test enroll with pending status and certrequest_approve True calls _certrequest_approve"""
        self.cahandler.certrequest_approve = True
        with patch(
            "examples.ca_handler.dogtag_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ), patch.object(self.cahandler, "_api_version_get"), patch.object(
            self.cahandler, "_certrequest_send", return_value=("reqid", "pending")
        ), patch.object(
            self.cahandler,
            "_certrequest_approve",
            return_value=("err", "bundle", "raw"),
        ) as mock_approve:
            error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll("csr")
            self.assertEqual(error, "err")
            self.assertEqual(cert_bundle, "bundle")
            self.assertEqual(cert_raw, "raw")
            self.assertIsNone(poll_identifier)
            mock_approve.assert_called_once_with("reqid")

    def test_055_enroll_success_pending_no_certrequest_approve(self):
        """Test enroll with pending status and certrequest_approve False sets poll_identifier"""
        self.cahandler.certrequest_approve = False
        with patch(
            "examples.ca_handler.dogtag_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ), patch.object(self.cahandler, "_api_version_get"), patch.object(
            self.cahandler, "_certrequest_send", return_value=("reqid", "pending")
        ):
            error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll("csr")
            self.assertIsNone(error)
            self.assertIsNone(cert_bundle)
            self.assertIsNone(cert_raw)
            self.assertEqual(poll_identifier, "reqid")

    def test_056_enroll_success_not_pending(self):
        """Test enroll with non-pending status returns all None except error"""
        self.cahandler.certrequest_approve = False
        with patch(
            "examples.ca_handler.dogtag_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ), patch.object(self.cahandler, "_api_version_get"), patch.object(
            self.cahandler, "_certrequest_send", return_value=("reqid", "issued")
        ):
            error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll("csr")
            self.assertIsNone(error)
            self.assertIsNone(cert_bundle)
            self.assertIsNone(cert_raw)
            self.assertIsNone(poll_identifier)

    def test_057_enroll_enrollment_config_log_called(self):
        """Test enroll calls enrollment_config_log if enrollment_config_log is True"""
        self.cahandler.certrequest_approve = False
        self.cahandler.enrollment_config_log = True
        with patch(
            "examples.ca_handler.dogtag_ca_handler.eab_profile_header_info_check",
            return_value=None,
        ), patch.object(self.cahandler, "_api_version_get"), patch.object(
            self.cahandler, "_certrequest_send", return_value=("reqid", "pending")
        ), patch(
            "examples.ca_handler.dogtag_ca_handler.enrollment_config_log"
        ) as mock_log:
            self.cahandler.enrollment_config_log_skip_list = ["foo"]
            self.cahandler.enroll("csr")
            mock_log.assert_called_once_with(
                self.cahandler.logger, self.cahandler, ["foo"]
            )

    def test_058_handler_check_success(self):
        """Test handler_check returns None for valid config and logs debug"""
        with patch(
            "examples.ca_handler.dogtag_ca_handler.handler_config_check",
            return_value=None,
        ) as mock_check, patch.object(self.cahandler.logger, "debug") as mock_log:
            result = self.cahandler.handler_check()
            self.assertIsNone(result)
            mock_check.assert_called_once_with(
                self.cahandler.logger, self.cahandler, ["api_host", "client_cert"]
            )
            mock_log.assert_any_call("CAhandler.check()")
            mock_log.assert_any_call("CAhandler.check() ended with %s", None)

    def test_059_handler_check_error(self):
        """Test handler_check returns error string and logs debug"""
        with patch(
            "examples.ca_handler.dogtag_ca_handler.handler_config_check",
            return_value="error",
        ) as mock_check, patch.object(self.cahandler.logger, "debug") as mock_log:
            result = self.cahandler.handler_check()
            self.assertEqual(result, "error")
            mock_check.assert_called_once_with(
                self.cahandler.logger, self.cahandler, ["api_host", "client_cert"]
            )
            mock_log.assert_any_call("CAhandler.check()")
            mock_log.assert_any_call("CAhandler.check() ended with %s", "error")

    def test_060_poll_returns_expected_tuple(self):
        """Test poll returns expected tuple and logs debug"""
        with patch.object(self.cahandler.logger, "debug") as mock_log:
            result = self.cahandler.poll("certname", "pollid", "csr")
            self.assertEqual(result, (None, None, None, "pollid", False))
            mock_log.assert_any_call("CAhandler.poll()")

    def test_061_trigger_returns_expected_tuple(self):
        """Test trigger returns expected tuple and logs debug messages"""
        with patch.object(self.cahandler.logger, "debug") as mock_log:
            result = self.cahandler.trigger("payload")
            self.assertEqual(result, (None, None, None))
            mock_log.assert_any_call("CAhandler.trigger()")
            mock_log.assert_any_call("CAhandler.trigger() ended with error: %s", None)

    def test_062_revoke_success(self):
        """Test revoke calls _revoke with extracted serial and returns its result"""
        with patch(
            "examples.ca_handler.dogtag_ca_handler.cert_serial_get",
            return_value="serial",
        ) as mock_serial, patch.object(
            self.cahandler, "_revoke", return_value=(200, "ok", "")
        ) as mock_revoke, patch.object(
            self.cahandler.logger, "debug"
        ) as mock_debug:
            code, msg, detail = self.cahandler.revoke("certdata")
            self.assertEqual((code, msg, detail), (200, "ok", ""))
            mock_serial.assert_called_once_with(
                self.cahandler.logger, "certdata", hexformat=True
            )
            mock_revoke.assert_called_once_with("serial")
            mock_debug.assert_any_call("CAhandler.revoke()")
            mock_debug.assert_any_call("Certificate.revoke() ended")

    def test_063_revoke_serial_extraction_fails(self):
        """Test revoke logs error and returns malformed if serial extraction fails"""
        with patch(
            "examples.ca_handler.dogtag_ca_handler.cert_serial_get", return_value=None
        ), patch.object(self.cahandler.logger, "error") as mock_error, patch.object(
            self.cahandler.logger, "debug"
        ) as mock_debug:
            code, msg, detail = self.cahandler.revoke("certdata")
            self.assertEqual(code, 400)
            self.assertEqual(msg, "urn:ietf:params:acme:error:malformed")
            self.assertEqual(
                detail, "Invalid certificate format or missing serial number"
            )
            mock_error.assert_any_call(
                "Failed to extract serial number from certificate for revocation"
            )
            mock_debug.assert_any_call("CAhandler.revoke()")
            mock_debug.assert_any_call("Certificate.revoke() ended")

    def test_064_revoke_no_cert_provided(self):
        """Test revoke logs error and returns malformed if no cert is provided"""
        with patch.object(self.cahandler.logger, "error") as mock_error, patch.object(
            self.cahandler.logger, "debug"
        ) as mock_debug:
            code, msg, detail = self.cahandler.revoke(None)
            self.assertEqual(code, 400)
            self.assertEqual(msg, "urn:ietf:params:acme:error:malformed")
            self.assertEqual(detail, "Certificate data is required for revocation")
            mock_error.assert_any_call("Certificate data is required for revocation")
            mock_debug.assert_any_call("CAhandler.revoke()")
            mock_debug.assert_any_call("Certificate.revoke() ended")

    def test_065_revoke_logs_debug(self):
        """Test revoke logs debug at entry and exit"""
        with patch(
            "examples.ca_handler.dogtag_ca_handler.cert_serial_get",
            return_value="serial",
        ), patch.object(
            self.cahandler, "_revoke", return_value=(200, "ok", "")
        ), patch.object(
            self.cahandler.logger, "debug"
        ) as mock_debug:
            self.cahandler.revoke("certdata")
            mock_debug.assert_any_call("CAhandler.revoke()")
            mock_debug.assert_any_call("Certificate.revoke() ended")

    def test_066_enter_calls_config_load_and_login_if_no_api_host(self):
        """Test __enter__ calls _config_load and _login if api_host is not set"""
        self.cahandler.api_host = None
        with patch.object(self.cahandler, "_config_load") as mock_config, patch.object(
            self.cahandler, "_login"
        ) as mock_login:
            result = self.cahandler.__enter__()
            mock_config.assert_called_once()
            mock_login.assert_called_once()
            self.assertIs(result, self.cahandler)

    def test_067_enter_skips_config_load_and_login_if_api_host_set(self):
        """Test __enter__ does not call _config_load or _login if api_host is set"""
        self.cahandler.api_host = "somehost"
        with patch.object(self.cahandler, "_config_load") as mock_config, patch.object(
            self.cahandler, "_login"
        ) as mock_login:
            result = self.cahandler.__enter__()
            mock_config.assert_not_called()
            mock_login.assert_not_called()
            self.assertIs(result, self.cahandler)

    def test_068_exit_closes_session_if_set(self):
        """Test __exit__ calls session.close and sets session to None if session is set"""
        mock_session = Mock()
        self.cahandler.session = mock_session
        self.cahandler.__exit__(None, None, None)
        mock_session.close.assert_called_once()
        self.assertIsNone(self.cahandler.session)

    def test_069_exit_does_nothing_if_session_none(self):
        """Test __exit__ does nothing if session is None"""
        self.cahandler.session = None
        # Should not raise
        self.cahandler.__exit__(None, None, None)

    def test_070_update_validity_attributes_sets_notbefore_and_notafter(self):
        """Test update_validity_attributes sets notBefore and notAfter and logs debug"""
        data = {
            "ProfilePolicySet": [
                {
                    "policies": [
                        {
                            "def": {
                                "attributes": [
                                    {"name": "notBefore", "Value": None},
                                    {"name": "notAfter", "Value": None},
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        mock_logger = Mock()
        self.update_validity_attributes(mock_logger, data, "2026-01-01", "2027-01-01")
        attrs = data["ProfilePolicySet"][0]["policies"][0]["def"]["attributes"]
        self.assertEqual(attrs[0]["Value"], "2026-01-01")
        self.assertEqual(attrs[1]["Value"], "2027-01-01")
        calls = [c[0][0] for c in mock_logger.debug.call_args_list]
        self.assertIn("update_validity_attributes()", calls[0])
        self.assertTrue(any("Setting notBefore" in msg for msg in calls))
        self.assertIn("update_validity_attributes() ended", calls[-1])

    def test_071_update_validity_attributes_only_notbefore(self):
        """Test update_validity_attributes sets only notBefore if notAfter missing"""
        data = {
            "ProfilePolicySet": [
                {
                    "policies": [
                        {
                            "def": {
                                "attributes": [
                                    {"name": "notBefore", "Value": None},
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        mock_logger = Mock()
        self.update_validity_attributes(mock_logger, data, "2026-01-01", "2027-01-01")
        attrs = data["ProfilePolicySet"][0]["policies"][0]["def"]["attributes"]
        self.assertEqual(attrs[0]["Value"], "2026-01-01")
        calls = [c[0][0] for c in mock_logger.debug.call_args_list]
        self.assertTrue(any("Setting notBefore" in msg for msg in calls))
        self.assertIn("update_validity_attributes() ended", calls[-1])

    def test_072_update_validity_attributes_only_notafter(self):
        """Test update_validity_attributes sets only notAfter if notBefore missing"""
        data = {
            "ProfilePolicySet": [
                {
                    "policies": [
                        {
                            "def": {
                                "attributes": [
                                    {"name": "notAfter", "Value": None},
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        mock_logger = Mock()
        self.update_validity_attributes(mock_logger, data, "2026-01-01", "2027-01-01")
        attrs = data["ProfilePolicySet"][0]["policies"][0]["def"]["attributes"]
        self.assertEqual(attrs[0]["Value"], "2027-01-01")
        calls = [c[0][0] for c in mock_logger.debug.call_args_list]
        self.assertTrue(any("Setting notAfter" in msg for msg in calls))
        self.assertIn("update_validity_attributes() ended", calls[-1])

    def test_073_update_validity_attributes_no_attributes(self):
        """Test update_validity_attributes does nothing if neither attribute present"""
        data = {
            "ProfilePolicySet": [
                {
                    "policies": [
                        {
                            "def": {
                                "attributes": [
                                    {"name": "foo", "Value": None},
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        mock_logger = Mock()
        self.update_validity_attributes(mock_logger, data, "2026-01-01", "2027-01-01")
        attrs = data["ProfilePolicySet"][0]["policies"][0]["def"]["attributes"]
        self.assertIsNone(attrs[0]["Value"])
        calls = [c[0][0] for c in mock_logger.debug.call_args_list]
        self.assertIn("update_validity_attributes()", calls[0])
        self.assertIn("update_validity_attributes() ended", calls[-1])

    def test_074_approve_profile_get_default(self):
        """Test approve_profile_get returns correct structure and logs for default call"""
        mock_logger = Mock()
        result = self.approve_profile_get(mock_logger)
        self.assertIn("ProfilePolicySet", result)
        self.assertIn("policies", result["ProfilePolicySet"][0])
        self.assertIn(
            "notBefore",
            [
                a["name"]
                for a in result["ProfilePolicySet"][0]["policies"][0]["def"][
                    "attributes"
                ]
            ],
        )
        self.assertIn(
            "notAfter",
            [
                a["name"]
                for a in result["ProfilePolicySet"][0]["policies"][0]["def"][
                    "attributes"
                ]
            ],
        )
        calls = [c[0][0] for c in mock_logger.debug.call_args_list]
        self.assertIn("approve_profile_get() called with request_id: %s", calls[0])
        self.assertIn("approve_profile_get() ended", calls[-1])

    def test_075_approve_profile_get_with_nonce_and_request_id(self):
        """Test approve_profile_get sets nonce and requestId and logs correctly"""
        mock_logger = Mock()
        result = self.approve_profile_get(
            mock_logger, nonce="abc123", request_id="req42"
        )
        self.assertEqual(result["nonce"], "abc123")
        self.assertEqual(result["requestId"], "req42")
        calls = [c[0][0] for c in mock_logger.debug.call_args_list]
        self.assertIn("approve_profile_get() called with request_id: %s", calls[0])
        self.assertIn("approve_profile_get() ended", calls[-1])

    def test_076_approve_profile_get_notbefore_notafter_values(self):
        """Test approve_profile_get sets notBefore and notAfter values via update_validity_attributes"""
        mock_logger = Mock()
        # Patch uts_now and uts_to_date_utc to control output
        with patch(
            "examples.ca_handler.dogtag_ca_handler.uts_now", return_value=1000000
        ), patch(
            "examples.ca_handler.dogtag_ca_handler.uts_to_date_utc",
            side_effect=["NB", "NA"],
        ):
            result = self.approve_profile_get(mock_logger, nonce="n", request_id="r")
        attrs = result["ProfilePolicySet"][0]["policies"][0]["def"]["attributes"]
        nb = next(a for a in attrs if a["name"] == "notBefore")
        na = next(a for a in attrs if a["name"] == "notAfter")
        self.assertEqual(nb["Value"], "NB")
        self.assertEqual(na["Value"], "NA")

    def test_077_approve_profile_get_does_not_log_nonce(self):
        """Test approve_profile_get does not log nonce value (sensitive)"""
        mock_logger = Mock()
        self.approve_profile_get(
            mock_logger, nonce="shouldnotappear", request_id="reqid"
        )
        # Ensure nonce value is not in any log message
        for call in mock_logger.debug.call_args_list:
            args = call[0]
            for arg in args:
                self.assertNotIn("shouldnotappear", str(arg))


if __name__ == "__main__":

    unittest.main()
