# -*- coding: utf-8 -*-
"""unittests for vault_ca_handler"""
# pylint: disable=C0415, R0904, W0212
import sys
import os
import unittest
import requests
from unittest.mock import Mock, MagicMock, patch
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestCAhandler(unittest.TestCase):
    def setUp(self):
        import logging
        from examples.ca_handler.vault_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)

    def test_001_trigger_not_implemented(self):
        error, cert_bundle, cert_raw = self.cahandler.trigger("payload")
        self.assertEqual(error, "Method not implemented.")
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)

    def test_002_poll_not_implemented(self):
        error, cert_bundle, cert_raw, poll_identifier, rejected = self.cahandler.poll(
            "cert_name", "poll_identifier", "csr"
        )
        self.assertEqual(error, "Method not implemented.")
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)

    def test_003_config_check_missing_params(self):

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "vault_url parameter in missing in config file",
                self.cahandler._config_check(),
            )
        self.assertIn(
            "ERROR:test_a2c:Configuration check ended with error: vault_url parameter in missing in config file",
            lcm.output,
        )

    def test_004_config_check_all_params_present(self):
        self.cahandler.vault_url = "url"
        self.cahandler.vault_path = "path"
        self.cahandler.vault_role = "role"
        self.cahandler.vault_token = "token"
        error = self.cahandler._config_check()
        self.assertIsNone(error)

    @patch("examples.ca_handler.vault_ca_handler.CAhandler._config_load")
    def test_005__enter__(self, mock_cfg):
        """test enter  called"""
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch("examples.ca_handler.vault_ca_handler.CAhandler._config_load")
    def test_006__enter__(self, mock_cfg):
        """test enter api hosts defined"""
        mock_cfg.return_value = True
        self.cahandler.vault_url = "vault_url"
        self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)

    @patch.object(requests, "post")
    def test_007__api_post(self, mock_req):
        """test _api_post()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = lambda: {"foo": "bar"}
        mock_req.return_value = mockresponse
        self.assertEqual(
            ("status_code", {"foo": "bar"}), self.cahandler._api_post("url", "data")
        )

    @patch("requests.post")
    def test_008__api_post(self, mock_req):
        """test _api_post()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = "aaaa"
        mock_req.return_value = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("status_code", "'str' object is not callable"),
                self.cahandler._api_post("url", "data"),
            )
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error during json parsing: 'str' object is not callable",
            lcm.output,
        )

    @patch("requests.post")
    def test_009__api_post(self, mock_req):
        """test _api_post()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.text = None
        mock_req.return_value = mockresponse
        self.assertEqual(("status_code", None), self.cahandler._api_post("url", "data"))

    @patch("requests.post")
    def test_010__api_post(self, mock_req):
        """test _api_post(="""
        self.cahandler.api_host = "api_host"
        self.cahandler.auth = "auth"
        mock_req.side_effect = Exception("exc_api_post")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (500, "exc_api_post"), self.cahandler._api_post("url", "data")
            )
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error: exc_api_post", lcm.output
        )

    @patch.object(requests, "get")
    def test_011__api_get(self, mock_req):
        """test _api_get()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = lambda: {"foo": "bar"}
        mock_req.return_value = mockresponse
        self.assertEqual(
            ("status_code", {"foo": "bar"}), self.cahandler._api_get("url")
        )

    @patch("requests.get")
    def test_012__api_get(self, mock_req):
        """test _api_get()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = "aaaa"
        mock_req.return_value = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("status_code", "'str' object is not callable"),
                self.cahandler._api_get("url"),
            )
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error during json parsing: 'str' object is not callable",
            lcm.output,
        )

    @patch("requests.get")
    def test_013__api_get(self, mock_req):
        """test _api_get()"""
        self.cahandler.api_host = "api_host"
        self.cahandler.auth = "auth"
        mock_req.side_effect = Exception("exc_api_get")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual((500, "exc_api_get"), self.cahandler._api_get("url"))
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error: exc_api_get", lcm.output
        )

    @patch.object(requests, "put")
    def test_014__api_put(self, mock_req):
        """test _api_put()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = lambda: {"foo": "bar"}
        mock_req.return_value = mockresponse
        self.assertEqual(
            ("status_code", {"foo": "bar"}), self.cahandler._api_put("url", "data")
        )

    @patch("requests.put")
    def test_015__api_put(self, mock_req):
        """test _api_put()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.json = "aaaa"
        mock_req.return_value = mockresponse
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ("status_code", "'str' object is not callable"),
                self.cahandler._api_put("url", "data"),
            )
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error during json parsing: 'str' object is not callable",
            lcm.output,
        )

    @patch("requests.put")
    def test_016__api_put(self, mock_req):
        """test _api_put()"""
        mockresponse = Mock()
        mockresponse.status_code = "status_code"
        mockresponse.text = None
        mock_req.return_value = mockresponse
        self.assertEqual(("status_code", None), self.cahandler._api_put("url", "data"))

    @patch("requests.put")
    def test_017__api_put(self, mock_req):
        """test _api_put()"""
        self.cahandler.api_host = "api_host"
        self.cahandler.auth = "auth"
        mock_req.side_effect = Exception("exc_api_put")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (500, "exc_api_put"), self.cahandler._api_put("url", "data")
            )
        self.assertIn(
            "ERROR:test_a2c:Request_operation returned error: exc_api_put", lcm.output
        )

    @patch("examples.ca_handler.vault_ca_handler.load_config")
    @patch(
        "examples.ca_handler.vault_ca_handler.config_allowed_domainlist_load",
        return_value=["example.com"],
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_eab_profile_load",
        return_value=(True, "handler"),
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_proxy_load",
        return_value={"http": "proxy"},
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_profile_load",
        return_value={"profile": "data"},
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_headerinfo_load", return_value=True
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_enroll_config_log_load",
        return_value=(True, ["skip1", "skip2"]),
    )
    def test_018_config_load_sets_attributes(
        self,
        mock_enroll,
        mock_headerinfo,
        mock_profile,
        mock_proxy,
        mock_eab,
        mock_domain,
        mock_load_config,
    ):
        # Simulate config_dic with needed structure
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "vault_url": "url",
            "vault_path": "path",
            "vault_role": "role",
            "vault_token": "token",
            "issuer_ref": "issuer",
            "request_timeout": "30",
            "cert_validity_days": "400",
            "ca_bundle": True,
        }

        mock_load_config.return_value = parser
        self.cahandler._config_load()
        self.assertEqual(self.cahandler.vault_url, "url")
        self.assertEqual(self.cahandler.vault_path, "path")
        self.assertEqual(self.cahandler.vault_role, "role")
        self.assertEqual(self.cahandler.vault_token, "token")
        self.assertEqual(self.cahandler.issuer_ref, "issuer")
        self.assertEqual(self.cahandler.request_timeout, 30)
        self.assertEqual(self.cahandler.cert_validity_days, 400)
        self.assertTrue(self.cahandler.ca_bundle)
        self.assertEqual(self.cahandler.allowed_domainlist, ["example.com"])
        self.assertEqual(self.cahandler.eab_profiling, True)
        self.assertEqual(self.cahandler.eab_handler, "handler")
        self.assertEqual(self.cahandler.proxy, {"http": "proxy"})
        self.assertEqual(self.cahandler.profiles, {"profile": "data"})
        self.assertTrue(self.cahandler.header_info_field)
        self.assertTrue(self.cahandler.enrollment_config_log)
        self.assertEqual(
            self.cahandler.enrollment_config_log_skip_list, ["skip1", "skip2"]
        )

    @patch("examples.ca_handler.vault_ca_handler.load_config")
    @patch(
        "examples.ca_handler.vault_ca_handler.config_allowed_domainlist_load",
        return_value=["example.com"],
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_eab_profile_load",
        return_value=(True, "handler"),
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_proxy_load",
        return_value={"http": "proxy"},
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_profile_load",
        return_value={"profile": "data"},
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_headerinfo_load", return_value=True
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.config_enroll_config_log_load",
        return_value=(True, ["skip1", "skip2"]),
    )
    def test_019_config_load_sets_attributes(
        self,
        mock_enroll,
        mock_headerinfo,
        mock_profile,
        mock_proxy,
        mock_eab,
        mock_domain,
        mock_load_config,
    ):
        # Simulate config_dic with needed structure
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "cert_validity_days": "aa",
            "request_timeout": "aa",
        }

        mock_load_config.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual(self.cahandler.cert_validity_days, 365)
        self.assertIn(
            "ERROR:test_a2c:Failed to parse cert_validity_days invalid literal for int() with base 10: 'aa' parameter",
            lcm.output,
        )
        self.assertEqual(self.cahandler.request_timeout, 20)
        self.assertIn(
            "ERROR:test_a2c:Failed to parse request_timeout parameter: invalid literal for int() with base 10: 'aa'",
            lcm.output,
        )

    @patch(
        "examples.ca_handler.vault_ca_handler.enrollment_config_log", return_value=None
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._csr_check", return_value=None
    )
    @patch("examples.ca_handler.vault_ca_handler.csr_cn_lookup", return_value="test-cn")
    @patch(
        "examples.ca_handler.vault_ca_handler.build_pem_file", return_value="pem-csr"
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.b64_url_recode", return_value="recode-csr"
    )
    @patch("examples.ca_handler.vault_ca_handler.CAhandler._api_post")
    @patch(
        "examples.ca_handler.vault_ca_handler.b64_encode", return_value="encoded-cert"
    )
    @patch("examples.ca_handler.vault_ca_handler.cert_pem2der", return_value="der-cert")
    def test_020_enroll_success(
        self,
        mock_cert_pem2der,
        mock_b64_encode,
        mock_api_post,
        mock_b64_url_recode,
        mock_build_pem_file,
        mock_csr_cn_lookup,
        mock_csr_check,
        mock_config_check,
        mock_log,
    ):
        # Simulate successful API response
        mock_api_post.return_value = (
            200,
            {"data": {"certificate": "CERT", "ca_chain": ["CA1", "CA2"]}},
        )

        error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll(
            "dummy-csr"
        )
        self.assertIsNone(error)
        self.assertIn("CERT", cert_bundle)
        self.assertIn("CA1", cert_bundle)
        self.assertIn("CA2", cert_bundle)
        self.assertEqual(cert_raw, "encoded-cert")
        self.assertIsNone(poll_identifier)
        mock_api_post.assert_called_once_with(
            "None/v1/None/sign/None", {"csr": "pem-csr", "common_name": "test-cn"}
        )
        self.assertFalse(mock_log.called)

    @patch(
        "examples.ca_handler.vault_ca_handler.enrollment_config_log", return_value=None
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._csr_check", return_value=None
    )
    @patch("examples.ca_handler.vault_ca_handler.csr_cn_lookup", return_value="test-cn")
    @patch(
        "examples.ca_handler.vault_ca_handler.build_pem_file", return_value="pem-csr"
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.b64_url_recode", return_value="recode-csr"
    )
    @patch("examples.ca_handler.vault_ca_handler.CAhandler._api_post")
    @patch(
        "examples.ca_handler.vault_ca_handler.b64_encode", return_value="encoded-cert"
    )
    @patch("examples.ca_handler.vault_ca_handler.cert_pem2der", return_value="der-cert")
    def test_021_enroll_success(
        self,
        mock_cert_pem2der,
        mock_b64_encode,
        mock_api_post,
        mock_b64_url_recode,
        mock_build_pem_file,
        mock_csr_cn_lookup,
        mock_csr_check,
        mock_config_check,
        mock_log,
    ):
        # Simulate successful API response
        mock_api_post.return_value = (
            200,
            {"data": {"certificate": "CERT", "ca_chain": ["CA1", "CA2"]}},
        )
        self.cahandler.enrollment_config_log = True
        error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll(
            "dummy-csr"
        )
        self.assertIsNone(error)
        self.assertIn("CERT", cert_bundle)
        self.assertIn("CA1", cert_bundle)
        self.assertIn("CA2", cert_bundle)
        self.assertEqual(cert_raw, "encoded-cert")
        self.assertIsNone(poll_identifier)
        mock_api_post.assert_called_once_with(
            "None/v1/None/sign/None", {"csr": "pem-csr", "common_name": "test-cn"}
        )
        self.assertTrue(mock_log.called)

    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._csr_check", return_value=None
    )
    @patch("examples.ca_handler.vault_ca_handler.csr_cn_lookup", return_value="test-cn")
    @patch(
        "examples.ca_handler.vault_ca_handler.build_pem_file", return_value="pem-csr"
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.b64_url_recode", return_value="recode-csr"
    )
    @patch("examples.ca_handler.vault_ca_handler.CAhandler._api_post")
    @patch(
        "examples.ca_handler.vault_ca_handler.b64_encode", return_value="encoded-cert"
    )
    @patch("examples.ca_handler.vault_ca_handler.cert_pem2der", return_value="der-cert")
    def test_022_enroll_success(
        self,
        mock_cert_pem2der,
        mock_b64_encode,
        mock_api_post,
        mock_b64_url_recode,
        mock_build_pem_file,
        mock_csr_cn_lookup,
        mock_csr_check,
        mock_config_check,
    ):
        # Simulate successful API response
        mock_api_post.return_value = (
            200,
            {"data": {"certificate": "CERT", "ca_chain": ["CA1", "CA2"]}},
        )
        self.cahandler.issuer_ref = "test-issuer"
        self.cahandler.vault_path = "path"
        self.cahandler.vault_url = "url"
        error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll(
            "dummy-csr"
        )
        self.assertIsNone(error)
        self.assertIn("CERT", cert_bundle)
        self.assertIn("CA1", cert_bundle)
        self.assertIn("CA2", cert_bundle)
        self.assertEqual(cert_raw, "encoded-cert")
        self.assertIsNone(poll_identifier)
        mock_api_post.assert_called_once_with(
            "url/v1/path/issuer/test-issuer/sign/None",
            {"csr": "pem-csr", "common_name": "test-cn"},
        )

    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._config_check",
        return_value="config error",
    )
    def test_023_enroll_config_error(self, mock_config_check):
        error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll(
            "dummy-csr"
        )
        self.assertEqual(error, "config error")
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertIsNone(poll_identifier)

    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._csr_check",
        return_value="csr error",
    )
    def test_024_enroll_csr_error(self, mock_csr_check, mock_config_check):
        error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll(
            "dummy-csr"
        )
        self.assertEqual(error, "csr error")
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertIsNone(poll_identifier)

    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._config_check",
        return_value=None,
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.CAhandler._csr_check", return_value=None
    )
    @patch("examples.ca_handler.vault_ca_handler.csr_cn_lookup", return_value="test-cn")
    @patch(
        "examples.ca_handler.vault_ca_handler.build_pem_file", return_value="pem-csr"
    )
    @patch(
        "examples.ca_handler.vault_ca_handler.b64_url_recode", return_value="recode-csr"
    )
    @patch("examples.ca_handler.vault_ca_handler.CAhandler._api_post")
    def test_025_enroll_api_error(
        self,
        mock_api_post,
        mock_b64_url_recode,
        mock_build_pem_file,
        mock_csr_cn_lookup,
        mock_csr_check,
        mock_config_check,
    ):
        # Simulate failed API response
        mock_api_post.return_value = (400, {"errors": ["api error"]})

        error, cert_bundle, cert_raw, poll_identifier = self.cahandler.enroll(
            "dummy-csr"
        )
        self.assertIsNotNone(error)
        self.assertIn("api error", error)
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)
        self.assertIsNone(poll_identifier)

    @patch(
        "examples.ca_handler.vault_ca_handler.cert_serial_get",
        return_value="abcdef1234",
    )
    def test_026_revoke_success(self, mock_cert_serial_get):
        self.cahandler._api_post = MagicMock(return_value=(200, {}))
        code, message, detail = self.cahandler.revoke("dummy_cert")
        self.cahandler._api_post.assert_called_once()
        self.assertEqual(code, 200)
        self.assertIsNone(message)
        self.assertIsNone(detail)

    @patch(
        "examples.ca_handler.vault_ca_handler.cert_serial_get",
        return_value="abcdef1234",
    )
    def test_027_revoke_api_error(self, mock_cert_serial_get):
        self.cahandler._api_post = MagicMock(return_value=(400, {"errors": ["fail"]}))
        code, message, detail = self.cahandler.revoke("dummy_cert")
        self.cahandler._api_post.assert_called_once()
        self.assertEqual(code, 400)
        self.assertFalse(message)
        self.assertEqual(detail, '["fail"]')

    @patch(
        "examples.ca_handler.vault_ca_handler.cert_serial_get",
        return_value="abcdef1234",
    )
    def test_028_revoke_api_error(self, mock_cert_serial_get):
        self.cahandler._api_post = MagicMock(return_value=(400, {"foo": ["fail"]}))
        code, message, detail = self.cahandler.revoke("dummy_cert")
        self.cahandler._api_post.assert_called_once()
        self.assertEqual(code, 400)
        self.assertFalse(message)
        self.assertEqual('{"foo": ["fail"]}', detail)

    @patch("examples.ca_handler.vault_ca_handler.cert_serial_get", return_value=None)
    def test_029_revoke_no_serial(self, mock_cert_serial_get):
        self.cahandler._api_post = MagicMock()
        code, message, detail = self.cahandler.revoke("dummy_cert")
        self.cahandler._api_post.assert_not_called()
        self.assertEqual(code, 500)
        self.assertIsNone(message)
        self.assertEqual(detail, "Failed to parse certificate serial")

    @patch("examples.ca_handler.vault_ca_handler.CAhandler._config_check")
    def test_030_handler_check(self, mock_config_check):
        mock_config_check.return_value = "foo"
        self.assertEqual("foo", self.cahandler.handler_check())

    @patch("examples.ca_handler.vault_ca_handler.eab_profile_header_info_check")
    @patch("examples.ca_handler.vault_ca_handler.allowed_domainlist_check")
    def test_031_csr_check(self, mock_adl, mock_hic):
        mock_adl.return_value = "mock_adl"
        mock_hic.return_value = "mock_hlc"
        self.assertEqual("mock_adl", self.cahandler._csr_check("dummy-csr"))
        self.assertTrue(mock_adl.called)
        self.assertFalse(mock_hic.called)

    @patch("examples.ca_handler.vault_ca_handler.eab_profile_header_info_check")
    @patch("examples.ca_handler.vault_ca_handler.allowed_domainlist_check")
    def test_032_csr_check(self, mock_adl, mock_hic):
        mock_adl.return_value = None
        mock_hic.return_value = "mock_hlc"
        self.assertEqual("mock_hlc", self.cahandler._csr_check("dummy-csr"))
        self.assertTrue(mock_adl.called)
        self.assertTrue(mock_hic.called)


if __name__ == "__main__":
    unittest.main()
