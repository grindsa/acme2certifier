# -*- coding: utf-8 -*-
""" unittest for renewalinfo.py """
import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Add the parent directory to sys.path so we can import acme_srv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acme_srv.renewalinfo import Renewalinfo, RenewalinfoConfig, RenewalinfoRepository


class TestRenewalinfoConfig(unittest.TestCase):
    def test_default_values(self):
        config = RenewalinfoConfig()
        self.assertFalse(config.renewal_force)
        self.assertEqual(config.renewalthreshold_pctg, 85.0)
        self.assertEqual(config.retry_after_timeout, 86400)


class TestRenewalinfoRepository(unittest.TestCase):
    def setUp(self):
        self.mock_dbstore = MagicMock()
        self.logger = MagicMock()
        self.repo = RenewalinfoRepository(self.mock_dbstore, self.logger)

    def test_get_certificate_by_certid_success(self):
        self.mock_dbstore.certificate_lookup.return_value = {"foo": "bar"}
        result = self.repo.get_certificate_by_certid("abc")
        self.assertEqual(result, {"foo": "bar"})

    def test_get_certificate_by_certid_exception(self):
        self.mock_dbstore.certificate_lookup.side_effect = Exception("fail")
        result = self.repo.get_certificate_by_certid("abc")
        self.assertIsNone(result)
        self.logger.critical.assert_called()

    def test_get_certificates_by_serial_success(self):
        self.mock_dbstore.certificates_search.return_value = [{"foo": "bar"}]
        result = self.repo.get_certificates_by_serial("serial")
        self.assertEqual(result, [{"foo": "bar"}])

    def test_get_certificates_by_serial_exception(self):
        self.mock_dbstore.certificates_search.side_effect = Exception("fail")
        result = self.repo.get_certificates_by_serial("serial")
        self.assertEqual(result, [])
        self.logger.critical.assert_called()

    def test_add_certificate(self):
        self.repo.add_certificate({"foo": "bar"})
        self.mock_dbstore.certificate_add.assert_called_with({"foo": "bar"})

    def test_get_housekeeping_param(self):
        self.repo.get_housekeeping_param("name")
        self.mock_dbstore.hkparameter_get.assert_called_with("name")

    def test_add_housekeeping_param(self):
        self.repo.add_housekeeping_param({"foo": "bar"})
        self.mock_dbstore.hkparameter_add.assert_called_with({"foo": "bar"})


class TestRenewalinfo(unittest.TestCase):
    def setUp(self):
        self.mock_dbstore = MagicMock()
        self.mock_logger = MagicMock()
        self.mock_message = MagicMock()
        self.mock_repository = MagicMock()
        self.mock_config = RenewalinfoConfig(
            renewal_force=True, renewalthreshold_pctg=90.0, retry_after_timeout=1234
        )
        patcher_db = patch(
            "acme_srv.renewalinfo.DBstore", return_value=self.mock_dbstore
        )
        patcher_msg = patch(
            "acme_srv.renewalinfo.Message", return_value=self.mock_message
        )
        patcher_err = patch(
            "acme_srv.renewalinfo.error_dic_get", return_value={"malformed": "malf"}
        )
        patcher_repo = patch(
            "acme_srv.renewalinfo.RenewalinfoRepository",
            return_value=self.mock_repository,
        )
        patcher_certid_hex = patch(
            "acme_srv.renewalinfo.certid_hex_get", return_value=(None, "hex")
        )
        self.addCleanup(patcher_db.stop)
        self.addCleanup(patcher_msg.stop)
        self.addCleanup(patcher_err.stop)
        self.addCleanup(patcher_repo.stop)
        self.addCleanup(patcher_certid_hex.stop)
        patcher_db.start()
        patcher_msg.start()
        patcher_err.start()
        patcher_repo.start()
        patcher_certid_hex.start()
        self.renewalinfo = Renewalinfo(
            debug=True, srv_name="srv", logger=self.mock_logger
        )
        self.renewalinfo.config = self.mock_config
        self.renewalinfo.repository = self.mock_repository

    def test_get_housekeeping_triggers_update(self):
        self.mock_repository.get_housekeeping_param.return_value = False
        self.mock_repository.add_housekeeping_param.return_value = True
        self.mock_repository.get_certificate_by_certid.return_value = {
            "expire_uts": 100000,
            "issue_uts": 90000,
        }
        self.mock_repository.get_certificates_by_serial.return_value = []
        with patch("acme_srv.renewalinfo.string_sanitize", return_value="foo"):
            self.renewalinfo._update_certificate_table_with_serial_and_aki = MagicMock()
            self.renewalinfo._get_renewalinfo_data = MagicMock(
                return_value={"suggestedWindow": {"start": "a", "end": "b"}}
            )
            result = self.renewalinfo.get("/acme/renewal-info/foo")
            self.assertEqual(result["code"], 200)
            self.assertIn("data", result)
            self.renewalinfo._update_certificate_table_with_serial_and_aki.assert_called()

    def test_get_returns_404(self):
        self.mock_repository.get_housekeeping_param.return_value = True
        self.renewalinfo._get_renewalinfo_data = MagicMock(return_value={})
        with patch("acme_srv.renewalinfo.string_sanitize", return_value="foo"):
            result = self.renewalinfo.get("/acme/renewal-info/foo")
            self.assertEqual(result["code"], 404)
            self.assertEqual(result["data"], "malf")

    def test_get_returns_400_on_exception(self):
        self.mock_repository.get_housekeeping_param.return_value = True
        self.renewalinfo._get_renewalinfo_data = MagicMock(
            side_effect=Exception("fail")
        )
        with patch("acme_srv.renewalinfo.string_sanitize", return_value="foo"):
            result = self.renewalinfo.get("/acme/renewal-info/foo")
            self.assertEqual(result["code"], 400)
            self.assertEqual(result["data"], "malf")

    def test_update_success(self):
        self.mock_message.check.return_value = (
            200,
            None,
            None,
            None,
            {"certid": "foo", "replaced": True},
            None,
        )
        self.mock_repository.get_certificate_by_certid.return_value = {
            "expire_uts": 100000,
            "issue_uts": 90000,
        }
        self.mock_repository.add_certificate.return_value = True
        with patch("acme_srv.renewalinfo.certid_hex_get", return_value=(None, "hex")):
            result = self.renewalinfo.update("content")
            self.assertEqual(result["code"], 200)

    def test_update_failure(self):
        self.mock_message.check.return_value = (
            200,
            None,
            None,
            None,
            {"certid": "foo", "replaced": True},
            None,
        )
        self.mock_repository.get_certificate_by_certid.return_value = None
        with patch("acme_srv.renewalinfo.certid_hex_get", return_value=(None, "hex")):
            result = self.renewalinfo.update("content")
            self.assertEqual(result["code"], 400)

    def test_update_payload_missing(self):
        self.mock_message.check.return_value = (
            200,
            None,
            None,
            None,
            {"foo": "bar"},
            None,
        )
        with patch("acme_srv.renewalinfo.certid_hex_get", return_value=(None, "hex")):
            result = self.renewalinfo.update("content")
            self.assertEqual(result["code"], 400)

    def test_lookup_certificate_by_renewalinfo_dot(self):
        self.renewalinfo._extract_serial_and_aki_from_string = MagicMock(
            return_value=("serial", "aki")
        )
        self.renewalinfo._lookup_certificate_by_serial_and_aki = MagicMock(
            return_value={"foo": "bar"}
        )
        result = self.renewalinfo._lookup_certificate_by_renewalinfo("serial.aki")
        self.assertEqual(result, {"foo": "bar"})

    def test_lookup_certificate_by_renewalinfo_nodot(self):
        with patch("acme_srv.renewalinfo.certid_hex_get", return_value=(None, "hex")):
            self.renewalinfo._lookup_certificate_by_certid = MagicMock(
                return_value={"foo": "bar"}
            )
            result = self.renewalinfo._lookup_certificate_by_renewalinfo("foo")
            self.assertEqual(result, {"foo": "bar"})

    def test_generate_renewalinfo_window_force(self):
        cert_dic = {"expire_uts": 100000, "issue_uts": 90000}
        self.renewalinfo.config.renewal_force = True
        with patch("acme_srv.renewalinfo.uts_now", return_value=100000):
            result = self.renewalinfo._generate_renewalinfo_window(cert_dic)
            self.assertIn("suggestedWindow", result)

    def test_generate_renewalinfo_window_normal(self):
        cert_dic = {"expire_uts": 100000, "issue_uts": 90000}
        self.renewalinfo.config.renewal_force = False
        result = self.renewalinfo._generate_renewalinfo_window(cert_dic)
        self.assertIn("suggestedWindow", result)

    def test_generate_renewalinfo_window_empty(self):
        cert_dic = {}
        result = self.renewalinfo._generate_renewalinfo_window(cert_dic)
        self.assertEqual(result, {})

    def test_generate_renewalinfo_window_no_expire_uts(self):
        renewalinfo = self.renewalinfo
        renewalinfo.logger = MagicMock()
        # cert_dic missing 'expire_uts' key
        result = renewalinfo._generate_renewalinfo_window({"foo": "bar"})
        self.assertEqual(result, {})
        # cert_dic with 'expire_uts' as None
        result2 = renewalinfo._generate_renewalinfo_window({"expire_uts": None})
        self.assertEqual(result2, {})
        # cert_dic with 'expire_uts' as 0
        result3 = renewalinfo._generate_renewalinfo_window({"expire_uts": 0})
        self.assertEqual(result3, {})
        # cert_dic with 'expire_uts' present, but 'issue_uts' missing: uts_now() should be called
        with patch("acme_srv.renewalinfo.uts_now", return_value=12345) as mock_uts_now:
            cert_dic = {"expire_uts": 100000}
            renewalinfo.config.renewal_force = False
            renewalinfo.config.renewalthreshold_pctg = 85.0
            renewalinfo._generate_renewalinfo_window(cert_dic)
            mock_uts_now.assert_called_once()

    def test_extract_serial_and_aki_from_string_valid(self):
        with patch("acme_srv.renewalinfo.b64_decode", return_value=b"abc"):
            with patch("acme_srv.renewalinfo.b64_url_recode", return_value="abc"):
                result = self.renewalinfo._extract_serial_and_aki_from_string("foo.bar")
                self.assertEqual(result, ("616263", "616263"))

    def test_extract_serial_and_aki_from_string_invalid(self):
        result = self.renewalinfo._extract_serial_and_aki_from_string("foo")
        self.assertEqual(result, (None, None))

    def test_load_configuration_all_valid(self):
        class DummyConfig:
            def getboolean(self, section, key, fallback=None):
                return True

            def get(self, section, key, fallback=None):
                if key == "renewalthreshold_pctg":
                    return "99.9"
                if key == "retry_after_timeout":
                    return "12345"
                return fallback

            def __contains__(self, key):
                return True

        with patch("acme_srv.renewalinfo.load_config", return_value=DummyConfig()):
            self.renewalinfo.logger = MagicMock()
            self.renewalinfo.config = RenewalinfoConfig()
            self.renewalinfo._load_configuration()
            self.assertTrue(self.renewalinfo.config.renewal_force)
            self.assertEqual(self.renewalinfo.config.renewalthreshold_pctg, 99.9)
            self.assertEqual(self.renewalinfo.config.retry_after_timeout, 12345)

    def test_load_configuration_defaults(self):
        class DummyConfig:
            def getboolean(self, section, key, fallback=None):
                return fallback

            def get(self, section, key, fallback=None):
                return fallback

            def __contains__(self, key):
                return True

        with patch("acme_srv.renewalinfo.load_config", return_value=DummyConfig()):
            self.renewalinfo.logger = MagicMock()
            self.renewalinfo.config = RenewalinfoConfig()
            self.renewalinfo._load_configuration()
            self.assertFalse(self.renewalinfo.config.renewal_force)
            self.assertEqual(self.renewalinfo.config.renewalthreshold_pctg, 85.0)
            self.assertEqual(self.renewalinfo.config.retry_after_timeout, 86400)

    def test_load_configuration_renewal_force_error(self):
        class DummyConfig:
            def getboolean(self, section, key, fallback=None):
                raise Exception("failbool")

            def get(self, section, key, fallback=None):
                return fallback

            def __contains__(self, key):
                return True

        with patch("acme_srv.renewalinfo.load_config", return_value=DummyConfig()):
            self.renewalinfo.logger = MagicMock()
            self.renewalinfo.config = RenewalinfoConfig()
            self.renewalinfo._load_configuration()
            # Should fallback to default False
            self.assertFalse(self.renewalinfo.config.renewal_force)

    def test_load_configuration_renewalthreshold_pctg_error(self):
        class DummyConfig:
            def getboolean(self, section, key, fallback=None):
                return False

            def get(self, section, key, fallback=None):
                if key == "renewalthreshold_pctg":
                    raise Exception("failpctg")
                return fallback

            def __contains__(self, key):
                return True

        with patch("acme_srv.renewalinfo.load_config", return_value=DummyConfig()):
            self.renewalinfo.logger = MagicMock()
            self.renewalinfo.config = RenewalinfoConfig()
            self.renewalinfo._load_configuration()
            self.renewalinfo.logger.error.assert_any_call(
                "renewalthreshold_pctg parsing error: %s", unittest.mock.ANY
            )
            self.assertEqual(self.renewalinfo.config.renewalthreshold_pctg, 85.0)

    def test_load_configuration_retry_after_timeout_error(self):
        class DummyConfig:
            def getboolean(self, section, key, fallback=None):
                return False

            def get(self, section, key, fallback=None):
                if key == "renewalthreshold_pctg":
                    return "85.0"
                if key == "retry_after_timeout":
                    raise Exception("failtimeout")
                return fallback

            def __contains__(self, key):
                return True

        with patch("acme_srv.renewalinfo.load_config", return_value=DummyConfig()):
            self.renewalinfo.logger = MagicMock()
            self.renewalinfo.config = RenewalinfoConfig()
            self.renewalinfo._load_configuration()
            self.renewalinfo.logger.error.assert_any_call(
                "retry_after_timeout parsing error: %s", unittest.mock.ANY
            )
            self.assertEqual(self.renewalinfo.config.retry_after_timeout, 86400)

    def test_exit_does_nothing_and_returns_none(self):
        renewalinfo = self.renewalinfo
        # __exit__ should just return None and not raise
        result = renewalinfo.__exit__(None, None, None)
        self.assertIsNone(result)

    def test_context_manager_usage(self):
        # Ensure __enter__ and __exit__ work in a with-statement
        renewalinfo = self.renewalinfo
        with patch.object(renewalinfo, "_load_configuration") as mock_load_config:
            with renewalinfo as ri:
                mock_load_config.assert_called_once()
                self.assertIs(ri, renewalinfo)

    def test_update_certificate_table_with_serial_and_aki_success(self):
        renewalinfo = self.renewalinfo
        mock_logger = MagicMock()
        renewalinfo.logger = mock_logger
        renewalinfo.repository = MagicMock()
        renewalinfo.dbstore = MagicMock()
        # Simulate two certs, one valid, one missing cert_raw
        certs = [
            {"cert_raw": b"raw1", "name": "n1", "cert": "c1"},
            {"name": "n2", "cert": "c2"},  # missing cert_raw, should be skipped
        ]
        renewalinfo.dbstore.certificates_search.return_value = certs
        with patch(
            "acme_srv.renewalinfo.cert_serial_get", return_value="serial1"
        ), patch("acme_srv.renewalinfo.cert_aki_get", return_value="aki1"):
            renewalinfo._update_certificate_table_with_serial_and_aki()
        # Only one add_certificate should be called
        renewalinfo.repository.add_certificate.assert_called_once_with(
            {
                "serial": "serial1",
                "aki": "aki1",
                "name": "n1",
                "cert_raw": b"raw1",
                "cert": "c1",
            }
        )
        # Should log start and end
        mock_logger.debug.assert_any_call(
            "Renewalinfo._update_certificate_table_with_serial_and_aki()"
        )
        mock_logger.debug.assert_any_call(
            "Renewalinfo._update_certificate_table_with_serial_and_aki(%s) - done", 1
        )

    def test_update_certificate_table_with_serial_and_aki_db_error(self):
        renewalinfo = self.renewalinfo
        mock_logger = MagicMock()
        renewalinfo.logger = mock_logger
        renewalinfo.repository = MagicMock()
        renewalinfo.dbstore = MagicMock()
        renewalinfo.dbstore.certificates_search.side_effect = Exception("dbfail")
        renewalinfo._update_certificate_table_with_serial_and_aki()
        # Should log the critical error
        mock_logger.critical.assert_called_with(
            "Database error: failed to retrieve certificate list for renewal info update: %s",
            unittest.mock.ANY,
        )
        # Should log end with 0
        mock_logger.debug.assert_any_call(
            "Renewalinfo._update_certificate_table_with_serial_and_aki(%s) - done", 0
        )
        # No add_certificate calls
        renewalinfo.repository.add_certificate.assert_not_called()

    def test_get_compat_success(self):
        renewalinfo = self.renewalinfo
        renewalinfo.logger = MagicMock()
        renewalinfo.repository = MagicMock()
        renewalinfo.err_msg_dic = {"malformed": "malf"}
        renewalinfo.config.retry_after_timeout = 123
        renewalinfo.repository.get_housekeeping_param.return_value = True
        renewalinfo._get_renewalinfo_data = MagicMock(return_value={"foo": "bar"})
        with patch("acme_srv.renewalinfo.string_sanitize", return_value="foo"):
            result = renewalinfo.get("/acme/renewal-info/foo")
            self.assertEqual(result["code"], 200)
            self.assertIn("data", result)
            self.assertIn("header", result)

    def test_get_compat_404(self):
        renewalinfo = self.renewalinfo
        renewalinfo.logger = MagicMock()
        renewalinfo.repository = MagicMock()
        renewalinfo.err_msg_dic = {"malformed": "malf"}
        renewalinfo.repository.get_housekeeping_param.return_value = True
        renewalinfo._get_renewalinfo_data = MagicMock(return_value={})
        with patch("acme_srv.renewalinfo.string_sanitize", return_value="foo"):
            result = renewalinfo.get("/acme/renewal-info/foo")
            self.assertEqual(result["code"], 404)
            self.assertEqual(result["data"], "malf")

    def test_get_compat_400(self):
        renewalinfo = self.renewalinfo
        renewalinfo.logger = MagicMock()
        renewalinfo.repository = MagicMock()
        renewalinfo.err_msg_dic = {"malformed": "malf"}
        renewalinfo.repository.get_housekeeping_param.return_value = True
        renewalinfo._get_renewalinfo_data = MagicMock(side_effect=Exception("fail"))
        with patch("acme_srv.renewalinfo.string_sanitize", return_value="foo"):
            result = renewalinfo.get("/acme/renewal-info/foo")
            self.assertEqual(result["code"], 400)
            self.assertEqual(result["data"], "malf")

    def test_update_compat_success(self):
        renewalinfo = self.renewalinfo
        renewalinfo.logger = MagicMock()
        renewalinfo.message = MagicMock()
        renewalinfo.repository = MagicMock()
        renewalinfo.err_msg_dic = {"malformed": "malf"}
        renewalinfo.message.check.return_value = (
            200,
            None,
            None,
            None,
            {"certid": "foo", "replaced": True},
            None,
        )
        renewalinfo._lookup_certificate_by_renewalinfo = MagicMock(
            return_value={"foo": "bar"}
        )
        renewalinfo.repository.add_certificate.return_value = True
        result = renewalinfo.update("content")
        self.assertEqual(result["code"], 200)

    def test_update_compat_failure(self):
        renewalinfo = self.renewalinfo
        renewalinfo.logger = MagicMock()
        renewalinfo.message = MagicMock()
        renewalinfo.repository = MagicMock()
        renewalinfo.err_msg_dic = {"malformed": "malf"}
        renewalinfo.message.check.return_value = (
            200,
            None,
            None,
            None,
            {"certid": "foo", "replaced": True},
            None,
        )
        renewalinfo._lookup_certificate_by_renewalinfo = MagicMock(return_value=None)
        result = renewalinfo.update("content")
        self.assertEqual(result["code"], 400)

    def test_update_compat_payload_missing(self):
        renewalinfo = self.renewalinfo
        renewalinfo.logger = MagicMock()
        renewalinfo.message = MagicMock()
        renewalinfo.repository = MagicMock()
        renewalinfo.err_msg_dic = {"malformed": "malf"}
        renewalinfo.message.check.return_value = (
            200,
            None,
            None,
            None,
            {"foo": "bar"},
            None,
        )
        result = renewalinfo.update("content")
        self.assertEqual(result["code"], 400)

    def test_lookup_certificate_by_serial_and_aki_found(self):
        # Setup: cert_list contains a cert with matching aki
        cert = {"aki": "aki123", "foo": "bar"}
        self.renewalinfo.repository.get_certificates_by_serial.return_value = [cert]
        result = self.renewalinfo._lookup_certificate_by_serial_and_aki(
            "serial123", "aki123"
        )
        self.assertEqual(result, cert)
        self.renewalinfo.repository.get_certificates_by_serial.assert_called_once_with(
            "serial123"
        )

    def test_lookup_certificate_by_serial_and_aki_leading_zero(self):
        # Setup: first call returns empty, second returns a cert with matching aki
        cert = {"aki": "aki456", "foo": "baz"}
        self.renewalinfo.repository.get_certificates_by_serial.side_effect = [
            [],
            [cert],
        ]
        result = self.renewalinfo._lookup_certificate_by_serial_and_aki(
            "0123", "aki456"
        )
        self.assertEqual(result, cert)
        self.assertEqual(
            self.renewalinfo.repository.get_certificates_by_serial.call_count, 2
        )
        self.renewalinfo.repository.get_certificates_by_serial.assert_any_call("0123")
        self.renewalinfo.repository.get_certificates_by_serial.assert_any_call("123")

    def test_lookup_certificate_by_serial_and_aki_not_found(self):
        # Setup: cert_list does not contain a cert with matching aki
        self.renewalinfo.repository.get_certificates_by_serial.return_value = [
            {"aki": "other"}
        ]
        result = self.renewalinfo._lookup_certificate_by_serial_and_aki(
            "serial", "aki999"
        )
        self.assertEqual(result, {})

    def test_lookup_certificate_by_serial_and_aki_empty_list(self):
        # Setup: cert_list is empty
        self.renewalinfo.repository.get_certificates_by_serial.return_value = []
        result = self.renewalinfo._lookup_certificate_by_serial_and_aki("serial", "aki")
        self.assertEqual(result, {})

    def test_get_renewalinfo_data(self):
        # Setup: _lookup_certificate_by_renewalinfo and _generate_renewalinfo_window are called
        cert_dic = {"expire_uts": 100000, "issue_uts": 90000}
        renewalinfo_dic = {
            "suggestedWindow": {"start": "2025-01-01", "end": "2026-01-01"}
        }
        self.renewalinfo._lookup_certificate_by_renewalinfo = MagicMock(
            return_value=cert_dic
        )
        self.renewalinfo._generate_renewalinfo_window = MagicMock(
            return_value=renewalinfo_dic
        )
        result = self.renewalinfo._get_renewalinfo_data("foo.bar")
        self.renewalinfo._lookup_certificate_by_renewalinfo.assert_called_once_with(
            "foo.bar"
        )
        self.renewalinfo._generate_renewalinfo_window.assert_called_once_with(cert_dic)
        self.assertEqual(result, renewalinfo_dic)


if __name__ == "__main__":
    unittest.main()
