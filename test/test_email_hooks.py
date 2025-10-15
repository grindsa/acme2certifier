import unittest
from unittest.mock import patch, MagicMock, PropertyMock
import sys
sys.path.insert(0, ".")
sys.path.insert(1, "..")



class DummyConfig:
    """Shim to emulate config parser used by Hooks"""
    def __init__(self, data):
        self._data = data
    def __contains__(self, key):
        return key in self._data
    def __getitem__(self, key):
        return self._data[key]
    def get(self, section, key, fallback=None):
        return self._data.get(section, {}).get(key, fallback)
    def getint(self, section, key, fallback=None):
        val = self.get(section, key, fallback)
        try:
            return int(val) if val is not None else fallback
        except (TypeError, ValueError):
            return fallback
    def getboolean(self, section, key, fallback=None):
        val = self.get(section, key, fallback)
        if val is None:
            return fallback
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("true", "1", "yes", "on")


class TestHooks(unittest.TestCase):
    """Tests for email_hooks.Hooks"""
    def setUp(self):
        import logging

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        # Start patching load_config before importing and instantiating Hooks
        self._config_patch = patch(
            "examples.hooks.email_hooks.load_config",
            return_value=DummyConfig({
                "Hooks": {
                    "appname": "acme2certifier",
                    "sender": "sender@example.com",
                    "rcpt": "rcpt@example.com",
                }
            }),
        )
        self._config_patch_started = self._config_patch.start()
        self.addCleanup(self._config_patch.stop)

        from examples.hooks.email_hooks import Hooks
        self.hooks = Hooks(self.logger)

    def test_001_init(self):
        """test init"""
        self.assertEqual(self.hooks.appname, "acme2certifier")
        self.assertEqual(self.hooks.sender, "sender@example.com")
        self.assertEqual(self.hooks.rcpt, "rcpt@example.com")

    def test_002_validate_configuration_valid(self):
        """validate_configuration passes for complete config"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "Hooks": {
                "appname": "acme2certifier",
                "sender": "sender@example.com",
                "rcpt": "rcpt@example.com",
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            self.assertEqual(h.appname, "acme2certifier")
            self.assertEqual(h.sender, "sender@example.com")
            self.assertEqual(h.rcpt, "rcpt@example.com")

    def test_003_validate_configuration_empty_config(self):
        """validate_configuration raises on None/empty config"""
        from examples.hooks.email_hooks import Hooks
        with patch("examples.hooks.email_hooks.load_config", return_value=None):
            with self.assertRaises(ValueError) as ctx:
                Hooks(self.logger)
            self.assertIn("Configuration dictionary is empty or None", str(ctx.exception))

    def test_004_validate_configuration_missing_section(self):
        """validate_configuration raises when [Hooks] missing"""
        from examples.hooks.email_hooks import Hooks
        cfg = {}
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            with self.assertRaises(ValueError) as ctx:
                Hooks(self.logger)
            self.assertIn("Missing 'Hooks' section in configuration", str(ctx.exception))

    def test_005_validate_configuration_missing_required_keys(self):
        """validate_configuration raises when required keys missing"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "Hooks": {
                "appname": "acme2certifier",
                # missing sender and rcpt
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            with self.assertRaises(ValueError) as ctx:
                Hooks(self.logger)
            msg = str(ctx.exception)
            self.assertIn("Missing required configuration key(s) in [Hooks]", msg)
            self.assertIn("sender", msg)
            self.assertIn("rcpt", msg)

    def test_006_validate_configuration_empty_required_keys(self):
        """validate_configuration raises when required keys empty/whitespace"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "Hooks": {
                "appname": " ",
                "sender": "\t",
                "rcpt": "",
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            with self.assertRaises(ValueError) as ctx:
                Hooks(self.logger)
            msg = str(ctx.exception)
            self.assertIn("Empty required configuration key(s) in [Hooks]", msg)
            # Ensure at least one of the empty keys is mentioned
            self.assertTrue(any(k in msg for k in ["appname", "sender", "rcpt"]))

    def test_010_smtp_valid_port_and_timeout(self):
        """Validates correct port and timeout do not log errors"""
        self.hooks.config_dic["Hooks"].update({
            "smtp_port": 587,
            "smtp_timeout": 30,
            "smtp_username": "user",
            "smtp_password": "pw"
        })
        # Should not raise or log errors for valid config
        self.hooks._validate_smtp_configuration()

    def test_011_smtp_invalid_timeout(self):
        """Logs error for invalid smtp_timeout"""
        self.hooks.config_dic["Hooks"]["smtp_timeout"] = 9999
        with self.assertLogs(self.logger, level="ERROR") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(any("Invalid SMTP timeout" in msg for msg in cm.output))

    def test_012_smtp_password_no_username(self):
        """Logs debug when password is set but username is missing"""
        self.hooks.config_dic["Hooks"].pop("smtp_username", None)
        self.hooks.config_dic["Hooks"]["smtp_password"] = "pw"
        with self.assertLogs(self.logger, level="DEBUG") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(any("SMTP password provided without username" in msg for msg in cm.output))

    def test_013_smtp_username_no_password(self):
        """Logs error when username is set but password is missing"""
        self.hooks.config_dic["Hooks"]["smtp_username"] = "user"
        self.hooks.config_dic["Hooks"].pop("smtp_password", None)
        with self.assertLogs(self.logger, level="ERROR") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(any("SMTP username provided but password is missing" in msg for msg in cm.output))

    def test_014_smtp_both_tls_and_starttls(self):
        """Logs warning if both smtp_use_tls and smtp_use_starttls are True"""
        self.hooks.config_dic["Hooks"]["smtp_use_tls"] = True
        self.hooks.config_dic["Hooks"]["smtp_use_starttls"] = True
        with self.assertLogs(self.logger, level="WARNING") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(any("Both smtp_use_tls and smtp_use_starttls are enabled" in msg for msg in cm.output))

    def test_015_smtp_port_465_without_tls(self):
        """Logs info if port 465 is used without TLS"""
        self.hooks.config_dic["Hooks"]["smtp_port"] = 465
        self.hooks.config_dic["Hooks"]["smtp_use_tls"] = False
        with self.assertLogs(self.logger, level="INFO") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(any("Port 465 typically requires TLS" in msg for msg in cm.output))

    def test_016_smtp_port_587_without_tls_or_starttls(self):
        """Logs info if port 587 is used without TLS or STARTTLS"""
        self.hooks.config_dic["Hooks"]["smtp_port"] = 587
        self.hooks.config_dic["Hooks"]["smtp_use_tls"] = False
        self.hooks.config_dic["Hooks"]["smtp_use_starttls"] = False
        with self.assertLogs(self.logger, level="INFO") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(any("Port 587 typically requires STARTTLS" in msg for msg in cm.output))

    def test_016_load_configuration_assigns_required_fields(self):
        self.hooks.config_dic["Hooks"].update({
            "appname": "TestApp",
            "sender": "test@example.com",
            "rcpt": "rcpt@example.com",
        })
        self.hooks._load_configuration()
        self.assertEqual(self.hooks.appname, "TestApp")
        self.assertEqual(self.hooks.sender, "test@example.com")
        self.assertEqual(self.hooks.rcpt, "rcpt@example.com")

    def test_017_load_configuration_optional_booleans(self):
        self.hooks.config_dic["Hooks"].update({
            "appname": "TestApp",
            "sender": "test@example.com",
            "rcpt": "rcpt@example.com",
            "report_failures": "False",
            "report_successes": "True",
        })
        self.hooks._load_configuration()
        self.assertFalse(self.hooks.report_failures)
        self.assertTrue(self.hooks.report_successes)

    def test_018_load_configuration_smtp_defaults(self):
        self.hooks.config_dic["Hooks"].update({
            "appname": "TestApp",
            "sender": "test@example.com",
            "rcpt": "rcpt@example.com",
        })
        self.hooks._load_configuration()
        self.assertEqual(self.hooks.smtp_server, "localhost")
        self.assertEqual(self.hooks.smtp_port, 25)
        self.assertEqual(self.hooks.smtp_timeout, 30)
        self.assertIsNone(self.hooks.smtp_username)
        self.assertIsNone(self.hooks.smtp_password)
        self.assertTrue(self.hooks.smtp_use_tls)
        self.assertFalse(self.hooks.smtp_use_starttls)

    def test_019_load_configuration_assigns_all_fields(self):
        self.hooks.config_dic["Hooks"].update({
            "appname": "TestApp",
            "sender": "test@example.com",
            "rcpt": "rcpt@example.com",
            "smtp_server": "smtp.example.com",
            "smtp_port": "2525",
            "subject_prefix": "[PREFIX]",
            "smtp_timeout": "42",
            "smtp_username": "user",
            "smtp_password": "pass",
            "smtp_use_tls": "False",
            "smtp_use_starttls": "True",
        })
        self.hooks._load_configuration()
        self.assertEqual(self.hooks.smtp_server, "smtp.example.com")
        self.assertEqual(self.hooks.smtp_port, 2525)
        self.assertEqual(self.hooks.email_subject_prefix, "[PREFIX]")
        self.assertEqual(self.hooks.smtp_timeout, 42)
        self.assertEqual(self.hooks.smtp_username, "user")
        self.assertEqual(self.hooks.smtp_password, "pass")
        self.assertFalse(self.hooks.smtp_use_tls)
        self.assertTrue(self.hooks.smtp_use_starttls)

    def test_020_load_configuration_uses_sender_as_username_if_password_only(self):
        self.hooks.config_dic["Hooks"].update({
            "appname": "TestApp",
            "sender": "test@example.com",
            "rcpt": "rcpt@example.com",
            "smtp_password": "pass",
        })
        with self.assertLogs(self.logger, "DEBUG") as cm:
            self.hooks._load_configuration()
        self.assertEqual(self.hooks.smtp_username, "test@example.com")
        self.assertIn("Using sender email as SMTP username", "\n".join(cm.output))

    def test_021_load_configuration_sets_envelope_fields(self):
        self.hooks.config_dic["Hooks"].update({
            "appname": "TestApp",
            "sender": "test@example.com",
            "rcpt": "rcpt@example.com",
        })
        self.hooks._load_configuration()
        self.assertIn("From", self.hooks.envelope)
        self.assertIn("To", self.hooks.envelope)
        self.assertIn("Date", self.hooks.envelope)
        self.assertEqual(self.hooks.envelope["From"], "TestApp <test@example.com>")
        self.assertEqual(self.hooks.envelope["To"], "rcpt@example.com")
        self.assertFalse(self.hooks.done)

    def test_025_done_multiple_calls_warns(self):
        self.hooks.done = True
        with self.assertLogs(self.logger, "WARNING") as cm:
            self.hooks._done()
        self.assertIn("email already sent", "\n".join(cm.output))

    def test_026_done_handles_exception_and_logs_error(self):
        self.hooks.smtp_use_tls = True
        self.hooks.smtp_server = "smtp.example.com"
        self.hooks.smtp_port = 465
        self.hooks.smtp_timeout = 10
        self.hooks.smtp_username = "user"
        self.hooks.smtp_password = "pass"
        self.hooks.sender = "sender@example.com"
        self.hooks.rcpt = "rcpt@example.com"
        self.hooks.envelope["Subject"] = "Test Subject"
        self.hooks.msg = ["Test message"]

        with patch("smtplib.SMTP_SSL", side_effect=Exception("SMTP error")):
            with self.assertLogs(self.logger, "ERROR") as cm:
                self.hooks._done()
            self.assertIn("Email sending failed", "\n".join(cm.output))
            self.assertTrue(self.hooks.done)

    def test_027_clean_san_valid_list(self):
        """_clean_san returns correct value for valid SAN list"""
        result = self.hooks._clean_san(["DNS:example.com"])
        self.assertEqual(result, "example.com")

    def test_029_clean_san_none(self):
        """_clean_san returns 'unknown' and logs warning for None input"""
        with self.assertLogs(self.logger, level="WARNING") as cm:
            result = self.hooks._clean_san(None)
        self.assertEqual(result, "unknown")
        self.assertTrue(any("Empty SAN list provided" in msg for msg in cm.output))

    def test_030_clean_san_not_a_list(self):
        """_clean_san returns 'unknown' and logs warning for non-list input"""
        with self.assertLogs(self.logger, level="WARNING") as cm:
            result = self.hooks._clean_san("DNS:example.com")
        self.assertEqual(result, "unknown")
        self.assertTrue(any("SAN is not a list" in msg for msg in cm.output))

    def test_031_clean_san_invalid_format(self):
        """_clean_san returns 'unknown' and logs warning for invalid format"""
        with self.assertLogs(self.logger, level="WARNING") as cm:
            result = self.hooks._clean_san(["example.com"])
        self.assertEqual(result, "unknown")
        self.assertTrue(any("Invalid SAN format" in msg for msg in cm.output))

    @patch("examples.hooks.email_hooks.build_pem_file", return_value="PEM DATA")
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_033_attach_csr_success(self, mock_mimeapp, mock_build_pem):
        """_attach_csr attaches CSR as expected when PEM is built"""
        request_key = "reqkey"
        csr = "csrdata"
        self.hooks.san = "example.com"
        self.hooks.envelope = MagicMock()
        self.hooks.msg = []
        part_mock = MagicMock()
        mock_mimeapp.return_value = part_mock
        self.hooks._attach_csr(request_key, csr)
        mock_build_pem.assert_called()
        mock_mimeapp.assert_called_with("PEM DATA", Name="example.com_reqkey.csr")
        self.hooks.envelope.attach.assert_called_with(part_mock)
        self.assertIn("To read example.com_reqkey.csr using CMD on Windows", "\n".join(self.hooks.msg))

    @patch("examples.hooks.email_hooks.build_pem_file", return_value=None)
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_034_attach_csr_pem_build_fails(self, mock_mimeapp, mock_build_pem):
        """_attach_csr logs error and does not attach if PEM build fails"""
        request_key = "reqkey"
        csr = "csrdata"
        self.hooks.san = "example.com"
        self.hooks.envelope = MagicMock()
        self.hooks.msg = []
        with self.assertLogs(self.logger, level="ERROR") as cm:
            self.hooks._attach_csr(request_key, csr)
        mock_build_pem.assert_called()
        mock_mimeapp.assert_not_called()
        self.assertTrue(any("Failed to build PEM file from CSR" in msg for msg in cm.output))

    @patch("examples.hooks.email_hooks.build_pem_file", side_effect=Exception("fail"))
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_035_attach_csr_exception(self, mock_mimeapp, mock_build_pem):
        """_attach_csr logs warning and appends message if exception occurs"""
        request_key = "reqkey"
        csr = "csrdata"
        self.hooks.san = "example.com"
        self.hooks.envelope = MagicMock()
        self.hooks.msg = []
        with self.assertLogs(self.logger, level="WARNING") as cm:
            self.hooks._attach_csr(request_key, csr)
        self.assertTrue(any("Failed to attach CSR" in msg for msg in cm.output))
        self.assertIn("CSR attachment failed: Exception", self.hooks.msg[-1])

    @patch("examples.hooks.email_hooks.x509.load_pem_x509_certificates", return_value=[MagicMock(), MagicMock()])
    @patch("examples.hooks.email_hooks.pkcs12.serialize_key_and_certificates", return_value=b"PFXDATA")
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_036_attach_cert_success(self, mock_mimeapp, mock_serialize, mock_load_x509):
        """_attach_cert attaches certificate as expected when parsing and serialization succeed"""
        request_key = "reqkey"
        certificate = "CERTDATA"
        self.hooks.san = "example.com"
        self.hooks.envelope = MagicMock()
        self.hooks.msg = []
        part_mock = MagicMock()
        mock_mimeapp.return_value = part_mock
        self.hooks._attach_cert(request_key, certificate)
        mock_load_x509.assert_called_with(certificate.encode("utf-8"))
        mock_serialize.assert_called()
        mock_mimeapp.assert_called_with(b"PFXDATA", Name="example.com_reqkey.pfx")
        self.hooks.envelope.attach.assert_called_with(part_mock)
        self.assertIn("To read example.com_reqkey.pfx using CMD on Windows", "\n".join(self.hooks.msg))

    @patch("examples.hooks.email_hooks.x509.load_pem_x509_certificates", side_effect=Exception("parsefail"))
    @patch("examples.hooks.email_hooks.pkcs12.serialize_key_and_certificates")
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_037_attach_cert_parse_error(self, mock_mimeapp, mock_serialize, mock_load_x509):
        """_attach_cert logs warning and appends message if certificate parsing fails"""
        request_key = "reqkey"
        certificate = "CERTDATA"
        self.hooks.san = "example.com"
        self.hooks.envelope = MagicMock()
        self.hooks.msg = []
        with self.assertLogs(self.logger, level="WARNING") as cm:
            self.hooks._attach_cert(request_key, certificate)
        self.assertTrue(any("Certificate attachment failed" in msg for msg in cm.output))
        self.assertIn("Certificate attachment failed: Exception", self.hooks.msg[-1])
        mock_serialize.assert_not_called()
        mock_mimeapp.assert_not_called()
    @patch("examples.hooks.email_hooks.x509.load_pem_x509_certificates", return_value=[MagicMock(), MagicMock()])
    @patch("examples.hooks.email_hooks.pkcs12.serialize_key_and_certificates", side_effect=Exception("serializefail"))
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_038_attach_cert_serialize_error(self, mock_mimeapp, mock_serialize, mock_load_x509):
        """_attach_cert logs warning and appends message if serialization fails"""
        request_key = "reqkey"
        certificate = "CERTDATA"
        self.hooks.san = "example.com"
        self.hooks.envelope = MagicMock()
        self.hooks.msg = []
        with self.assertLogs(self.logger, level="WARNING") as cm:
            self.hooks._attach_cert(request_key, certificate)
        self.assertTrue(any("Certificate attachment failed" in msg for msg in cm.output))
        self.assertIn("Certificate attachment failed: Exception", self.hooks.msg[-1])
        mock_mimeapp.assert_not_called()

    def test_039_format_subject_with_prefix(self):
        """_format_subject includes prefix if set"""
        self.hooks.appname = "TestApp"
        self.hooks.email_subject_prefix = "[PREFIX]"
        subject = self.hooks._format_subject("success", "example.com")
        self.assertTrue(subject.startswith("[PREFIX] "))
        self.assertIn("TestApp success: example.com", subject)

    def test_040_format_subject_without_prefix(self):
        """_format_subject omits prefix if not set"""
        self.hooks.appname = "TestApp"
        self.hooks.email_subject_prefix = ""
        subject = self.hooks._format_subject("failure", "example.com")
        self.assertEqual(subject, "TestApp failure: example.com")

    def test_041_format_message_header_success(self):
        """_format_message_header returns expected header for success"""
        self.hooks.appname = "TestApp"
        header = self.hooks._format_message_header("success", "example.com")
        self.assertIn("ACME Certificate Success Notification", header)
        self.assertIn("Application: TestApp", header)
        self.assertIn("Subject Alternative Name: example.com", header)
        self.assertIn("Timestamp:", header)
        self.assertIn("-" * 50, header)

    def test_042_format_message_header_failure(self):
        """_format_message_header returns expected header for failure"""
        self.hooks.appname = "TestApp"
        header = self.hooks._format_message_header("failure", "test-san")
        self.assertIn("ACME Certificate Failure Notification", header)
        self.assertIn("Application: TestApp", header)
        self.assertIn("Subject Alternative Name: test-san", header)
        self.assertIn("Timestamp:", header)
        self.assertIn("-" * 50, header)

    @patch("examples.hooks.email_hooks.csr_san_get", return_value=["DNS:example.com"])
    def test_043_post_hook_success(self, mock_csr_san_get):
        """post_hook sends failure email with correct subject and message"""
        from examples.hooks.email_hooks import Hooks
        # Setup a real Hooks instance with mocks for envelope and _done
        hooks = Hooks(self.logger)
        hooks.san = "example.com"
        hooks.envelope = {"Subject": None}
        hooks._format_subject = lambda status, san: f"subject-{status}-{san}"
        hooks._format_message_header = lambda status, san: f"header-{status}-{san}"
        hooks._attach_csr = MagicMock()
        hooks._done = MagicMock()
        hooks.msg = []
        hooks.report_failures = True
        hooks.post_hook("reqkey", "order", "csr", "error-details")
        self.assertEqual(hooks.envelope["Subject"], "subject-failure-example.com")
        self.assertIn("header-failure-example.com", hooks.msg[0])
        self.assertIn("Error Details", hooks.msg[1])
        hooks._attach_csr.assert_called_with("reqkey", "csr")
        hooks._done.assert_called()

    def test_044_post_hook_report_failures_false(self):
        """post_hook does nothing if report_failures is False"""
        from examples.hooks.email_hooks import Hooks
        hooks = Hooks(self.logger)
        hooks.report_failures = False
        hooks._done = MagicMock()
        hooks._attach_csr = MagicMock()
        hooks.envelope = {"Subject": None}
        hooks.msg = []
        hooks.post_hook("reqkey", "order", "csr", "error-details")
        hooks._done.assert_not_called()
        hooks._attach_csr.assert_not_called()
        self.assertEqual(hooks.msg, [])

    @patch("examples.hooks.email_hooks.csr_san_get", side_effect=Exception("fail"))
    def test_045_post_hook_exception(self, mock_csr_san_get):
        """post_hook logs error if exception occurs"""
        from examples.hooks.email_hooks import Hooks
        hooks = Hooks(self.logger)
        hooks.report_failures = True
        hooks._done = MagicMock()
        hooks._attach_csr = MagicMock()
        hooks.envelope = {"Subject": None}
        hooks.msg = []
        with self.assertLogs(self.logger, level="ERROR") as cm:
            hooks.post_hook("reqkey", "order", "csr", "error-details")
        self.assertTrue(any("Error in post_hook" in msg for msg in cm.output))

    @patch("examples.hooks.email_hooks.cert_san_get", return_value=["DNS:example.com"])
    def test_046_success_hook_normal(self, mock_cert_san_get):
        """success_hook sends success email with correct subject and message"""
        self.hooks.san = "example.com"
        self.hooks.envelope = {"Subject": None}
        self.hooks._format_subject = lambda status, san: f"subject-{status}-{san}"
        self.hooks._format_message_header = lambda status, san: f"header-{status}-{san}"
        self.hooks._attach_csr = MagicMock()
        self.hooks._attach_cert = MagicMock()
        self.hooks._done = MagicMock()
        self.hooks.msg = []
        self.hooks.report_successes = True
        self.hooks.success_hook("reqkey", "order", "csr", "cert", "cert_raw", "pollid")
        self.assertEqual(self.hooks.envelope["Subject"], "subject-success-example.com")
        self.assertIn("header-success-example.com", self.hooks.msg[0])
        self.assertIn("Certificate issued successfully!", self.hooks.msg[1])
        self.hooks._attach_csr.assert_called_with("reqkey", "csr")
        self.hooks._attach_cert.assert_called_with("reqkey", "cert")
        self.hooks._done.assert_called()

    def test_047_success_hook_report_successes_false(self):
        """success_hook does nothing if report_successes is False"""
        self.hooks.report_successes = False
        self.hooks._done = MagicMock()
        self.hooks._attach_csr = MagicMock()
        self.hooks._attach_cert = MagicMock()
        self.hooks.envelope = {"Subject": None}
        self.hooks.msg = []
        self.hooks.success_hook("reqkey", "order", "csr", "cert", "cert_raw", "pollid")
        self.hooks._done.assert_not_called()
        self.hooks._attach_csr.assert_not_called()
        self.hooks._attach_cert.assert_not_called()
        self.assertEqual(self.hooks.msg, [])

    @patch("examples.hooks.email_hooks.cert_san_get", side_effect=Exception("fail"))
    def test_048_success_hook_exception(self, mock_cert_san_get):
        """success_hook logs error if exception occurs"""
        self.hooks.report_successes = True
        self.hooks._done = MagicMock()
        self.hooks._attach_csr = MagicMock()
        self.hooks._attach_cert = MagicMock()
        self.hooks.envelope = {"Subject": None}
        self.hooks.msg = []
        with self.assertLogs(self.logger, level="ERROR") as cm:
            self.hooks.success_hook("reqkey", "order", "csr", "cert", "cert_raw", "pollid")
        self.assertTrue(any("Error in success_hook" in msg for msg in cm.output))

    @patch("examples.hooks.email_hooks.cert_san_get", return_value=["DNS:example.com"])
    def test_049_success_hook_normal(self, mock_cert_san_get):
        """success_hook sends success email with correct subject and message"""

        certificate = (
            "-----BEGIN CERTIFICATE-----\nMIIECjCCAnKgAwIBAgIRALGHaaUUFeRgIrUBibd8K3owDQYJKoZ"
            "IhvcNAQELBQAw\nVTEeMBwGA1UEChMVbWtjZXJ0IGRldmVsb3BtZW50IENBMRUwEwYDVQQLDAxyb290"
            "\nQGJhc3Rpb24xHDAaBgNVBAMME21rY2VydCByb290QGJhc3Rpb24wHhcNMjUxMDAx\nMTQyMjMxWhcN"
            "MjgwMTAxMTQyMjMxWjBAMScwJQYDVQQKEx5ta2NlcnQgZGV2ZWxv\ncG1lbnQgY2VydGlmaWNhdGUxFT"
            "ATBgNVBAsMDHJvb3RAYmFzdGlvbjCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMVJJSx0"
            "7B5xVBF7iT1jwvP9Q7sQHBAa\nOSctCmm8FMgQAn0B1i/M5RORrxmsxe9TGYQN23mgZPrkhfFREbK3jF"
            "1qDyi5aqyv\nRUCY8c6V8gVNHqeFY/Fbo7eVpUmL6cEWCQa4/IyC8HZgWZPvK8DiNEKTS6fa++Wg\ng7"
            "hEl0Du9IENEdnJZ8S63UGUklNaUmn/lsD2SMgtDq0OJUYmU5Zn1Uryh8I4MJCu\nHY/+i4CV+6tirKYN"
            "eQYvX2lxY8AcYnRsg8x18IVO5fu7DoH18uK0YtlTMEYac+AX\nOI/6B0C6NqXse71cQs53UF/O7ew+OC"
            "kZ67CoYobAqeuiOVEEA+qTSUsCAwEAAaNq\nMGgwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsG"
            "AQUFBwMBMB8GA1UdIwQY\nMBaAFEW2GtPZX80jY6cvOq8rMMAfW1hsMCAGA1UdEQQZMBeCFXNvbWV0aG"
            "luZy5l\neGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAYEAkDCKBHuqVxcXgx7vhftzDE3M\nj8x7WC"
            "4di+rkIrxyJ3ulGHc7Pl2gyvMoKJxRCqcK4WgLH7AqDkRsQSF+/yvv+c0H\nbUYjauPfDo1yUlLIQpo3"
            "7uwJjsfQt4j/AFLpYHw2myqAsqMw1jwbXRuLyyiHWSay\nljyHhWVnbZcLZNvBwL6bV0RCuRlWCFfjlA"
            "6buXW3a23krjs8k5I4UhKaeX7d0Pvk\nx/3JxjlGlOA8tYBT8+6Aq1xOIC1MuD8h/32Cxa7vDI9VyspY"
            "bsbCBl5m2XD566/P\nRE5rn62kBBHEXiIpFrE0R1d8MFTx9PEC00jVFDWnec3Ayl2TiTpptCF/Cb5S9K"
            "6g\nEdUFUkQj9dTxX8owUbm/tYGIYrwibWzTtscb75KjSzExnZApMfNgngke8r1f6P4Y\nHRQQU7/0Bc"
            "Di2GPzCy83rN3d2DFn6U66TZG0EEEdV1e1A0gsqfgx/b6YAZsZv26H\nZ5IkqXdj3IZRDcwdYgaTrlsl"
            "kPsantdPl+x/kxP5\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\nMIIE"
            "ejCCAuKgAwIBAgIRAI5dQJ4OEZYF5sy28Iw+/zkwDQYJKoZIhvcNAQELBQAw\nVTEeMBwGA1UEChMVbW"
            "tjZXJ0IGRldmVsb3BtZW50IENBMRUwEwYDVQQLDAxyb290\nQGJhc3Rpb24xHDAaBgNVBAMME21rY2Vy"
            "dCByb290QGJhc3Rpb24wHhcNMjUxMDAx\nMTQyMjMwWhcNMzUxMDAxMTQyMjMwWjBVMR4wHAYDVQQKEx"
            "Vta2NlcnQgZGV2ZWxv\ncG1lbnQgQ0ExFTATBgNVBAsMDHJvb3RAYmFzdGlvbjEcMBoGA1UEAwwTbWtj"
            "ZXJ0\nIHJvb3RAYmFzdGlvbjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKo5\nMM8/lupi"
            "8cOQqh5igXfGFrunERIiShzhV3EHVpQN+h3SU0BQF50DZHDTL1rHQqAn\nhPK4fgZ37s9HjssysejgYK"
            "61w9YgvoOd6dlsCTSYjpF19T9Dz5SY8yZz3lNLHcbg\nN111PZP4hyN3BtNw4ttENGuKAqHgvFO/xmzM"
            "gJtT62G4qq8VwHa8ktFa3b9Lh14/\njEOjUIkgAgHE869/deebb2ENox7nL+W0VB9o0XCqMDYF0ZF6pw"
            "4gVP2FgNbwjSgM\nci/NCW99biGHOKA5LVG4d6nNxFgOg7GdEFExzzHjjyIYQBC/ZB7ulDyQQ6KcQRn5"
            "\nbvn83SuUZ1cGRSWSndosR3LhEJaxDLbr68X7byL7PNkBM4ILAGpd+oZLCM4Z9cpF\njGW4GxilijEg"
            "Smo7gLZk++oEh3O31Wt5dyGs2BHeUDf0rHG7z+agpzK0H6Ar9Rj5\nurfDJvswioyU7jUxrpOg+4Wk/J"
            "aJWncbU49fZRtAiwYZVVHyvKf5bn+bRJK+bQID\nAQABo0UwQzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0T"
            "AQH/BAgwBgEB/wIBADAdBgNV\nHQ4EFgQURbYa09lfzSNjpy86ryswwB9bWGwwDQYJKoZIhvcNAQELBQ"
            "ADggGBAF+y\nWudDZVtWEbNpsSz5YvZ3W0BuNwaFo5TFYhzhh4ougs/SUhvPW5dAsVBJBjTgJ4fy\nXm"
            "miptcVzrvZiaB2+muL1PT/vUhFomuyqw46smzBIrUyHHmjqdoVIhmJ4XJq/eLS\n7wMLDpTeH3kQaQWt"
            "cK1EqlPOIMn5m/st663280lB2ICyv1zSQgWIkv4YpmzAuJcm\nwYw899emEsSdf3q1lQoLR0NkBdRPSN"
            "Zcnb9+wR98Iw5Rjca/7P0A1RbbEmbayXzf\n4adhIZaaCBDhADcU6SBC5v8HsIj0tolyf7nTKarKJoKy"
            "eY1i1sXrK28vZyWykLLD\nQ7FHcRDfoAtJ2QUvxbpBXpDg/F79PDjrdjc6n8nn4RG+JIwO8j7t3GMB5c"
            "MWOnKC\nruQ4NuKcsWkcIaQIcxJTx+tOYyGqyAMzxA+VFTQ+HNjcFBnue/XJOya4dpOo1BEG\nAacSqy"
            "ipP2lMM8Xbje7snzwmutRdATxiyGKDzacEJWUMHzlkrX8WsFIUnVNMUA==\n-----END CERTIFICATE"
            "-----"
        )
        self.hooks.san = "example.com"
        self.hooks.envelope = {"Subject": None}
        self.hooks._format_subject = lambda status, san: f"subject-{status}-{san}"
        self.hooks._format_message_header = lambda status, san: f"header-{status}-{san}"
        self.hooks._attach_csr = MagicMock()
        self.hooks._attach_cert = MagicMock()
        self.hooks._done = MagicMock()
        self.hooks.msg = []
        self.hooks.report_successes = True
        with self.assertLogs(self.logger, level="DEBUG") as cm:
            self.hooks.success_hook("reqkey", "order", "csr", certificate, "cert_raw", "pollid")
        self.assertTrue(any("Parsing certificate details for email" in msg for msg in cm.output))
        self.assertEqual(self.hooks.envelope["Subject"], "subject-success-example.com")
        self.assertIn("header-success-example.com", self.hooks.msg[0])
        self.assertIn("Certificate issued successfully!", self.hooks.msg[1])
        self.hooks._attach_csr.assert_called_with("reqkey", "csr")
        self.hooks._attach_cert.assert_called_with("reqkey", certificate)
        self.hooks._done.assert_called()

    @patch("examples.hooks.email_hooks.cert_san_get", return_value=["DNS:example.com"])
    @patch("examples.hooks.email_hooks.x509.load_pem_x509_certificates")
    def test_050_success_hook_cert_not_valid_before_utc_exception(self, mock_load_x509, mock_cert_san_get):
        """success_hook handles exception in cert.not_valid_before_utc and logs error"""
        # Create a mock cert with not_valid_before_utc raising
        cert_mock = MagicMock()
        type(cert_mock).serial_number = PropertyMock(return_value=123)
        type(cert_mock).not_valid_before_utc = PropertyMock(side_effect=Exception("fail not_valid_before_utc"))
        type(cert_mock).not_valid_after_utc = PropertyMock(return_value="future")
        mock_load_x509.return_value = [cert_mock]
        self.hooks.report_successes = True
        self.hooks._done = MagicMock()
        self.hooks._attach_csr = MagicMock()
        self.hooks._attach_cert = MagicMock()
        self.hooks.envelope = {"Subject": None}
        self.hooks.msg = []
        # This should not raise, but should log an error
        with self.assertLogs(self.logger, level="DEBUG") as cm:
            self.hooks.success_hook("reqkey", "order", "csr", "cert", "cert_raw", "pollid")
        self.assertTrue(any("Falling back to not_valid_before and not_valid_after for certificate dates" in msg for msg in cm.output))

    def test_051_pre_hook(self):
        """pre_hook handles missing CSR gracefully"""
        with self.assertLogs(self.logger, level="DEBUG") as cm:
            self.hooks.pre_hook("reqkey", "order", None)
        self.assertTrue(any("called - no action required" in msg for msg in cm.output))

if __name__ == "__main__":
    unittest.main()
