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
            return_value=DummyConfig(
                {
                    "Hooks": {
                        "appname": "acme2certifier",
                        "sender": "sender@example.com",
                        "rcpt": "rcpt@example.com",
                    }
                }
            ),
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
        with patch(
            "examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)
        ):
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
            self.assertIn(
                "Configuration dictionary is empty or None", str(ctx.exception)
            )

    def test_004_validate_configuration_missing_section(self):
        """Fails when both Hooks and DEFAULT sections are missing from configuration"""
        from examples.hooks.email_hooks import Hooks

        config = DummyConfig({"SomeOther": {"key": "value"}})
        with patch("examples.hooks.email_hooks.load_config", return_value=config):
            with self.assertRaises(ValueError) as ctx:
                Hooks(self.logger)
            self.assertIn(
                "Missing 'Hooks' or 'DEFAULT' section in configuration",
                str(ctx.exception),
            )

    def test_005_validate_configuration_missing_required_keys(self):
        """validate_configuration raises when required keys missing"""
        from examples.hooks.email_hooks import Hooks

        cfg = {
            "Hooks": {
                "foo": "acme2certifier",
                # missing sender and rcpt
            }
        }
        with patch(
            "examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)
        ):
            with self.assertRaises(ValueError) as ctx:
                Hooks(self.logger)
            msg = str(ctx.exception)
            self.assertIn("Missing required configuration key(s) in [Hooks]", msg)

    def test_006_validate_configuration_empty_required_keys(self):
        """Fails when required keys have empty values"""
        from examples.hooks.email_hooks import Hooks

        config = DummyConfig(
            {
                "Hooks": {
                    "appname": "",  # Empty required key
                    "sender": "",  # Empty required key
                    "rcpt": "",  # Empty required key
                    "smtp_server": "smtp.example.com",
                    "smtp_port": "25",
                    "smtp_user": "",
                    "smtp_password": "",
                    "smtp_timeout": "",
                    "ssl_use": "",
                    "ssl_starttls": "",
                    "ssl_noverify": "",
                    "subject": "ACME certificate renewal",
                    "body": "Certificate for {subject} expires on {expires}.",
                    "certificate_list": "/path/to/certs",
                }
            }
        )
        with patch("examples.hooks.email_hooks.load_config", return_value=config):
            with self.assertRaises(ValueError) as ctx:
                Hooks(self.logger)
            msg = str(ctx.exception)
            self.assertIn("Empty required configuration key(s): appname", msg)

    def test_007_smtp_valid_port_and_timeout(self):
        """Validates correct port and timeout do not log errors"""
        self.hooks.config_dic["Hooks"].update(
            {
                "smtp_port": 587,
                "smtp_timeout": 30,
                "smtp_username": "user",
                "smtp_password": "pw",
            }
        )
        # Should not raise or log errors for valid config
        self.hooks._validate_smtp_configuration()

    def test_008_smtp_invalid_timeout(self):
        """Logs error for invalid smtp_timeout"""
        self.hooks.config_dic["Hooks"]["smtp_timeout"] = 9999
        with self.assertLogs(self.logger, level="ERROR") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(any("Invalid SMTP timeout" in msg for msg in cm.output))

    def test_009_smtp_password_no_username(self):
        """Logs debug when password is set but username is missing"""
        self.hooks.config_dic["Hooks"].pop("smtp_username", None)
        self.hooks.config_dic["Hooks"]["smtp_password"] = "pw"
        with self.assertLogs(self.logger, level="DEBUG") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(
            any("SMTP password provided without username" in msg for msg in cm.output)
        )

    def test_010_smtp_username_no_password(self):
        """Logs error when username is set but password is missing"""
        self.hooks.config_dic["Hooks"]["smtp_username"] = "user"
        self.hooks.config_dic["Hooks"].pop("smtp_password", None)
        with self.assertLogs(self.logger, level="ERROR") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(
            any(
                "SMTP username provided but password is missing" in msg
                for msg in cm.output
            )
        )

    def test_011_smtp_both_tls_and_starttls(self):
        """Logs warning if both smtp_use_tls and smtp_use_starttls are True"""
        self.hooks.config_dic["Hooks"]["smtp_use_tls"] = True
        self.hooks.config_dic["Hooks"]["smtp_use_starttls"] = True
        with self.assertLogs(self.logger, level="WARNING") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(
            any(
                "Both smtp_use_tls and smtp_use_starttls are enabled" in msg
                for msg in cm.output
            )
        )

    def test_012_smtp_port_465_without_tls(self):
        """Logs info if port 465 is used without TLS"""
        self.hooks.config_dic["Hooks"]["smtp_port"] = 465
        self.hooks.config_dic["Hooks"]["smtp_use_tls"] = False
        with self.assertLogs(self.logger, level="INFO") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(
            any("Port 465 typically requires TLS" in msg for msg in cm.output)
        )

    def test_013_smtp_port_587_without_tls_or_starttls(self):
        """Logs info if port 587 is used without TLS or STARTTLS"""
        self.hooks.config_dic["Hooks"]["smtp_port"] = 587
        self.hooks.config_dic["Hooks"]["smtp_use_tls"] = False
        self.hooks.config_dic["Hooks"]["smtp_use_starttls"] = False
        with self.assertLogs(self.logger, level="INFO") as cm:
            self.hooks._validate_smtp_configuration()
        self.assertTrue(
            any("Port 587 typically requires STARTTLS" in msg for msg in cm.output)
        )

    def test_014_load_configuration_assigns_required_fields(self):
        self.hooks.config_dic["Hooks"].update(
            {
                "appname": "TestApp",
                "sender": "test@example.com",
                "rcpt": "rcpt@example.com",
            }
        )
        self.hooks._load_configuration()
        self.assertEqual(self.hooks.appname, "TestApp")
        self.assertEqual(self.hooks.sender, "test@example.com")
        self.assertEqual(self.hooks.rcpt, "rcpt@example.com")

    def test_015_load_configuration_optional_booleans(self):
        self.hooks.config_dic["Hooks"].update(
            {
                "appname": "TestApp",
                "sender": "test@example.com",
                "rcpt": "rcpt@example.com",
                "report_failures": "False",
                "report_successes": "True",
            }
        )
        self.hooks._load_configuration()
        self.assertFalse(self.hooks.report_failures)
        self.assertTrue(self.hooks.report_successes)

    def test_016_load_configuration_smtp_defaults(self):
        self.hooks.config_dic["Hooks"].update(
            {
                "appname": "TestApp",
                "sender": "test@example.com",
                "rcpt": "rcpt@example.com",
            }
        )
        self.hooks._load_configuration()
        self.assertEqual(self.hooks.smtp_server, "localhost")
        self.assertEqual(self.hooks.smtp_port, 25)
        self.assertEqual(self.hooks.smtp_timeout, 30)
        self.assertIsNone(self.hooks.smtp_username)
        self.assertIsNone(self.hooks.smtp_password)
        self.assertTrue(self.hooks.smtp_use_tls)
        self.assertFalse(self.hooks.smtp_use_starttls)

    def test_017_load_configuration_assigns_all_fields(self):
        self.hooks.config_dic["Hooks"].update(
            {
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
            }
        )
        self.hooks._load_configuration()
        self.assertEqual(self.hooks.smtp_server, "smtp.example.com")
        self.assertEqual(self.hooks.smtp_port, 2525)
        self.assertEqual(self.hooks.email_subject_prefix, "[PREFIX]")
        self.assertEqual(self.hooks.smtp_timeout, 42)
        self.assertEqual(self.hooks.smtp_username, "user")
        self.assertEqual(self.hooks.smtp_password, "pass")
        self.assertFalse(self.hooks.smtp_use_tls)
        self.assertTrue(self.hooks.smtp_use_starttls)

    def test_018_load_configuration_uses_sender_as_username_if_password_only(self):
        self.hooks.config_dic["Hooks"].update(
            {
                "appname": "TestApp",
                "sender": "test@example.com",
                "rcpt": "rcpt@example.com",
                "smtp_password": "pass",
            }
        )
        with self.assertLogs(self.logger, "DEBUG") as cm:
            self.hooks._load_configuration()
        self.assertEqual(self.hooks.smtp_username, "test@example.com")
        self.assertIn("Using sender email as SMTP username", "\n".join(cm.output))

    def test_019_load_configuration_sets_envelope_fields(self):
        self.hooks.config_dic["Hooks"].update(
            {
                "appname": "TestApp",
                "sender": "test@example.com",
                "rcpt": "rcpt@example.com",
            }
        )
        self.hooks._load_configuration()
        self.assertIn("From", self.hooks.envelope)
        self.assertIn("To", self.hooks.envelope)
        self.assertIn("Date", self.hooks.envelope)
        self.assertEqual(self.hooks.envelope["From"], "TestApp <test@example.com>")
        self.assertEqual(self.hooks.envelope["To"], "rcpt@example.com")
        self.assertFalse(self.hooks.done)

    def test_059_done_already_sent_warning(self):
        """_done warns when called multiple times"""
        self.hooks.done = True

        with self.assertLogs(self.logger, level="WARNING") as cm:
            self.hooks._done()

        self.assertIn("email already sent", "\n".join(cm.output))

    def test_060_config_from_default_section(self):
        """Configuration loads from DEFAULT section when Hooks section is missing values"""
        from examples.hooks.email_hooks import Hooks

        cfg = {
            "DEFAULT": {
                "appname": "default-app",
                "sender": "default@example.com",
                "rcpt": "admin@example.com",
                "smtp_server": "default.smtp.com",
                "smtp_port": "465",
            },
            "Hooks": {},
        }
        with patch(
            "examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)
        ):
            h = Hooks(self.logger)
            self.assertEqual(h.appname, "default-app")
            self.assertEqual(h.sender, "default@example.com")
            self.assertEqual(h.smtp_server, "default.smtp.com")
            self.assertEqual(h.smtp_port, 465)

    def test_061_config_hooks_precedence_over_default(self):
        """Configuration in Hooks section takes precedence over DEFAULT section"""
        from examples.hooks.email_hooks import Hooks

        cfg = {
            "DEFAULT": {
                "appname": "default-app",
                "sender": "default@example.com",
                "rcpt": "admin@example.com",
                "smtp_server": "default.smtp.com",
                "smtp_port": "25",
            },
            "Hooks": {
                "appname": "hooks-app",  # Should override DEFAULT
                "sender": "hooks@example.com",  # Should override DEFAULT
                "rcpt": "admin@example.com"
                # smtp_server and smtp_port should come from DEFAULT
            },
        }
        with patch(
            "examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)
        ):
            h = Hooks(self.logger)
            self.assertEqual(h.appname, "hooks-app")  # From Hooks section
            self.assertEqual(h.sender, "hooks@example.com")  # From Hooks section
            self.assertEqual(h.smtp_server, "default.smtp.com")  # From DEFAULT section
            self.assertEqual(h.smtp_port, 25)  # From DEFAULT section

    def test_062_config_missing_both_sections_fails(self):
        """Configuration validation fails when neither Hooks nor DEFAULT section exists"""
        from examples.hooks.email_hooks import Hooks

        cfg = {"SomeOther": {"key": "value"}}
        with patch(
            "examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)
        ):
            with self.assertRaises(ValueError) as ctx:
                Hooks(self.logger)
            self.assertIn("Missing 'Hooks' or 'DEFAULT' section", str(ctx.exception))

    def test_063_config_required_keys_from_mixed_sections(self):
        """Required keys can be satisfied from a mix of Hooks and DEFAULT sections"""
        from examples.hooks.email_hooks import Hooks

        cfg = {
            "DEFAULT": {
                "sender": "default@example.com",
                "smtp_server": "default.smtp.com",
            },
            "Hooks": {
                "appname": "hooks-app",
                "rcpt": "admin@example.com"
                # sender comes from DEFAULT
            },
        }
        with patch(
            "examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)
        ):
            h = Hooks(self.logger)
            self.assertEqual(h.appname, "hooks-app")  # From Hooks
            self.assertEqual(h.sender, "default@example.com")  # From DEFAULT
            self.assertEqual(h.rcpt, "admin@example.com")  # From Hooks
            self.assertEqual(h.smtp_server, "default.smtp.com")  # From DEFAULT

    def test_064_get_config_int_from_hooks_section(self):
        """_get_config_int retrieves integer value from Hooks section"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "DEFAULT": {
                "smtp_port": "25",
                "timeout": "60"
            },
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com",
                "smtp_port": "465",  # Should override DEFAULT
                "connection_timeout": "30"
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # Test values from Hooks section
            self.assertEqual(h._get_config_int("smtp_port"), 465)
            self.assertEqual(h._get_config_int("connection_timeout"), 30)
            # Test value from DEFAULT section when not in Hooks
            self.assertEqual(h._get_config_int("timeout"), 60)

    def test_065_get_config_int_fallback_to_default_section(self):
        """_get_config_int falls back to DEFAULT section when key not in Hooks"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "DEFAULT": {
                "smtp_port": "587",
                "smtp_timeout": "45"
            },
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com"
                # No smtp_port or smtp_timeout in Hooks
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # Values should come from DEFAULT section
            self.assertEqual(h._get_config_int("smtp_port"), 587)
            self.assertEqual(h._get_config_int("smtp_timeout"), 45)

    def test_066_get_config_int_with_fallback_value(self):
        """_get_config_int returns fallback when key not found in either section"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com"
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # Should return fallback value
            self.assertEqual(h._get_config_int("missing_key", 999), 999)
            self.assertIsNone(h._get_config_int("missing_key"))

    def test_067_get_config_int_invalid_conversion(self):
        """_get_config_int returns fallback when value cannot be converted to int"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com",
                "invalid_port": "not_a_number",
                "float_value": "25.5"
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # Should return fallback for invalid values
            self.assertEqual(h._get_config_int("invalid_port", 25), 25)
            self.assertEqual(h._get_config_int("float_value", 80), 80)
            self.assertIsNone(h._get_config_int("invalid_port"))

    def test_068_get_config_int_edge_cases(self):
        """_get_config_int handles edge cases like empty strings and zero"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "DEFAULT": {
                "zero_value": "0",
                "negative_value": "-1"
            },
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com",
                "empty_value": "",
                "whitespace_value": "  123  "
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # Valid conversions
            self.assertEqual(h._get_config_int("zero_value"), 0)
            self.assertEqual(h._get_config_int("negative_value"), -1)
            self.assertEqual(h._get_config_int("whitespace_value"), 123)
            # Empty string should return fallback
            self.assertEqual(h._get_config_int("empty_value", 42), 42)

    def test_069_get_config_boolean_from_hooks_section(self):
        """_get_config_boolean retrieves boolean value from Hooks section"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "DEFAULT": {
                "ssl_use": "false",
                "debug_mode": "0"
            },
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com",
                "ssl_use": "true",  # Should override DEFAULT
                "smtp_use_starttls": "yes"
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # Test values from Hooks section
            self.assertTrue(h._get_config_boolean("ssl_use"))
            self.assertTrue(h._get_config_boolean("smtp_use_starttls"))
            # Test value from DEFAULT section when not in Hooks
            self.assertFalse(h._get_config_boolean("debug_mode"))

    def test_070_get_config_boolean_fallback_to_default_section(self):
        """_get_config_boolean falls back to DEFAULT section when key not in Hooks"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "DEFAULT": {
                "smtp_use_tls": "true",
                "ssl_noverify": "1"
            },
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com"
                # No boolean values in Hooks
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # Values should come from DEFAULT section
            self.assertTrue(h._get_config_boolean("smtp_use_tls"))
            self.assertTrue(h._get_config_boolean("ssl_noverify"))

    def test_071_get_config_boolean_various_true_values(self):
        """_get_config_boolean recognizes various true value formats"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com",
                "bool_true": "true",
                "bool_True": "True",
                "bool_TRUE": "TRUE",
                "bool_1": "1",
                "bool_yes": "yes",
                "bool_YES": "YES",
                "bool_on": "on",
                "bool_ON": "ON",
                "bool_with_spaces": "  true  "
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # All should evaluate to True
            self.assertTrue(h._get_config_boolean("bool_true"))
            self.assertTrue(h._get_config_boolean("bool_True"))
            self.assertTrue(h._get_config_boolean("bool_TRUE"))
            self.assertTrue(h._get_config_boolean("bool_1"))
            self.assertTrue(h._get_config_boolean("bool_yes"))
            self.assertTrue(h._get_config_boolean("bool_YES"))
            self.assertTrue(h._get_config_boolean("bool_on"))
            self.assertTrue(h._get_config_boolean("bool_ON"))
            self.assertTrue(h._get_config_boolean("bool_with_spaces"))

    def test_072_get_config_boolean_various_false_values(self):
        """_get_config_boolean recognizes various false value formats"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com",
                "bool_false": "false",
                "bool_False": "False",
                "bool_FALSE": "FALSE",
                "bool_0": "0",
                "bool_no": "no",
                "bool_NO": "NO",
                "bool_off": "off",
                "bool_OFF": "OFF",
                "bool_empty": "",
                "bool_random": "random_text"
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # All should evaluate to False
            self.assertFalse(h._get_config_boolean("bool_false"))
            self.assertFalse(h._get_config_boolean("bool_False"))
            self.assertFalse(h._get_config_boolean("bool_FALSE"))
            self.assertFalse(h._get_config_boolean("bool_0"))
            self.assertFalse(h._get_config_boolean("bool_no"))
            self.assertFalse(h._get_config_boolean("bool_NO"))
            self.assertFalse(h._get_config_boolean("bool_off"))
            self.assertFalse(h._get_config_boolean("bool_OFF"))
            self.assertFalse(h._get_config_boolean("bool_empty"))
            self.assertFalse(h._get_config_boolean("bool_random"))

    def test_073_get_config_boolean_with_fallback_value(self):
        """_get_config_boolean returns fallback when key not found in either section"""
        from examples.hooks.email_hooks import Hooks
        cfg = {
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com"
            }
        }
        with patch("examples.hooks.email_hooks.load_config", return_value=DummyConfig(cfg)):
            h = Hooks(self.logger)
            # Should return fallback value
            self.assertTrue(h._get_config_boolean("missing_key", True))
            self.assertFalse(h._get_config_boolean("missing_key", False))
            self.assertIsNone(h._get_config_boolean("missing_key"))

    def test_074_get_config_boolean_already_boolean_type(self):
        """_get_config_boolean handles values that are already boolean type"""
        from examples.hooks.email_hooks import Hooks

        cfg = {
            "Hooks": {
                "appname": "test-app",
                "sender": "test@example.com",
                "rcpt": "admin@example.com",
                "bool_true": True,  # Actual boolean, not string
                "bool_false": False  # Actual boolean, not string
            }
        }

        # Extend DummyConfig to handle boolean types
        config = DummyConfig(cfg)

        with patch("examples.hooks.email_hooks.load_config", return_value=config):
            h = Hooks(self.logger)
            # Should handle actual boolean values correctly
            self.assertTrue(h._get_config_boolean("bool_true"))
            self.assertFalse(h._get_config_boolean("bool_false"))

    def test_021_done_handles_exception_and_logs_error(self):
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

    def test_022_clean_san_valid_list(self):
        """_clean_san returns correct value for valid SAN list"""
        result = self.hooks._clean_san(["DNS:example.com"])
        self.assertEqual(result, "example.com")

    def test_023_clean_san_none(self):
        """_clean_san returns 'unknown' and logs warning for None input"""
        with self.assertLogs(self.logger, level="WARNING") as cm:
            result = self.hooks._clean_san(None)
        self.assertEqual(result, "unknown")
        self.assertTrue(any("Empty SAN list provided" in msg for msg in cm.output))

    def test_024_clean_san_not_a_list(self):
        """_clean_san returns 'unknown' and logs warning for non-list input"""
        with self.assertLogs(self.logger, level="WARNING") as cm:
            result = self.hooks._clean_san("DNS:example.com")
        self.assertEqual(result, "unknown")
        self.assertTrue(any("SAN is not a list" in msg for msg in cm.output))

    def test_025_clean_san_invalid_format(self):
        """_clean_san returns 'unknown' and logs warning for invalid format"""
        with self.assertLogs(self.logger, level="WARNING") as cm:
            result = self.hooks._clean_san(["example.com"])
        self.assertEqual(result, "unknown")
        self.assertTrue(any("Invalid SAN format" in msg for msg in cm.output))

    @patch("examples.hooks.email_hooks.build_pem_file", return_value="PEM DATA")
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_026_attach_csr_success(self, mock_mimeapp, mock_build_pem):
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
        self.assertIn(
            "To read example.com_reqkey.csr using CMD on Windows",
            "\n".join(self.hooks.msg),
        )

    @patch("examples.hooks.email_hooks.build_pem_file", return_value=None)
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_027_attach_csr_pem_build_fails(self, mock_mimeapp, mock_build_pem):
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
        self.assertTrue(
            any("Failed to build PEM file from CSR" in msg for msg in cm.output)
        )

    @patch("examples.hooks.email_hooks.build_pem_file", side_effect=Exception("fail"))
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_028_attach_csr_exception(self, mock_mimeapp, mock_build_pem):
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

    @patch(
        "examples.hooks.email_hooks.x509.load_pem_x509_certificates",
        return_value=[MagicMock(), MagicMock()],
    )
    @patch(
        "examples.hooks.email_hooks.pkcs12.serialize_key_and_certificates",
        return_value=b"PFXDATA",
    )
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_029_attach_cert_success(
        self, mock_mimeapp, mock_serialize, mock_load_x509
    ):
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
        self.assertIn(
            "To read example.com_reqkey.pfx using CMD on Windows",
            "\n".join(self.hooks.msg),
        )

    @patch(
        "examples.hooks.email_hooks.x509.load_pem_x509_certificates",
        side_effect=Exception("parsefail"),
    )
    @patch("examples.hooks.email_hooks.pkcs12.serialize_key_and_certificates")
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_030_attach_cert_parse_error(
        self, mock_mimeapp, mock_serialize, mock_load_x509
    ):
        """_attach_cert logs warning and appends message if certificate parsing fails"""
        request_key = "reqkey"
        certificate = "CERTDATA"
        self.hooks.san = "example.com"
        self.hooks.envelope = MagicMock()
        self.hooks.msg = []
        with self.assertLogs(self.logger, level="WARNING") as cm:
            self.hooks._attach_cert(request_key, certificate)
        self.assertTrue(
            any("Certificate attachment failed" in msg for msg in cm.output)
        )
        self.assertIn("Certificate attachment failed: Exception", self.hooks.msg[-1])
        mock_serialize.assert_not_called()
        mock_mimeapp.assert_not_called()

    @patch(
        "examples.hooks.email_hooks.x509.load_pem_x509_certificates",
        return_value=[MagicMock(), MagicMock()],
    )
    @patch(
        "examples.hooks.email_hooks.pkcs12.serialize_key_and_certificates",
        side_effect=Exception("serializefail"),
    )
    @patch("examples.hooks.email_hooks.MIMEApplication")
    def test_031_attach_cert_serialize_error(
        self, mock_mimeapp, mock_serialize, mock_load_x509
    ):
        """_attach_cert logs warning and appends message if serialization fails"""
        request_key = "reqkey"
        certificate = "CERTDATA"
        self.hooks.san = "example.com"
        self.hooks.envelope = MagicMock()
        self.hooks.msg = []
        with self.assertLogs(self.logger, level="WARNING") as cm:
            self.hooks._attach_cert(request_key, certificate)
        self.assertTrue(
            any("Certificate attachment failed" in msg for msg in cm.output)
        )
        self.assertIn("Certificate attachment failed: Exception", self.hooks.msg[-1])
        mock_mimeapp.assert_not_called()

    def test_032_format_subject_with_prefix(self):
        """_format_subject includes prefix if set"""
        self.hooks.appname = "TestApp"
        self.hooks.email_subject_prefix = "[PREFIX]"
        subject = self.hooks._format_subject("success", "example.com")
        self.assertTrue(subject.startswith("[PREFIX] "))
        self.assertIn("TestApp success: example.com", subject)

    def test_033_format_subject_without_prefix(self):
        """_format_subject omits prefix if not set"""
        self.hooks.appname = "TestApp"
        self.hooks.email_subject_prefix = ""
        subject = self.hooks._format_subject("failure", "example.com")
        self.assertEqual(subject, "TestApp failure: example.com")

    def test_034_format_message_header_success(self):
        """_format_message_header returns expected header for success"""
        self.hooks.appname = "TestApp"
        header = self.hooks._format_message_header("success", "example.com")
        self.assertIn("ACME Certificate Success Notification", header)
        self.assertIn("Application: TestApp", header)
        self.assertIn("Subject Alternative Name: example.com", header)
        self.assertIn("Timestamp:", header)
        self.assertIn("-" * 50, header)

    def test_035_format_message_header_failure(self):
        """_format_message_header returns expected header for failure"""
        self.hooks.appname = "TestApp"
        header = self.hooks._format_message_header("failure", "test-san")
        self.assertIn("ACME Certificate Failure Notification", header)
        self.assertIn("Application: TestApp", header)
        self.assertIn("Subject Alternative Name: test-san", header)
        self.assertIn("Timestamp:", header)
        self.assertIn("-" * 50, header)

    @patch("examples.hooks.email_hooks.csr_san_get", return_value=["DNS:example.com"])
    def test_036_post_hook_success(self, mock_csr_san_get):
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

    def test_037_post_hook_report_failures_false(self):
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
    def test_038_post_hook_exception(self, mock_csr_san_get):
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
    def test_039_success_hook_normal(self, mock_cert_san_get):
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

    def test_040_success_hook_report_successes_false(self):
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
    def test_041_success_hook_exception(self, mock_cert_san_get):
        """success_hook logs error if exception occurs"""
        self.hooks.report_successes = True
        self.hooks._done = MagicMock()
        self.hooks._attach_csr = MagicMock()
        self.hooks._attach_cert = MagicMock()
        self.hooks.envelope = {"Subject": None}
        self.hooks.msg = []
        with self.assertLogs(self.logger, level="ERROR") as cm:
            self.hooks.success_hook(
                "reqkey", "order", "csr", "cert", "cert_raw", "pollid"
            )
        self.assertTrue(any("Error in success_hook" in msg for msg in cm.output))

    @patch("examples.hooks.email_hooks.cert_san_get", return_value=["DNS:example.com"])
    def test_042_success_hook_normal(self, mock_cert_san_get):
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
            self.hooks.success_hook(
                "reqkey", "order", "csr", certificate, "cert_raw", "pollid"
            )
        self.assertTrue(
            any("Parsing certificate details for email" in msg for msg in cm.output)
        )
        self.assertEqual(self.hooks.envelope["Subject"], "subject-success-example.com")
        self.assertIn("header-success-example.com", self.hooks.msg[0])
        self.assertIn("Certificate issued successfully!", self.hooks.msg[1])
        self.hooks._attach_csr.assert_called_with("reqkey", "csr")
        self.hooks._attach_cert.assert_called_with("reqkey", certificate)
        self.hooks._done.assert_called()

    @patch("examples.hooks.email_hooks.cert_san_get", return_value=["DNS:example.com"])
    @patch("examples.hooks.email_hooks.x509.load_pem_x509_certificates")
    def test_043_success_hook_cert_not_valid_before_utc_exception(
        self, mock_load_x509, mock_cert_san_get
    ):
        """success_hook handles exception in cert.not_valid_before_utc and logs error"""
        # Create a mock cert with not_valid_before_utc raising
        cert_mock = MagicMock()
        type(cert_mock).serial_number = PropertyMock(return_value=123)
        type(cert_mock).not_valid_before_utc = PropertyMock(
            side_effect=Exception("fail not_valid_before_utc")
        )
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
            self.hooks.success_hook(
                "reqkey", "order", "csr", "cert", "cert_raw", "pollid"
            )
        self.assertTrue(
            any(
                "Falling back to not_valid_before and not_valid_after for certificate dates"
                in msg
                for msg in cm.output
            )
        )

    def test_044_pre_hook(self):
        """pre_hook handles missing CSR gracefully"""
        with self.assertLogs(self.logger, level="DEBUG") as cm:
            self.hooks.pre_hook("reqkey", "order", None)
        self.assertTrue(any("called - no action required" in msg for msg in cm.output))

    @patch("examples.hooks.email_hooks.smtplib.SMTP_SSL")
    def test_045_done_sends_email_with_tls(self, mock_smtp_ssl):
        """_done sends email using SMTP_SSL when smtp_use_tls is True"""
        self.hooks.smtp_use_tls = True
        self.hooks.smtp_use_starttls = False
        self.hooks.smtp_server = "smtp.example.com"
        self.hooks.smtp_port = 465
        self.hooks.smtp_timeout = 10
        self.hooks.smtp_username = "user"
        self.hooks.smtp_password = "pass"
        self.hooks.sender = "sender@example.com"
        self.hooks.rcpt = "rcpt@example.com"
        self.hooks.envelope["Subject"] = "Test Subject"
        self.hooks.msg = ["Test message"]

        # Create a mock SMTP instance
        smtp_instance = MagicMock()
        mock_smtp_ssl.return_value.__enter__.return_value = smtp_instance

        # Call the method
        with self.assertLogs(self.logger, level="INFO") as cm:
            self.hooks._done()

        # Verify SMTP_SSL was called with correct parameters
        mock_smtp_ssl.assert_called_with("smtp.example.com", 465, timeout=10)

        # Verify done flag is set and success is logged
        self.assertTrue(self.hooks.done)
        log_output = "\n".join(cm.output)
        self.assertIn("Email notification sent successfully", log_output)

    @patch("examples.hooks.email_hooks.smtplib.SMTP")
    def test_046_done_sends_email_with_starttls(self, mock_smtp):
        """_done sends email using SMTP with STARTTLS when smtp_use_starttls is True"""
        self.hooks.smtp_use_tls = False
        self.hooks.smtp_use_starttls = True
        self.hooks.smtp_server = "smtp.example.com"
        self.hooks.smtp_port = 587
        self.hooks.smtp_timeout = 10
        self.hooks.smtp_username = "user"
        self.hooks.smtp_password = "pass"
        self.hooks.sender = "sender@example.com"
        self.hooks.rcpt = "rcpt@example.com"
        self.hooks.envelope["Subject"] = "Test Subject"
        self.hooks.msg = ["Test message"]

        smtp_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = smtp_instance

        with self.assertLogs(self.logger, level="INFO") as cm:
            self.hooks._done()

        mock_smtp.assert_called_with("smtp.example.com", 587, timeout=10)
        self.assertTrue(self.hooks.done)
        log_output = "\n".join(cm.output)
        self.assertIn("Email notification sent successfully", log_output)

    @patch("examples.hooks.email_hooks.smtplib.SMTP")
    def test_047_done_sends_email_without_auth(self, mock_smtp):
        """_done sends email without authentication when no credentials provided"""
        self.hooks.smtp_use_tls = False
        self.hooks.smtp_use_starttls = False
        self.hooks.smtp_server = "smtp.example.com"
        self.hooks.smtp_port = 25
        self.hooks.smtp_timeout = 30
        self.hooks.smtp_username = None
        self.hooks.smtp_password = None
        self.hooks.sender = "sender@example.com"
        self.hooks.rcpt = "rcpt@example.com"
        self.hooks.envelope["Subject"] = "Test Subject"
        self.hooks.msg = ["Test message"]

        smtp_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = smtp_instance

        with self.assertLogs(self.logger, level="INFO") as cm:
            self.hooks._done()

        mock_smtp.assert_called_with("smtp.example.com", 25, timeout=30)
        self.assertTrue(self.hooks.done)
        log_output = "\n".join(cm.output)
        self.assertIn("Email notification sent successfully", log_output)

    @patch("examples.hooks.email_hooks.smtplib.SMTP")
    def test_048_done_logs_debug_info(self, mock_smtp):
        """_done logs detailed debug information about SMTP connection"""
        self.hooks.smtp_use_tls = False
        self.hooks.smtp_use_starttls = False
        self.hooks.smtp_server = "smtp.example.com"
        self.hooks.smtp_port = 25
        self.hooks.smtp_timeout = 30
        self.hooks.smtp_username = "testuser"
        self.hooks.smtp_password = "testpass"
        self.hooks.sender = "sender@example.com"
        self.hooks.rcpt = "rcpt@example.com"
        self.hooks.envelope["Subject"] = "Test Subject"
        self.hooks.msg = ["Test message"]

        smtp_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = smtp_instance

        with self.assertLogs(self.logger, level="DEBUG") as cm:
            self.hooks._done()

        log_output = "\n".join(cm.output)
        self.assertIn("Attempting to send email notification", log_output)
        self.assertIn("TLS settings", log_output)
        self.assertIn("Authentication - username: testuser", log_output)
        self.assertIn("password: ***", log_output)
        self.assertTrue(self.hooks.done)

    @patch(
        "examples.hooks.email_hooks.smtplib.SMTP_SSL",
        side_effect=Exception("Connection failed"),
    )
    def test_049_done_handles_smtp_connection_error(self, mock_smtp_ssl):
        """_done handles SMTP connection errors gracefully"""
        self.hooks.smtp_use_tls = True
        self.hooks.smtp_server = "smtp.example.com"
        self.hooks.smtp_port = 465
        self.hooks.smtp_timeout = 10
        self.hooks.sender = "sender@example.com"
        self.hooks.rcpt = "rcpt@example.com"
        self.hooks.envelope["Subject"] = "Test Subject"
        self.hooks.msg = ["Test message"]

        with self.assertLogs(self.logger, level="ERROR") as cm:
            self.hooks._done()

        self.assertTrue(any("Email sending failed" in msg for msg in cm.output))
        self.assertTrue(any("Connection failed" in msg for msg in cm.output))
        self.assertTrue(self.hooks.done)  # Still sets done=True even on error

    @patch(
        "examples.hooks.email_hooks.smtplib.SMTP",
        side_effect=Exception("Connection failed"),
    )
    def test_050_done_handles_smtp_auth_error(self, mock_smtp):
        """_done handles SMTP connection errors gracefully"""
        self.hooks.smtp_use_tls = False
        self.hooks.smtp_use_starttls = False
        self.hooks.smtp_server = "smtp.example.com"
        self.hooks.smtp_port = 25
        self.hooks.smtp_timeout = 30
        self.hooks.smtp_username = "user"
        self.hooks.smtp_password = "wrongpass"
        self.hooks.sender = "sender@example.com"
        self.hooks.rcpt = "rcpt@example.com"
        self.hooks.envelope["Subject"] = "Test Subject"
        self.hooks.msg = ["Test message"]

        with self.assertLogs(self.logger, level="ERROR") as cm:
            self.hooks._done()

        self.assertTrue(any("Email sending failed" in msg for msg in cm.output))
        self.assertTrue(any("Connection failed" in msg for msg in cm.output))
        self.assertTrue(self.hooks.done)

    @patch("examples.hooks.email_hooks.smtplib.SMTP")
    def test_051_done_logs_success_info(self, mock_smtp):
        """_done logs success information when email is sent"""
        self.hooks.smtp_use_tls = False
        self.hooks.smtp_use_starttls = False
        self.hooks.smtp_server = "smtp.example.com"
        self.hooks.smtp_port = 25
        self.hooks.smtp_timeout = 30
        self.hooks.sender = "sender@example.com"
        self.hooks.rcpt = "rcpt@example.com"
        self.hooks.envelope["Subject"] = "Test Subject"
        self.hooks.msg = ["Test message"]

        smtp_instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = smtp_instance

        with self.assertLogs(self.logger, level="INFO") as cm:
            self.hooks._done()

        log_output = "\n".join(cm.output)
        self.assertIn("Email notification sent successfully", log_output)
        self.assertIn("rcpt@example.com", log_output)
        self.assertIn("Subject: Test Subject", log_output)
        self.assertTrue(self.hooks.done)

    def test_052_done_already_sent_warning(self):
        """_done warns when called multiple times"""
        self.hooks.done = True

        with self.assertLogs(self.logger, level="WARNING") as cm:
            self.hooks._done()

        self.assertIn("email already sent", "\n".join(cm.output))


if __name__ == "__main__":
    unittest.main()
