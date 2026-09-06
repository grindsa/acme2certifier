# -*- coding: utf-8 -*-
"""unittests for helpers.config.config_option_load"""

# pylint: disable=C0415
import configparser
import logging
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestConfigOptionLoad(unittest.TestCase):
    """test class for config_option_load"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")

    def test_001_unset_returns_current(self):
        from acme2certifier.acme_srv.helpers.config import config_option_load

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"api_url": "https://example.com"}
        self.assertEqual(
            config_option_load(
                self.logger, parser, "requester_password", current="keep"
            ),
            "keep",
        )

    def test_002_direct_option(self):
        from acme2certifier.acme_srv.helpers.config import config_option_load

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"requester_password": "cfg_pw"}
        self.assertEqual(
            config_option_load(self.logger, parser, "requester_password"),
            "cfg_pw",
        )

    @patch.dict("os.environ", {"HARICA_PW": "env_pw"}, clear=False)
    def test_003_from_variable(self):
        from acme2certifier.acme_srv.helpers.config import config_option_load

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"requester_password_variable": "HARICA_PW"}
        self.assertEqual(
            config_option_load(self.logger, parser, "requester_password"),
            "env_pw",
        )

    @patch.dict("os.environ", {"HARICA_PW": "env_pw"}, clear=False)
    def test_004_direct_overwrites_variable(self):
        from acme2certifier.acme_srv.helpers.config import config_option_load

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "requester_password_variable": "HARICA_PW",
            "requester_password": "cfg_pw",
        }
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            value = config_option_load(self.logger, parser, "requester_password")
        self.assertEqual(value, "cfg_pw")
        self.assertTrue(
            any("Overwrite requester_password" in line for line in lcm.output)
        )

    def test_005_missing_env_keeps_current(self):
        from acme2certifier.acme_srv.helpers.config import config_option_load

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"requester_password_variable": "HARICA_MISSING_PW"}
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            value = config_option_load(
                self.logger, parser, "requester_password", current=None
            )
        self.assertIsNone(value)
        self.assertIn("Could not load requester_password_variable", lcm.output[0])

    def test_006_custom_variable_option_name(self):
        from acme2certifier.acme_srv.helpers.config import config_option_load

        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cmp_ref_variable": "CMP_REF"}
        with patch.dict("os.environ", {"CMP_REF": "ref-from-env"}, clear=False):
            value = config_option_load(
                self.logger,
                parser,
                "ref",
                variable_option="cmp_ref_variable",
            )
        self.assertEqual(value, "ref-from-env")

    def test_007_no_section_returns_current(self):
        from acme2certifier.acme_srv.helpers.config import config_option_load

        parser = configparser.ConfigParser()
        self.assertEqual(
            config_option_load(self.logger, parser, "password", current="x"),
            "x",
        )


if __name__ == "__main__":
    unittest.main()
