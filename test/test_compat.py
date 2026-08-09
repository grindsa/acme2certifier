# -*- coding: utf-8 -*-
"""Unit tests for handler-config deprecation helpers."""

import logging
import unittest
import warnings
from unittest.mock import patch

from acme2certifier import compat


class TestCompatDeprecation(unittest.TestCase):
    """Tests for acme2certifier.compat warnings."""

    def setUp(self):
        compat._WARNED.clear()

    def tearDown(self):
        compat._WARNED.clear()

    def test_001_warn_file_config_deprecated(self):
        logger = logging.getLogger("test_compat")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertLogs("test_compat", level="WARNING") as lcm:
                compat.warn_file_config_deprecated(
                    logger,
                    "handler_file",
                    "handler_module",
                    "acme2certifier.cahandlers.openssl_ca_handler",
                )
        self.assertEqual(len(caught), 1)
        self.assertIn("handler_file is deprecated", str(caught[0].message))
        self.assertTrue(any("handler_file is deprecated" in line for line in lcm.output))

    def test_002_warn_default_ca_handler(self):
        logger = logging.getLogger("test_compat")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertLogs("test_compat", level="WARNING") as lcm:
                compat.warn_default_ca_handler(logger)
        self.assertEqual(len(caught), 1)
        self.assertIn("acme_srv.ca_handler", str(caught[0].message))
        self.assertTrue(any("acme_srv.ca_handler" in line for line in lcm.output))


class TestPluginLoaderFileDeprecated(unittest.TestCase):
    """plugin_loader warns on handler_file."""

    def setUp(self):
        compat._WARNED.clear()
        self.logger = logging.getLogger("test_compat_plugin")

    def tearDown(self):
        compat._WARNED.clear()

    @patch("importlib.util")
    def test_001_ca_handler_file_deprecated(self, mock_util):
        from acme2certifier.acme_srv.helpers.plugin_loader import ca_handler_load

        mock_util.module_from_spec = lambda spec: "foo"
        config_dic = {"CAhandler": {"handler_file": "foo"}}
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertLogs("test_compat_plugin", level="WARNING") as lcm:
                self.assertEqual("foo", ca_handler_load(self.logger, config_dic))
        self.assertTrue(
            any("handler_file is deprecated" in str(w.message) for w in caught)
        )
        self.assertTrue(any("handler_file is deprecated" in line for line in lcm.output))


if __name__ == "__main__":
    unittest.main()
