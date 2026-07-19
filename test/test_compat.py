# -*- coding: utf-8 -*-
"""Unit tests for package-layout deprecation helpers."""

import logging
import sys
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

    def test_warn_legacy_import_emits_once(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            compat.warn_legacy_import("acme_srv.account", "acme2certifier.acme_srv.account")
            compat.warn_legacy_import("acme_srv.account", "acme2certifier.acme_srv.account")
        self.assertEqual(len(caught), 1)
        self.assertTrue(issubclass(caught[0].category, DeprecationWarning))
        self.assertIn("acme_srv.account", str(caught[0].message))
        self.assertIn(f"acme2certifier {compat.REMOVAL_VERSION}", str(caught[0].message))

    def test_warn_legacy_handler_module(self):
        logger = logging.getLogger("test_compat")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertLogs("test_compat", level="WARNING") as lcm:
                compat.warn_legacy_handler_module(
                    logger, "examples.ca_handler.openssl_ca_handler"
                )
        self.assertEqual(len(caught), 1)
        self.assertIn("acme2certifier.cahandlers.openssl_ca_handler", str(caught[0].message))
        self.assertTrue(
            any("examples.ca_handler.openssl_ca_handler" in line for line in lcm.output)
        )

    def test_warn_legacy_handler_module_ignores_preferred(self):
        logger = logging.getLogger("test_compat")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            compat.warn_legacy_handler_module(
                logger, "acme2certifier.cahandlers.openssl_ca_handler"
            )
        self.assertEqual(caught, [])

    def test_warn_file_config_deprecated(self):
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

    def test_warn_default_ca_handler(self):
        logger = logging.getLogger("test_compat")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertLogs("test_compat", level="WARNING") as lcm:
                compat.warn_default_ca_handler(logger)
        self.assertEqual(len(caught), 1)
        self.assertIn("acme_srv.ca_handler", str(caught[0].message))
        self.assertTrue(any("acme_srv.ca_handler" in line for line in lcm.output))

    def test_shim_import_warns(self):
        # Drop cached shim so import re-executes warning path.
        for key in list(sys.modules):
            if key == "acme_srv.version" or key.startswith("acme_srv.version."):
                del sys.modules[key]
        compat._WARNED.clear()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            # Import a lightweight shim module.
            if "acme_srv.version" in sys.modules:
                del sys.modules["acme_srv.version"]
            import acme_srv.version  # noqa: F401

        self.assertTrue(
            any(
                issubclass(w.category, DeprecationWarning)
                and "acme_srv.version" in str(w.message)
                for w in caught
            )
        )


class TestPluginLoaderLegacyModule(unittest.TestCase):
    """plugin_loader warns on examples.* handler_module paths."""

    def setUp(self):
        compat._WARNED.clear()
        self.logger = logging.getLogger("test_compat_plugin")

    def tearDown(self):
        compat._WARNED.clear()

    @patch("importlib.import_module", return_value="mod")
    def test_ca_handler_module_examples_path_warns(self, mock_imp):
        from acme2certifier.acme_srv.helpers.plugin_loader import ca_handler_load

        config_dic = {
            "CAhandler": {
                "handler_module": "examples.ca_handler.openssl_ca_handler"
            }
        }
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertLogs("test_compat_plugin", level="WARNING") as lcm:
                self.assertEqual("mod", ca_handler_load(self.logger, config_dic))
        self.assertTrue(
            any("examples.ca_handler.openssl_ca_handler" in str(w.message) for w in caught)
        )
        self.assertTrue(
            any("acme2certifier.cahandlers.openssl_ca_handler" in line for line in lcm.output)
        )
        mock_imp.assert_called_with("examples.ca_handler.openssl_ca_handler")


if __name__ == "__main__":
    unittest.main()
