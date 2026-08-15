#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for mswcce_ca_handler deprecated alias"""

# pylint: disable=C0415
import importlib
import sys
import unittest
import warnings

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class TestACMEHandler(unittest.TestCase):
    """test class for mswcce_ca_handler"""

    def setUp(self):
        """setup unittest"""
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    def test_002_reexports_msicpr_cahandler(self):
        """mswcce CAhandler is the msicpr CAhandler"""
        from acme2certifier.cahandlers.msicpr_ca_handler import (
            CAhandler as MsicprCAhandler,
        )

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from acme2certifier.cahandlers.mswcce_ca_handler import CAhandler

        self.assertIs(CAhandler, MsicprCAhandler)

    def test_003_import_emits_deprecation_warning(self):
        """importing mswcce_ca_handler emits DeprecationWarning"""
        sys.modules.pop("acme2certifier.cahandlers.mswcce_ca_handler", None)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            import acme2certifier.cahandlers.mswcce_ca_handler as mswcce

            importlib.reload(mswcce)
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))
        self.assertTrue(
            any(
                "mswcce_ca_handler is deprecated" in str(w.message)
                and "msicpr_ca_handler" in str(w.message)
                for w in caught
            )
        )

    def test_004_all_exports_cahandler(self):
        """__all__ exports CAhandler"""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            import acme2certifier.cahandlers.mswcce_ca_handler as mswcce

        self.assertEqual(["CAhandler"], mswcce.__all__)

    def test_005_cahandler_constructs_from_alias(self):
        """CAhandler from the alias can be constructed"""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from acme2certifier.cahandlers.mswcce_ca_handler import CAhandler

        handler = CAhandler(False, self.logger)
        self.assertEqual(self.logger, handler.logger)


if __name__ == "__main__":
    unittest.main()
