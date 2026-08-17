#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for account.py"""

# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, ".")
sys.path.insert(1, "..")


class FakeDBStore(object):
    """face DBStore class needed for mocking"""

    # pylint: disable=W0107, R0903
    pass


class TestACMEHandler(unittest.TestCase):
    """test class for ACMEHandler"""

    acme = None

    def setUp(self):
        """setup unittest"""
        models_mock = MagicMock()
        modules = {"acme2certifier.acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.acmechallenge import Acmechallenge

        self.acmechallenge = Acmechallenge(False, None, self.logger)
        self.acmechallenge.dbstore.reset_mock()

    def test_001__enter_(self):
        """test enter"""
        self.acmechallenge.__enter__()

    def test_002__enter_(self):
        """test enter"""
        self.acmechallenge.__exit__()

    def test_003_lookup(self):
        """test lookup without pathinfo"""
        path_info = None
        self.assertFalse(self.acmechallenge.lookup(path_info))

    def test_004_lookup(self):
        """test lookup strange token returning wrong data"""
        path_info = "foo"
        self.acmechallenge.dbstore.cahandler_lookup.return_value = "lookup"
        self.assertFalse(self.acmechallenge.lookup(path_info))
        self.acmechallenge.dbstore.cahandler_lookup.assert_called_once_with(
            "name", "foo"
        )

    def test_005_lookup(self):
        """test lookup strips well-known path prefix"""
        path_info = "/.well-known/acme-challenge/foo1"
        self.acmechallenge.dbstore.cahandler_lookup.return_value = "lookup"
        self.assertFalse(self.acmechallenge.lookup(path_info))
        self.acmechallenge.dbstore.cahandler_lookup.assert_called_once_with(
            "name", "foo1"
        )

    def test_006_lookup(self):
        """test lookup returns key_authorization without logging secrets at INFO"""
        path_info = "/.well-known/acme-challenge/foo"
        self.acmechallenge.dbstore.cahandler_lookup.return_value = {
            "value1": "key_authorization"
        }
        with self.assertRaises(AssertionError):
            with self.assertLogs("test_a2c", level="INFO"):
                self.assertEqual(
                    "key_authorization", self.acmechallenge.lookup(path_info)
                )

    def test_007_lookup_no_info_token_leak(self):
        """test lookup does not log challenge token at INFO"""
        path_info = "/.well-known/acme-challenge/secret-token"
        self.acmechallenge.dbstore.cahandler_lookup.return_value = "lookup"
        with self.assertRaises(AssertionError):
            with self.assertLogs("test_a2c", level="INFO"):
                self.assertFalse(self.acmechallenge.lookup(path_info))


if __name__ == "__main__":
    unittest.main()
