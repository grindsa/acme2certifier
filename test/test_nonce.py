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
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {"acme_srv.db_handler": models_mock}
        patch.dict("sys.modules", modules).start()
        import logging

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme_srv.nonce import Nonce

        self.nonce = Nonce(False, self.logger)

    def test_001_nonce__generate_nonce_value(self):
        """test Nonce.new() and check if we get something back"""
        self.assertIsNotNone(self.nonce._generate_nonce_value())

    def test_002_nonce_generate_and_add(self):
        """test Nonce.nonce_generate_and_add() and check if we get something back"""
        self.assertIsNotNone(self.nonce.generate_and_add())

    def test_003_nonce_check(self):
        """test Nonce.nonce_validate_and_consume_nonce"""
        self.assertEqual(
            (400, "urn:ietf:params:acme:error:badNonce", "NONE"),
            self.nonce.check({"foo": "bar"}),
        )

    @patch("acme_srv.nonce.Nonce._validate_and_consume_nonce")
    def test_004_nonce_check(self, mock_validate_and_consume_nonce):
        """test Nonce.nonce_validate_and_consume_nonce"""
        mock_validate_and_consume_nonce.return_value = (200, None, None)
        self.assertEqual((200, None, None), self.nonce.check({"nonce": "aaa"}))

    @patch("acme_srv.nonce.DBstore")
    def test_005_nonce__validate_and_consume_nonce(self, mock_dbstore_class):
        """test Nonce.nonce_validate_and_consume_nonce"""
        # Setup mock to return True for nonce_check
        mock_dbstore_instance = MagicMock()
        mock_dbstore_instance.nonce_check.return_value = True
        mock_dbstore_instance.nonce_delete.return_value = None
        mock_dbstore_class.return_value = mock_dbstore_instance

        # Create a new nonce instance with the mocked dbstore
        from acme_srv.nonce import Nonce

        nonce = Nonce(False, self.logger)

        self.assertEqual((200, None, None), nonce._validate_and_consume_nonce("aaa"))

    @patch("acme_srv.nonce.DBstore")
    def test_006_nonce_generate_and_add(self, mock_dbstore_class):
        """test Nonce._add() if dbstore.nonce_add raises an exception"""
        # Setup mock to raise exception
        mock_dbstore_instance = MagicMock()
        mock_dbstore_instance.nonce_add.side_effect = Exception("exc_nonce_add")
        mock_dbstore_class.return_value = mock_dbstore_instance

        # Create a new nonce instance with the mocked dbstore
        from acme_srv.nonce import Nonce

        nonce = Nonce(False, self.logger)

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            nonce.generate_and_add()
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to add new nonce: exc_nonce_add",
            lcm.output,
        )

    @patch("acme_srv.nonce.DBstore")
    def test_007_nonce__validate_and_consume_nonce(self, mock_dbstore_class):
        """test Nonce._validate_and_consume_nonce() if dbstore.nonce_delete raises an exception"""
        # Setup mock: nonce_check returns True, nonce_delete raises exception
        mock_dbstore_instance = MagicMock()
        mock_dbstore_instance.nonce_check.return_value = True
        mock_dbstore_instance.nonce_delete.side_effect = Exception("exc_nonce_delete")
        mock_dbstore_class.return_value = mock_dbstore_instance

        # Create a new nonce instance with the mocked dbstore
        from acme_srv.nonce import Nonce

        nonce = Nonce(False, self.logger)

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            nonce._validate_and_consume_nonce("nonce")
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to delete nonce: exc_nonce_delete",
            lcm.output,
        )

    @patch("acme_srv.nonce.DBstore")
    def test_008_nonce__validate_and_consume_nonce(self, mock_dbstore_class):
        """test Nonce._validate_and_consume_nonce() if dbstore.nonce_check raises an exception"""
        # Setup mock to raise exception on nonce_check
        mock_dbstore_instance = MagicMock()
        mock_dbstore_instance.nonce_check.side_effect = Exception("exc_nonce_check")
        mock_dbstore_class.return_value = mock_dbstore_instance

        # Create a new nonce instance with the mocked dbstore
        from acme_srv.nonce import Nonce

        nonce = Nonce(False, self.logger)

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            nonce._validate_and_consume_nonce("nonce")
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to check nonce: exc_nonce_check",
            lcm.output,
        )

    def test_009__enter_(self):
        """test enter"""
        self.nonce.__enter__()


if __name__ == "__main__":
    unittest.main()
