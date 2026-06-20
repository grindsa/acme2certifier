#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for nonce.py"""

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


class TestNonce(unittest.TestCase):
    """tests for Nonce"""

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

    def test_001_generate_nonce_value(self):
        """test Nonce._generate_nonce_value() and check if we get something back"""
        self.assertIsNotNone(self.nonce._generate_nonce_value())

    def test_002_generate_and_add(self):
        """test Nonce._generate_and_add() and check if we get something back"""
        self.assertIsNotNone(self.nonce.generate_and_add())

    def test_003_nonce_check(self):
        """test Nonce.check() with missing nonce"""
        self.assertEqual(
            (400, "urn:ietf:params:acme:error:badNonce", "NONE"),
            self.nonce.check({"foo": "bar"}),
        )

    @patch("acme_srv.nonce.Nonce._validate_and_consume_nonce")
    def test_004_nonce_check(self, mock_validate_and_consume_nonce):
        """test Nonce.check() calls _validate_and_consume_nonce()"""
        mock_validate_and_consume_nonce.return_value = (200, None, None)
        self.assertEqual((200, None, None), self.nonce.check({"nonce": "aaa"}))

    @patch("acme_srv.nonce.DBstore")
    def test_005_nonce__validate_and_consume_nonce(self, mock_dbstore_class):
        """test Nonce._validate_and_consume_nonce()"""
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

    @patch("acme_srv.nonce.load_config", return_value=None)
    def test_010_load_configuration_without_config(self, _mock_load_config):
        """test _load_configuration() keeps default validity if config is missing"""
        self.nonce.config.validity = 7200
        self.nonce._load_configuration()
        self.assertEqual(7200, self.nonce.config.validity)

    @patch("acme_srv.nonce.load_config")
    def test_011_load_configuration_with_validity(self, mock_load_config):
        """test _load_configuration() applies Nonce.validity from config"""
        config_mock = MagicMock()
        config_mock.get.return_value = "3600"
        mock_load_config.return_value = config_mock

        self.nonce.config.validity = 7200
        self.nonce._load_configuration()

        self.assertEqual(3600, self.nonce.config.validity)
        config_mock.get.assert_called_once_with("Nonce", "validity", fallback=7200)

    @patch("acme_srv.nonce.load_config")
    def test_012_load_configuration_invalid_validity(self, mock_load_config):
        """test _load_configuration() raises ConfigurationError on invalid validity"""
        config_mock = MagicMock()
        config_mock.get.return_value = "invalid"
        mock_load_config.return_value = config_mock

        from acme_srv.nonce import ConfigurationError

        with self.assertRaises(ConfigurationError) as ctx:
            self.nonce._load_configuration()

        self.assertIn("Invalid validity parameter", str(ctx.exception))

    @patch("acme_srv.nonce.load_config")
    def test_013_load_configuration_uses_current_fallback(self, mock_load_config):
        """test _load_configuration() uses current validity as fallback value"""
        config_mock = MagicMock()
        config_mock.get.return_value = "1800"
        mock_load_config.return_value = config_mock

        self.nonce.config.validity = 999
        self.nonce._load_configuration()

        config_mock.get.assert_called_once_with("Nonce", "validity", fallback=999)
        self.assertEqual(1800, self.nonce.config.validity)

    def test_014_expire_nonces_skips_if_validity_disabled(self):
        """test expire_nonces() returns empty result when validity <= 0"""
        repo_mock = MagicMock()
        from acme_srv.nonce import Nonce

        nonce = Nonce(False, self.logger, repo=repo_mock)
        nonce.config.validity = 0

        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            result = nonce.expire_nonces(timestamp=10000)

        self.assertEqual(([], []), result)
        self.assertIn(
            "Nonce.expire_nonces() skipped: validity is set to 0", lcm.output[0]
        )
        repo_mock.search_expired_nonces.assert_not_called()
        repo_mock.delete_nonces.assert_not_called()

    def test_015_expire_nonces_no_expired_entries(self):
        """test expire_nonces() with no expired nonce entries"""
        repo_mock = MagicMock()
        repo_mock.search_expired_nonces.return_value = []
        from acme_srv.nonce import Nonce

        nonce = Nonce(False, self.logger, repo=repo_mock)
        nonce.config.validity = 120

        result = nonce.expire_nonces(timestamp=5000)

        self.assertEqual(([], []), result)
        repo_mock.search_expired_nonces.assert_called_once_with(4880)
        repo_mock.delete_nonces.assert_not_called()

    def test_016_expire_nonces_with_expired_entries(self):
        """test expire_nonces() deletes found expired nonces"""
        repo_mock = MagicMock()
        repo_mock.search_expired_nonces.return_value = ["n1", "n2", "n3"]
        repo_mock.delete_nonces.return_value = 3
        from acme_srv.nonce import Nonce

        nonce = Nonce(False, self.logger, repo=repo_mock)
        nonce.config.validity = 300

        result = nonce.expire_nonces(timestamp=2000)

        self.assertEqual(([], ["n1", "n2", "n3"]), result)
        repo_mock.search_expired_nonces.assert_called_once_with(1700)
        repo_mock.delete_nonces.assert_called_once_with(["n1", "n2", "n3"])

    def test_017_expire_nonces_handles_search_exception(self):
        """test expire_nonces() handles repository search errors"""
        repo_mock = MagicMock()
        repo_mock.search_expired_nonces.side_effect = Exception("exc_search")
        from acme_srv.nonce import Nonce

        nonce = Nonce(False, self.logger, repo=repo_mock)
        nonce.config.validity = 60

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = nonce.expire_nonces(timestamp=1000)

        self.assertEqual(([], []), result)
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to search expired nonces: exc_search",
            lcm.output,
        )
        repo_mock.delete_nonces.assert_not_called()

    def test_018_expire_nonces_handles_delete_exception(self):
        """test expire_nonces() handles repository delete errors"""
        repo_mock = MagicMock()
        repo_mock.search_expired_nonces.return_value = ["n1", "n2"]
        repo_mock.delete_nonces.side_effect = Exception("exc_delete")
        from acme_srv.nonce import Nonce

        nonce = Nonce(False, self.logger, repo=repo_mock)
        nonce.config.validity = 100

        with self.assertLogs("test_a2c", level="INFO") as lcm:
            result = nonce.expire_nonces(timestamp=1000)

        self.assertEqual(([], ["n1", "n2"]), result)
        self.assertIn(
            "CRITICAL:test_a2c:Database error: failed to search expired nonces: exc_delete",
            lcm.output,
        )
        repo_mock.search_expired_nonces.assert_called_once_with(900)
        repo_mock.delete_nonces.assert_called_once_with(["n1", "n2"])


class TestNonceRepository(unittest.TestCase):
    """tests for NonceRepository pass-through methods"""

    def setUp(self):
        """setup repository test fixtures"""
        from acme_srv.nonce import NonceRepository

        self.dbstore_mock = MagicMock()
        self.repo = NonceRepository(self.dbstore_mock)

    def test_019_repository_delete_nonces(self):
        """test NonceRepository.delete_nonces() forwards call to DB layer"""
        self.dbstore_mock.nonce_delete_bulk.return_value = 2

        result = self.repo.delete_nonces(["n1", "n2"])

        self.assertEqual(2, result)
        self.dbstore_mock.nonce_delete_bulk.assert_called_once_with(["n1", "n2"])

    def test_020_repository_check_nonce(self):
        """test NonceRepository.check_nonce() forwards call to DB layer"""
        self.dbstore_mock.nonce_check.return_value = True

        result = self.repo.check_nonce("nonce-1")

        self.assertTrue(result)
        self.dbstore_mock.nonce_check.assert_called_once_with("nonce-1")

    def test_021_repository_delete_nonce(self):
        """test NonceRepository.delete_nonce() forwards call to DB layer"""
        self.dbstore_mock.nonce_delete.return_value = None

        result = self.repo.delete_nonce("nonce-2")

        self.assertIsNone(result)
        self.dbstore_mock.nonce_delete.assert_called_once_with("nonce-2")

    def test_022_repository_add_nonce(self):
        """test NonceRepository.add_nonce() forwards call to DB layer"""
        self.dbstore_mock.nonce_add.return_value = 42

        result = self.repo.add_nonce("nonce-3")

        self.assertEqual(42, result)
        self.dbstore_mock.nonce_add.assert_called_once_with("nonce-3")

    def test_023_repository_search_expired_nonces(self):
        """test NonceRepository.search_expired_nonces() forwards timestamp filter"""
        self.dbstore_mock.nonce_search_by_timestamp.return_value = ["n1", "n2"]

        result = self.repo.search_expired_nonces(1234)

        self.assertEqual(["n1", "n2"], result)
        self.dbstore_mock.nonce_search_by_timestamp.assert_called_once_with(1234)


if __name__ == "__main__":
    unittest.main()
