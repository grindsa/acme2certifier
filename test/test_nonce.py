#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    # pylint: disable=W0107, R0903
    pass

class TestACMEHandler(unittest.TestCase):
    """ test class for ACMEHandler """
    acme = None
    def setUp(self):
        """ setup unittest """
        models_mock = MagicMock()
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {'acme_srv.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from acme_srv.nonce import Nonce
        self.nonce = Nonce(False, self.logger)

    def test_001_nonce__new(self):
        """ test Nonce.new() and check if we get something back """
        self.assertIsNotNone(self.nonce._new())

    def test_002_nonce_generate_and_add(self):
        """ test Nonce.nonce_generate_and_add() and check if we get something back """
        self.assertIsNotNone(self.nonce.generate_and_add())

    def test_003_nonce_check(self):
        """ test Nonce.nonce_check_and_delete """
        self.assertEqual((400, 'urn:ietf:params:acme:error:badNonce', 'NONE'), self.nonce.check({'foo':'bar'}))

    def test_004_nonce_check(self):
        """ test Nonce.nonce_check_and_delete """
        self.assertEqual((200, None, None), self.nonce.check({'nonce':'aaa'}))

    def test_005_nonce__check_and_delete(self):
        """ test Nonce.nonce_check_and_delete """
        self.assertEqual((200, None, None), self.nonce._check_and_delete('aaa'))

    def test_006_nonce_generate_and_add(self):
        """ test Nonce._add() if dbstore.nonce_add raises an exception """
        self.nonce.dbstore.nonce_add.side_effect = Exception('exc_nonce_add')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.nonce.generate_and_add()
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Nonce.generate_and_add(): exc_nonce_add', lcm.output)

    def test_007_nonce__check_and_delete(self):
        """ test Nonce._add() if dbstore.nonce_add raises an exception """
        self.nonce.dbstore.nonce_check.return_value = True
        self.nonce.dbstore.nonce_delete.side_effect = Exception('exc_nonce_delete')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.nonce._check_and_delete('nonce')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error during nonce_delete() in Nonce._check_and_delete(): exc_nonce_delete', lcm.output)

    def test_008_nonce__check_and_delete(self):
        """ test Nonce._add() if dbstore.nonce_add raises an exception """
        self.nonce.dbstore.nonce_check.side_effect = Exception('exc_nonce_check')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.nonce._check_and_delete('nonce')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error during nonce_check() in Nonce._check_and_delete(): exc_nonce_check', lcm.output)

    def test_009__enter_(self):
        """ test enter """
        self.nonce.__enter__()

if __name__ == '__main__':
    unittest.main()
