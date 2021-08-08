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
        from acme_srv.acmechallenge import Acmechallenge
        self.acmechallenge = Acmechallenge(False, None, self.logger)

    def test_001__enter_(self):
        """ test enter """
        self.acmechallenge.__enter__()

    def test_002__enter_(self):
        """ test enter """
        self.acmechallenge.__exit__()

    def test_003_lookup(self):
        """ test lookup without pathinfo """
        path_info = None
        self.assertFalse(self.acmechallenge.lookup(path_info))

    def test_004_lookup(self):
        """ test lookup strange token returning wrong data """
        path_info = 'foo'
        self.acmechallenge.dbstore.cahandler_lookup.return_value = ('lookup')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.acmechallenge.lookup(path_info))
        self.assertIn('INFO:test_a2c:Acmechallenge.lookup() token: foo', lcm.output)

    def test_005_lookup(self):
        """ test lookup strange token rest replace """
        path_info = '/.well-known/acme-challenge/foo1'
        self.acmechallenge.dbstore.cahandler_lookup.return_value = ('lookup')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.acmechallenge.lookup(path_info))
        self.assertIn('INFO:test_a2c:Acmechallenge.lookup() token: foo1', lcm.output)

    def test_006_lookup(self):
        """ test lookup strange token rest replace """
        path_info = '/.well-known/acme-challenge/foo'
        self.acmechallenge.dbstore.cahandler_lookup.return_value = {'value1': 'key_authorization'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('key_authorization', self.acmechallenge.lookup(path_info))
        self.assertIn('INFO:test_a2c:Acmechallenge.lookup() token: foo', lcm.output)

if __name__ == '__main__':
    unittest.main()
