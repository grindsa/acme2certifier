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
        models_mock.acme.db_handler.DBstore.return_value = FakeDBStore
        modules = {'acme.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from acme.directory import Directory
        self.directory = Directory(False, 'http://tester.local', self.logger)

    def test_001_directory_servername_get(self):
        """ test Directory.get_server_name() method """
        self.assertEqual('http://tester.local', self.directory.servername_get())

    def test_002_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newNonce': 'http://tester.local/acme/newnonce'}, self.directory.directory_get())

    def test_003_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newAccount': 'http://tester.local/acme/newaccount'}, self.directory.directory_get())

    def test_004_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.supress_version = True
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier'}}, self.directory.directory_get())

    def test_005_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.tos_url = 'foo'
        self.directory.supress_version = True
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'termsOfService': 'foo'}}, self.directory.directory_get())

    def test_006_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.version = '0.1'
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'version': '0.1'}}, self.directory.directory_get())

    def test_007_directory_directory_get(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.version = '0.1'
        self.directory.tos_url = 'foo'
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'version': '0.1', 'termsOfService': 'foo'}}, self.directory.directory_get())

if __name__ == '__main__':
    unittest.main()
