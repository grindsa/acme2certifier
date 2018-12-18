#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
import unittest
import sys
import os
sys.path.insert(0, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """
    def setUp(self):
        """ setup unittest """
        from acme.wsgi_handler import DBstore
        self.dbstore = DBstore(False, 'acme_test.db')

    def test_001_nonce_add(self):
        """ test DBstore.nonce_add() method """
        self.assertEqual(1, self.dbstore.nonce_add('aaa'))

    def test_002_nonce_add_2(self):
        """ test DBstore.nonce_add() method """
        self.assertEqual(2, self.dbstore.nonce_add('bbb'))

    def test_003_nonce_check_1(self):
        """ test DBstore.nonce_check() method """
        self.assertTrue(self.dbstore.nonce_check('aaa'))

    def test_004_nonce_check_2(self):
        """ test DBstore.nonce_check() method """
        self.assertTrue(self.dbstore.nonce_check('bbb'))

    def test_005_nonce_check_3(self):
        """ test DBstore.nonce_check() method for a non existing entry"""
        self.assertFalse(self.dbstore.nonce_check('ccc'))

    def test_006_nonce_delete(self):
        """ test DBstore.nonce_delete() method """
        self.assertEqual(None, self.dbstore.nonce_delete('bbb'))

    def test_007_nonce_delete_check(self):
        """ test DBstore.nonce_delete() method for deleted entry """
        self.assertFalse(self.dbstore.nonce_check('bbb'))

    def test_008_accout_add_1(self):
        """ test DBstore.account_add() method for a new entry """
        self.assertEqual((1, True), self.dbstore.account_add('alg', 'exponent', 'kty', 'modulus', 'contact'))

    def test_009_accout_add_2(self):
        """ test DBstore.account_add() method for a new entry """
        self.assertEqual((2, True), self.dbstore.account_add('alg2', 'exponent2', 'kty2', 'modulus2', 'contact2'))

    def test_010_accout_add_3(self):
        """ test DBstore.account_add() method for an existing entry """
        self.assertEqual((1, False), self.dbstore.account_add('alg', 'exponent', 'kty', 'modulus', 'contact'))

    def test_011_accout_search_alg(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('exponent2'), self.dbstore.account_search('alg', 'alg2'))

    def test_012_accout_search_kty(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('exponent2'), self.dbstore.account_search('kty', 'kty2'))

    def test_013_accout_search_mod(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('exponent2'), self.dbstore.account_search('modulus', 'modulus2'))

    def test_014_accout_search_contact(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('exponent2'), self.dbstore.account_search('contact', 'contact2'))

    def test_015_accout_search_exponent(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('modulus2'), self.dbstore.account_search('exponent', 'exponent2'))

    def test_016_jkw_load(self):
        """ test DBstore.jwk_load() for an exisitng key"""
        self.assertEqual({'alg': u'alg', 'e': u'exponent', 'kty': u'kty', 'n': u'modulus'}, self.dbstore.jwk_load(1))

    def test_017_jkw_load(self):
        """ test DBstore.jwk_load() for an not exisitng key"""
        self.assertEqual({}, self.dbstore.jwk_load(3))

    def test_018_account_delete(self):
        """ test DBstore.account_delete() for an exisitng key"""
        self.assertEqual(True, self.dbstore.account_delete(2))

    def test_019_account_delete(self):
        """ test DBstore.account_delete() for an non exisitng key"""
        self.assertEqual(False, self.dbstore.account_delete(3))

if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
