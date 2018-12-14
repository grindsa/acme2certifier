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
        from acme.cgi_handler import DBstore
        self.dbstore = DBstore()

    def test_nonce_add_1(self):
        """ test DBstore.nonce_add() method """
        self.assertEqual(1, self.dbstore.nonce_add('aaa'))

    def test_nonce_add_2(self):
        """ test DBstore.nonce_add() method """
        self.assertEqual(2, self.dbstore.nonce_add('bbb'))

    def test_nonce_check_1(self):
        """ test DBstore.nonce_check() method """
        self.assertTrue(self.dbstore.nonce_check('aaa'))

    def test_nonce_check_2(self):
        """ test DBstore.nonce_check() method """
        self.assertTrue(self.dbstore.nonce_check('bbb'))

    def test_nonce_check_3(self):
        """ test DBstore.nonce_check() method for a non existing entry"""
        self.assertFalse(self.dbstore.nonce_check('ccc'))

    def test_nonce_delete(self):
        """ test DBstore.nonce_delete() method """
        self.assertEqual(None, self.dbstore.nonce_delete('bbb'))

    def test_nonce_delete_check(self):
        """ test DBstore.nonce_delete() method for deleted entry """
        self.assertFalse(self.dbstore.nonce_check('bbb'))

    def test_accout_add_1(self):
        """ test DBstore.account_add() method for a new entry """
        self.assertEqual((1, True), self.dbstore.account_add('alg', 'exponent', 'kty', 'modulus', 'contact'))

    def test_accout_add_2(self):
        """ test DBstore.account_add() method for a new entry """
        self.assertEqual((2, True), self.dbstore.account_add('alg2', 'exponent2', 'kty2', 'modulus2', 'contact2'))

    def test_accout_add_3(self):
        """ test DBstore.account_add() method for an existing entry """
        self.assertEqual((1, False), self.dbstore.account_add('alg', 'exponent', 'kty', 'modulus', 'contact'))

    def test_accout_search_alg(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('exponent2'), self.dbstore.account_search('alg', 'alg2'))

    def test_accout_search_kty(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('exponent2'), self.dbstore.account_search('kty', 'kty2'))

    def test_accout_search_mod(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('exponent2'), self.dbstore.account_search('modulus', 'modulus2'))

    def test_accout_search_contact(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('exponent2'), self.dbstore.account_search('contact', 'contact2'))

    def test_accout_search_exponent(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('modulus2'), self.dbstore.account_search('exponent', 'exponent2'))

if __name__ == '__main__':

    if os.path.exists('acme.db'):
        os.remove('acme.db')
    unittest.main()
