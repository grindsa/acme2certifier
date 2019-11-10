#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
import unittest
import sys
import os
try:
    from mock import patch, MagicMock
except ImportError:
    from unittest.mock import patch, MagicMock
sys.path.insert(0, '..')

def dict_from_row(row):
    """ small helper to convert a select list into a dictionary """
    return dict(zip(row.keys(), row))

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """
    def setUp(self):
        """ setup unittest """
        # from acme.wsgi_handler import DBstore
        from examples.db_handler.wsgi_handler import DBstore
        import logging
        logging.basicConfig(
            # format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            format='%(asctime)s - acme2certifier - %(levelname)s - %(message)s',
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.INFO)
        self.logger = logging.getLogger('test_acme2certifier')
        self.dbstore = DBstore(False, self.logger, 'acme_test.db')

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

    def test_008_accout_add(self):
        """ test DBstore.account_add() method for a new entry """
        data_dic = {
            'alg' : 'alg1',
            'jwk' : '{"key11": "val11", "key12": "val12"}',
            'contact' : 'contact1',
            'name' : 'name1'}
        self.assertEqual(('name1', True), self.dbstore.account_add(data_dic))

    def test_009_accout_add(self):
        """ test DBstore.account_add() method for a new entry """
        data_dic = {
            'alg' : 'alg2',
            'jwk' : 'jwk2',
            'contact' : 'contact2',
            'name' : 'name2'}
        self.assertEqual(('name2', True), self.dbstore.account_add(data_dic))

    def test_010_accout_add(self):
        """ test DBstore.account_add() method for an new entry """
        data_dic = {
            'alg' : 'alg3',
            'jwk' : 'jwk3',
            'contact' : 'contact3',
            'name' : 'name3'}
        self.assertEqual(('name3', True), self.dbstore.account_add(data_dic))

    def test_011_accout_add(self):
        """ test DBstore.account_add() method for an existing entry (jwk already exists) """
        data_dic = {
            'alg' : 'alg4',
            'jwk' : 'jwk3',
            'contact' : 'contact4',
            'name' : 'name4'}
        self.assertEqual(('name3', False), self.dbstore.account_add(data_dic))

    def test_011_accout_search_alg(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('contact2'), self.dbstore.account_search('alg', 'alg2'))

    def test_012_accout_search_jwk(self):
        """ test DBstore.account_seach() method for jwk """
        self.assertIn(('contact1'), self.dbstore.account_search('jwk', '{"key11": "val11", "key12": "val12"}'))

    def test_013_accout_search_jwk(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('contact2'), self.dbstore.account_search('jwk', 'jwk2'))

    def test_014_accout_search_contact(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('jwk2'), self.dbstore.account_search('contact', 'contact2'))

    def test_015_accout_search_exponent(self):
        """ test DBstore.account_seach() method for alg field"""
        self.assertIn(('name1'), self.dbstore.account_search('name', 'name1'))

    def test_016_jkw_load(self):
        """ test DBstore.jwk_load() for an existing key"""
        self.assertEqual({'alg': u'alg1', u'key11': u'val11', u'key12': u'val12'}, self.dbstore.jwk_load('name1'))

    def test_017_jkw_load(self):
        """ test DBstore.jwk_load() for an not existing key"""
        self.assertEqual({}, self.dbstore.jwk_load('not_existing'))

    def test_018_account_delete(self):
        """ test DBstore.account_delete() for an existing key"""
        self.assertTrue(self.dbstore.account_delete('name3'))

    def test_019_account_delete(self):
        """ test DBstore.account_delete() for an non existing key"""
        self.assertFalse(self.dbstore.account_delete('not_existing'))

    @patch('examples.db_handler.wsgi_handler.datestr_to_date')
    def test_020_account_lookup(self, mock_datestr):
        """ test DBstore.account_delete() for an existing key"""
        mock_datestr.return_value = 'datestr'
        self.assertEqual({'id': 1, 'name': u'name1', 'jwk': '{"key11": "val11", "key12": "val12"}', 'contact': 'contact1', 'alg': 'alg1', 'created_at': 'datestr'}, self.dbstore.account_lookup('jwk', '{"key11": "val11", "key12": "val12"}'))

    def test_021_account_lookup(self):
        """ test DBstore.account_delete() for an non exisitng key"""
        self.assertFalse(self.dbstore.account_lookup('jwk', 'jwk4'))

    def test_022_order_add(self):
        """ test DBstore.order_add() method for a new entry """
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.assertEqual(1, self.dbstore.order_add(data_dic))

    def test_023_order_add(self):
        """ test DBstore.order_add() method for a new entry with notbefore and notafter entries """
        data_dic = {'name' : 'name2', 'identifiers' : 'identifiers', 'notbefore': 10, 'notafter': 20, 'account' : 'name2', 'status' : 2, 'expires' : '25'}
        self.assertEqual(2, self.dbstore.order_add(data_dic))
        
    def test_024_authorization_add(self):
        """ test DBstore.authorization_add() method  """
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.assertEqual(1, self.dbstore.authorization_add(data_dic))

    def test_025_authorization_add(self):
        """ test DBstore.authorization_add() method  """
        data_dic = {'name' : 'name2', 'type' : 'type2', 'value': 'value2', 'order' : 2}
        self.assertEqual(2, self.dbstore.authorization_add(data_dic))

    def test_026_authorization_update(self):
        """ test DBstore.authorization_update() method  """
        data_dic = {'name' : 'name1', 'token' : 'token1', 'expires': '25'}
        self.assertEqual(1, self.dbstore.authorization_update(data_dic))

    def test_027_authorization_search(self):
        """ test DBstore.authorization_search() by name """
        self.assertIn('token1', dict_from_row(self.dbstore.authorization_search('name', 'name1')[0])['token'])
        
    def test_028_authorization_search(self):
        """ test DBstore.authorization_search() by token """
        self.assertIn('name2', dict_from_row(self.dbstore.authorization_search('type', 'type2')[0])['name'])

    def test_029_authorization_lookup(self):
        """ test DBstore.authorization_lookup() by name """
        self.assertEqual([{'type': u'type2', 'value': u'value2'}], self.dbstore.authorization_lookup('name', 'name2'))

    def test_30_authorization_lookup(self):
        """ test DBstore.authorization_lookup() by token """
        self.assertEqual([{'type': u'type1', 'value': u'value1'}], self.dbstore.authorization_lookup('token', 'token1'))

    def test_031_challenge_add(self):
        """ test DBstore.challenge_add() method  """
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.assertEqual(1, self.dbstore.challenge_add(data_dic))

    def test_032_challenge_add(self):
        """ test DBstore.challenge_add() method  """
        data_dic = {'name' : 'challenge2', 'token' : 'token2', 'authorization': 'name2', 'expires' : 25, 'type' : 'type2'}
        self.assertEqual(2, self.dbstore.challenge_add(data_dic))

    def test_033_challenge_search(self):
        """ test DBstore.challenge_search() method  """
        self.assertIn(('type1'), self.dbstore.challenge_search('name', 'challenge1'))

    def test_034_challenge_search(self):
        """ test DBstore.challenge_search() method for not existing challenges  """
        self.assertFalse(self.dbstore.challenge_search('name', 'challenge3'))

    def test_035_challenge_lookup(self):
        """ test DBstore.challenge_lookup() method  """
        self.assertEqual({'status': u'pending', 'token': u'token1', 'type': u'type1'}, self.dbstore.challenge_lookup('name', 'challenge1'))

    def test_036_challenge_lookup(self):
        """ test DBstore.challenge_lookup() method  """
        self.assertEqual({'status': u'pending', 'token': u'token2', 'type': u'type2'}, self.dbstore.challenge_lookup('name', 'challenge2'))

    def test_037_challenge_update(self):
        """ test DBstore.challenge_update() method  without any parameter"""
        data_dic = {'name' : 'challenge1'}
        self.assertFalse(self.dbstore.challenge_update(data_dic))

    def test_038_challenge_update(self):
        """ test DBstore.challenge_update() method  with keyauth only"""
        data_dic = {'name' : 'challenge1', 'status' : 'valid', 'keyauthorization' : 'auth'}
        self.assertFalse(self.dbstore.challenge_update(data_dic))

    def test_039_challenge_update(self):
        """ test DBstore.challenge_update() method  with status only"""
        data_dic = {'name' : 'challenge1', 'status' : 'valid'}
        self.assertFalse(self.dbstore.challenge_update(data_dic))

    def test_040_challenge_update(self):
        """ test DBstore.challenge_update() method  with both"""
        data_dic = {'name' : 'challenge2', 'status' : 'valid', 'keyauthorization' : 'auth2'}
        self.assertFalse(self.dbstore.challenge_update(data_dic))

    def test_041_order_search(self):
        """ test DBstore.order_search() method (unsuccesful) """
        self.assertEqual(None, self.dbstore.order_search('name', 'order'))

    def test_042_order_search(self):
        """ test DBstore.order_search() method (succesful) """
        self.assertEqual('name', dict_from_row(self.dbstore.order_search('name', 'name'))['name'])        

if __name__ == '__main__':

    if os.path.exists('acme_test.db'):
        os.remove('acme_test.db')
    unittest.main()
