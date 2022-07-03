#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
import unittest
import sys
import os
try:
    from mock import patch, MagicMock, Mock
except ImportError:
    from unittest.mock import patch, MagicMock, Mock

sys.path.insert(0, '.')
sys.path.insert(1, '..')

def dict_from_row(row):
    """ small helper to convert a select list into a dictionary """
    return dict(zip(row.keys(), row))

def _cleanup(dir_path):
    """ cleanup function """
    # remove old db
    if os.path.exists(dir_path + '/acme_test.db'):
         os.remove(dir_path + '/acme_test.db')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """
    def setUp(self):
        """ setup unittest """
        # from acme_srv.wsgi_handler import DBstore
        from examples.db_handler.wsgi_handler import DBstore, initialize
        from acme_srv.version import __dbversion__
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        self.dbstore = DBstore(False, self.logger, self.dir_path + '/acme_test.db')
        self.initialize = initialize
        self.dbversion = __dbversion__
        _cleanup(self.dir_path)
        self.dbstore._db_create()

    def tearDown(self):
        """ teardown """
        _cleanup(self.dir_path)

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    def test_002_nonce_add(self):
        """ test DBstore.nonce_add() method """
        self.assertEqual(1, self.dbstore.nonce_add('aaa'))

    def test_003_nonce_add_2(self):
        """ test DBstore.nonce_add() method """
        self.dbstore.nonce_add('aaa')
        self.assertEqual(2, self.dbstore.nonce_add('bbb'))

    def test_004_nonce_check_1(self):
        """ test DBstore.nonce_check() method """
        self.dbstore.nonce_add('aaa')
        self.assertTrue(self.dbstore.nonce_check('aaa'))

    def test_005_nonce_check_2(self):
        """ test DBstore.nonce_check() method """
        self.dbstore.nonce_add('aaa')
        self.dbstore.nonce_add('bbb')
        self.assertTrue(self.dbstore.nonce_check('bbb'))

    def test_006_nonce_check_3(self):
        """ test DBstore.nonce_check() method for a non existing entry"""
        self.assertFalse(self.dbstore.nonce_check('ccc'))

    def test_007_nonce_delete(self):
        """ test DBstore.nonce_delete() method """
        self.dbstore.nonce_add('bbb')
        self.assertEqual(None, self.dbstore.nonce_delete('bbb'))

    def test_008_nonce_delete_check(self):
        """ test DBstore.nonce_delete() method for deleted entry """
        self.assertFalse(self.dbstore.nonce_check('bbb'))

    def test_009_accout_add(self):
        """ test DBstore.account_add() method for a new entry without eab_kid """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.assertEqual(('name1', True), self.dbstore.account_add(data_dic))

    def test_010_accout_add(self):
        """ test DBstore.account_add() method for a new entry including eab_kid """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1', 'eab_kid': 'eab_kid1'}
        self.assertEqual(('name1', True), self.dbstore.account_add(data_dic))

    def test_011_accout_add(self):
        """ test DBstore.account_add() method for a new entry """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.assertEqual(('name2', True), self.dbstore.account_add(data_dic))

    def test_012_accout_add(self):
        """ test DBstore.account_add() method for an new entry """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg3', 'jwk' : 'jwk3', 'contact' : 'contact3', 'name' : 'name3'}
        self.assertEqual(('name3', True), self.dbstore.account_add(data_dic))

    def test_013_accout_add(self):
        """ test DBstore.account_add() method for an existing entry (jwk already exists) """
        data_dic = {'alg' : 'alg3', 'jwk' : 'jwk3', 'contact' : 'contact3', 'name' : 'name3'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg4', 'jwk' : 'jwk3', 'contact' : 'contact4', 'name' : 'name4'}
        self.assertEqual(('name3', False), self.dbstore.account_add(data_dic))

    def test_014_accout_add(self):
        """ test DBstore.account_add() method for an existing entry (jwk already exists) which has an eab-kid """
        data_dic = {'alg' : 'alg3', 'jwk' : 'jwk3', 'contact' : 'contact3', 'name' : 'name3', 'eab_kid': 'eab_kid3'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg4', 'jwk' : 'jwk3', 'contact' : 'contact4', 'name' : 'name4'}
        self.assertEqual(('name3', False), self.dbstore.account_add(data_dic))

    def test_015_accout_search_alg(self):
        """ test DBstore.account_seach() method for alg field"""
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        self.assertIn(('contact2'), self.dbstore._account_search('alg', 'alg2'))

    def test_016_accout_search_alg(self):
        """ test DBstore.account_seach() method for alg field including eab_kid"""
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2', 'eab_kid': 'eab_kid2'}
        self.dbstore.account_add(data_dic)
        self.assertIn(('contact2'), self.dbstore._account_search('alg', 'alg2'))
        self.assertIn(('eab_kid2'), self.dbstore._account_search('alg', 'alg2'))

    def test_017_accout_search_jwk(self):
        """ test DBstore.account_seach() method for jwk """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        self.assertIn(('contact1'), self.dbstore._account_search('jwk', '{"key11": "val11", "key12": "val12"}'))

    def test_018_accout_search_jwk(self):
        """ test DBstore.account_seach() method for jwk field"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        self.assertIn(('contact2'), self.dbstore._account_search('jwk', 'jwk2'))

    def test_019_accout_search_contact(self):
        """ test DBstore.account_seach() method for eab_kid2 field"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        self.assertIn(('jwk2'), self.dbstore._account_search('contact', 'contact2'))

    def test_020_accout_search_contact(self):
        """ test DBstore.account_seach() method for contact field"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2', 'eab_kid': 'eab_kid2'}
        self.dbstore.account_add(data_dic)
        self.assertIn(('jwk2'), self.dbstore._account_search('contact', 'contact2'))
        self.assertIn(('eab_kid2'), self.dbstore._account_search('contact', 'contact2'))

    def test_021_accout_search_eab(self):
        """ test DBstore.account_seach() method for eab field"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2', 'eab_kid': 'eab_kid2'}
        self.dbstore.account_add(data_dic)
        self.assertIn(('jwk2'), self.dbstore._account_search('eab_kid', 'eab_kid2'))
        self.assertIn(('eab_kid2'), self.dbstore._account_search('eab_kid', 'eab_kid2'))

    def test_022_accout_search_exponent(self):
        """ test DBstore.account_seach() method for alg field"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        self.assertIn(('name1'), self.dbstore._account_search('name', 'name1'))

    def test_023_jkw_load(self):
        """ test DBstore.jwk_load() for an existing key"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        self.assertEqual({'alg': u'alg1', u'key11': u'val11', u'key12': u'val12'}, self.dbstore.jwk_load('name1'))

    def test_024_jkw_load(self):
        """ test DBstore.jwk_load() for an not existing key"""
        self.assertEqual({}, self.dbstore.jwk_load('not_existing'))

    def test_025_account_delete(self):
        """ test DBstore.account_delete() for an existing key"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        self.assertTrue(self.dbstore.account_delete('name2'))

    def test_026_account_delete(self):
        """ test DBstore.account_delete() for an non existing key"""
        self.assertFalse(self.dbstore.account_delete('not_existing'))

    @patch('examples.db_handler.wsgi_handler.datestr_to_date')
    def test_027_account_lookup(self, mock_datestr):
        """ test DBstore.account_lookup() for an existing value include eab_lid"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1', 'eab_kid': 'eab_kid'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        mock_datestr.return_value = 'datestr'
        self.assertEqual({'id': 1, 'name': u'name1', 'jwk': '{"key11": "val11", "key12": "val12"}', 'contact': 'contact1', 'alg': 'alg1', 'created_at': 'datestr', 'eab_kid': 'eab_kid'}, self.dbstore.account_lookup('jwk', '{"key11": "val11", "key12": "val12"}'))

    @patch('examples.db_handler.wsgi_handler.datestr_to_date')
    def test_028_account_lookup(self, mock_datestr):
        """ test DBstore.account_lookup() for an existing value"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        mock_datestr.return_value = 'datestr'
        self.assertEqual({'id': 1, 'name': u'name1', 'jwk': '{"key11": "val11", "key12": "val12"}', 'contact': 'contact1', 'alg': 'alg1', 'created_at': 'datestr', 'eab_kid': ''}, self.dbstore.account_lookup('jwk', '{"key11": "val11", "key12": "val12"}'))

    def test_029_account_lookup(self):
        """ test DBstore.account_lookup() for an not existing value"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        self.assertFalse(self.dbstore.account_lookup('jwk', 'jwk4'))

    def test_030_account_lookup(self):
        """ test DBstore.account_lookup() for an non existing key"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        self.assertFalse(self.dbstore.account_lookup('nam', 'name3'))

    def test_031_order_add(self):
        """ test DBstore.order_add() method for a new entry """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name': 'name', 'identifiers': 'identifiers', 'account': 'name1', 'status': 1, 'expires': '25'}
        self.assertEqual(1, self.dbstore.order_add(data_dic))

    def test_032_order_add(self):
        """ test DBstore.order_add() method for a new entry with notbefore and notafter entries """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name2', 'identifiers' : 'identifiers', 'notbefore': 10, 'notafter': 20, 'account' : 'name2', 'status' : 2, 'expires' : '25'}
        self.assertEqual(2, self.dbstore.order_add(data_dic))

    def test_033_order_add(self):
        """ test DBstore.order_add() method - account lookup failed """
        data_dic = {'name': 'name', 'identifiers': 'identifiers', 'account': 'name1', 'status': 1, 'expires': '25'}
        self.assertFalse(self.dbstore.order_add(data_dic))

    def test_034_order_lookup(self):
        """ test DBstore.order_lookup() method for an existing entry """
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name2', 'identifiers' : 'identifiers', 'notbefore': 10, 'notafter': 20, 'account' : 'name2', 'status' : 2, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        self.assertEqual( {'status': u'pending', 'notafter': 20, 'identifiers': u'identifiers', 'expires': 25, 'notbefore': 10}, self.dbstore.order_lookup('name', 'name2'))

    def test_035_order_lookup(self):
        """ test DBstore.order_lookup() method for a not existing entry """
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name2', 'identifiers' : 'identifiers', 'notbefore': 10, 'notafter': 20, 'account' : 'name2', 'status' : 2, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        self.assertFalse(self.dbstore.order_lookup('name', 'name3'))

    def test_036_order_lookup(self):
        """ test DBstore.order_lookup() method for a not existing entry """
        self.assertFalse(self.dbstore.order_lookup('nam', 'name1'))

    def test_037_order_lookup(self):
        """ test DBstore.order_lookup() method with modified output list """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name2', 'identifiers' : 'identifiers', 'notbefore': 10, 'notafter': 20, 'account' : 'name2', 'status' : 2, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        self.assertEqual({'account__name': u'name2', 'name': u'name2', 'status': u'pending'}, self.dbstore.order_lookup('name', 'name2', ('name', 'status__name', 'account__name')))

    def test_038_authorization_add(self):
        """ test DBstore.authorization_add() method  """
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.assertEqual(1, self.dbstore.authorization_add(data_dic))

    def test_039_authorization_add(self):
        """ test DBstore.authorization_add() method  """
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'name2', 'type' : 'type2', 'value': 'value2', 'order' : 2}
        self.assertEqual(2, self.dbstore.authorization_add(data_dic))

    def test_040_authorization_update(self):
        """ test DBstore.authorization_update() method  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'name1', 'token' : 'token1', 'expires': '25'}
        self.assertEqual(1, self.dbstore.authorization_update(data_dic))

    def test_041_authorization_update(self):
        """ test DBstore.authorization_update() method  no expires """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'name1', 'token' : 'token2'}
        self.assertEqual(1, self.dbstore.authorization_update(data_dic))
        self.assertEqual('token2', dict_from_row(self.dbstore._authorization_search('name', 'name1')[0])['token'])

    def test_042_authorization_update(self):
        """ test DBstore.authorization_update() method  no expires """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'name1', 'expires' : '35'}
        self.assertEqual(1, self.dbstore.authorization_update(data_dic))
        self.assertEqual(35, dict_from_row(self.dbstore._authorization_search('name', 'name1')[0])['expires'])

    def test_043_authorization_update(self):
        """ test DBstore.authorization_update() method  no expires """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'expires' : '35'}
        self.assertFalse(self.dbstore.authorization_update(data_dic))

    def test_044_authorization_update(self):
        """ test DBstore.authorization_update() method  no expires """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'name1', 'expires' : '35', 'status': 'valid'}
        self.assertEqual(1, self.dbstore.authorization_update(data_dic))
        self.assertEqual(35, dict_from_row(self.dbstore._authorization_search('name', 'name1')[0])['expires'])
        self.assertEqual(5, dict_from_row(self.dbstore._authorization_search('name', 'name1')[0])['status_id'])
        self.assertEqual('valid', dict_from_row(self.dbstore._authorization_search('name', 'name1')[0])['status__name'])

    def test_045_authorization_search(self):
        """ test DBstore.authorization_search() by name """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'name1', 'token' : 'token1', 'expires': '25'}
        self.dbstore.authorization_update(data_dic)
        self.assertIn('token1', dict_from_row(self.dbstore._authorization_search('name', 'name1')[0])['token'])

    def test_046_authorization_search(self):
        """ test DBstore.authorization_search() by token """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'name1', 'token' : 'token1', 'expires': '25'}
        self.dbstore.authorization_update(data_dic)
        self.assertIn('name1', dict_from_row(self.dbstore._authorization_search('type', 'type1')[0])['name'])

    def test_047_authorization_lookup(self):
        """ test DBstore.authorization_lookup() by name """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        self.assertEqual([{'type': u'type1', 'value': u'value1'}], self.dbstore.authorization_lookup('name', 'name1'))

    def test_048_authorization_lookup(self):
        """ test DBstore.authorization_lookup() by token """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'name1', 'token' : 'token1', 'expires': '25'}
        self.dbstore.authorization_update(data_dic)
        self.assertEqual([{'type': u'type1', 'value': u'value1'}], self.dbstore.authorization_lookup('token', 'token1'))

    def test_049_authorization_lookup(self):
        """ test DBstore.authorization_lookup() for a not existing entry """
        self.assertFalse(self.dbstore.authorization_lookup('name', 'name3'))

    def test_050_authorization_lookup(self):
        """ test DBstore.authorization_lookup() for a not existing key """
        self.assertFalse(self.dbstore.authorization_lookup('nam', 'name1'))

    def test_051_authorization_lookup(self):
        """ test DBstore.authorization_lookup() for a modified output """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        self.assertEqual([{'name': u'name1', 'order__account__name': u'name1', 'order__name': u'name1'}], self.dbstore.authorization_lookup('name', 'name1', ('name', 'order__name', 'order__account__name')))

    def test_052_challenge_add(self):
        """ test DBstore.challenge_add() method  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.assertEqual(1, self.dbstore.challenge_add('value', 'mtype', data_dic))

    def test_053_challenge_add(self):
        """ test DBstore.challenge_add() method  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        data_dic = {'name' : 'challenge2', 'token' : 'token2', 'authorization': 'name1', 'expires' : 25, 'type' : 'type2'}
        self.assertEqual(2, self.dbstore.challenge_add('value', 'mtype', data_dic))

    def test_054_challenge_add(self):
        """ test DBstore.challenge_add() method - authorization lookup failed """
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.assertFalse(self.dbstore.challenge_add('value', 'mtype', data_dic))

    def test_055_challenge_search(self):
        """ test DBstore.challenge_search() method  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        self.assertIn(('type1'), self.dbstore._challenge_search('name', 'challenge1'))

    def test_056_challenge_search(self):
        """ test DBstore.challenge_search() method for not existing challenges  """
        self.assertFalse(self.dbstore._challenge_search('name', 'challenge3'))

    def test_057_challenge_lookup(self):
        """ test DBstore.challenge_lookup() method  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        self.assertEqual({'status': u'pending', 'token': u'token1', 'type': u'type1'}, self.dbstore.challenge_lookup('name', 'challenge1'))

    def test_058_challenge_lookup(self):
        """ test DBstore.challenge_lookup() method  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge2', 'token' : 'token2', 'authorization': 'name1', 'expires' : 25, 'type' : 'type2'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        self.assertEqual({'status': u'pending', 'token': u'token2', 'type': u'type2'}, self.dbstore.challenge_lookup('name', 'challenge2'))

    def test_059_challenge_lookup(self):
        """ test DBstore.challenge_lookup() method  for a not existing entry """
        self.assertFalse(self.dbstore.challenge_lookup('name', 'challenge3'))

    def test_060_challenge_lookup(self):
        """ test DBstore.challenge_lookup() method for not existing key """
        self.assertFalse(self.dbstore.challenge_lookup('nam', 'challenge1'))

    def test_061_challenge_lookup(self):
        """ test DBstore.challenge_lookup() methodwith modified output  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        self.assertEqual({'authorization': u'name1', 'authorization__order__account__name': u'name1', 'name': u'challenge1', 'authorization__order__name': u'name'}, self.dbstore.challenge_lookup('name', 'challenge1', ('name', 'authorization__name', 'authorization__order__name', 'authorization__order__account__name')))

    def test_062_challenge_update(self):
        """ test DBstore.challenge_update() method  without any parameter"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        data_dic = {'name' : 'challenge1'}
        self.assertFalse(self.dbstore.challenge_update(data_dic))

    def test_063_challenge_update(self):
        """ test DBstore.challenge_update() method  with keyauth only"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        data_dic = {'name' : 'challenge1', 'status' : 'valid', 'keyauthorization' : 'auth'}
        self.assertFalse(self.dbstore.challenge_update(data_dic))

    def test_064_challenge_update(self):
        """ test DBstore.challenge_update() method  with status only"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        data_dic = {'name' : 'challenge1', 'status' : 'valid'}
        self.assertFalse(self.dbstore.challenge_update(data_dic))

    def test_065_challenge_update(self):
        """ test DBstore.challenge_update() method  with both"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        data_dic = {'name' : 'challenge1', 'status' : 'valid', 'keyauthorization' : 'auth1'}
        self.assertFalse(self.dbstore.challenge_update(data_dic))

    def test_066_order_search(self):
        """ test DBstore.order_search() method (unsuccesful) """
        self.assertEqual(None, self.dbstore._order_search('name', 'order'))

    def test_067_order_search(self):
        """ test DBstore.order_search() method (succesful) """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        self.assertEqual('name', dict_from_row(self.dbstore._order_search('name', 'name'))['name'])

    def test_068_certificate_add(self):
        """ test DBstore.certificate_add() method (succesful) """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name'}
        self.assertEqual(1, self.dbstore.certificate_add(data_dic))

    def test_069_certificate_add(self):
        """ test DBstore.certificate_add() method (succesful) """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname2', 'csr': 'csr2', 'order': 'name1'}
        self.assertEqual(2, self.dbstore.certificate_add(data_dic))

    def test_070_certificate_add(self):
        """ test DBstore.certificate_add() method with error """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname2', 'csr': 'csr2', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname3', 'csr': 'csr3', 'order': 'name2', 'error': 'error3'}
        self.assertEqual(3, self.dbstore.certificate_add(data_dic))

    def test_071_certificate_add(self):
        """ test DBstore.certificate_add() method for existing certificate """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname1', 'cert': 'cert', 'cert_raw': 'cert_raw'}
        self.assertEqual(1, self.dbstore.certificate_add(data_dic))

    def test_072_certificate_add(self):
        """ test DBstore.certificate_add() method existing certificate with error """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname2', 'csr': 'csr2', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname2', 'error': 'error3', 'poll_identifier': None}
        self.assertEqual(2, self.dbstore.certificate_add(data_dic))

    def test_073_certificate_add(self):
        """ test DBstore.certificate_add() method csr add """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'order': 'name1'}
        self.assertEqual(1, self.dbstore.certificate_add(data_dic))
        self.assertEqual({'cert': None, 'order': u'name1', 'order__name': u'name1', 'name': u'certname1', 'csr': u''}, self.dbstore.certificate_lookup('name', 'certname1'))

    def test_074_certificate_lookup(self):
        """ test DBstore.certificate_lookup() by name (successful) """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname1', 'cert': 'cert', 'cert_raw': 'cert_raw'}
        self.dbstore.certificate_add(data_dic)
        self.assertEqual({'cert': u'cert', 'order': u'name1', 'order__name': u'name1', 'name': u'certname1', 'csr': u'csr1'}, self.dbstore.certificate_lookup('name', 'certname1'))

    def test_075_certificate_lookup(self):
        """ test DBstore.certificate_lookup() by name (successful) """
        self.assertFalse(self.dbstore.certificate_lookup('name', 'certname'))

    def test_076_certificate_lookup(self):
        """ test DBstore.certificate_lookup() methodwith modified output  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname1', 'cert': 'cert', 'cert_raw': 'cert_raw'}
        self.dbstore.certificate_add(data_dic)
        self.assertEqual({'name': u'certname1', 'order__account__name': u'name1'}, self.dbstore.certificate_lookup('name', 'certname1', ('name', 'order__account__name')))

    def test_077_certificate_lookup(self):
        """ test DBstore.certificate_lookup() method with modified output  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname1', 'cert': 'cert', 'cert_raw': 'cert_raw'}
        self.dbstore.certificate_add(data_dic)
        self.assertFalse(self.dbstore.certificate_lookup('name', 'certname', ('name', 'order__account__name')))

    def test_078_certificate_account_check(self):
        """ test DBstore.certificate_account_check() successful """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name1', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name1'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname1', 'cert': 'cert', 'cert_raw': 'cert_raw'}
        self.dbstore.certificate_add(data_dic)
        self.assertEqual('name1', self.dbstore.certificate_account_check('name1', 'cert_raw'))

    def test_079_certificate_account_check(self):
        """ test DBstore.certificate_account_check() cert lookup failed """
        self.assertFalse(self.dbstore.certificate_account_check('name1', 'cert_failed'))

    def test_080_certificate_account_check(self):
        """ test DBstore.certificate_account_check() cert lookup failed """
        self.assertFalse(self.dbstore.certificate_account_check('name1', 'cert_failed'))

    @patch('examples.db_handler.wsgi_handler.DBstore.order_lookup')
    @patch('examples.db_handler.wsgi_handler.DBstore.certificate_lookup')
    def test_081_certificate_account_check(self, mock_certlookup, mock_orderlookup):
        """ test DBstore.certificate_account_check() order lookup failed """
        mock_certlookup.return_value = {'order__name': 'foo'}
        mock_orderlookup.return_value = {}
        self.assertFalse(self.dbstore.certificate_account_check('name1', 'cert_failed'))

    @patch('examples.db_handler.wsgi_handler.DBstore.order_lookup')
    @patch('examples.db_handler.wsgi_handler.DBstore.certificate_lookup')
    def test_082_certificate_account_check(self, mock_certlookup, mock_orderlookup):
        """ test DBstore.certificate_account_check() order lookup return different account_name"""
        mock_certlookup.return_value = {'order__name': 'foo'}
        mock_orderlookup.return_value = {'account__name': 'xxx'}
        self.assertFalse(self.dbstore.certificate_account_check('name1', 'cert_failed'))

    @patch('examples.db_handler.wsgi_handler.DBstore.order_lookup')
    @patch('examples.db_handler.wsgi_handler.DBstore.certificate_lookup')
    def test_083_certificate_account_check(self, mock_certlookup, mock_orderlookup):
        """ test DBstore.certificate_account_check() order lookup retured same account_name"""
        mock_certlookup.return_value = {'order__name': 'foo'}
        mock_orderlookup.return_value = {'account__name': 'name1'}
        self.assertEqual('foo', self.dbstore.certificate_account_check('name1', 'cert_failed'))

    @patch('examples.db_handler.wsgi_handler.DBstore.order_lookup')
    @patch('examples.db_handler.wsgi_handler.DBstore.certificate_lookup')
    def test_084_certificate_account_check(self, mock_certlookup, mock_orderlookup):
        """ test DBstore.certificate_account_check() order lookup retured same account_name"""
        mock_certlookup.return_value = {'order__name': 'foo1'}
        mock_orderlookup.return_value = {'account__name': 'name1'}
        self.assertEqual('foo1', self.dbstore.certificate_account_check(None, 'cert_failed'))

    @patch('examples.db_handler.wsgi_handler.DBstore.order_lookup')
    @patch('examples.db_handler.wsgi_handler.DBstore.certificate_lookup')
    def test_085_certificate_account_check(self, mock_certlookup, mock_orderlookup):
        """ test DBstore.certificate_account_check() order lookup retured no account__name """
        mock_certlookup.return_value = {'order__name': 'foo1'}
        mock_orderlookup.return_value = {'foo': 'name1'}
        self.assertFalse(self.dbstore.certificate_account_check(None, 'cert_failed'))

    def test_086_initialize(self):
        """ test initialize function """
        self.assertEqual(None, self.initialize())

    @patch('examples.db_handler.wsgi_handler.datestr_to_date')
    def test_087_account_update(self, mock_datestr):
        """ test account update all ok """
        mock_datestr.return_value = 'datestr'
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.assertEqual(('name2', True), self.dbstore.account_add(data_dic))
        update_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact20', 'name' : 'name2'}
        self.assertEqual(2, self.dbstore.account_update(update_dic))
        result = {'id': 2, 'name': 'name2', 'alg': 'alg2', 'contact': 'contact20', 'created_at': 'datestr', 'eab_kid': '', 'jwk': 'jwk2'}
        self.assertEqual(result, self.dbstore.account_lookup('name', 'name2'))

    @patch('examples.db_handler.wsgi_handler.datestr_to_date')
    def test_088_account_update(self, mock_datestr):
        """ test account update without alg """
        mock_datestr.return_value = 'datestr'
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact20', 'name' : 'name2'}
        self.assertEqual(('name2', True), self.dbstore.account_add(data_dic))
        update_dic = {'jwk' : 'jwk2', 'contact' : 'contact20', 'name' : 'name2'}
        self.assertEqual(2, self.dbstore.account_update(update_dic))
        result = {'id': 2, 'name': 'name2', 'alg': 'alg2', 'contact': 'contact20', 'created_at': 'datestr', 'eab_kid': '', 'jwk': 'jwk2'}
        self.assertEqual(result, self.dbstore.account_lookup('name', 'name2'))

    @patch('examples.db_handler.wsgi_handler.datestr_to_date')
    def test_089_account_update(self, mock_datestr):
        """ test account update without jwk """
        mock_datestr.return_value = 'datestr'
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact21', 'name' : 'name2'}
        self.assertEqual(('name2', True), self.dbstore.account_add(data_dic))
        update_dic = {'alg' : 'alg2', 'contact' : 'contact20', 'name' : 'name2'}
        self.assertEqual(2, self.dbstore.account_update(update_dic))
        result = {'id': 2, 'name': 'name2', 'alg': 'alg2', 'contact': 'contact20', 'created_at': 'datestr', 'eab_kid': '', 'jwk': 'jwk2'}
        self.assertEqual(result, self.dbstore.account_lookup('name', 'name2'))

    @patch('examples.db_handler.wsgi_handler.datestr_to_date')
    def test_090_account_update(self, mock_datestr):
        """ test account update without jwk """
        mock_datestr.return_value = 'datestr'
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2'}
        self.assertEqual(('name2', True), self.dbstore.account_add(data_dic))
        update_dic = {'alg' : 'alg2', 'jwk' : 'jwk20', 'name' : 'name2'}
        self.assertEqual(2, self.dbstore.account_update(update_dic))
        result = {'id': 2, 'name': 'name2', 'alg': 'alg2', 'contact': 'contact2', 'created_at': 'datestr', 'eab_kid': '', 'jwk': 'jwk20'}
        self.assertEqual(result, self.dbstore.account_lookup('name', 'name2'))

    @patch('examples.db_handler.wsgi_handler.datestr_to_date')
    def test_091_account_update(self, mock_datestr):
        """ test account update without eab_kid but eab_kid inserted in account_add() """
        mock_datestr.return_value = 'datestr'
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'name' : 'name2', 'eab_kid': 'eab_kid'}
        self.assertEqual(('name2', True), self.dbstore.account_add(data_dic))
        update_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact20', 'name' : 'name2'}
        self.assertEqual(2, self.dbstore.account_update(update_dic))
        result = {'id': 2, 'name': 'name2', 'alg': 'alg2', 'contact': 'contact20', 'created_at': 'datestr', 'eab_kid': 'eab_kid', 'jwk': 'jwk2'}
        self.assertEqual(result, self.dbstore.account_lookup('name', 'name2'))

    def test_092_account_update(self):
        """ test account update - account.search() did not return anything """
        update_dic = {'alg' : 'alg2', 'jwk' : 'jwk2', 'contact' : 'contact20', 'name' : 'name2'}
        self.assertFalse(self.dbstore.account_update(update_dic))

    def test_093_accountlist_get(self):
        """ test DBstore.accountlist_get """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value1', 'mtype1', data_dic)
        data_dic = {'name' : 'challenge2', 'token' : 'token2', 'authorization': 'name1', 'expires' : 25, 'type' : 'type2'}
        self.dbstore.challenge_add('value2', 'mtype2', data_dic)
        vlist = ['id', 'name', 'eab_kid', 'contact', 'created_at', 'jwk', 'alg', 'order__id', 'order__name', 'order__status__id', 'order__status__name', 'order__notbefore', 'order__notafter', 'order__expires', 'order__identifiers', 'order__authorization__id', 'order__authorization__name', 'order__authorization__type', 'order__authorization__value', 'order__authorization__expires', 'order__authorization__token', 'order__authorization__created_at', 'order__authorization__status__id', 'order__authorization__status__name', 'order__authorization__challenge__id', 'order__authorization__challenge__name', 'order__authorization__challenge__token', 'order__authorization__challenge__expires', 'order__authorization__challenge__type', 'order__authorization__challenge__keyauthorization', 'order__authorization__challenge__created_at', 'order__authorization__challenge__status__id', 'order__authorization__challenge__status__name']
        account_list = {'id': 1, 'name': 'name1', 'eab_kid': '', 'contact': 'contact1', 'jwk': '{"key11": "val11", "key12": "val12"}', 'alg': 'alg1', 'order__id': 1, 'order__name': 'name', 'order__status__id': 1, 'order__status__name': 'invalid', 'order__notbefore': '', 'order__notafter': '', 'order__expires': 25, 'order__identifiers': 'identifiers', 'order__authorization__id': 1, 'order__authorization__name': 'name1', 'order__authorization__type': 'type1', 'order__authorization__value': 'value1', 'order__authorization__expires': None, 'order__authorization__token': None, 'order__authorization__status__id': 2, 'order__authorization__status__name': 'pending', 'order__authorization__challenge__id': 1, 'order__authorization__challenge__name': 'challenge1', 'order__authorization__challenge__token': 'token1', 'order__authorization__challenge__expires': 25, 'order__authorization__challenge__type': 'type1', 'order__authorization__challenge__keyauthorization': None, 'order__authorization__challenge__status__id': 2, 'order__authorization__challenge__status__name': 'pending'}
        (result_vlist, result_account_list) = self.dbstore.accountlist_get()
        self.assertEqual(vlist, result_vlist)
        self.assertTrue(set(account_list.items()).issubset( set(result_account_list[0].items())))

    def test_094_authorizations_expired_search(self):
        """ test DBstore.authorizations_expired_search() """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        result = {'id': 1, 'name': 'name1', 'expires': None, 'value': 'value1', 'token': None, 'status__id': 2, 'status__name': 'pending', 'order__id': 1, 'order__name': 'name'}
        result_list = self.dbstore.authorizations_expired_search('name', 'name1')
        self.assertTrue(set(result.items()).issubset( set(result_list[0].items())))

    def test_095_certificate_delete(self):
        """ test DBstore.certificate_delete() method (succesful) """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name'}
        self.dbstore.certificate_add(data_dic)
        result = {'name': 'certname1', 'csr': 'csr1',  'order': 'name', 'order__name': 'name', 'cert': None}
        self.assertEqual(result, self.dbstore.certificate_lookup('name', 'certname1'))
        self.dbstore.certificate_delete('name', 'certname1')
        self.assertFalse(self.dbstore.certificate_lookup('name', 'certname1'))

    def test_096_certificatelist_get(self):
        """ test DBstore.certificatelist_get() """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname1', 'cert': 'cert', 'cert_raw': 'cert_raw'}
        self.assertEqual(1, self.dbstore.certificate_add(data_dic))
        vlist = ['id', 'name', 'cert_raw', 'csr', 'poll_identifier', 'created_at', 'issue_uts', 'expire_uts', 'order__id', 'order__name', 'order__status__name', 'order__notbefore', 'order__notafter', 'order__expires', 'order__identifiers', 'order__account__name', 'order__account__contact', 'order__account__created_at', 'order__account__jwk', 'order__account__alg', 'order__account__eab_kid']
        certlist = {'id': 1, 'name': 'certname1', 'cert_raw': 'cert_raw', 'csr': 'csr1', 'poll_identifier': None, 'issue_uts': 0, 'expire_uts': 0, 'order__id': 1, 'order__name': 'name', 'order__status__name': 1, 'order__notbefore': '', 'order__notafter': '', 'order__expires': 25, 'order__identifiers': 'identifiers', 'order__account__name': 'name1', 'order__account__contact': 'contact1', 'order__account__jwk': '{"key11": "val11", "key12": "val12"}', 'order__account__alg': 'alg1', 'order__account__eab_kid': ''}
        (result_vlist, result_certifcate_list) = self.dbstore.certificatelist_get()
        self.assertEqual(vlist, result_vlist)
        self.assertTrue(set(certlist.items()).issubset( set(result_certifcate_list[0].items())))

    def test_097_dbversion(self):
        """ test db_version """
        self.assertEqual((self.dbversion, 'tools/db_update.py'), self.dbstore.dbversion_get())

    @patch('examples.db_handler.wsgi_handler.DBstore._db_close')
    @patch('examples.db_handler.wsgi_handler.DBstore._db_open')
    def test_098_dbversion(self, mock_open, mock_close):
        """ test db_version no result """
        self.dbstore.cursor = Mock()
        self.dbstore.cursor.fetchone = Mock(return_value=[])
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'tools/db_update.py'), self.dbstore.dbversion_get())
        self.assertIn('ERROR:test_a2c:DBStore.dbversion_get() lookup failed', lcm.output)

    def test_099_certificates_search(self):
        """ test DBstore.certificates_search() """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname1', 'cert': 'cert', 'cert_raw': 'cert_raw'}
        self.dbstore.certificate_add(data_dic)
        self.assertEqual([{'name': 'certname1', 'csr': 'csr1', 'cert': 'cert', 'order__name': 'name', 'order': 'name'}], self.dbstore.certificates_search('cert', 'cert'))
        self.assertEqual([{'name': 'certname1', 'csr': 'csr1', 'cert': 'cert', 'order__name': 'name', 'order': 'name'}], self.dbstore.certificates_search('cert_raw', 'cert_raw'))
        self.assertEqual([{'name': 'certname1', 'csr': 'csr1', 'cert': 'cert', 'order__name': 'name', 'order': 'name'}], self.dbstore.certificates_search('certificate.name', 'certname1'))
        self.assertEqual([{'cert': 'cert', 'name': 'certname1'}], self.dbstore.certificates_search('certificate.name', 'certname1', vlist=['name', 'cert']))

    def test_100_certificates_search(self):
        """ test DBstore.certificates_search() no result"""
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname1', 'cert': 'cert', 'cert_raw': 'cert_raw'}
        self.dbstore.certificate_add(data_dic)
        self.assertFalse(self.dbstore.certificates_search('cert', 'cert1'))

    def test_101_certificates_search(self):
        """ test DBstore.certificates_search() rewrite order_status_id """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name': 'certname1', 'csr': 'csr1', 'order': 'name'}
        self.dbstore.certificate_add(data_dic)
        data_dic = {'name': 'certname1', 'cert': 'cert', 'cert_raw': 'cert_raw'}
        self.dbstore.certificate_add(data_dic)
        self.assertEqual([{'name': 'certname1', 'csr': 'csr1', 'cert': 'cert', 'order__name': 'name', 'order': 'name'}], self.dbstore.certificates_search('order__status_id', 1))

    def test_102_challenge_search(self):
        """ test DBstore.challenge_search method  """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        result = [{'name': 'challenge1', 'status': 'pending', 'status__name': 'pending', 'token': 'token1', 'type': 'type1'}]
        self.assertEqual(result, self.dbstore.challenges_search('challenge.name', 'challenge1'))
        self.assertEqual(result, self.dbstore.challenges_search('challenge.token', 'token1'))
        self.assertEqual(result, self.dbstore.challenges_search('status__name', 'pending'))
        self.assertEqual([{'name': 'challenge1', 'token': 'token1'}], self.dbstore.challenges_search('status__name', 'pending', vlist=['name', 'token']))

    def test_103_challenge_search(self):
        """ test DBstore.challenge_search failed """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name' : 'name', 'identifiers' : 'identifiers', 'account' : 'name1', 'status' : 1, 'expires' : '25'}
        self.dbstore.order_add(data_dic)
        data_dic = {'name' : 'name1', 'type' : 'type1', 'value': 'value1', 'order' : 1}
        self.dbstore.authorization_add(data_dic)
        data_dic = {'name' : 'challenge1', 'token' : 'token1', 'authorization': 'name1', 'expires' : 25, 'type' : 'type1'}
        self.dbstore.challenge_add('value', 'mtype', data_dic)
        self.assertFalse(self.dbstore.challenges_search('challenge.name', 'challenge'))

    @patch('examples.db_handler.wsgi_handler.DBstore._db_close')
    @patch('examples.db_handler.wsgi_handler.DBstore._db_open')
    def test_104_db_update(self, mock_open, mock_close):
        """ test dbupdate - not alter certificates table """
        self.dbstore.cursor = Mock()
        self.dbstore.cursor.fetchall = Mock(return_value=[[2, 'poll_identifier'], [2, 'issue_uts'], [2, 'expire_uts']])
        self.dbstore.cursor.fetchone = Mock(return_value=[1, 2, 3, 4, 5])
        mock_open.return_value = Mock()
        mock_close.return_value = Mock()
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertTrue = self.dbstore.db_update()
        self.assertIn('INFO:test_a2c:alter challenge table - add validated', lcm.output)
        self.assertIn('INFO:test_a2c:alter account table - add eab_kid', lcm.output)
        self.assertIn('INFO:test_a2c:alter account table - add eab_kid', lcm.output)

    @patch('examples.db_handler.wsgi_handler.DBstore._db_close')
    @patch('examples.db_handler.wsgi_handler.DBstore._db_open')
    def test_105_db_update(self, mock_open, mock_close):
        """ test dbupdate - not alter challenge table """
        self.dbstore.cursor = Mock()
        self.dbstore.cursor.fetchall = Mock(return_value=[[2, 'validated']])
        self.dbstore.cursor.fetchone = Mock(return_value=[1, 2, 3, 4, 5])
        mock_open.return_value = Mock()
        mock_close.return_value = Mock()
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertTrue = self.dbstore.db_update()
        self.assertIn('INFO:test_a2c:alter certificate table - add poll_identifier', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add issue_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add expire_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter account table - add eab_kid', lcm.output)

    @patch('examples.db_handler.wsgi_handler.DBstore._db_close')
    @patch('examples.db_handler.wsgi_handler.DBstore._db_open')
    def test_106_db_update(self, mock_open, mock_close):
        """ test dbupdate - not alter account table """
        self.dbstore.cursor = Mock()
        self.dbstore.cursor.fetchall = Mock(return_value=[[2, 'eab_kid']])
        self.dbstore.cursor.fetchone = Mock(return_value=[1, 2, 3, 4, 5])
        mock_open.return_value = Mock()
        mock_close.return_value = Mock()
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertTrue = self.dbstore.db_update()
        self.assertIn('INFO:test_a2c:alter certificate table - add poll_identifier', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add issue_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add expire_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter challenge table - add validated', lcm.output)

    @patch('examples.db_handler.wsgi_handler.DBstore._db_close')
    @patch('examples.db_handler.wsgi_handler.DBstore._db_open')
    def test_107_db_update(self, mock_open, mock_close):
        """ test dbupdate - status update """
        self.dbstore.cursor = Mock()
        self.dbstore.cursor.fetchall = Mock(return_value=[[2, 'foo']])
        self.dbstore.cursor.fetchone = Mock(side_effect=[None, [1, 2, 3, 4, 5], [1, 2], [0,2]])
        mock_open.return_value = Mock()
        mock_close.return_value = Mock()
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.dbstore.db_update()
        self.assertIn('INFO:test_a2c:alter certificate table - add poll_identifier', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add issue_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add expire_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter challenge table - add validated', lcm.output)
        self.assertIn('INFO:test_a2c:alter account table - add eab_kid', lcm.output)
        self.assertIn('INFO:test_a2c:adding additional status', lcm.output)
        self.assertIn('INFO:test_a2c:create cliaccount table', lcm.output)

    @patch('examples.db_handler.wsgi_handler.DBstore._db_close')
    @patch('examples.db_handler.wsgi_handler.DBstore._db_open')
    def test_108_db_update(self, mock_open, mock_close):
        """ test dbupdate - housekeeping update """
        self.dbstore.cursor = Mock()
        self.dbstore.cursor.fetchall = Mock(return_value=[[2, 'foo']])
        self.dbstore.cursor.fetchone = Mock(side_effect=[None, [2, 2, 3, 4, 5], [1, 2], [1,2]])
        mock_open.return_value = Mock()
        mock_close.return_value = Mock()
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.dbstore.db_update()
        self.assertIn('INFO:test_a2c:alter certificate table - add poll_identifier', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add issue_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add expire_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter challenge table - add validated', lcm.output)
        self.assertIn('INFO:test_a2c:alter account table - add eab_kid', lcm.output)
        self.assertIn('INFO:test_a2c:adding additional status', lcm.output)
        self.assertIn('INFO:test_a2c:alter account table - add eab_kid', lcm.output)
        self.assertIn('INFO:test_a2c:create housekeeping table and trigger', lcm.output)


    @patch('examples.db_handler.wsgi_handler.DBstore._db_close')
    @patch('examples.db_handler.wsgi_handler.DBstore._db_open')
    def test_109_db_update(self, mock_open, mock_close):
        """ test dbupdate -  update """
        self.dbstore.cursor = Mock()
        self.dbstore.cursor.fetchall = Mock(return_value=[[2, 'foo']])
        self.dbstore.cursor.fetchone = Mock(side_effect=[None, [1, 2, 3, 4, 5], [2, 2], [2, 2]])
        mock_open.return_value = Mock()
        mock_close.return_value = Mock()
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.dbstore.db_update()
        self.assertIn('INFO:test_a2c:alter certificate table - add poll_identifier', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add issue_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter certificate table - add expire_uts', lcm.output)
        self.assertIn('INFO:test_a2c:alter challenge table - add validated', lcm.output)
        self.assertIn('INFO:test_a2c:alter account table - add eab_kid', lcm.output)
        self.assertIn('INFO:test_a2c:adding additional status', lcm.output)
        self.assertIn('INFO:test_a2c:alter account table - add eab_kid', lcm.output)
        self.assertIn('INFO:test_a2c:create cahandler table', lcm.output)
        self.assertIn('INFO:test_a2c:create cliaccount table', lcm.output)

    def test_110_order_update(self):
        """ test DBstore.order_add() method for a new entry """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name': 'name', 'identifiers': 'identifiers', 'account': 'name1', 'status': 1, 'expires': '25'}
        self.assertEqual(1, self.dbstore.order_add(data_dic))
        update_dic = {'name': 'name', 'status': 'valid'}
        self.dbstore.order_update(update_dic)
        result = {'expires': 25, 'notbefore': 0, 'notafter': 0, 'identifiers': 'identifiers', 'status': 'valid'}
        self.assertEqual(result, self.dbstore.order_lookup('name', 'name'))

    def test_111_order_update(self):
        """ test DBstore.order_add() method for a new entry """
        data_dic = {'alg' : 'alg1', 'jwk' : '{"key11": "val11", "key12": "val12"}', 'contact' : 'contact1', 'name' : 'name1'}
        self.dbstore.account_add(data_dic)
        data_dic = {'name': 'name1', 'identifiers': 'identifiers2', 'account': 'name1', 'status': 1, 'expires': '25'}
        self.assertEqual(1, self.dbstore.order_add(data_dic))
        data_dic = {'name': 'name2', 'identifiers': 'identifiers2', 'account': 'name1', 'status': 2, 'expires': '25'}
        self.assertEqual(2, self.dbstore.order_add(data_dic))
        expected_result = {'account__contact': 'contact1', 'account__id': 1, 'account__name': 'name1', 'expires': 25, 'id': 2, 'identifiers': 'identifiers2', 'name': 'name2', 'status__id': 2, 'status__name': 'pending'}
        order_list = self.dbstore.orders_invalid_search('name', 'name2')
        self.assertTrue(set(expected_result.items()).issubset( set(order_list[0].items())))

    @patch('examples.db_handler.wsgi_handler.DBstore._db_create')
    @patch('examples.db_handler.wsgi_handler.load_config')
    def test_112__init__(self, mock_cfg, mock_create):
        """ test init no dbfile specifiction """
        self.dbstore.db_name = None
        mock_create.return_value = True
        self.dbstore.__init__()
        self.assertTrue(mock_cfg.called)
        self.assertIn('acme_srv.db', self.dbstore.db_name)

    @patch('examples.db_handler.wsgi_handler.DBstore._db_create')
    @patch('examples.db_handler.wsgi_handler.load_config')
    def test_113__init__(self, mock_cfg, mock_create):
        """ test init no dbfile specifiction """
        self.dbstore.db_name = None
        mock_create.return_value = True
        mock_cfg.return_value = {'FOO': {'foo': 'bar'}}
        self.dbstore.__init__()
        self.assertTrue(mock_cfg.called)
        self.assertIn('acme_srv.db', self.dbstore.db_name)

    @patch('examples.db_handler.wsgi_handler.DBstore._db_create')
    @patch('examples.db_handler.wsgi_handler.load_config')
    def test_114__init__(self, mock_cfg, mock_create):
        """ test init DBhandler but no dbfile specifiction """
        self.dbstore.db_name = None
        mock_create.return_value = True
        mock_cfg.return_value = {'DBhandler': {'foo': 'bar'}}
        self.dbstore.__init__()
        self.assertTrue(mock_cfg.called)
        self.assertIn('acme_srv.db', self.dbstore.db_name)

    @patch('examples.db_handler.wsgi_handler.DBstore._db_create')
    @patch('examples.db_handler.wsgi_handler.load_config')
    def test_115__init__(self, mock_cfg, mock_create):
        """ test init DBhandler but no dbfile specifiction """
        self.dbstore.db_name = None
        mock_create.return_value = True
        mock_cfg.return_value = {'DBhandler': {'dbfile': 'foo.db'}}
        self.dbstore.__init__()
        self.assertTrue(mock_cfg.called)
        self.assertIn('foo.db', self.dbstore.db_name)

    def test_116_cahandler_add(self):
        """ test DBstore.cahandler_add() method for a new entry  """
        data_dic = {'name' : 'name1', 'value1' : 'value1'}
        self.assertEqual(1, self.dbstore.cahandler_add(data_dic))
        data_dic = {'name' : 'name2', 'value1' : 'value1', 'value2' : 'value2'}
        self.assertEqual(2, self.dbstore.cahandler_add(data_dic))

    def test_117_cahandler_add(self):
        """ test DBstore.cahandler_add() method for an existing entry  """
        data_dic = {'name' : 'name1', 'value1' : 'value1'}
        self.assertEqual(1, self.dbstore.cahandler_add(data_dic))
        data_dic = {'name' : 'name1', 'value1' : 'value1', 'value2' : 'value2'}
        self.assertEqual(1, self.dbstore.cahandler_add(data_dic))

    def test_118_cahandler_lookup(self):
        """ test DBstore.cahandler_lookup() method  """
        data_dic = {'name' : 'name1', 'value1' : 'value1'}
        self.assertEqual(1, self.dbstore.cahandler_add(data_dic))
        result = {'name': 'name1', 'value1': 'value1', 'value2': ''}
        self.assertEqual(result, self.dbstore.cahandler_lookup('name', 'name1', ('name', 'value1', 'value2')))

    def test_119_cahandler_search(self):
        """ test DBstore.cahandler_lookup() method  """
        data_dic = {'name' : 'name1', 'value1' : 'value1'}
        self.assertEqual(1, self.dbstore.cahandler_add(data_dic))
        result = {'name': 'name1', 'value1': 'value1', 'value2': ''}
        self.assertIn(('name1'), self.dbstore._cahandler_search('name', 'name1'))

    @patch('examples.db_handler.wsgi_handler.DBstore._db_close')
    @patch('examples.db_handler.wsgi_handler.DBstore._db_open')
    def test_120_cahandler_search(self, mock_open, mock_close):
        """ test DBstore.cahandler_lookup() triggers exception  """
        self.dbstore.cursor = Mock()
        self.dbstore.cursor.fetchone =Exception('foo')
        mock_open.return_value = Mock()
        mock_close.return_value = Mock()
        result = {'name': 'name1', 'value1': 'value1', 'value2': ''}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.dbstore._cahandler_search('name', 'name1'))
        self.assertIn("ERROR:test_a2c:DBStore._cahandler_search(column:name, pattern:name1) failed with err: 'Exception' object is not callable", lcm.output)

    def test_121_hkparameter_add(self):
        """ test DBstore.hkparameter_add() method for a new entry  """
        data_dic = {'name': 'name1', 'value' : 'value1'}
        self.assertEqual(('name1', True), self.dbstore.hkparameter_add(data_dic))
        data_dic = {'name': 'name2', 'value' : 'value2'}
        self.assertEqual(('name2', True), self.dbstore.hkparameter_add(data_dic))

    def test_122_hkparameter_add(self):
        """ test DBstore.hkparameter_add() method for an existing entry  """
        data_dic = {'name': 'name1', 'value' : 'value1'}
        self.assertEqual(('name1', True), self.dbstore.hkparameter_add(data_dic))
        data_dic = {'name': 'name1', 'value' : 'value2'}
        self.assertEqual(('name1', False), self.dbstore.hkparameter_add(data_dic))

    def test_123_hkparameter_get(self):
        """ test DBstore.hkparameter_add() method for a new entry  """
        data_dic = {'name' : 'name1', 'value' : 'value1'}
        self.assertEqual(('name1', True), self.dbstore.hkparameter_add(data_dic))
        self.assertEqual('value1', self.dbstore.hkparameter_get('name1'))

    def test_124_cliaccount_add(self):
        """ test DBstore.cliaccount_add() method for an new entry"""
        data_dic = {'name' : 'name1', 'jwk' : 'jwk1', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        data_dic = {'name' : 'name2', 'jwk' : 'jwk2', 'contact' : 'contact2', 'cliadmin': False, 'certificateadmin': False, 'reportadmin': False}
        self.assertEqual(2, self.dbstore.cliaccount_add(data_dic))
        cli_account_list = self.dbstore.cliaccountlist_get()
        result1 = {'id': 1, 'name': 'name1', 'jwk': 'jwk1', 'contact': 'contact1', 'cliadmin': 1, 'reportadmin': 1, 'certificateadmin': 1}
        result2 = {'id': 2, 'name': 'name2', 'jwk': 'jwk2', 'contact': 'contact2', 'cliadmin': 0, 'reportadmin': 0, 'certificateadmin': 0}
        self.assertTrue(set(result1.items()).issubset( set(cli_account_list[0].items())))
        self.assertTrue(set(result2.items()).issubset( set(cli_account_list[1].items())))

    def test_125_cliaccount_add(self):
        """ test DBstore.cliaccount_add() update jwk """
        data_dic = {'name' : 'name1', 'jwk' : 'jwk1', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        data_dic = {'name' : 'name1', 'jwk' : 'jwk2', 'cliadmin': False, 'certificateadmin': False, 'reportadmin': False}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        result = {'id': 1, 'name': 'name1', 'jwk': 'jwk2', 'contact': 'contact1', 'cliadmin': 0, 'reportadmin': 0, 'certificateadmin': 0}
        cli_account_list = self.dbstore.cliaccountlist_get()
        self.assertTrue(set(result.items()).issubset( set(cli_account_list[0].items())))

    def test_126_cliaccount_add(self):
        """ test DBstore.cliaccount_add() update contact """
        data_dic = {'name' : 'name1', 'jwk' : 'jwk1', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        data_dic = {'name' : 'name1', 'contact' : 'contact2', 'cliadmin': False, 'certificateadmin': False, 'reportadmin': False}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        result = {'id': 1, 'name': 'name1', 'jwk': 'jwk1', 'contact': 'contact2', 'cliadmin': 0, 'reportadmin': 0, 'certificateadmin': 0}
        cli_account_list = self.dbstore.cliaccountlist_get()
        self.assertTrue(set(result.items()).issubset( set(cli_account_list[0].items())))

    def test_127_cliaccount_delete(self):
        """ test DBstore.cliaccount_delete() sucessful """
        data_dic = {'name' : 'name1', 'jwk' : 'jwk1', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        self.dbstore.cliaccount_delete({'name': 'name1'})
        self.assertFalse(self.dbstore.cliaccountlist_get())

    def test_128_cliaccount_delete(self):
        """ test DBstore.cliaccount_delete() sucessful """
        data_dic = {'name' : 'name1', 'jwk' : 'jwk1', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.dbstore.cliaccount_delete({'name': 'name2'})
        self.assertIn('ERROR:test_a2c:DBStore.cliaccount_delete() failed for kid: name2', lcm.output)
        cli_account_list = self.dbstore.cliaccountlist_get()
        result = {'id': 1, 'name': 'name1', 'jwk': 'jwk1', 'contact': 'contact1', 'cliadmin': 1, 'reportadmin': 1, 'certificateadmin': 1}
        self.assertTrue(set(result.items()).issubset( set(cli_account_list[0].items())))

    def test_129_cli_jwk_load(self):
        """ test cli_jwk_load for an existing entry """
        data_dic = {'name' : 'name1', 'jwk' : '{"foo": "bar"}', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        self.assertEqual({"foo": "bar"}, self.dbstore.cli_jwk_load('name1'))

    def test_130_cli_jwk_load(self):
        """ test cli_jwk_load for a not existing entry """
        data_dic = {'name' : 'name1', 'jwk' : '{"foo": "bar"}', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        self.assertFalse(self.dbstore.cli_jwk_load('name2'))

    def test_131_cli_permissions_get(self):
        """ test cli_jwk_load for an existing entry """
        data_dic = {'name' : 'name1', 'jwk' : '{"foo": "bar"}', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        self.assertEqual({'cliadmin': 1, 'reportadmin': 1, 'certificateadmin': 1}, self.dbstore.cli_permissions_get('name1'))

    def test_132_cli_permissions_get(self):
        """ test cli_jwk_load for a not existing entry """
        data_dic = {'name' : 'name1', 'jwk' : '{"foo": "bar"}', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        self.assertFalse(self.dbstore.cli_permissions_get('name2'))

    def test_133__cliaccount_search(self):
        """ test cliaccount_search exception """
        data_dic = {'name' : 'name1', 'jwk' : 'jwk', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        self.assertEqual(1, self.dbstore.cliaccount_add(data_dic))
        result = {'name' : 'name1', 'jwk' : 'jwk', 'contact' : 'contact1', 'cliadmin': True, 'certificateadmin': True, 'reportadmin': True}
        cli_account_list = self.dbstore._cliaccount_search('name', 'name1')
        self.assertTrue(set(result.items()).issubset( set(dict(cli_account_list).items())))

    @patch('examples.db_handler.wsgi_handler.DBstore._db_close')
    @patch('examples.db_handler.wsgi_handler.DBstore._db_open')
    def test_134__cliaccount_search(self, mock_open, mock_close):
        self.dbstore.cursor = Mock()
        self.dbstore.cursor.fetchone =Exception('foo')
        mock_open.return_value = Mock()
        mock_close.return_value = Mock()
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.dbstore._cliaccount_search('name', 'name2'))
        self.assertIn("ERROR:test_a2c:DBStore._cliaccount_search(column:name, pattern:name2) failed with err: 'Exception' object is not callable", lcm.output)

if __name__ == '__main__':

    unittest.main()
