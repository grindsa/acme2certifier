#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import importlib
import configparser
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
        from acme_srv.authorization import Authorization
        from acme_srv.challenge import Challenge
        from acme_srv.order import Order
        from acme_srv.signature import Signature
        self.authorization = Authorization(False, 'http://tester.local', self.logger)
        self.challenge = Challenge(False, 'http://tester.local', self.logger)
        self.order = Order(False, 'http://tester.local', self.logger)
        self.signature = Signature(False, 'http://tester.local', self.logger)

    @patch('acme_srv.order.uts_now')
    @patch('acme_srv.order.generate_random_string')
    def test_001_order__add(self, mock_name, mock_uts):
        """ test Oder.add() without identifier in payload """
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        message = {}
        e_result = ('urn:ietf:params:acme:error:unsupportedIdentifier', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme_srv.order.uts_now')
    @patch('acme_srv.order.generate_random_string')
    def test_002_order__add(self, mock_name, mock_uts):
        """ test Oder.add() with empty identifier in payload dbstore-add returns None"""
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        self.signature.dbstore.order_add.return_value = False
        message = {'identifiers' : {}}
        e_result = ('urn:ietf:params:acme:error:malformed', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme_srv.order.uts_now')
    @patch('acme_srv.order.generate_random_string')
    def test_003_order__add(self, mock_name, mock_uts):
        """ test Oder.add() with single identifier in payload dbstore-add returns something real"""
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        self.order.dbstore.order_add.return_value = 1
        self.order.dbstore.authorization_add.return_value = True
        message = {'identifiers' : [{"type": "dns", "value": "example.com"}]}
        e_result = (None, 'aaaaa', {'aaaaa': {'type': 'dns', 'value': 'example.com'}}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme_srv.order.uts_now')
    @patch('acme_srv.order.generate_random_string')
    def test_004_order__add(self, mock_name, mock_uts):
        """ test Oder.add() with multiple identifier in payload dbstore-add returns something real"""
        mock_name.side_effect = ['order', 'identifier1', 'identifier2']
        mock_uts.return_value = 1543640400
        self.order.dbstore.order_add.return_value = 1
        self.order.dbstore.authorization_add.return_value = True
        message = {'identifiers' : [{"type": "dns", "value": "example1.com"}, {"type": "dns", "value": "example2.com"}]}
        e_result = (None, 'order', {'identifier1': {'type': 'dns', 'value': 'example1.com'}, 'identifier2': {'type': 'dns', 'value': 'example2.com'}}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme_srv.message.Message.check')
    def test_005_order_new(self, mock_mcheck):
        """ Order.new() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'type': 'message', 'status': 400}}, self.order.new(message))

    @patch('acme_srv.order.Order._add')
    @patch('acme_srv.message.Message.check')
    def test_006_order_new(self, mock_mcheck, mock_orderadd):
        """ Order.new() failed bcs of db_add failed """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = ('urn:ietf:params:acme:error:malformed', None, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'type': 'urn:ietf:params:acme:error:malformed', 'detail': 'could not process order'}}, self.order.new(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.order.Order._add')
    @patch('acme_srv.message.Message.check')
    def test_007_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order with a single identifier """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = (None, 'foo_order', {'foo_auth': {u'type': u'dns', u'value': u'acme_srv.nclm-samba.local'}}, 'expires')
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{u'type': u'dns', u'value': u'acme_srv.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.order.Order._add')
    @patch('acme_srv.message.Message.check')
    def test_008_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order with multiple identifiers """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = (None, 'foo_order', {'foo_auth1': {u'type': u'dns', u'value': u'acme1.nclm-samba.local'}, 'foo_auth2': {u'type': u'dns', u'value': u'acme2.nclm-samba.local'}}, 'expires')
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        if sys.version_info[0] < 3:
            self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{'type': 'dns', 'value': 'acme2.nclm-samba.local'}, {'type': 'dns', 'value': 'acme1.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth2', 'http://tester.local/acme/authz/foo_auth1'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))
        else:
            self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{'type': 'dns', 'value': 'acme1.nclm-samba.local'}, {'type': 'dns', 'value': 'acme2.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth1', 'http://tester.local/acme/authz/foo_auth2'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.order.Order._add')
    @patch('acme_srv.message.Message.check')
    def test_009_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order without identifiers """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_nnonce.return_value = 'new_nonce'
        mock_orderadd.return_value = (None, 'foo_order', {}, 'expires')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [], 'authorizations': [], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme_srv.order.Order._info')
    def test_010_order__lookup(self, mock_oinfo):
        """ test order lookup with empty hash """
        mock_oinfo.return_value = {}
        self.assertEqual({}, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_011_order__lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and wrong authorization hash"""
        self.order.dbstore.authorization_lookup.return_value = [{'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': []}, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_012_order__lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and correct authorization hash"""
        self.order.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz/name']}, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_013_order__lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and authorization hash having multiple entries"""
        self.order.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2']}, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_014_order__lookup(self, mock_oinfo):
        """ test order lookup status in dict and authorization dict having multiple entries"""
        self.order.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2']}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_015_order__lookup(self, mock_oinfo):
        """ test order lookup status, expires in dict and authorization dict having multiple entries"""
        self.order.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_016_order__lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore (0) in dict and authorization dict having multiple entries"""
        self.order.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_017_order__lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (0) in dict and authorization dict having multiple entries"""
        self.order.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 0, 'notafter' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_018_order__lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid) in dict and authorization dict having multiple entries"""
        self.order.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_019_order__lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and authorization dict having multiple entries"""
        self.order.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_020_order__lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and worng authorization"""
        self.order.dbstore.authorization_lookup.return_value = 'foo'
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': [], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_021_order__lookup(self, mock_oinfo):
        """ test order lookup correct identifier for oder info"""
        self.order.dbstore.authorization_lookup.return_value = 'foo'
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifiers': '{"foo": "bar"}'}
        e_result = {'status': 'status_value', 'authorizations': [], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z', 'identifiers': {'foo': 'bar'}}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme_srv.order.Order._info')
    def test_022_order__lookup(self, mock_oinfo):
        """ test order lookup incorrect identifier for oder info"""
        self.order.dbstore.authorization_lookup.return_value = 'foo'
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifiers': 'wrongvalue'}
        e_result = {'status': 'status_value', 'authorizations': [], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(e_result, self.order._lookup('foo'))
        self.assertIn('ERROR:test_a2c:Order._order_dic_create(): error while parsing the identifier wrongvalue', lcm.output)

    @patch('acme_srv.order.Order._update')
    @patch('acme_srv.order.Order._info')
    def test_023_order__lookup(self, mock_oinfo, mock_update):
        """ test order lookup correct identifier for oder info status - pending order-update """
        self.order.dbstore.authorization_lookup.return_value = [{'name': 'name', 'status__name': 'valid'}]
        mock_oinfo.return_value = {'status' : 'pending', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifiers': '{"foo": "bar"}'}
        e_result = {'status': 'pending', 'authorizations': ['http://tester.local/acme/authz/name'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z', 'identifiers': {'foo': 'bar'}}
        self.assertEqual(e_result, self.order._lookup('foo'))
        self.assertTrue(mock_update.called)

    @patch('acme_srv.order.Order._update')
    @patch('acme_srv.order.Order._info')
    def test_024_order__lookup(self, mock_oinfo, mock_update):
        """ test order lookup correct identifier for oder info status - pending order-update """
        self.order.dbstore.authorization_lookup.return_value = [{'name': 'name', 'status__name': 'valid'}]
        mock_oinfo.return_value = {'status' : 'notpending', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifiers': '{"foo": "bar"}'}
        e_result = {'status': 'notpending', 'authorizations': ['http://tester.local/acme/authz/name'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z', 'identifiers': {'foo': 'bar'}}
        self.assertEqual(e_result, self.order._lookup('foo'))
        self.assertFalse(mock_update.called)

    @patch('acme_srv.order.Order._update')
    @patch('acme_srv.order.Order._info')
    def test_025_order__lookup(self, mock_oinfo, mock_update):
        """ test order lookup correct identifier for oder info status - invalid statusname """
        self.order.dbstore.authorization_lookup.return_value = [{'name': 'name', 'status__name': 'invalid'}]
        mock_oinfo.return_value = {'status' : 'pending', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifiers': '{"foo": "bar"}'}
        e_result = {'status': 'pending', 'authorizations': ['http://tester.local/acme/authz/name'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z', 'identifiers': {'foo': 'bar'}}
        self.assertEqual(e_result, self.order._lookup('foo'))
        self.assertFalse(mock_update.called)

    @patch('acme_srv.order.Order._info')
    def test_026_order__csr_process(self, mock_oinfo):
        """ test order prcoess_csr with empty order_dic """
        mock_oinfo.return_value = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized', 'order: order_name not found'), self.order._csr_process('order_name', 'csr'))

    @patch('importlib.import_module')
    @patch('acme_srv.certificate.Certificate.store_csr')
    @patch('acme_srv.order.Order._info')
    def test_027_order__csr_process(self, mock_oinfo, mock_certname, mock_import):
        """ test order prcoess_csr with failed csr dbsave"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = None
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'CSR processing failed'), self.order._csr_process('order_name', 'csr'))

    @patch('importlib.import_module')
    @patch('acme_srv.certificate.Certificate.enroll_and_store')
    @patch('acme_srv.certificate.Certificate.store_csr')
    @patch('acme_srv.order.Order._info')
    def test_028_order__csr_process(self, mock_oinfo, mock_certname, mock_enroll, mock_import):
        """ test order prcoess_csr with failed cert enrollment"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = 'foo'
        mock_enroll.return_value = ('error', 'detail')
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual((400, 'error', 'detail'), self.order._csr_process('order_name', 'csr'))

    @patch('importlib.import_module')
    @patch('acme_srv.certificate.Certificate.enroll_and_store')
    @patch('acme_srv.certificate.Certificate.store_csr')
    @patch('acme_srv.order.Order._info')
    def test_029_order__csr_process(self, mock_oinfo, mock_certname, mock_enroll, mock_import):
        """ test order prcoess_csr with successful cert enrollment"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = 'foo'
        mock_enroll.return_value = (None, None)
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual((200, 'foo', None), self.order._csr_process('order_name', 'csr'))

    def test_030_order__name_get(self):
        """ Order.name_get() http"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo'))

    def test_031_order__name_get(self):
        """ Order.name_get() http with further path (finalize)"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo/bar'))

    def test_032_order__name_get(self):
        """ Order.name_get() http with parameters"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo?bar'))

    def test_033_order__name_get(self):
        """ Order.name_get() http with key/value parameters"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo?key=value'))

    def test_034_order__name_get(self):
        """ Order.name_get() https with key/value parameters"""
        self.assertEqual('foo', self.order._name_get('https://tester.local/acme/order/foo?key=value'))

    @patch('acme_srv.message.Message.check')
    def test_035_order_parse(self, mock_mcheck):
        """ Order.parse() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'type': 'message', 'status': 400}}, self.order.parse(message))

    @patch('acme_srv.message.Message.check')
    def test_036_order_parse(self, mock_mcheck):
        """ Order.parse() failed bcs. no url key in protected """
        mock_mcheck.return_value = (200, None, None, {'foo_protected' : 'bar_protected'}, {"foo_payload" : "bar_payload"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'url is missing in protected', 'type': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.order.parse(message))

    @patch('acme_srv.order.Order._name_get')
    @patch('acme_srv.message.Message.check')
    def test_037_order_parse(self, mock_mcheck, mock_oname):
        """ Order.parse() name_get failed """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = None
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'order name is missing', 'type': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.order.parse(message))

    @patch('acme_srv.order.Order._lookup')
    @patch('acme_srv.order.Order._name_get')
    @patch('acme_srv.message.Message.check')
    def test_038_order_parse(self, mock_mcheck, mock_oname, mock_lookup):
        """ Order.parse() failed as order lookup failed """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = None
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 403, 'data': {'detail': 'order not found', 'type': 'urn:ietf:params:acme:error:orderNotReady', 'status': 403}}, self.order.parse(message))

    @patch('acme_srv.order.Order._process')
    @patch('acme_srv.order.Order._lookup')
    @patch('acme_srv.order.Order._name_get')
    @patch('acme_srv.message.Message.check')
    def test_039_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process):
        """ Order.parse() succ, oder process returned non 200 """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = 'foo'
        mock_process.return_value = (400, 'message', 'detail', None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'type': 'message', 'status': 400}}, self.order.parse(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.order.Order._process')
    @patch('acme_srv.order.Order._lookup')
    @patch('acme_srv.order.Order._name_get')
    @patch('acme_srv.message.Message.check')
    def test_040_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and no certname """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar'}
        mock_process.return_value = (200, 'message', 'detail', None)
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce'}}, self.order.parse(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.order.Order._process')
    @patch('acme_srv.order.Order._lookup')
    @patch('acme_srv.order.Order._name_get')
    @patch('acme_srv.message.Message.check')
    def test_041_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname and valid status """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar', 'status': 'valid'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'certificate': 'http://tester.local/acme/cert/certname', 'foo': 'bar', 'status': 'valid'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce'}}, self.order.parse(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.order.Order._process')
    @patch('acme_srv.order.Order._lookup')
    @patch('acme_srv.order.Order._name_get')
    @patch('acme_srv.message.Message.check')
    def test_042_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname without status """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce'}}, self.order.parse(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.order.Order._process')
    @patch('acme_srv.order.Order._lookup')
    @patch('acme_srv.order.Order._name_get')
    @patch('acme_srv.message.Message.check')
    def test_043_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname and non-valid status """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar', 'status': 'foobar'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar', 'status': 'foobar'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce'}}, self.order.parse(message))

    def test_044_order__identifiers_check(self):
        """ order identifers check with empty identifer list"""
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check([]))

    def test_045_order__identifiers_check(self):
        """ order identifers check with string identifier """
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check('foo'))

    def test_046_order__identifiers_check(self):
        """ order identifers check with dictionary identifier """
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check({'type': 'dns', 'value': 'foo.bar'}))

    def test_047_order__identifiers_check(self):
        """ order identifers check with correct identifer but case-insensitive """
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check([{'Type': 'dns', 'value': 'value'}]))

    def test_048_order__identifiers_check(self):
        """ order identifers check with wrong identifer in list"""
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'foo', 'value': 'value'}]))

    def test_049_order__identifiers_check(self):
        """ order identifers check with correct identifer in list"""
        self.assertEqual(None, self.order._identifiers_check([{'type': 'dns', 'value': 'value'}]))

    def test_050_order__identifiers_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'dns', 'value': 'value'}, {'type': 'foo', 'value': 'value'}]))

    def test_051_order__identifiers_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'foo', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_052_order__identifiers_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual(None, self.order._identifiers_check([{'type': 'dns', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_053_order__identifiers_check(self):
        """ order identifers check with tnauthlist identifier and support false """
        self.order.tnauthlist_support = False
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_054_order__identifiers_check(self):
        """ order identifers check with tnauthlist identifier and support True """
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_055_order__identifiers_check(self):
        """ order identifers check with tnauthlist identifier and support True """
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}]))

    def test_056_order__identifiers_check(self):
        """ order identifers check with tnauthlist identifier a wrong identifer and support True """
        self.order.tnauthlist_support = True
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'type', 'value': 'value'}]))

    def test_057_order__identifiers_check(self):
        """ order identifers check with wrong identifer in list and tnauthsupport true"""
        self.order.tnauthlist_support = True
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'foo', 'value': 'value'}]))

    def test_058_order__identifiers_check(self):
        """ order identifers check with correct identifer in list and tnauthsupport true"""
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order._identifiers_check([{'type': 'dns', 'value': 'value'}]))

    def test_059_order__process(self):
        """ Order.prcoess() without url in protected header """
        order_name = 'order_name'
        protected = 'protected'
        payload = 'payload'
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'url is missing in protected', None), self.order._process(order_name, protected, payload))

    def test_060_order__process(self):
        """ Order.prcoess() polling request with failed certificate lookup """
        order_name = 'order_name'
        protected = {'url': 'foo'}
        payload = 'payload'
        self.order.dbstore.certificate_lookup.return_value = {}
        self.assertEqual((200, None, None, None), self.order._process(order_name, protected, payload))

    def test_061_order__process(self):
        """ Order.prcoess() polling request with successful certificate lookup """
        order_name = 'order_name'
        protected = {'url': 'foo'}
        payload = 'payload'
        self.order.dbstore.certificate_lookup.return_value = {'name': 'cert_name'}
        self.assertEqual((200, None, None, 'cert_name'), self.order._process(order_name, protected, payload))

    @patch('acme_srv.order.Order._info')
    def test_062_order__process(self, mock_info):
        """ Order.prcoess() finalize request with empty orderinfo """
        mock_info.return_value = {}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:orderNotReady', 'Order is not ready', None), self.order._process(order_name, protected, payload))

    @patch('acme_srv.order.Order._info')
    def test_063_order__process(self, mock_info):
        """ Order.prcoess() finalize request with orderinfo without status"""
        mock_info.return_value = {'foo': 'bar'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:orderNotReady', 'Order is not ready', None), self.order._process(order_name, protected, payload))

    @patch('acme_srv.order.Order._info')
    def test_064_order__process(self, mock_info):
        """ Order.prcoess() finalize request with orderinfo with wrong status"""
        mock_info.return_value = {'status': 'bar'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:orderNotReady', 'Order is not ready', None), self.order._process(order_name, protected, payload))

    @patch('acme_srv.order.Order._info')
    def test_065_order__process(self, mock_info):
        """ Order.prcoess() finalize request without CSR """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((400, 'urn:ietf:params:acme:error:badCSR', 'csr is missing in payload', None), self.order._process(order_name, protected, payload))

    @patch('acme_srv.order.Order._csr_process')
    @patch('acme_srv.order.Order._info')
    def test_066_order__process(self, mock_info, mock_process_csr):
        """ Order.prcoess() finalize request with CSR but csr_process failed """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = {'csr': 'csr'}
        mock_process_csr.return_value = (400, 'cert_name', 'detail')
        self.assertEqual((400, 'cert_name', 'enrollment failed', 'cert_name'), self.order._process(order_name, protected, payload))

    @patch('acme_srv.order.Order._update')
    @patch('acme_srv.order.Order._csr_process')
    @patch('acme_srv.order.Order._info')
    def test_067_order__process(self, mock_info, mock_process_csr, mock_update):
        """ Order.prcoess() finalize request with CSR but all good """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = {'csr': 'csr'}
        mock_process_csr.return_value = (200, 'cert_name', 'detail')
        mock_update.return_value = None
        self.assertEqual((200, None, 'detail', 'cert_name'), self.order._process(order_name, protected, payload))
        self.assertTrue(mock_update.called)

    @patch('acme_srv.order.Order._update')
    @patch('acme_srv.order.Order._csr_process')
    @patch('acme_srv.order.Order._info')
    def test_068_order__process(self, mock_info, mock_process_csr, mock_update):
        """ Order.prcoess() timeout in csr processing """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = {'csr': 'csr'}
        mock_process_csr.return_value = (400, 'timeout', 'detail')
        mock_update.return_value = None
        self.assertEqual((200, 'timeout', 'detail', 'timeout'), self.order._process(order_name, protected, payload))
        self.assertTrue(mock_update.called)

    @patch('acme_srv.order.Order._update')
    @patch('acme_srv.order.Order._csr_process')
    @patch('acme_srv.order.Order._info')
    def test_069_order__process(self, mock_info, mock_process_csr, mock_update):
        """ Order.prcoess() finalize request with detail none """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = {'csr': 'csr'}
        mock_process_csr.return_value = (200, 'cert_name', None)
        mock_update.return_value = None
        self.assertEqual((200, None, None, 'cert_name'), self.order._process(order_name, protected, payload))
        self.assertTrue(mock_update.called)

    @patch('importlib.import_module')
    @patch('acme_srv.certificate.Certificate.enroll_and_store')
    @patch('acme_srv.certificate.Certificate.store_csr')
    @patch('acme_srv.order.Order._info')
    def test_070_order__csr_process(self, mock_oinfo, mock_certname, mock_enroll, mock_import):
        """ test order prcoess_csr with failed cert enrollment with internal error (response code must be corrected by 500)"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = 'foo'
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        mock_enroll.return_value = ('urn:ietf:params:acme:error:serverInternal', 'detail')
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'detail'), self.order._csr_process('order_name', 'csr'))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.order.Order._process')
    @patch('acme_srv.order.Order._lookup')
    @patch('acme_srv.order.Order._name_get')
    @patch('acme_srv.message.Message.check')
    def test_071_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname processing status default retry after-header """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar', 'status': 'processing'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar', 'status': 'processing'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce', 'Retry-After': '600'}}, self.order.parse(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.order.Order._process')
    @patch('acme_srv.order.Order._lookup')
    @patch('acme_srv.order.Order._name_get')
    @patch('acme_srv.message.Message.check')
    def test_072_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname processing status configurable retry after-header """
        self.order.retry_after = 60
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar', 'status': 'processing'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar', 'status': 'processing'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce', 'Retry-After': '60'}}, self.order.parse(message))

    def test_073_order_invalidate(self):
        """ test Order.invalidate() empty order list """
        self.order.dbstore.orders_invalid_search.return_value = []
        self.assertEqual((['id', 'name', 'expires', 'identifiers', 'created_at', 'status__id', 'status__name', 'account__id', 'account__name', 'account__contact'], []), self.order.invalidate())

    def test_074_order_invalidate(self):
        """ test Certificate._fieldlist_normalize() - wrong return list (no status__name included) """
        self.order.dbstore.orders_invalid_search.return_value = [{'foo': 'bar'}]
        self.assertEqual((['id', 'name', 'expires', 'identifiers', 'created_at', 'status__id', 'status__name', 'account__id', 'account__name', 'account__contact'], []), self.order.invalidate())

    def test_075_order_invalidate(self):
        """ test Certificate._fieldlist_normalize() - no name but status__name """
        self.order.dbstore.orders_invalid_search.return_value = [{'foo': 'bar', 'status__name': 'foo'}]
        self.assertEqual((['id', 'name', 'expires', 'identifiers', 'created_at', 'status__id', 'status__name', 'account__id', 'account__name', 'account__contact'], []), self.order.invalidate())

    def test_076_order_invalidate(self):
        """ test Certificate._fieldlist_normalize() - name but no status__name """
        self.order.dbstore.orders_invalid_search.return_value = [{'foo': 'bar', 'name': 'foo'}]
        self.assertEqual((['id', 'name', 'expires', 'identifiers', 'created_at', 'status__id', 'status__name', 'account__id', 'account__name', 'account__contact'], []), self.order.invalidate())

    def test_077_order_invalidate(self):
        """ test Certificate._fieldlist_normalize() - name and status__name but invalid """
        self.order.dbstore.orders_invalid_search.return_value = [{'foo': 'bar', 'name': 'foo', 'status__name': 'invalid'}]
        self.assertEqual((['id', 'name', 'expires', 'identifiers', 'created_at', 'status__id', 'status__name', 'account__id', 'account__name', 'account__contact'], []), self.order.invalidate())

    def test_078_order_invalidate(self):
        """ test Certificate._fieldlist_normalize() - name and status__name but invalid """
        self.order.dbstore.orders_invalid_search.return_value = [{'foo': 'bar', 'name': 'foo', 'status__name': 'foobar'}]
        self.assertEqual((['id', 'name', 'expires', 'identifiers', 'created_at', 'status__id', 'status__name', 'account__id', 'account__name', 'account__contact'], [{'foo': 'bar', 'name': 'foo', 'status__name': 'foobar'}]), self.order.invalidate())

    @patch('acme_srv.order.Order._identifiers_check')
    def test_079_order__add(self, mock_idchk):
        """ test Order._add - dbstore.authorization_add() raises an exception  """
        self.order.dbstore.authorization_add.side_effect = Exception('exc_order_add')
        self.order.dbstore.order_add.return_value = 'oid'
        mock_idchk.return_value = False
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order._add({'foo': 'bar', 'identifiers': [{'type': 'dns', 'value': 'example1.com'}]}, 'aname')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Order._add() authz: exc_order_add', lcm.output)

    @patch('acme_srv.order.Order._identifiers_check')
    def test_080_order__add(self, mock_idchk):
        """ test Order._add - dbstore.order_add() raises an exception  """
        self.order.dbstore.order_add.side_effect = Exception('exc_order_add')
        mock_idchk.return_value = False
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order._add({'foo': 'bar', 'identifiers': 'identifiers'}, 'aname')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Order._add() order: exc_order_add', lcm.output)

    def test_081_order__info(self):
        """ test Order._info - dbstore.order_lookup() raises an exception  """
        self.order.dbstore.order_lookup.side_effect = Exception('exc_order_info')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order._info('oname')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Order._info(): exc_order_info', lcm.output)

    def test_082_order__process(self):
        """ test Order._process - dbstore.order_lookup() raises an exception  """
        self.order.dbstore.certificate_lookup.side_effect = Exception('exc_order_process')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order._process('oname', {'url': 'url'}, 'payload')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Order._process(): exc_order_process', lcm.output)

    def test_083_order__update(self):
        """ test Order._update - dbstore.order_update() raises an exception  """
        self.order.dbstore.order_update.side_effect = Exception('exc_order_upd')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order._update({'url': 'url'})
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Order._update(): exc_order_upd', lcm.output)

    @patch('acme_srv.order.Order._info')
    def test_084_order__lookup(self, mock_info):
        """ test Order._lookup - dbstore.authorization_lookup() raises an exception  """
        self.order.dbstore.authorization_lookup.side_effect = Exception('exc_authz_lookup')
        mock_info.return_value = {'status': 'valid'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order._lookup('oname')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Order._authz_list_lookup(): exc_authz_lookup', lcm.output)

    def test_085_order_invalidate(self):
        """ test Order.invalidate - dbstore.order_update() raises an exception  """
        self.order.dbstore.order_update.side_effect = Exception('exc_order_upd')
        self.order.dbstore.order_invalid_search.return_value = ['foo']
        timestamp = 1543640400
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order.invalidate(timestamp)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Order._invalidate() upd: exc_order_upd', lcm.output)

    def test_086_order_invalidate(self):
        """ test Order.invalidate - dbstore.order_update() raises an exception  """
        self.order.dbstore.orders_invalid_search.side_effect = Exception('exc_order_search')
        timestamp = 1543640400
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order.invalidate(timestamp)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Order._invalidate() search: exc_order_search', lcm.output)

    @patch('acme_srv.order.Order._config_load')
    def test_087__enter__(self, mock_cfg):
        """ test enter """
        mock_cfg.return_value = True
        self.order.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch('acme_srv.order.load_config')
    def test_088_config_load(self, mock_load_cfg):
        """ test _config_load empty config """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)

    @patch('acme_srv.order.load_config')
    def test_089_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)

    @patch('acme_srv.order.load_config')
    def test_090_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'tnauthlist_support': False}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)

    @patch('acme_srv.order.load_config')
    def test_091_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'tnauthlist_support': True}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertTrue(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)

    @patch('acme_srv.order.load_config')
    def test_092_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'expiry_check_disable': False}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)

    @patch('acme_srv.order.load_config')
    def test_093_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'expiry_check_disable': True}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertTrue(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)

    @patch('acme_srv.order.load_config')
    def test_094_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'retry_after_timeout': 1200}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(1200, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)

    @patch('acme_srv.order.load_config')
    def test_095_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'retry_after_timeout': '1200'}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(1200, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)

    @patch('acme_srv.order.load_config')
    def test_096_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'retry_after_timeout': 'foo'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)
        self.assertIn('WARNING:test_a2c:Order._config_load(): failed to parse retry_after: foo', lcm.output)

    @patch('acme_srv.order.load_config')
    def test_097_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'validity': 1200}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(1200, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)

    @patch('acme_srv.order.load_config')
    def test_098_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'validity': '1200'}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(1200, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)

    @patch('acme_srv.order.load_config')
    def test_099_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Order'] = {'validity': 'foo'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)
        self.assertIn('WARNING:test_a2c:Order._config_load(): failed to parse validity: foo', lcm.output)

    @patch('acme_srv.order.load_config')
    def test_100_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Authorization'] = {'validity': 1200}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(1200, self.order.authz_validity)

    @patch('acme_srv.order.load_config')
    def test_101_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Authorization'] = {'validity': '1200'}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(1200, self.order.authz_validity)

    @patch('acme_srv.order.load_config')
    def test_102_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Authorization'] = {'validity': 'foo'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertFalse(self.order.expiry_check_disable)
        self.assertEqual(600, self.order.retry_after)
        self.assertEqual(86400, self.order.validity)
        self.assertEqual(86400, self.order.authz_validity)
        self.assertIn('WARNING:test_a2c:Order._config_load(): failed to parse authz validity: foo', lcm.output)

    @patch('acme_srv.order.load_config')
    def test_103_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'url_prefix': 'url_prefix'}
        mock_load_cfg.return_value = parser
        self.order._config_load()
        self.assertFalse(self.order.tnauthlist_support)
        self.assertEqual({'authz_path': 'url_prefix/acme/authz/', 'cert_path': 'url_prefix/acme/cert/', 'order_path': 'url_prefix/acme/order/'}, self.order.path_dic)

if __name__ == '__main__':
    unittest.main()
