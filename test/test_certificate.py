#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import json
import datetime
import importlib
import configparser
from unittest.mock import patch, MagicMock, Mock

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
        from acme_srv.account import Account
        from acme_srv.certificate import Certificate
        self.account = Account(False, 'http://tester.local', self.logger)
        self.certificate = Certificate(False, 'http://tester.local', self.logger)
        #hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        #self.certificate.hooks = hooks_module.Hooks(self.logger)

    @patch('acme_srv.certificate.generate_random_string')
    def test_001_certificate_store_csr(self, mock_name):
        """ test Certificate.store_csr() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'foo'
        mock_name.return_value = 'bar'
        self.assertEqual('bar', self.certificate.store_csr('order_name', 'csr'))

    def test_002_certificate__store_cert(self):
        """ test Certificate.store_cert() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'bar'
        self.assertEqual('bar', self.certificate._store_cert('cert_name', 'cert', 'raw'))

    @patch('acme_srv.certificate.generate_random_string')
    def test_003_certificate_store_csr(self, mock_name):
        """ test Certificate.store_csr() with an exception store_csr """
        self.certificate.dbstore.certificate_add.side_effect = Exception('exc_cert_add')
        mock_name.return_value = 'bar'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('bar', self.certificate.store_csr('order_name', 'csr'))
        self.assertIn('CRITICAL:test_a2c:Database error in Certificate.store_csr(): exc_cert_add', lcm.output)

    def test_004_certificate__store_cert(self):
        """ test Certificate.store_cert() and check if we get something back """
        self.certificate.dbstore.certificate_add.side_effect = Exception('exc_cert_add')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.certificate._store_cert('cert_name', 'cert', 'raw'))
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._store_cert(): exc_cert_add', lcm.output)

    def test_005_certificate__info(self):
        """ test Certificate.new_get() """
        self.certificate.dbstore.certificate_lookup.return_value = 'foo'
        self.assertEqual('foo', self.certificate._info('cert_name'))

    @patch('acme_srv.certificate.Certificate._info')
    def test_006_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without certificate"""
        mock_info.return_value = {}
        self.assertEqual({'code': 500, 'data': 'urn:ietf:params:acme:error:serverInternal'}, self.certificate.new_get('url'))

    @patch('acme_srv.certificate.Certificate._info')
    def test_007_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without unknown order_status_id"""
        mock_info.return_value = {'order__status_id': 'foo'}
        self.assertEqual({'code': 403, 'data': 'urn:ietf:params:acme:error:orderNotReady'}, self.certificate.new_get('url'))

    @patch('acme_srv.certificate.Certificate._info')
    def test_008_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 4 (processing)"""
        mock_info.return_value = {'order__status_id': 4}
        self.assertEqual({'code': 403, 'data': 'urn:ietf:params:acme:error:rateLimited', 'header': {'Retry-After': '600'}}, self.certificate.new_get('url'))

    @patch('acme_srv.certificate.Certificate._info')
    def test_009_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) but no certificate in"""
        mock_info.return_value = {'order__status_id': 5}
        self.assertEqual({'code': 500, 'data': 'urn:ietf:params:acme:error:serverInternal'}, self.certificate.new_get('url'))

    @patch('acme_srv.certificate.Certificate._info')
    def test_010_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) and empty certificate field"""
        mock_info.return_value = {'order__status_id': 5, 'cert': None}
        self.assertEqual({'code': 500, 'data': 'urn:ietf:params:acme:error:serverInternal'}, self.certificate.new_get('url'))

    @patch('acme_srv.certificate.Certificate._info')
    def test_011_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) but no certificate in"""
        mock_info.return_value = {'order__status_id': 5, 'cert': 'foo-bar'}
        self.assertEqual({'code': 200, 'data': 'foo-bar', 'header': {'Content-Type': 'application/pem-certificate-chain'}}, self.certificate.new_get('url'))

    @patch('acme_srv.message.Message.check')
    def test_012_certificate_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  json.dumps({'status': 400, 'type': 'urn:ietf:params:acme:error:malformed', 'detail': 'detail'})}, self.certificate.new_post('content'))

    @patch('acme_srv.message.Message.check')
    def test_013_certificate_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': json.dumps({'status': 400, 'type': 'urn:ietf:params:acme:error:malformed', 'detail': 'url missing in protected header'})}, self.certificate.new_post('content'))

    @patch('acme_srv.message.Message.prepare_response')
    @patch('acme_srv.certificate.Certificate.new_get')
    @patch('acme_srv.message.Message.check')
    def test_014_certificate_new_post(self, mock_mcheck, mock_certget, mock_response):
        """ test Certificate.new_post() message check returns ok  """
        mock_mcheck.return_value = (200, None, None, {'url' : 'example.com'}, 'payload', 'account_name')
        mock_certget.return_value = {'code': 403, 'data': 'foo'}
        mock_response.return_value = {'data': 'foo'}
        self.assertEqual({'data': 'foo'}, self.certificate.new_post('content'))

    def test_015_certificate__revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with allowed reason"""
        rev_reason = 0
        self.assertEqual('unspecified', self.certificate._revocation_reason_check(rev_reason))

    def test_016_certificate__revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with non-allowed reason"""
        rev_reason = 8
        self.assertFalse(self.certificate._revocation_reason_check(rev_reason))

    @patch('acme_srv.certificate.cert_san_get')
    def test_017_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans but failed order lookup"""
        self.certificate.dbstore.order_lookup.return_value = {}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_018_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order returning wrong values (no 'identifiers' key) """
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_019_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order lookup returning identifiers without json structure) """
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_020_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with wrong sans) """
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_021_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with SAN entry which is not in the identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_022_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with single SAN entry and correct entry in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_023_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with multiple SAN entries and correct entries in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_024_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with one SAN entry and multiple entries in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_025_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with uppercase SAN entries and lowercase entries in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:SAN1.EXAMPLE.COM', 'DNS:SAN2.EXAMPLE.COM']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_026_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lowercase SAN entries and uppercase entries in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"TYPE": "DNS", "VALUE": "SAN1.EXAMPLE.COM"}, {"TYPE": "DNS", "VALUE": "SAN2.EXAMPLE.COM"}]'}
        mock_san.return_value = ['dns:san1.example.com', 'dns:san2.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    def test_027_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lSAN entries (return none) and entries in identifier containing None"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "None", "value": "None"}]'}
        mock_san.return_value = ['san1.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_028_certificate__revocation_request_validate(self):
        """ test Certificate.revocation_request_validate empty payload"""
        payload = {}
        self.assertEqual((400, 'unspecified'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme_srv.certificate.Certificate._revocation_reason_check')
    def test_029_certificate__revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns None"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:badRevocationReason'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme_srv.certificate.Certificate._revocation_reason_check')
    def test_030_certificate__revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns a reason"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = 'revrcheck'
        self.assertEqual((400, 'revrcheck'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme_srv.certificate.Certificate._authorization_check')
    @patch('acme_srv.certificate.Certificate._account_check')
    @patch('acme_srv.certificate.Certificate._revocation_reason_check')
    def test_031_certificate__revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check failed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme_srv.certificate.Certificate._authorization_check')
    @patch('acme_srv.certificate.Certificate._account_check')
    @patch('acme_srv.certificate.Certificate._revocation_reason_check')
    def test_032_certificate__revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check succeed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = True
        self.assertEqual((200, 'revrcheck'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme_srv.message.Message.check')
    def test_033_certificate_revoke(self, mock_mcheck):
        """ test Certificate.revoke with failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'type': 'message', 'detail': 'detail'}}, self.certificate.revoke('content'))

    @patch('acme_srv.message.Message.check')
    def test_034_certificate_revoke(self, mock_mcheck):
        """ test Certificate.revoke with incorrect payload """
        mock_mcheck.return_value = (200, 'message', 'detail', None, {}, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'type': 'urn:ietf:params:acme:error:malformed', 'detail': 'certificate not found'}}, self.certificate.revoke('content'))

    @patch('acme_srv.certificate.Certificate._revocation_request_validate')
    @patch('acme_srv.message.Message.check')
    def test_035_certificate_revoke(self, mock_mcheck, mock_validate):
        """ test Certificate.revoke with failed request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (400, 'error')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'type': 'error'}}, self.certificate.revoke('content'))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.certificate.Certificate._revocation_request_validate')
    @patch('acme_srv.message.Message.check')
    def test_036_certificate_revoke(self, mock_mcheck, mock_validate, mock_nnonce):
        """ test Certificate.revoke with sucessful request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (200, 'reason')
        mock_nnonce.return_value = 'new_nonce'
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.revoke = Mock(return_value=(200, 'message', 'detail'))
        self.assertEqual({'code': 200, 'header': {'Replay-Nonce': 'new_nonce'}}, self.certificate.revoke('content'))

    def test_037_certificate__revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with a valid revocation reason"""
        self.assertEqual('unspecified', self.certificate._revocation_reason_check(0))

    def test_038_certificate__revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with an invalid revocation reason"""
        self.assertFalse(self.certificate._revocation_reason_check(2))

    def test_039_certificate__tnauth_identifier_check(self):
        """ identifier check empty """
        identifier_dic = []
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_040_certificate__tnauth_identifier_check(self):
        """ identifier check none input"""
        identifier_dic = None
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_041_certificate__tnauth_identifier_check(self):
        """ identifier check none input"""
        identifier_dic = 'foo'
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_042_certificate__tnauth_identifier_check(self):
        """ identifier check one identifier """
        identifier_dic = [{'foo': 'bar'}]
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_043_certificate__tnauth_identifier_check(self):
        """ identifier check two identifiers """
        identifier_dic = [{'foo': 'bar'}, {'foo': 'bar'}]
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_044_certificate__tnauth_identifier_check(self):
        """ identifier check hit first identifiers """
        identifier_dic = [{'type': 'bar'}, {'foo': 'bar'}]
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_045_certificate__tnauth_identifier_check(self):
        """ identifier check hit first identifiers """
        identifier_dic = [{'type': 'TNAUTHLIST'}, {'foo': 'bar'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_046_certificate__tnauth_identifier_check(self):
        """ identifier check hit first identifiers """
        identifier_dic = [{'type': 'tnauthlist'}, {'foo': 'bar'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_047_certificate__tnauth_identifier_check(self):
        """ identifier check hit 2nd identifiers """
        identifier_dic = [{'type': 'bar'}, {'type': 'tnauthlist'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_048_certificate__tnauth_identifier_check(self):
        """ identifier check hit 2nd identifiers """
        identifier_dic = [{'type': 'bar'}, {'type': 'TNAUTHLIST'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_049_certificate__identifer_status_list(self):
        """ failed check identifiers against san """
        identifier_dic = [{'foo': 'bar'}, {'foo': 'bar'}]
        san_list = ['foo:bar', 'foo:bar']
        self.assertEqual([False, False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_050_certificate__identifer_status_list(self):
        """ failed check no sans """
        identifier_dic = [{'foo': 'bar'}]
        san_list = []
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_051_certificate__identifer_status_list(self):
        """ failed check no identifiers """
        identifier_dic = []
        san_list = ['foo:bar']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_052_certificate__identifer_status_list(self):
        """ failed check no identifiers """
        identifier_dic = []
        san_list = ['bar']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_053_certificate__identifer_status_list(self):
        """ succ check no identifiers """
        identifier_dic = [{'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar']
        self.assertEqual([True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_054_certificate__identifer_status_list(self):
        """ failed check san in identifier """
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}]
        san_list = ['dns:bar']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_055_certificate__identifer_status_list(self):
        """ failed check identifier in san """
        identifier_dic = [{'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar1']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_056_certificate__identifer_status_list(self):
        """ failed check identifier one identifier two sans"""
        identifier_dic = [{'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar', 'dns:bar2']
        self.assertEqual([True, False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_057_certificate__identifer_status_list(self):
        """ failed check identifier two identifier one san"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar1']
        self.assertEqual([True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_058_certificate__identifer_status_list(self):
        """ failed check identifier both ok"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar1', 'dns:bar2']
        self.assertEqual([True, True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_059_certificate__identifer_status_list(self):
        """ failed check identifier both ok - wrong order"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar2', 'dns:bar1']
        self.assertEqual([True, True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_060_certificate__identifer_status_list(self):
        """ failed check identifier first ok 2nd nok"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar1', 'dns:bar2']
        self.assertEqual([True, False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_061_certificate__identifer_status_list(self):
        """ failed check identifier first nook 2nd ok"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar', 'dns:bar2']
        self.assertEqual([False, True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_062_certificate__identifer_tnauth_list(self):
        """ empty identifier dic but tnauth exists """
        identifier_dic = []
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_063_certificate__identifer_tnauth_list(self):
        """ identifier dic but no tnauth """
        identifier_dic = {'foo': 'bar'}
        tnauthlist = None
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_064_certificate__identifer_tnauth_list(self):
        """ wrong identifier """
        identifier_dic = {'identifiers': '[{"foo": "bar"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_065_certificate__identifer_tnauth_list(self):
        """ wrong type """
        identifier_dic = {'identifiers': '[{"type": "bar"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_066_certificate__identifer_tnauth_list(self):
        """ correct type but no value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_067_certificate__identifer_tnauth_list(self):
        """ correct type but wrong value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt", "value": "bar"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_068_certificate__identifer_tnauth_list(self):
        """ correct type but wrong value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt", "value": "foo"}]'}
        tnauthlist = 'foo'
        self.assertEqual([True], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_069_certificate__identifer_tnauth_list(self):
        """ correct type but wrong value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt", "value": "foo"}, {"type": "dns", "value": "foo"}]'}
        tnauthlist = 'foo'
        self.assertEqual([True, False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    @patch('acme_srv.certificate.Certificate._info')
    def test_070_certificate__csr_check(self, mock_certinfo):
        """ csr-check certname lookup failed """
        mock_certinfo.return_value = {}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.Certificate._info')
    def test_071_certificate__csr_check(self, mock_certinfo):
        """ csr-check order lookup failed """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.return_value = {}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.Certificate._info')
    def test_072_certificate__csr_check(self, mock_certinfo):
        """ csr-check order lookup returns rubbish """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.Certificate._info')
    def test_073_certificate__csr_check(self, mock_certinfo):
        """ csr-check order lookup returns an identifier """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_074_certificate__csr_check(self, mock_certinfo, mock_tnauthin):
        """ csr-check no tnauth """
        mock_certinfo.return_value = {'order': 'order'}
        mock_tnauthin.return_value = False
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_075_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check no tnauth  status true """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_076_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check no tnauth  status False """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_077_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check no tnauth  status True, False """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_078_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check no tnauth  status True, False, True """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False, True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_079_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support off  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_extensions_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_080_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns true  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_extensions_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_081_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns true  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [False]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_extensions_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_082_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns True, False  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_extensions_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_083_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns True, False  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False, True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme_srv.certificate.csr_extensions_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.Certificate._info')
    def test_084_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns True, False  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.side_effect = Exception('mock_status')
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))
        self.assertIn('WARNING:test_a2c:Certificate._csr_check() error while parsing csr.\nerror: mock_status', lcm.output)

    def test_085_certificate__authorization_check(self):
        """ _authorization_check order lookup failed """
        self.certificate.dbstore.order_lookup.return_value = {}
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_086_certificate__authorization_check(self):
        """ _authorization_check order lookup returns rubbish """
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar'}
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_087_certificate__authorization_check(self):
        """ _authorization_check order lookup returns an identifier """
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_088_certificate__authorization_check(self, mock_tnauthin):
        """ _authorization_check no tnauth """
        mock_tnauthin.return_value = False
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_089_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status true """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_090_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status true """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_091_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status False """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_092_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status True, False """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_093_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status True, False, True """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False, True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_san_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_094_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support off  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_extensions_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_095_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support on and returns true  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_extensions_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_096_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support on and returns true  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [False]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_extensions_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_097_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support on and returns True, False  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.cert_extensions_get')
    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    def test_098_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support on and returns True, False  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False, True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme_srv.certificate.Certificate._csr_check')
    def test_099_certificate_enroll_and_store(self, mock_csr):
        """ Certificate.enroll_and_store() csr_check failed """
        mock_csr.return_value = False
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual(('urn:ietf:params:acme:error:badCSR', 'CSR validation failed'), self.certificate.enroll_and_store(certificate_name, csr))

    @patch('acme_srv.threadwithreturnvalue.ThreadWithReturnValue.join')
    @patch('acme_srv.threadwithreturnvalue.ThreadWithReturnValue.start')
    @patch('acme_srv.certificate.Certificate._csr_check')
    def test_100_certificate_enroll_and_store(self, mock_csr, tr_start, tr_join):
        """ Certificate.enroll_and_store() csr_check successful - timeout during enrollment """
        mock_csr.return_value = True
        tr_start.return_value = True
        tr_join.return_value = None
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual(('timeout', 'timeout'), self.certificate.enroll_and_store(certificate_name, csr))

    @patch('acme_srv.threadwithreturnvalue.ThreadWithReturnValue.join')
    @patch('acme_srv.threadwithreturnvalue.ThreadWithReturnValue.start')
    @patch('acme_srv.certificate.Certificate._csr_check')
    def test_101_certificate_enroll_and_store(self, mock_csr, tr_start, tr_join):
        """ Certificate.enroll_and_store() csr_check successful - enrollment returns something useful """
        mock_csr.return_value = True
        tr_start.return_value = True
        tr_join.return_value = ('foo', 'bar', 'foobar')
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual(('bar', 'foobar'), self.certificate.enroll_and_store(certificate_name, csr))

    @patch('acme_srv.threadwithreturnvalue.ThreadWithReturnValue.join')
    @patch('acme_srv.threadwithreturnvalue.ThreadWithReturnValue.start')
    @patch('acme_srv.certificate.Certificate._csr_check')
    def test_102_certificate_enroll_and_store(self, mock_csr, tr_start, tr_join):
        """ Certificate.enroll_and_store() csr_check successful - enrollment returns something unexpected """
        mock_csr.return_value = True
        tr_start.return_value = True
        tr_join.return_value = 'unexpected'
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('urn:ietf:params:acme:error:serverInternal', 'unexpected enrollment result'), self.certificate.enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:acme2certifier database error in Certificate.enroll_and_store(): split of unexpected failed with err: too many values to unpack (expected 3)', lcm.output)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_103_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment failed without polling_identifier """
        # self.certificate.dbstore.order_update.return_value = 'foo'
        mock_store_err.return_value = True
        mock_store.return_value = True
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=('error', None, None, None))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'urn:ietf:params:acme:error:serverInternal', None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:acme2certifier enrollment error: error', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(mock_store_err.called)
        self.assertFalse(mock_store.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_104_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment failed with polling_identifier - no order update """
        mock_store_err.return_value = True
        mock_store.return_value = True
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=('error', None, None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'error', 'poll_identifier'), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:acme2certifier enrollment error: error', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertFalse(mock_oupd.called)
        self.assertTrue(mock_store_err.called)
        self.assertFalse(mock_store.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_105_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment failed - exception in store_cert_error"""
        self.certificate.dbstore.order_update.return_value = 'foo'
        mock_store_err.side_effect = Exception('ex_cert_error_store')
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=('error', None, None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'error', 'poll_identifier'), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._enroll_and_store() _store_cert_error: ex_cert_error_store', lcm.output)
        self.assertIn('ERROR:test_a2c:acme2certifier enrollment error: error', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertFalse(mock_oupd.called)
        self.assertTrue(mock_store_err.called)
        self.assertFalse(mock_store.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_106_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment succhessful with polling_identifier"""
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_107_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment succhessful without polling_identifier"""
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_108_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment succhessful _store_cert returns None """
        mock_store_err.return_value = True
        mock_store.return_value = None
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual((None, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertFalse(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_109_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment Exception in store_cert """
        mock_store_err.return_value = True
        mock_store.side_effect = Exception('ex_cert_store')
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._enroll_and_store(): ex_cert_store', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertFalse(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_110_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store()  _cert_reusage_check successful """
        self.certificate.cert_reusage_timeframe = 86400
        mock_chk.return_value = (None, 'certificate', 'certificate_raw', 'poll_identifier')
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertTrue(mock_chk.called)
        self.assertFalse(self.certificate.cahandler.enroll.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_111_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store()  _cert_reusage_check no cert """
        self.certificate.cert_reusage_timeframe = 86400
        mock_chk.return_value = (None, None, 'certificate_raw', 'poll_identifier')
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertTrue(mock_chk.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_112_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store()  _cert_reusage_check no cert_raw """
        self.certificate.cert_reusage_timeframe = 86400
        mock_chk.return_value = (None, 'certificate', None, 'poll_identifier')
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertTrue(mock_chk.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_113_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store()  _cert_reusage_check no cert and no cert_raw """
        self.certificate.cert_reusage_timeframe = 86400
        mock_chk.return_value = (None, None, None, 'poll_identifier')
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertTrue(mock_chk.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_114_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment hooks successful """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock()
        self.certificate.hooks.success_hook = Mock()
        self.certificate.hooks.post_hook = Mock()
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertTrue(self.certificate.hooks.success_hook.called)
        self.assertTrue(self.certificate.hooks.post_hook.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_115_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment pre_hook exception """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock(side_effect=Exception('ex_pre_hook'))
        self.certificate.hooks.success_hook = Mock()
        self.certificate.hooks.post_hook = Mock()
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'pre_hook_error', 'ex_pre_hook'), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:Certificate._enroll_and_store(): pre_hook exception: ex_pre_hook', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertFalse(mock_dates.called)
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertFalse(mock_oupd.called)
        self.assertFalse(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertFalse(self.certificate.hooks.success_hook.called)
        self.assertFalse(self.certificate.hooks.post_hook.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_116_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment pre_hook exception / ingore_pre_hook_failure is set to true """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock(side_effect=Exception('ex_pre_hook'))
        self.certificate.ignore_pre_hook_failure = True
        self.certificate.hooks.success_hook = Mock()
        self.certificate.hooks.post_hook = Mock()
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:Certificate._enroll_and_store(): pre_hook exception: ex_pre_hook', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertTrue(self.certificate.hooks.success_hook.called)
        self.assertTrue(self.certificate.hooks.post_hook.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_117_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment pre_hook exception  / ingore_pre_hook_failure is set to false """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock(side_effect=Exception('ex_pre_hook'))
        self.certificate.ignore_pre_hook_failure = False
        self.certificate.hooks.success_hook = Mock()
        self.certificate.hooks.post_hook = Mock()
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'pre_hook_error', 'ex_pre_hook'), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:Certificate._enroll_and_store(): pre_hook exception: ex_pre_hook', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertFalse(mock_dates.called)
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertFalse(mock_oupd.called)
        self.assertFalse(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertFalse(self.certificate.hooks.success_hook.called)
        self.assertFalse(self.certificate.hooks.post_hook.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_118_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment success_hook exception """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock()
        self.certificate.hooks.success_hook = Mock(side_effect=Exception('ex_success_hook'))
        self.certificate.hooks.post_hook = Mock()
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'success_hook_error', 'ex_success_hook'), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:Certificate._enroll_and_store: success_hook exception: ex_success_hook', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertTrue(self.certificate.hooks.success_hook.called)
        self.assertFalse(self.certificate.hooks.post_hook.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_119_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment success_hook exception   / ignore_success_hook_failure is set to False """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock()
        self.certificate.hooks.success_hook = Mock(side_effect=Exception('ex_success_hook'))
        self.certificate.ignore_success_hook_failure = False
        self.certificate.hooks.post_hook = Mock()
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'success_hook_error', 'ex_success_hook'), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:Certificate._enroll_and_store: success_hook exception: ex_success_hook', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertTrue(self.certificate.hooks.success_hook.called)
        self.assertFalse(self.certificate.hooks.post_hook.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_120_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment success_hook exception   / ignore_success_hook_failure is set to True """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock()
        self.certificate.hooks.success_hook = Mock(side_effect=Exception('ex_success_hook'))
        self.certificate.ignore_success_hook_failure = True
        self.certificate.hooks.post_hook = Mock()
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:Certificate._enroll_and_store: success_hook exception: ex_success_hook', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertTrue(self.certificate.hooks.success_hook.called)
        self.assertTrue(self.certificate.hooks.post_hook.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_121_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment post_hook exception """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock()
        self.certificate.hooks.success_hook = Mock()
        self.certificate.hooks.post_hook = Mock(side_effect=Exception('ex_post_hook'))
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:Certificate._enroll_and_store(): post_hook exception: ex_post_hook', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertTrue(self.certificate.hooks.success_hook.called)
        self.assertTrue(self.certificate.hooks.post_hook.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_122_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment post_hook exception / ignore_post_hook_failure is set to True """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock()
        self.certificate.hooks.success_hook = Mock()
        self.certificate.hooks.post_hook = Mock(side_effect=Exception('ex_post_hook'))
        self.certificate.ignore_post_hook_failure = True
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((True, None, None), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:Certificate._enroll_and_store(): post_hook exception: ex_post_hook', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertTrue(self.certificate.hooks.success_hook.called)
        self.assertTrue(self.certificate.hooks.post_hook.called)

    @patch('acme_srv.certificate.Certificate._cert_reusage_check')
    @patch('acme_srv.certificate.Certificate._order_update')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.Certificate._store_cert_error')
    def test_123_certificate_enroll_and_store(self, mock_store_err, mock_store, mock_dates, mock_oupd, mock_chk):
        """ Certificate.enroll_and_store() enrollment post_hook exception / ignore_post_hook_failure is set to False """
        hooks_module = importlib.import_module('examples.hooks.skeleton_hooks')
        self.certificate.hooks = hooks_module.Hooks(self.logger)
        self.certificate.hooks.pre_hook = Mock()
        self.certificate.hooks.success_hook = Mock()
        self.certificate.hooks.post_hook = Mock(side_effect=Exception('ex_post_hook'))
        self.certificate.ignore_post_hook_failure = False
        mock_store_err.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'post_hook_error', 'ex_post_hook'), self.certificate._enroll_and_store(certificate_name, csr))
        self.assertIn('ERROR:test_a2c:Certificate._enroll_and_store(): post_hook exception: ex_post_hook', lcm.output)
        self.assertFalse(mock_chk.called)
        self.assertTrue(mock_dates.called)
        self.assertTrue(mock_store.called)
        self.assertFalse(mock_store_err.called)
        self.assertTrue(mock_oupd.called)
        self.assertTrue(self.certificate.cahandler.enroll.called)
        self.assertTrue(self.certificate.hooks.pre_hook.called)
        self.assertTrue(self.certificate.hooks.success_hook.called)
        self.assertTrue(self.certificate.hooks.post_hook.called)

    def test_124_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - empty dict """
        cert_entry = {}
        timestamp = 1596240000
        self.assertEqual((True, {}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_125_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - wrong dict """
        cert_entry = {'foo': 'bar'}
        timestamp = 1596240000
        self.assertEqual((True, {'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_126_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - certname in but rest ist wrong """
        cert_entry = {'name': 'certname', 'foo': 'bar'}
        timestamp = 1596240000
        self.assertEqual((False, {'name': 'certname', 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_127_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - non zero expiry date """
        cert_entry = {'name': 'certname', 'expire_uts': 10}
        timestamp = 1596240000
        self.assertEqual((True, {'expire_uts': 10, 'name': 'certname'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_128_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - expire_uts zero but no cert_raw """
        cert_entry = {'name': 'certname', 'expire_uts': 0}
        timestamp = 1596240000
        self.assertEqual((True, {'expire_uts': 0, 'name': 'certname'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_129_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - expire_uts zero but no cert_raw """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'cert_raw': 'cert_raw'}
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'cert_raw': 'cert_raw'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme_srv.certificate.cert_dates_get')
    def test_130_certificate__invalidation_check(self, mock_dates):
        """ test Certificate._invalidation_check() - with expiry date lower than timestamp """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'cert_raw': 'cert_raw'}
        mock_dates.return_value = (10, 1596200000)
        timestamp = 1596240000
        self.assertEqual((True, {'expire_uts': 1596200000, 'issue_uts': 10, 'name': 'certname', 'cert_raw': 'cert_raw'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme_srv.certificate.cert_dates_get')
    def test_131_certificate__invalidation_check(self, mock_dates):
        """ test Certificate._invalidation_check() - with expiry date at timestamp """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'cert_raw': 'cert_raw'}
        mock_dates.return_value = (10, 1596240000)
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'cert_raw': 'cert_raw'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme_srv.certificate.cert_dates_get')
    def test_132_certificate__invalidation_check(self, mock_dates):
        """ test Certificate._invalidation_check() - with expiry date higher than timestamp """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'cert_raw': 'cert_raw'}
        mock_dates.return_value = (10, 1596250000)
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'cert_raw': 'cert_raw'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_133_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - without created_at date """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'csr': 'csr'}
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'csr': 'csr'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme_srv.certificate.date_to_uts_utc')
    def test_134_certificate__invalidation_check(self, mock_date):
        """ test Certificate._invalidation_check() - with zero created_at date """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'csr': 'csr', 'created_at': 'created_at'}
        mock_date.return_value = 0
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'csr': 'csr', 'created_at': 'created_at'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme_srv.certificate.date_to_uts_utc')
    def test_135_certificate__invalidation_check(self, mock_date):
        """ test Certificate._invalidation_check() - with zero created_at date lower than threshold"""
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'csr': 'csr', 'created_at': 'created_at'}
        mock_date.return_value = 1591240000
        timestamp = 1596240000
        self.assertEqual((True, {'expire_uts': 0, 'name': 'certname', 'csr': 'csr', 'created_at': 'created_at'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme_srv.certificate.date_to_uts_utc')
    def test_136_certificate__invalidation_check(self, mock_date):
        """ test Certificate._invalidation_check() - with zero created_at higher than threshold """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'csr': 'csr', 'created_at': 'created_at'}
        mock_date.return_value = 1596220000
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'csr': 'csr', 'created_at': 'created_at'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_137_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - removed by in cert """
        cert_entry = {'name': 'certname', 'cert': 'removed by foo-bar', 'foo': 'bar'}
        timestamp = 159624000
        self.assertEqual((False, {'name': 'certname', 'cert': 'removed by foo-bar', 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_138_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - removed by in cert """
        cert_entry = {'name': 'certname', 'cert': 'removed by foo-bar', 'foo': 'bar'}
        timestamp = 159624000
        self.assertEqual((True, {'name': 'certname', 'cert': 'removed by foo-bar', 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp, True))

    def test_139_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - removed by in cert but in upper-cases """
        cert_entry = {'name': 'certname', 'cert': 'ReMoved By foo-bar', 'foo': 'bar'}
        timestamp = 159624000
        self.assertEqual((False, {'name': 'certname', 'cert': 'ReMoved By foo-bar', 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_140_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - cert None """
        cert_entry = {'name': 'certname', 'cert': None, 'foo': 'bar'}
        timestamp = 159624000
        self.assertEqual((False, {'name': 'certname', 'cert': None, 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_141_certificate_poll(self):
        """ test Certificate.poll - dbstore.order_update() raises an exception  """
        self.certificate.dbstore.order_update.side_effect = Exception('exc_cert_poll')
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.poll = Mock(return_value=('error', 'certificate', 'certificate_raw', 'poll_identifier', 'rejected'))
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.poll('certificate_name', 'poll_identifier', 'csr', 'order_name')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.poll(): exc_cert_poll', lcm.output)

    def test_142_certificate_poll(self):
        """ test Certificate.poll - dbstore.order_update() raises an exception  and certreq rejected """
        self.certificate.dbstore.order_update.side_effect = Exception('exc_cert_poll')
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.poll = Mock(return_value=('error', None, 'certificate_raw', 'poll_identifier', 'rejected'))
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.poll('certificate_name', 'poll_identifier', 'csr', 'order_name')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.poll(): exc_cert_poll', lcm.output)

    def test_143_certificate__store_cert(self):
        """ test Certificate.store_cert() - dbstore.certificate_add raises an exception  """
        self.certificate.dbstore.certificate_add.side_effect = Exception('exc_cert_add')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._store_cert('cert_name', 'cert', 'raw')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._store_cert(): exc_cert_add', lcm.output)

    def test_144_certificate__store_cert_error(self):
        """ test Certificate.store_cert_error() - dbstore.certificate_add raises an exception  """
        self.certificate.dbstore.certificate_add.side_effect = Exception('exc_cert_add_error')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._store_cert_error('cert_name', 'error', 'poll')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._store_cert(): exc_cert_add_error', lcm.output)

    def test_145_certificate__account_check(self):
        """ test Certificate._account_check() - dbstore.certificate_account_check raises an exception  """
        self.certificate.dbstore.certificate_account_check.side_effect = Exception('exc_acc_chk')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._account_check('account_name', 'cert')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._account_check(): exc_acc_chk', lcm.output)

    def test_146_certificate__authorization_check(self):
        """ test Certificate._authorization_check() - dbstore.certificate_account_check raises an exception  """
        self.certificate.dbstore.order_lookup.side_effect = Exception('exc_authz_chk')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._authorization_check('order_name', 'cert')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._authorization_check(): exc_authz_chk', lcm.output)

    @patch('acme_srv.certificate.Certificate._info')
    def test_147_certificate__csr_check(self, mock_certinfo):
        """ csr-check - dbstore.order_lookup() raises an exception """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.side_effect = Exception('exc_csr_chk')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._csr_check('cert_name', 'csr')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._csr_check(): exc_csr_chk', lcm.output)
        # self.certificate.dbstore.order_lookup.side_effect = []

    def test_148_certificate__info(self):
        """ test Certificate._info - dbstore.certificate_lookup() raises an exception  """
        self.certificate.dbstore.certificate_lookup.side_effect = Exception('exc_cert_info')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._info('cert_name')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._info(): exc_cert_info', lcm.output)

    @patch('acme_srv.certificate.uts_now')
    def test_149__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - one certificate returned """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 90000
        result = [{'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 100000, 'issue_uts': 1000, 'created_at': datetime.datetime(1970, 1, 1, 9, 30, 0)}]
        self.certificate.dbstore.certificates_search.return_value = result
        self.assertEqual((None, 'cert1', 'cert_raw1', 'reused certificate from id: 1'), self.certificate._cert_reusage_check('csr'))

    @patch('acme_srv.certificate.uts_now')
    def test_150__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - two certificates found """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 90000
        result = [
            {'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 100001, 'issue_uts': 1001, 'created_at': datetime.datetime(1970, 1, 1, 9, 31, 0)},
            {'id': 2, 'cert': 'cert2', 'cert_raw': 'cert_raw2', 'expire_uts': 100002, 'issue_uts': 1002, 'created_at': datetime.datetime(1970, 1, 1, 9, 32, 0)}
            ]
        self.certificate.dbstore.certificates_search.return_value = result
        self.assertEqual((None, 'cert2', 'cert_raw2', 'reused certificate from id: 2'), self.certificate._cert_reusage_check('csr'))

    @patch('acme_srv.certificate.uts_now')
    def test_151__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - three certificates found """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 90000
        result = [
            {'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 100001, 'issue_uts': 1001, 'created_at': datetime.datetime(1970, 1, 1, 9, 31, 0)},
            {'id': 2, 'cert': 'cert2', 'cert_raw': 'cert_raw2', 'expire_uts': 100002, 'issue_uts': 1002, 'created_at': datetime.datetime(1970, 1, 1, 9, 32, 0)},
            {'id': 3, 'cert': 'cert3', 'cert_raw': 'cert_raw3', 'expire_uts': 100003, 'issue_uts': 1003, 'created_at': datetime.datetime(1970, 1, 1, 9, 33, 0)}
            ]
        self.certificate.dbstore.certificates_search.return_value = result
        self.assertEqual((None, 'cert3', 'cert_raw3', 'reused certificate from id: 3'), self.certificate._cert_reusage_check('csr'))

    @patch('acme_srv.certificate.uts_now')
    def test_152__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - three certificates found in wrong order """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 90000
        result = [
            {'id': 2, 'cert': 'cert2', 'cert_raw': 'cert_raw2', 'expire_uts': 100002, 'issue_uts': 1002, 'created_at': datetime.datetime(1970, 1, 1, 9, 32, 0)},
            {'id': 3, 'cert': 'cert3', 'cert_raw': 'cert_raw3', 'expire_uts': 100003, 'issue_uts': 1003, 'created_at': datetime.datetime(1970, 1, 1, 9, 33, 0)},
            {'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 100001, 'issue_uts': 1001, 'created_at': datetime.datetime(1970, 1, 1, 9, 31, 0)}
            ]
        self.certificate.dbstore.certificates_search.return_value = result
        self.assertEqual((None, 'cert3', 'cert_raw3', 'reused certificate from id: 3'), self.certificate._cert_reusage_check('csr'))

    @patch('acme_srv.certificate.uts_now')
    def test_153__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - three certificates found latest certificate exipred """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 90000
        result = [
            {'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 100001, 'issue_uts': 1001, 'created_at': datetime.datetime(1970, 1, 1, 9, 31, 0)},
            {'id': 2, 'cert': 'cert2', 'cert_raw': 'cert_raw2', 'expire_uts': 100002, 'issue_uts': 1002, 'created_at': datetime.datetime(1970, 1, 1, 9, 32, 0)},
            {'id': 3, 'cert': 'cert3', 'cert_raw': 'cert_raw3', 'expire_uts': 2003, 'issue_uts': 1003, 'created_at': datetime.datetime(1970, 1, 1, 9, 33, 0)}
            ]
        self.certificate.dbstore.certificates_search.return_value = result
        self.assertEqual((None, 'cert2', 'cert_raw2', 'reused certificate from id: 2'), self.certificate._cert_reusage_check('csr'))

    @patch('acme_srv.certificate.uts_now')
    def test_154__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - three certificates found - last certificate empty cert field """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 90000
        result = [
            {'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 100001, 'issue_uts': 1001, 'created_at': datetime.datetime(1970, 1, 1, 9, 31, 0)},
            {'id': 2, 'cert': 'cert2', 'cert_raw': 'cert_raw2', 'expire_uts': 100002, 'issue_uts': 1002, 'created_at': datetime.datetime(1970, 1, 1, 9, 32, 0)},
            {'id': 3, 'cert': '', 'cert_raw': 'cert_raw3', 'expire_uts': 100003, 'issue_uts': 1003, 'created_at': datetime.datetime(1970, 1, 1, 9, 33, 0)}
            ]
        self.certificate.dbstore.certificates_search.return_value = result
        self.assertEqual((None, 'cert2', 'cert_raw2', 'reused certificate from id: 2'), self.certificate._cert_reusage_check('csr'))

    @patch('acme_srv.certificate.uts_now')
    def test_155__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - three certificates found - last certificate empty cert_raw field """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 90000
        result = [
            {'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 100001, 'issue_uts': 1001, 'created_at': datetime.datetime(1970, 1, 1, 9, 31, 0)},
            {'id': 2, 'cert': 'cert2', 'cert_raw': 'cert_raw2', 'expire_uts': 100002, 'issue_uts': 1002, 'created_at': datetime.datetime(1970, 1, 1, 9, 32, 0)},
            {'id': 3, 'cert': 'cert3', 'cert_raw': '', 'expire_uts': 100003, 'issue_uts': 1003, 'created_at': datetime.datetime(1970, 1, 1, 9, 33, 0)}
            ]
        self.certificate.dbstore.certificates_search.return_value = result
        self.assertEqual((None, 'cert2', 'cert_raw2', 'reused certificate from id: 2'), self.certificate._cert_reusage_check('csr'))

    @patch('acme_srv.certificate.uts_now')
    def test_156__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - three certificates found - last certificate empty 'created_add' """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 90000
        result = [
            {'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 100001, 'issue_uts': 1001, 'created_at': datetime.datetime(1970, 1, 1, 9, 31, 0)},
            {'id': 2, 'cert': 'cert2', 'cert_raw': 'cert_raw2', 'expire_uts': 100002, 'issue_uts': 1002, 'created_at': datetime.datetime(1970, 1, 1, 9, 32, 0)},
            {'id': 3, 'cert': 'cert3', 'cert_raw': '', 'expire_uts': 100003, 'issue_uts': 1003, 'created_at': ''}
            ]
        self.certificate.dbstore.certificates_search.return_value = result
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'cert2', 'cert_raw2', 'reused certificate from id: 2'), self.certificate._cert_reusage_check('csr'))
            self.assertIn('ERROR:test_a2c:acme2certifier date_to_uts_utc() error in Certificate._cert_reusage_check(): id:3/created_at:', lcm.output)

    @patch('acme_srv.certificate.uts_now')
    def test_157__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - three certificates found last certificate out of range """
        self.certificate.cert_reusage_timeframe = 43200
        mock_uts.return_value = 100000
        result = [
            {'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 100001, 'issue_uts': 1001, 'created_at': datetime.datetime(1970, 1, 2, 9, 31, 0)},
            {'id': 2, 'cert': 'cert2', 'cert_raw': 'cert_raw2', 'expire_uts': 100002, 'issue_uts': 1002, 'created_at': datetime.datetime(1970, 1, 2, 9, 32, 0)},
            {'id': 3, 'cert': 'cert3', 'cert_raw': 'cert_raw3', 'expire_uts': 100003, 'issue_uts': 1003, 'created_at': datetime.datetime(1970, 1, 1, 9, 33, 0)}
            ]
        self.certificate.dbstore.certificates_search.return_value = result
        self.assertEqual((None, 'cert2', 'cert_raw2', 'reused certificate from id: 2'), self.certificate._cert_reusage_check('csr'))

    @patch('acme_srv.certificate.uts_now')
    def test_158__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - no match """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 200000
        result = [
            {'id': 1, 'cert': 'cert1', 'cert_raw': 'cert_raw1', 'expire_uts': 300001, 'issue_uts': 1001, 'created_at': datetime.datetime(1970, 1, 1, 9, 31, 0)},
            {'id': 2, 'cert': 'cert2', 'cert_raw': 'cert_raw2', 'expire_uts': 300002, 'issue_uts': 1002, 'created_at': datetime.datetime(1970, 1, 1, 9, 32, 0)},
            {'id': 3, 'cert': 'cert3', 'cert_raw': 'cert_raw3', 'expire_uts': 300003, 'issue_uts': 1003, 'created_at': datetime.datetime(1970, 1, 1, 9, 33, 0)}
            ]
        self.certificate.dbstore.certificates_search.return_value = result
        self.assertEqual((None, None, None, None), self.certificate._cert_reusage_check('csr'))

    @patch('acme_srv.certificate.Certificate._invalidation_check')
    def test_159_certificate_cleanup(self, mock_chk):
        """ test Certificate.cleanup - dbstore.certificate_add() raises an exception  """
        mock_chk.return_value = (True, {'name': 'name', 'expire_uts': 1543640400, 'issue_uts': 1543640400, 'cert_raw': 'cert_raw'})
        self.certificate.dbstore.certificates_search.return_value = [{'name', 'name'},]
        self.certificate.dbstore.certificate_add.side_effect = Exception('exc_cert_cleanup1')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.cleanup(1543640400)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.cleanup() add: exc_cert_cleanup1', lcm.output)

    @patch('acme_srv.certificate.Certificate._invalidation_check')
    def test_160_certificate_cleanup(self, mock_chk):
        """ test Certificate.cleanup - dbstore.certificate_delete() raises an exception  """
        mock_chk.return_value = (True, {'id': 2, 'name': 'name', 'expire_uts': 1543640400, 'issue_uts': 1543640400, 'cert_raw': 'cert_raw'})
        self.certificate.dbstore.certificates_search.return_value = [{'name', 'name'},]
        self.certificate.dbstore.certificate_delete.side_effect = Exception('exc_cert_cleanup2')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.cleanup(1543640400, True)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.cleanup() delete: exc_cert_cleanup2', lcm.output)

    def test_161_certificate_cleanup(self):
        """ test Certificate.cleanup - dbstore.certificates_search() raises an exception  """
        self.certificate.dbstore.certificates_search.side_effect = Exception('exc_cert_cleanup')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.cleanup('timestamp')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.cleanup() search: exc_cert_cleanup', lcm.output)

    @patch('acme_srv.certificate.uts_now')
    def test_162__cert_reusage_check(self, mock_uts):
        """ test Certificate._cert_reusage_check() - one certificate returned """
        self.certificate.cert_reusage_timeframe = 86400
        mock_uts.return_value = 90000
        self.certificate.dbstore.certificates_search.side_effect = Exception('ex_cert_reusage')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None, None), self.certificate._cert_reusage_check('csr'))
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._cert_reusage_check(): ex_cert_reusage', lcm.output)

    @patch('acme_srv.certificate.load_config')
    def test_163_config_load(self, mock_load_cfg):
        """ test _config_load empty dictionary """
        mock_load_cfg.return_value = {}
        self.certificate._config_load()
        self.assertFalse(self.certificate.tnauthlist_support)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_164_config_load(self, mock_load_cfg):
        """ test _config_load missing ca_handler """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertIn('ERROR:test_a2c:Helper.ca_handler_load(): CAhandler configuration missing in config file', lcm.output)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_165_config_load(self, mock_load_cfg):
        """ test _config_load missing ca_handler """
        parser = configparser.ConfigParser()
        parser['Order'] = {'tnauthlist_support': False}
        mock_load_cfg.return_value = parser
        self.certificate._config_load()
        self.assertFalse(self.certificate.tnauthlist_support)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_166_config_load(self, mock_load_cfg):
        """ test _config_load missing ca_handler """
        parser = configparser.ConfigParser()
        parser['Order'] = {'tnauthlist_support': True}
        mock_load_cfg.return_value = parser
        self.certificate._config_load()
        self.assertTrue(self.certificate.tnauthlist_support)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.ca_handler_load')
    @patch('acme_srv.certificate.load_config')
    def test_167_config_load(self, mock_load_cfg, mock_handler):
        """ test _config_load missing ca_handler """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'handler_file': 'foo'}
        mock_load_cfg.return_value = parser
        mock_handler.return_value = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertIn('CRITICAL:test_a2c:Certificate._config_load(): No ca_handler loaded', lcm.output)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('importlib.import_module')
    @patch('acme_srv.certificate.load_config')
    def test_168_config_load(self, mock_load_cfg, mock_imp):
        """ test _config_load missing ca_handler """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'handler_file': 'foo'}
        mock_load_cfg.return_value = parser
        mock_imp.return_value = Mock()
        self.certificate._config_load()
        self.assertTrue(self.certificate.cahandler)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_169_config_load(self, mock_load_cfg):
        """ test _config_load missing ca_handler """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'foo': 'bar', 'url_prefix': 'url_prefix'}
        mock_load_cfg.return_value = parser
        self.certificate._config_load()
        self.assertFalse(self.certificate.tnauthlist_support)
        self.assertEqual({'cert_path': 'url_prefix/acme/cert/'}, self.certificate.path_dic)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('importlib.import_module')
    @patch('acme_srv.certificate.load_config')
    def test_170_config_load(self, mock_load_cfg, mock_imp):
        """ test _config_load  ca_handler but no handler_file """
        parser = configparser.ConfigParser()
        parser['CAhandler'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        mock_imp.return_value = Mock()
        self.certificate._config_load()
        self.assertTrue(mock_imp.called)
        self.assertTrue(self.certificate.cahandler)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_171_config_load(self, mock_load_cfg):
        """ test _config_load no cert_reusage_timeframe """
        parser = configparser.ConfigParser()
        parser['Certificate'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.certificate._config_load()
        self.assertFalse(self.certificate.cert_reusage_timeframe)
        self.assertEqual(5, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_172_config_load(self, mock_load_cfg):
        """ test _config_load cert_reusage_timeframe 120 """
        parser = configparser.ConfigParser()
        parser['Certificate'] = {'cert_reusage_timeframe': 1200}
        mock_load_cfg.return_value = parser
        self.certificate._config_load()
        self.assertEqual(1200, self.certificate.cert_reusage_timeframe)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_173_config_load(self, mock_load_cfg):
        """ test _config_load cert_reusage_timeframe 0 """
        parser = configparser.ConfigParser()
        parser['Certificate'] = {'cert_reusage_timeframe': 0}
        mock_load_cfg.return_value = parser
        self.certificate._config_load()
        self.assertFalse(self.certificate.cert_reusage_timeframe)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_174_config_load(self, mock_load_cfg):
        """ test _config_load cert_reusage_timeframe text """
        parser = configparser.ConfigParser()
        parser['Certificate'] = {'cert_reusage_timeframe': 'aaa'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertFalse(self.certificate.cert_reusage_timeframe)
        self.assertIn("ERROR:test_a2c:acme2certifier Certificate._config_load() cert_reusage_timout parsing error: invalid literal for int() with base 10: 'aaa'", lcm.output)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_175_config_load(self, mock_load_cfg):
        """ test _config_load enrollment_timeout 120 """
        parser = configparser.ConfigParser()
        parser['Certificate'] = {'enrollment_timeout': 120}
        mock_load_cfg.return_value = parser
        self.certificate._config_load()
        self.assertEqual(120, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.load_config')
    def test_176_config_load(self, mock_load_cfg):
        """ test _config_load certificate text """
        parser = configparser.ConfigParser()
        parser['Certificate'] = {'enrollment_timeout': 'aaa'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertEqual(5, self.certificate.enrollment_timeout)
        self.assertIn("ERROR:test_a2c:acme2certifier Certificate._config_load() enrollment_timeout parsing error: invalid literal for int() with base 10: 'aaa'", lcm.output)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.hooks_load')
    @patch('acme_srv.certificate.load_config')
    def test_177_config_load(self, mock_load_cfg, mock_hooks):
        """ test _config_load hooks_load() returns None """
        parser = configparser.ConfigParser()
        parser['Certificate'] = {'enrollment_timeout': 120}
        mock_load_cfg.return_value = parser
        mock_hooks.return_value = None
        self.certificate._config_load()
        self.assertEqual(120, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.hooks_load')
    @patch('acme_srv.certificate.load_config')
    def test_178_config_load(self, mock_load_cfg, mock_hooks):
        """ test _config_load hooks_load() returns module """
        parser = configparser.ConfigParser()
        parser['Certificate'] = {'enrollment_timeout': 120}
        mock_load_cfg.return_value = parser
        mock_hooks = Mock(return_value='foo')
        self.certificate._config_load()
        self.assertEqual(120, self.certificate.enrollment_timeout)
        self.assertTrue(self.certificate.hooks)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.hooks_load')
    @patch('acme_srv.certificate.load_config')
    def test_179_config_load(self, mock_load_cfg, mock_hooks):
        """ test _config_load hooks_load() returns non-module object """
        parser = configparser.ConfigParser()
        parser['Certificate'] = {'enrollment_timeout': 120}
        mock_load_cfg.return_value = parser
        mock_hooks.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertEqual(120, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertIn("CRITICAL:test_a2c:Certificate._config_load(): Hooks could not be loaded: 'str' object has no attribute 'Hooks'", lcm.output)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.hooks_load')
    @patch('acme_srv.certificate.load_config')
    def test_180_config_load(self, mock_load_cfg, mock_hooks):
        """ test _config_load ignore_pre_hook_failure False """
        parser = configparser.ConfigParser()
        parser['Hooks'] = {'ignore_pre_hook_failure': False}
        mock_load_cfg.return_value = parser
        mock_hooks.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertEqual(5, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertIn("CRITICAL:test_a2c:Certificate._config_load(): Hooks could not be loaded: 'str' object has no attribute 'Hooks'", lcm.output)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.hooks_load')
    @patch('acme_srv.certificate.load_config')
    def test_181_config_load(self, mock_load_cfg, mock_hooks):
        """ test _config_load ignore_pre_hook_failure True """
        parser = configparser.ConfigParser()
        parser['Hooks'] = {'ignore_pre_hook_failure': True}
        mock_load_cfg.return_value = parser
        mock_hooks.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertEqual(5, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertIn("CRITICAL:test_a2c:Certificate._config_load(): Hooks could not be loaded: 'str' object has no attribute 'Hooks'", lcm.output)
        self.assertTrue(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.hooks_load')
    @patch('acme_srv.certificate.load_config')
    def test_182_config_load(self, mock_load_cfg, mock_hooks):
        """ test _config_load ignore_post_hook_failure False """
        parser = configparser.ConfigParser()
        parser['Hooks'] = {'ignore_post_hook_failure': False}
        mock_load_cfg.return_value = parser
        mock_hooks.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertEqual(5, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertIn("CRITICAL:test_a2c:Certificate._config_load(): Hooks could not be loaded: 'str' object has no attribute 'Hooks'", lcm.output)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertFalse(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.hooks_load')
    @patch('acme_srv.certificate.load_config')
    def test_183_config_load(self, mock_load_cfg, mock_hooks):
        """ test _config_load ignore_post_hook_failure True """
        parser = configparser.ConfigParser()
        parser['Hooks'] = {'ignore_post_hook_failure': True}
        mock_load_cfg.return_value = parser
        mock_hooks.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertEqual(5, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertIn("CRITICAL:test_a2c:Certificate._config_load(): Hooks could not be loaded: 'str' object has no attribute 'Hooks'", lcm.output)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.hooks_load')
    @patch('acme_srv.certificate.load_config')
    def test_184_config_load(self, mock_load_cfg, mock_hooks):
        """ test _config_load ignore_success_hook_failure False """
        parser = configparser.ConfigParser()
        parser['Hooks'] = {'ignore_success_hook_failure': False}
        mock_load_cfg.return_value = parser
        mock_hooks.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertEqual(5, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertIn("CRITICAL:test_a2c:Certificate._config_load(): Hooks could not be loaded: 'str' object has no attribute 'Hooks'", lcm.output)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertFalse(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.hooks_load')
    @patch('acme_srv.certificate.load_config')
    def test_185_config_load(self, mock_load_cfg, mock_hooks):
        """ test _config_load ignore_success_hook_failure True """
        parser = configparser.ConfigParser()
        parser['Hooks'] = {'ignore_success_hook_failure': True}
        mock_load_cfg.return_value = parser
        mock_hooks.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertEqual(5, self.certificate.enrollment_timeout)
        self.assertFalse(self.certificate.hooks)
        self.assertIn("CRITICAL:test_a2c:Certificate._config_load(): Hooks could not be loaded: 'str' object has no attribute 'Hooks'", lcm.output)
        self.assertFalse(self.certificate.ignore_pre_hook_failure)
        self.assertTrue(self.certificate.ignore_post_hook_failure)
        self.assertTrue(self.certificate.ignore_success_hook_failure)

    @patch('acme_srv.certificate.cert_san_get')
    def test_186_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check - cert_san_get raises exception) """
        self.certificate.dbstore.order_lookup.side_effect = None
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.side_effect = Exception('cert_san_get')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))
        self.assertIn('WARNING:test_a2c:Certificate._authorization_check() error while loading parsing certifcate. Error: cert_san_get', lcm.output)

    @patch('acme_srv.certificate.Certificate._identifer_status_list')
    @patch('acme_srv.certificate.cert_san_get')
    def test_187_certificate__authorization_check(self, mock_san, mock_statlist):
        """ test Certificate.authorization_check - cert_san_get raises exception) """
        self.certificate.dbstore.order_lookup.side_effect = None
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['foo']
        mock_statlist.side_effect = Exception('idstat_exc')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))
        self.assertIn('WARNING:test_a2c:Certificate._authorization_check() error while loading parsing certifcate. Error: idstat_exc', lcm.output)

    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.cert_extensions_get')
    def test_188_certificate__authorization_check(self, mock_certext, mock_tnin):
        """ test Certificate.authorization_check cert_extensions_get raises exception) """
        self.certificate.dbstore.order_lookup.side_effect = None
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        self.certificate.tnauthlist_support = True
        mock_tnin.return_value = True
        mock_certext.side_effect = Exception('cert_ext_get')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))
        self.assertIn('WARNING:test_a2c:Certificate._authorization_check() error while loading parsing certifcate. Error: cert_ext_get', lcm.output)

    @patch('acme_srv.certificate.Certificate._identifer_tnauth_list')
    @patch('acme_srv.certificate.Certificate._tnauth_identifier_check')
    @patch('acme_srv.certificate.cert_extensions_get')
    def test_189_certificate__authorization_check(self, mock_certext, mock_tnin, mock_tnlist):
        """ test Certificate.authorization_check _identifer_tnauth_list raises exception) """
        self.certificate.dbstore.order_lookup.side_effect = None
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        self.certificate.tnauthlist_support = True
        mock_tnin.return_value = True
        mock_certext.return_value = ['foo']
        mock_tnlist.side_effect = Exception('tnauth_in_exc')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))
        self.assertIn('WARNING:test_a2c:Certificate._authorization_check() error while loading parsing certifcate. Error: tnauth_in_exc', lcm.output)

    @patch('acme_srv.certificate.Certificate.certlist_search')
    def test_190_dates_update(self, mock_search):
        """ dates update """
        mock_search.return_value = [{'foo': 'bar'}, {'foo1': 'bar1'}]
        self.certificate.dates_update()

    @patch('acme_srv.certificate.Certificate.certlist_search')
    def test_191_dates_update(self, mock_search):
        """ dates update """
        mock_search.return_value = [{'issue_uts': 0, 'expire_uts': 0, 'cert_raw': 'cert_raw'}, {'foo1': 'bar1'}]
        self.certificate.dates_update()

    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate.certlist_search')
    def test_192_dates_update(self, mock_search, mock_dates_get, mock_store):
        """ dates update with a none zero issue-uts """
        mock_search.return_value = [{'issue_uts': 2, 'expire_uts': 0, 'cert_raw': 'cert_raw', 'name': 'name', 'cert': 'cert'}, {'foo1': 'bar1'}]
        mock_dates_get.return_value = (42, 42)
        self.certificate.dates_update()
        self.assertFalse(mock_dates_get.called)
        self.assertFalse(mock_store.called)

    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate.certlist_search')
    def test_193_dates_update(self, mock_search, mock_dates_get, mock_store):
        """ dates update with a none zero expire-uts """
        mock_search.return_value = [{'issue_uts': 0, 'expire_uts': 2, 'cert_raw': 'cert_raw', 'name': 'name', 'cert': 'cert'}, {'foo1': 'bar1'}]
        mock_dates_get.return_value = (42, 42)
        self.certificate.dates_update()
        self.assertFalse(mock_dates_get.called)
        self.assertFalse(mock_store.called)

    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate.certlist_search')
    def test_194_dates_update(self, mock_search, mock_dates_get, mock_store):
        """ dates update call _cert_store """
        mock_search.return_value = [{'issue_uts': 0, 'expire_uts': 0, 'cert_raw': 'cert_raw', 'name': 'name', 'cert': 'cert'}, {'foo1': 'bar1'}]
        mock_dates_get.return_value = (42, 42)
        self.certificate.dates_update()
        self.assertTrue(mock_dates_get.called)
        self.assertTrue(mock_store.called)

    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate.certlist_search')
    def test_195_dates_update(self, mock_search, mock_dates_get, mock_store):
        """ dates update call _cert_store """
        mock_search.return_value = [{'issue_uts': 0, 'expire_uts': 0, 'cert_raw': 'cert_raw', 'name': 'name', 'cert': 'cert'}, {'foo1': 'bar1'}]
        mock_dates_get.return_value = (42, 0)
        self.certificate.dates_update()
        self.assertTrue(mock_dates_get.called)
        self.assertTrue(mock_store.called)

    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate.certlist_search')
    def test_196_dates_update(self, mock_search, mock_dates_get, mock_store):
        """ dates update call _cert_store """
        mock_search.return_value = [{'issue_uts': 0, 'expire_uts': 0, 'cert_raw': 'cert_raw', 'name': 'name', 'cert': 'cert'}, {'foo1': 'bar1'}]
        mock_dates_get.return_value = (0, 42)
        self.certificate.dates_update()
        self.assertTrue(mock_dates_get.called)
        self.assertTrue(mock_store.called)

    @patch('acme_srv.certificate.Certificate._store_cert')
    @patch('acme_srv.certificate.cert_dates_get')
    @patch('acme_srv.certificate.Certificate.certlist_search')
    def test_197_dates_update(self, mock_search, mock_dates_get, mock_store):
        """ dates update do not call _cert_store bcs cert_dates_get return 0/0 """
        mock_search.return_value = [{'issue_uts': 0, 'expire_uts': 0, 'cert_raw': 'cert_raw', 'name': 'name', 'cert': 'cert'}, {'foo1': 'bar1'}]
        mock_dates_get.return_value = (0, 0)
        self.certificate.dates_update()
        self.assertTrue(mock_dates_get.called)
        self.assertFalse(mock_store.called)

    def test_198_order_update(self):
        """ test Certificate._order_update - dbstore.order_update() raises an exception  """
        self.certificate.dbstore.order_update.side_effect = Exception('exc_order_upd')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._order_update({'url': 'url'})
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._order_update(): exc_order_upd', lcm.output)

    def test_199_certificate_certlist_search(self):
        """ test Certificate.certlist_search - dbstore.certificates_search() raises an exception  """
        self.certificate.dbstore.certificates_search.side_effect = Exception('exc_certlist_search')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.certlist_search('type', 'value')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.certlist_search(): exc_certlist_search', lcm.output)

if __name__ == '__main__':
    unittest.main()
