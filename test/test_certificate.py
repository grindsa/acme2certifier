#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
import json
import importlib
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
        models_mock.acme.db_handler.DBstore.return_value = FakeDBStore
        modules = {'acme.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from acme.account import Account
        from acme.certificate import Certificate
        self.account = Account(False, 'http://tester.local', self.logger)
        self.certificate = Certificate(False, 'http://tester.local', self.logger)

    @patch('acme.certificate.generate_random_string')
    def test_001_certificate_store_csr(self, mock_name):
        """ test Certificate.store_csr() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'foo'
        mock_name.return_value = 'bar'
        self.assertEqual('bar', self.certificate.store_csr('order_name', 'csr'))

    def test_002_certificate__store_cert(self):
        """ test Certificate.store_cert() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'bar'
        self.assertEqual('bar', self.certificate._store_cert('cert_name', 'cert', 'raw'))

    def test_003_certificate__info(self):
        """ test Certificate.new_get() """
        self.certificate.dbstore.certificate_lookup.return_value = 'foo'
        self.assertEqual('foo', self.certificate._info('cert_name'))

    @patch('acme.certificate.Certificate._info')
    def test_004_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without certificate"""
        mock_info.return_value = {}
        self.assertEqual({'code': 500, 'data': 'urn:ietf:params:acme:error:serverInternal'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_005_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without unknown order_status_id"""
        mock_info.return_value = {'order__status_id': 'foo'}
        self.assertEqual({'code': 403, 'data': 'urn:ietf:params:acme:error:orderNotReady'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_006_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 4 (processing)"""
        mock_info.return_value = {'order__status_id': 4}
        self.assertEqual({'code': 403, 'data': 'urn:ietf:params:acme:error:rateLimited', 'header': {'Retry-After': '600'}}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_007_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) but no certificate in"""
        mock_info.return_value = {'order__status_id': 5}
        self.assertEqual({'code': 500, 'data': 'urn:ietf:params:acme:error:serverInternal'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_008_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) and empty certificate field"""
        mock_info.return_value = {'order__status_id': 5, 'cert': None}
        self.assertEqual({'code': 500, 'data': 'urn:ietf:params:acme:error:serverInternal'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_009_certificate_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) but no certificate in"""
        mock_info.return_value = {'order__status_id': 5, 'cert': 'foo-bar'}
        self.assertEqual({'code': 200, 'data': 'foo-bar', 'header': {'Content-Type': 'application/pem-certificate-chain'}}, self.certificate.new_get('url'))

    @patch('acme.message.Message.check')
    def test_010_certificate_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  json.dumps({'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'detail'})}, self.certificate.new_post('content'))

    @patch('acme.message.Message.check')
    def test_011_certificate_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': json.dumps({'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'url missing in protected header'})}, self.certificate.new_post('content'))

    @patch('acme.message.Message.prepare_response')
    @patch('acme.certificate.Certificate.new_get')
    @patch('acme.message.Message.check')
    def test_012_certificate_new_post(self, mock_mcheck, mock_certget, mock_response):
        """ test Certificate.new_post() message check returns ok  """
        mock_mcheck.return_value = (200, None, None, {'url' : 'example.com'}, 'payload', 'account_name')
        mock_certget.return_value = {'code': 403, 'data': 'foo'}
        mock_response.return_value = {'data': 'foo'}
        self.assertEqual({'data': 'foo'}, self.certificate.new_post('content'))

    def test_013_certificate__revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with allowed reason"""
        rev_reason = 0
        self.assertEqual('unspecified', self.certificate._revocation_reason_check(rev_reason))

    def test_014_certificate__revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with non-allowed reason"""
        rev_reason = 8
        self.assertFalse(self.certificate._revocation_reason_check(rev_reason))

    @patch('acme.certificate.cert_san_get')
    def test_015_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans but failed order lookup"""
        self.certificate.dbstore.order_lookup.return_value = {}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_016_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order returning wrong values (no 'identifiers' key) """
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_017_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order lookup returning identifiers without json structure) """
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_018_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with wrong sans) """
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_019_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with SAN entry which is not in the identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_020_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with single SAN entry and correct entry in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_021_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with multiple SAN entries and correct entries in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_022_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with one SAN entry and multiple entries in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_023_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with uppercase SAN entries and lowercase entries in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:SAN1.EXAMPLE.COM', 'DNS:SAN2.EXAMPLE.COM']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_024_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lowercase SAN entries and uppercase entries in identifier list"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"TYPE": "DNS", "VALUE": "SAN1.EXAMPLE.COM"}, {"TYPE": "DNS", "VALUE": "SAN2.EXAMPLE.COM"}]'}
        mock_san.return_value = ['dns:san1.example.com', 'dns:san2.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_025_certificate__authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lSAN entries (return none) and entries in identifier containing None"""
        self.certificate.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "None", "value": "None"}]'}
        mock_san.return_value = ['san1.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_026_certificate__revocation_request_validate(self):
        """ test Certificate.revocation_request_validate empty payload"""
        payload = {}
        self.assertEqual((400, 'unspecified'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_027_certificate__revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns None"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:badRevocationReason'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_028_certificate__revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns a reason"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = 'revrcheck'
        self.assertEqual((400, 'revrcheck'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._authorization_check')
    @patch('acme.certificate.Certificate._account_check')
    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_029_certificate__revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check failed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._authorization_check')
    @patch('acme.certificate.Certificate._account_check')
    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_030_certificate__revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check succeed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = True
        self.assertEqual((200, 'revrcheck'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.message.Message.check')
    def test_031_certificate_revoke(self, mock_mcheck):
        """ test Certificate.revoke with failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'message', 'detail': 'detail'}}, self.certificate.revoke('content'))

    @patch('acme.message.Message.check')
    def test_032_certificate_revoke(self, mock_mcheck):
        """ test Certificate.revoke with incorrect payload """
        mock_mcheck.return_value = (200, 'message', 'detail', None, {}, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'certificate not found'}}, self.certificate.revoke('content'))

    @patch('acme.certificate.Certificate._revocation_request_validate')
    @patch('acme.message.Message.check')
    def test_033_certificate_revoke(self, mock_mcheck, mock_validate):
        """ test Certificate.revoke with failed request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (400, 'error')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'error'}}, self.certificate.revoke('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.certificate.Certificate._revocation_request_validate')
    @patch('acme.message.Message.check')
    def test_034_certificate_revoke(self, mock_mcheck, mock_validate, mock_nnonce):
        """ test Certificate.revoke with sucessful request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (200, 'reason')
        mock_nnonce.return_value = 'new_nonce'
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.revoke = Mock(return_value=(200, 'message', 'detail'))
        self.assertEqual({'code': 200, 'header': {'Replay-Nonce': 'new_nonce'}}, self.certificate.revoke('content'))

    def test_035_certificate__revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with a valid revocation reason"""
        self.assertEqual('unspecified', self.certificate._revocation_reason_check(0))

    def test_036_certificate__revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with an invalid revocation reason"""
        self.assertFalse(self.certificate._revocation_reason_check(2))

    def test_037_certificate__tnauth_identifier_check(self):
        """ identifier check empty """
        identifier_dic = []
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_038_certificate__tnauth_identifier_check(self):
        """ identifier check none input"""
        identifier_dic = None
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_039_certificate__tnauth_identifier_check(self):
        """ identifier check none input"""
        identifier_dic = 'foo'
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_040_certificate__tnauth_identifier_check(self):
        """ identifier check one identifier """
        identifier_dic = [{'foo': 'bar'}]
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_041_certificate__tnauth_identifier_check(self):
        """ identifier check two identifiers """
        identifier_dic = [{'foo': 'bar'}, {'foo': 'bar'}]
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_042_certificate__tnauth_identifier_check(self):
        """ identifier check hit first identifiers """
        identifier_dic = [{'type': 'bar'}, {'foo': 'bar'}]
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_043_certificate__tnauth_identifier_check(self):
        """ identifier check hit first identifiers """
        identifier_dic = [{'type': 'TNAUTHLIST'}, {'foo': 'bar'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_044_certificate__tnauth_identifier_check(self):
        """ identifier check hit first identifiers """
        identifier_dic = [{'type': 'tnauthlist'}, {'foo': 'bar'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_045_certificate__tnauth_identifier_check(self):
        """ identifier check hit 2nd identifiers """
        identifier_dic = [{'type': 'bar'}, {'type': 'tnauthlist'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_046_certificate__tnauth_identifier_check(self):
        """ identifier check hit 2nd identifiers """
        identifier_dic = [{'type': 'bar'}, {'type': 'TNAUTHLIST'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_047_certificate__identifer_status_list(self):
        """ failed check identifiers against san """
        identifier_dic = [{'foo': 'bar'}, {'foo': 'bar'}]
        san_list = ['foo:bar', 'foo:bar']
        self.assertEqual([False, False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_048_certificate__identifer_status_list(self):
        """ failed check no sans """
        identifier_dic = [{'foo': 'bar'}]
        san_list = []
        self.assertEqual([], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_049_certificate__identifer_status_list(self):
        """ failed check no identifiers """
        identifier_dic = []
        san_list = ['foo:bar']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_050_certificate__identifer_status_list(self):
        """ failed check no identifiers """
        identifier_dic = []
        san_list = ['bar']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_051_certificate__identifer_status_list(self):
        """ succ check no identifiers """
        identifier_dic = [{'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar']
        self.assertEqual([True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_052_certificate__identifer_status_list(self):
        """ failed check san in identifier """
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}]
        san_list = ['dns:bar']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_053_certificate__identifer_status_list(self):
        """ failed check identifier in san """
        identifier_dic = [{'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar1']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_054_certificate__identifer_status_list(self):
        """ failed check identifier one identifier two sans"""
        identifier_dic = [{'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar', 'dns:bar2']
        self.assertEqual([True, False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_055_certificate__identifer_status_list(self):
        """ failed check identifier two identifier one san"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar1']
        self.assertEqual([True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_056_certificate__identifer_status_list(self):
        """ failed check identifier both ok"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar1', 'dns:bar2']
        self.assertEqual([True, True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_057_certificate__identifer_status_list(self):
        """ failed check identifier both ok - wrong order"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar2', 'dns:bar1']
        self.assertEqual([True, True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_058_certificate__identifer_status_list(self):
        """ failed check identifier first ok 2nd nok"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar1', 'dns:bar2']
        self.assertEqual([True, False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_059_certificate__identifer_status_list(self):
        """ failed check identifier first nook 2nd ok"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar', 'dns:bar2']
        self.assertEqual([False, True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_060_certificate__identifer_tnauth_list(self):
        """ empty identifier dic but tnauth exists """
        identifier_dic = []
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_061_certificate__identifer_tnauth_list(self):
        """ identifier dic but no tnauth """
        identifier_dic = {'foo': 'bar'}
        tnauthlist = None
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_062_certificate__identifer_tnauth_list(self):
        """ wrong identifier """
        identifier_dic = {'identifiers': '[{"foo": "bar"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_063_certificate__identifer_tnauth_list(self):
        """ wrong type """
        identifier_dic = {'identifiers': '[{"type": "bar"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_064_certificate__identifer_tnauth_list(self):
        """ correct type but no value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_065_certificate__identifer_tnauth_list(self):
        """ correct type but wrong value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt", "value": "bar"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_066_certificate__identifer_tnauth_list(self):
        """ correct type but wrong value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt", "value": "foo"}]'}
        tnauthlist = 'foo'
        self.assertEqual([True], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_067_certificate__identifer_tnauth_list(self):
        """ correct type but wrong value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt", "value": "foo"}, {"type": "dns", "value": "foo"}]'}
        tnauthlist = 'foo'
        self.assertEqual([True, False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    @patch('acme.certificate.Certificate._info')
    def test_068_certificate__csr_check(self, mock_certinfo):
        """ csr-check certname lookup failed """
        mock_certinfo.return_value = {}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.Certificate._info')
    def test_069_certificate__csr_check(self, mock_certinfo):
        """ csr-check order lookup failed """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.return_value = {}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.Certificate._info')
    def test_070_certificate__csr_check(self, mock_certinfo):
        """ csr-check order lookup returns rubbish """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.Certificate._info')
    def test_071_certificate__csr_check(self, mock_certinfo):
        """ csr-check order lookup returns an identifier """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_072_certificate__csr_check(self, mock_certinfo, mock_tnauthin):
        """ csr-check no tnauth """
        mock_certinfo.return_value = {'order': 'order'}
        mock_tnauthin.return_value = False
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_073_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check no tnauth  status true """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_074_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check no tnauth  status False """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_075_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check no tnauth  status True, False """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_076_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check no tnauth  status True, False, True """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False, True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_san_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_077_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support off  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_extensions_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_078_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns true  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_extensions_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_079_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns true  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [False]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_extensions_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_080_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns True, False  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_extensions_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_081_certificate__csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns True, False  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False, True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    def test_082_certificate__authorization_check(self):
        """ _authorization_check order lookup failed """
        self.certificate.dbstore.order_lookup.return_value = {}
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_083_certificate__authorization_check(self):
        """ _authorization_check order lookup returns rubbish """
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar'}
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_084_certificate__authorization_check(self):
        """ _authorization_check order lookup returns an identifier """
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_085_certificate__authorization_check(self, mock_tnauthin):
        """ _authorization_check no tnauth """
        mock_tnauthin.return_value = False
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_086_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status true """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_087_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status true """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_088_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status False """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_089_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status True, False """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_090_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status True, False, True """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False, True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_091_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support off  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_extensions_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_092_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support on and returns true  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_extensions_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_093_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support on and returns true  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [False]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_extensions_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_094_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support on and returns True, False  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_extensions_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_095_certificate__authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support on and returns True, False  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False, True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.Certificate._csr_check')
    def test_096_certificate_enroll_and_store(self, mock_csr):
        """ Certificate.enroll_and_store() csr_check failed """
        mock_csr.return_value = False
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual(('urn:ietf:params:acme:badCSR', 'CSR validation failed'), self.certificate.enroll_and_store(certificate_name, csr))

    @patch('acme.certificate.Certificate._store_cert_error')
    @patch('acme.certificate.Certificate._csr_check')
    def test_097_certificate_enroll_and_store(self, mock_csr, mock_store):
        """ Certificate.enroll_and_store() enrollment failed without polling_identifier """
        mock_csr.return_value = True
        mock_store.return_value = True
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=('error', None, None, None))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual(('urn:ietf:params:acme:error:serverInternal', None), self.certificate.enroll_and_store(certificate_name, csr))

    @patch('acme.certificate.Certificate._store_cert_error')
    @patch('acme.certificate.Certificate._csr_check')
    def test_098_certificate_enroll_and_store(self, mock_csr, mock_store):
        """ Certificate.enroll_and_store() enrollment with polling_identifier"""
        mock_csr.return_value = True
        mock_store.return_value = True
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=('error', None, None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual(('error', 'poll_identifier'), self.certificate.enroll_and_store(certificate_name, csr))

    @patch('acme.certificate.cert_dates_get')
    @patch('acme.certificate.Certificate._store_cert')
    @patch('acme.certificate.Certificate._csr_check')
    def test_099_certificate_enroll_and_store(self, mock_csr, mock_store, mock_dates):
        """ Certificate.enroll_and_store() enrollment with polling_identifier"""
        mock_csr.return_value = True
        mock_store.return_value = True
        mock_dates.return_value = (1, 2)
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.enroll = Mock(return_value=(None, 'certificate', None, 'poll_identifier'))
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual((None, None), self.certificate.enroll_and_store(certificate_name, csr))

    def test_100_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - empty dict """
        cert_entry = {}
        timestamp = 1596240000
        self.assertEqual((True, {}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_101_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - wrong dict """
        cert_entry = {'foo': 'bar'}
        timestamp = 1596240000
        self.assertEqual((True, {'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_102_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - certname in but rest ist wrong """
        cert_entry = {'name': 'certname', 'foo': 'bar'}
        timestamp = 1596240000
        self.assertEqual((False, {'name': 'certname', 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_103_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - non zero expiry date """
        cert_entry = {'name': 'certname', 'expire_uts': 10}
        timestamp = 1596240000
        self.assertEqual((True, {'expire_uts': 10, 'name': 'certname'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_104_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - expire_uts zero but no cert_raw """
        cert_entry = {'name': 'certname', 'expire_uts': 0}
        timestamp = 1596240000
        self.assertEqual((True, {'expire_uts': 0, 'name': 'certname'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_105_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - expire_uts zero but no cert_raw """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'cert_raw': 'cert_raw'}
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'cert_raw': 'cert_raw'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme.certificate.cert_dates_get')
    def test_106_certificate__invalidation_check(self, mock_dates):
        """ test Certificate._invalidation_check() - with expiry date lower than timestamp """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'cert_raw': 'cert_raw'}
        mock_dates.return_value = (10, 1596200000)
        timestamp = 1596240000
        self.assertEqual((True, {'expire_uts': 1596200000, 'issue_uts': 10, 'name': 'certname', 'cert_raw': 'cert_raw'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme.certificate.cert_dates_get')
    def test_107_certificate__invalidation_check(self, mock_dates):
        """ test Certificate._invalidation_check() - with expiry date at timestamp """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'cert_raw': 'cert_raw'}
        mock_dates.return_value = (10, 1596240000)
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'cert_raw': 'cert_raw'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme.certificate.cert_dates_get')
    def test_108_certificate__invalidation_check(self, mock_dates):
        """ test Certificate._invalidation_check() - with expiry date higher than timestamp """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'cert_raw': 'cert_raw'}
        mock_dates.return_value = (10, 1596250000)
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'cert_raw': 'cert_raw'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_109_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - without created_at date """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'csr': 'csr'}
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'csr': 'csr'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme.certificate.date_to_uts_utc')
    def test_110_certificate__invalidation_check(self, mock_date):
        """ test Certificate._invalidation_check() - with zero created_at date """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'csr': 'csr', 'created_at': 'created_at'}
        mock_date.return_value = 0
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'csr': 'csr', 'created_at': 'created_at'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme.certificate.date_to_uts_utc')
    def test_111_certificate__invalidation_check(self, mock_date):
        """ test Certificate._invalidation_check() - with zero created_at date lower than threshold"""
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'csr': 'csr', 'created_at': 'created_at'}
        mock_date.return_value = 1591240000
        timestamp = 1596240000
        self.assertEqual((True, {'expire_uts': 0, 'name': 'certname', 'csr': 'csr', 'created_at': 'created_at'}), self.certificate._invalidation_check(cert_entry, timestamp))

    @patch('acme.certificate.date_to_uts_utc')
    def test_112_certificate__invalidation_check(self, mock_date):
        """ test Certificate._invalidation_check() - with zero created_at higher than threshold """
        cert_entry = {'name': 'certname', 'expire_uts': 0, 'csr': 'csr', 'created_at': 'created_at'}
        mock_date.return_value = 1596220000
        timestamp = 1596240000
        self.assertEqual((False, {'expire_uts': 0, 'name': 'certname', 'csr': 'csr', 'created_at': 'created_at'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_113_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - removed by in cert """
        cert_entry = {'name': 'certname', 'cert': 'removed by foo-bar', 'foo': 'bar'}
        timestamp = 159624000
        self.assertEqual((False, {'name': 'certname', 'cert': 'removed by foo-bar', 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_114_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - removed by in cert """
        cert_entry = {'name': 'certname', 'cert': 'removed by foo-bar', 'foo': 'bar'}
        timestamp = 159624000
        self.assertEqual((True, {'name': 'certname', 'cert': 'removed by foo-bar', 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp, True))

    def test_115_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - removed by in cert but in upper-cases """
        cert_entry = {'name': 'certname', 'cert': 'ReMoved By foo-bar', 'foo': 'bar'}
        timestamp = 159624000
        self.assertEqual((False, {'name': 'certname', 'cert': 'ReMoved By foo-bar', 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_116_certificate__invalidation_check(self):
        """ test Certificate._invalidation_check() - cert None """
        cert_entry = {'name': 'certname', 'cert': None, 'foo': 'bar'}
        timestamp = 159624000
        self.assertEqual((False, {'name': 'certname', 'cert': None, 'foo': 'bar'}), self.certificate._invalidation_check(cert_entry, timestamp))

    def test_117_certificate_poll(self):
        """ test Certificate.poll - dbstore.order_update() raises an exception  """
        self.certificate.dbstore.order_update.side_effect = Exception('exc_cert_poll')
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.poll = Mock(return_value=('error', 'certificate', 'certificate_raw', 'poll_identifier', 'rejected'))
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.poll('certificate_name', 'poll_identifier', 'csr', 'order_name')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.poll(): exc_cert_poll', lcm.output)

    def test_118_certificate_poll(self):
        """ test Certificate.poll - dbstore.order_update() raises an exception  and certreq rejected """
        self.certificate.dbstore.order_update.side_effect = Exception('exc_cert_poll')
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.poll = Mock(return_value=('error', None, 'certificate_raw', 'poll_identifier', 'rejected'))
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.poll('certificate_name', 'poll_identifier', 'csr', 'order_name')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.poll(): exc_cert_poll', lcm.output)

    def test_119_certificate__store_cert(self):
        """ test Certificate.store_cert() - dbstore.certificate_add raises an exception  """
        self.certificate.dbstore.certificate_add.side_effect = Exception('exc_cert_add')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._store_cert('cert_name', 'cert', 'raw')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._store_cert(): exc_cert_add', lcm.output)

    def test_120_certificate__store_cert_error(self):
        """ test Certificate.store_cert_error() - dbstore.certificate_add raises an exception  """
        self.certificate.dbstore.certificate_add.side_effect = Exception('exc_cert_add_error')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._store_cert_error('cert_name', 'error', 'poll')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._store_cert(): exc_cert_add_error', lcm.output)

    def test_121_certificate__account_check(self):
        """ test Certificate._account_check() - dbstore.certificate_account_check raises an exception  """
        self.certificate.dbstore.certificate_account_check.side_effect = Exception('exc_acc_chk')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._account_check('account_name', 'cert')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._account_check(): exc_acc_chk', lcm.output)

    def test_122_certificate__authorization_check(self):
        """ test Certificate._authorization_check() - dbstore.certificate_account_check raises an exception  """
        self.certificate.dbstore.order_lookup.side_effect = Exception('exc_authz_chk')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._authorization_check('order_name', 'cert')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._authorization_check(): exc_authz_chk', lcm.output)

    @patch('acme.certificate.Certificate._info')
    def test_123_certificate__csr_check(self, mock_certinfo):
        """ csr-check - dbstore.order_lookup() raises an exception """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.side_effect = Exception('exc_csr_chk')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._csr_check('cert_name', 'csr')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._csr_check(): exc_csr_chk', lcm.output)

    def test_124_certificate__info(self):
        """ test Certificate._info - dbstore.certificate_lookup() raises an exception  """
        self.certificate.dbstore.certificate_lookup.side_effect = Exception('exc_cert_info')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._info('cert_name')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate._info(): exc_cert_info', lcm.output)

    @patch('acme.certificate.Certificate._invalidation_check')
    def test_125_certificate_cleanup(self, mock_chk):
        """ test Certificate.cleanup - dbstore.certificate_add() raises an exception  """
        mock_chk.return_value = (True, {'name': 'name', 'expire_uts': 1543640400, 'issue_uts': 1543640400, 'cert_raw': 'cert_raw'})
        self.certificate.dbstore.certificates_search.return_value = [{'name', 'name'},]
        self.certificate.dbstore.certificate_add.side_effect = Exception('exc_cert_cleanup1')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.cleanup(1543640400)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.cleanup() add: exc_cert_cleanup1', lcm.output)

    @patch('acme.certificate.Certificate._invalidation_check')
    def test_126_certificate_cleanup(self, mock_chk):
        """ test Certificate.cleanup - dbstore.certificate_delete() raises an exception  """
        mock_chk.return_value = (True, {'id': 2, 'name': 'name', 'expire_uts': 1543640400, 'issue_uts': 1543640400, 'cert_raw': 'cert_raw'})
        self.certificate.dbstore.certificates_search.return_value = [{'name', 'name'},]
        self.certificate.dbstore.certificate_delete.side_effect = Exception('exc_cert_cleanup2')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.cleanup(1543640400, True)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.cleanup() delete: exc_cert_cleanup2', lcm.output)

    def test_127_certificate_cleanup(self):
        """ test Certificate.cleanup - dbstore.certificates_search() raises an exception  """
        self.certificate.dbstore.certificates_search.side_effect = Exception('exc_cert_cleanup')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.cleanup('timestamp')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.cleanup() search: exc_cert_cleanup', lcm.output)

    def test_128_certificate_certlist_search(self):
        """ test Certificate.certlist_search - dbstore.certificates_search() raises an exception  """
        self.certificate.dbstore.certificates_search.side_effect = Exception('exc_certlist_search')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate.certlist_search('type', 'value')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Certificate.certlist_search(): exc_certlist_search', lcm.output)

    @patch('acme.certificate.load_config')
    def test_129_config_load(self, mock_load_cfg):
        """ test _config_load empty dictionary """
        mock_load_cfg.return_value = {}
        self.certificate._config_load()
        self.assertFalse(self.certificate.tnauthlist_support)

    @patch('acme.certificate.load_config')
    def test_130_config_load(self, mock_load_cfg):
        """ test _config_load missing ca_handler """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.certificate._config_load()
        self.assertIn('ERROR:test_a2c:Certificate._config_load(): CAhandler configuration missing in config file', lcm.output)

if __name__ == '__main__':
    unittest.main()
