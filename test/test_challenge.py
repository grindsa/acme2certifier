#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import sys
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
        from acme_srv.challenge import Challenge
        self.challenge = Challenge(False, 'http://tester.local', self.logger)

    @patch('acme_srv.challenge.generate_random_string')
    def test_001_challenge__new(self, mock_random):
        """ test challenge generation """
        mock_random.return_value = 'foo'
        # self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'mtype', 'status': 'pending'}, self.challenge._new('authz_name', 'mtype', 'token'))

    @patch('acme_srv.challenge.generate_random_string')
    def test_002_challenge__new(self, mock_random):
        """ test challenge generation for tnauthlist challenge """
        mock_random.return_value = 'foo'
        # self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'tkauth-01', 'tkauth-type': 'atc', 'status': 'pending'}, self.challenge._new('authz_name', 'tkauth-01', 'token'))

    @patch('acme_srv.challenge.Challenge._new')
    def test_003_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token'))

    @patch('acme_srv.challenge.Challenge._new')
    def test_004_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set with tnauth true """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}], self.challenge.new_set('authz_name', 'token', True))

    @patch('acme_srv.challenge.Challenge._new')
    def test_005_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set with empty challenge """
        mock_challenge.side_effect = [{'foo1' : 'bar1'}, {}, {'foo3' : 'bar3'}]
        self.assertEqual([{'foo1': 'bar1'}, {'foo3': 'bar3'}], self.challenge.new_set('authz_name', 'token', False))

    def test_006_challenge__info(self):
        """ test challenge.info() """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.assertEqual({'status': 'pending', 'token': 'token', 'type': 'http-01'}, self.challenge._info('foo'))

    def test_007_challenge__info(self):
        """ test challenge.info()  test no "status" field in """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'validated': 'foo'}
        self.assertEqual({'token': 'token', 'type': 'http-01'}, self.challenge._info('foo'))

    def test_008_challenge__info(self):
        """ test challenge.info()  test to pop "validated" key """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending', 'validated': 'foo'}
        self.assertEqual({'status': 'pending', 'token': 'token', 'type': 'http-01'}, self.challenge._info('foo'))

    def test_009_challenge__info(self):
        """ test challenge.info()  test to pop validated key no "status" and "validated" in """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01'}
        self.assertEqual({'token': 'token', 'type': 'http-01'}, self.challenge._info('foo'))

    def test_010_challenge__info(self):
        """ test challenge.info()  test to pop "validated" key """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'valid', 'validated': 'foo'}
        self.assertEqual({'status': 'valid', 'token': 'token', 'type': 'http-01'}, self.challenge._info('foo'))

    def test_011_challenge__info(self):
        """ test challenge.info()  test to pop "validated" key """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'valid', 'validated': 1543640400}
        self.assertEqual({'status': 'valid', 'token': 'token', 'type': 'http-01', 'validated': '2018-12-01T05:00:00Z'}, self.challenge._info('foo'))

    @patch('acme_srv.message.Message.check')
    def test_012_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed bcs. message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  {'detail': 'detail', 'type': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme_srv.message.Message.check')
    def test_013_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'url missing in protected header', 'type': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme_srv.challenge.Challenge._name_get')
    @patch('acme_srv.message.Message.check')
    def test_014_challenge_parse(self, mock_mcheck, mock_cname):
        """ Challenge.parse() message check returns ok with tnauhlist enabled failed tnauth check """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'url' : 'foo'}, {}, 'account_name')
        mock_cname.return_value = None
        self.assertEqual({'code': 400, 'data' : {'detail': 'could not get challenge', 'type': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}, self.challenge.parse('content'))

    @patch('acme_srv.challenge.Challenge._info')
    @patch('acme_srv.challenge.Challenge._name_get')
    @patch('acme_srv.message.Message.check')
    def test_015_challenge_parse(self, mock_mcheck, mock_cname, mock_info):
        """ Challenge.parse() message check returns challenge.info() failed """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'url' : 'foo'}, {}, 'account_name')
        mock_cname.return_value = 'foo'
        mock_info.return_value = {}
        self.assertEqual({'code': 400, 'data' : {'detail': 'invalid challenge: foo', 'type': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}, self.challenge.parse('content'))

    @patch('acme_srv.challenge.Challenge._validate_tnauthlist_payload')
    @patch('acme_srv.challenge.Challenge._info')
    @patch('acme_srv.challenge.Challenge._name_get')
    @patch('acme_srv.message.Message.check')
    def test_016_challenge_parse(self, mock_mcheck, mock_cname, mock_info, mock_tnauth):
        """ Challenge.parse() with tnauhlist enabled and failed tnauth check """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'url' : 'foo'}, {}, 'account_name')
        mock_cname.return_value = 'foo'
        mock_info.return_value = {'foo': 'bar'}
        mock_tnauth.return_value = (400, 'foo', 'bar')
        self.assertEqual({'code': 400, 'data' : {'detail': 'bar', 'type': 'foo', 'status': 400}, 'header': {}}, self.challenge.parse('content'))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.challenge.Challenge._validate_tnauthlist_payload')
    @patch('acme_srv.challenge.Challenge._info')
    @patch('acme_srv.challenge.Challenge._name_get')
    @patch('acme_srv.message.Message.check')
    def test_017_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce):
        """ Challenge.parse() successful with TNauthlist enabled """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.return_value = {'challenge_foo' : 'challenge_bar'}
        mock_tnauth.return_value = (200, 'foo', 'bar')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'new_nonce'}, 'data': {'challenge_foo': 'challenge_bar', 'url': 'bar'}}, self.challenge.parse('content'))
        self.assertTrue(mock_tnauth.called)

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.challenge.Challenge._validate_tnauthlist_payload')
    @patch('acme_srv.challenge.Challenge._info')
    @patch('acme_srv.challenge.Challenge._name_get')
    @patch('acme_srv.message.Message.check')
    def test_018_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce):
        """ Challenge.parse() successful with TNauthlist disabled """
        self.challenge.tnauthlist_support = False
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.return_value = {'challenge_foo' : 'challenge_bar'}
        mock_tnauth.return_value = (200, 'foo', 'bar')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'new_nonce'}, 'data': {'challenge_foo': 'challenge_bar', 'url': 'bar'}}, self.challenge.parse('content'))
        self.assertFalse(mock_tnauth.called)

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.challenge.Challenge._validate_tnauthlist_payload')
    @patch('acme_srv.challenge.Challenge._info')
    @patch('acme_srv.challenge.Challenge._name_get')
    @patch('acme_srv.message.Message.check')
    def test_019_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce):
        """ Challenge.parse() successful with valid status """
        self.challenge.tnauthlist_support = False
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.return_value = {'challenge_foo' : 'challenge_bar', 'status': 'valid'}
        mock_tnauth.return_value = (200, 'foo', 'bar')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'new_nonce'}, 'data': {'challenge_foo': 'challenge_bar', 'url': 'bar', 'status': 'valid'}}, self.challenge.parse('content'))
        self.assertFalse(mock_tnauth.called)

    @patch('acme_srv.challenge.Challenge._validate')
    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.challenge.Challenge._validate_tnauthlist_payload')
    @patch('acme_srv.challenge.Challenge._info')
    @patch('acme_srv.challenge.Challenge._name_get')
    @patch('acme_srv.message.Message.check')
    def test_020_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce, mock_validate):
        """ Challenge.parse() successful with some status and statusupdate """
        self.challenge.tnauthlist_support = False
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.side_effect = [{'challenge_foo' : 'challenge_bar', 'status': 'status'}, {'challenge_foo' : 'challenge_bar', 'status': 'new'}]
        mock_tnauth.return_value = (200, 'foo', 'bar')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'new_nonce'}, 'data': {'challenge_foo': 'challenge_bar', 'url': 'bar', 'status': 'new'}}, self.challenge.parse('content'))
        self.assertFalse(mock_tnauth.called)
        self.assertTrue(mock_validate.called)

    def test_021_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty challenge_dic """
        payload = {'foo': 'bar'}
        challenge_dic = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'invalid challenge: {}'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_022_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty challenge_dic """
        payload = {}
        challenge_dic = {'type': 'foo'}
        self.assertEqual((200, None, None), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_023_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload without atc claim """
        payload = {}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'atc claim is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_024_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty atc claim """
        payload = {'atc' : None}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'SPC token is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_025_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with '' atc claim """
        payload = {'atc' : ''}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'SPC token is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_026_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with spc token in atc claim """
        payload = {'atc' : 'a'}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((200, None, None), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.url_get')
    def test_027_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() with a wrong challenge """
        mock_url.return_value = 'foo'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((False, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.url_get')
    def test_028_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() with a correct challenge """
        mock_url.return_value = 'token.jwk_thumbprint'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((True, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.proxy_check')
    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.url_get')
    def test_029_challenge__validate_http_challenge(self, mock_url, mock_resolve, mock_proxy):
        """ test Chalölenge.validate_http_challenge() with a correct challenge """
        mock_url.return_value = 'token.jwk_thumbprint'
        self.challenge.proxy_server_list = 'proxy_server_list'
        mock_proxy.return_value = 'proxy'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((True, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.url_get')
    def test_030_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() without response """
        mock_url.return_value = None
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((False, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.url_get')
    def test_031_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Challenge.validate_http_challenge() failed with NX-domain error """
        mock_url.return_value = None
        mock_resolve.return_value = (None, True)
        self.assertEqual((False, True), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.url_get')
    def test_032_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() failed with NX-domain error - non existing case but to be tested"""
        mock_url.return_value = 'foo'
        mock_resolve.return_value = ('foo', True)
        self.assertEqual((False, True), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.sha256_hash')
    @patch('acme_srv.challenge.b64_url_encode')
    @patch('acme_srv.challenge.txt_get')
    def test_033_challenge__validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Chalölenge.validate_dns_challenge() with incorrect response """
        mock_dns.return_value = ['foo']
        mock_code.return_value = 'bar'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((False, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.sha256_hash')
    @patch('acme_srv.challenge.b64_url_encode')
    @patch('acme_srv.challenge.txt_get')
    def test_034_challenge__validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Chalölenge.validate_dns_challenge() with correct response """
        mock_dns.return_value = ['foo']
        mock_code.return_value = 'foo'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((True, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.sha256_hash')
    @patch('acme_srv.challenge.b64_url_encode')
    @patch('acme_srv.challenge.txt_get')
    def test_035_challenge__validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Challenge.validate_dns_challenge() with invalid response - obsolete """
        mock_dns.return_value = ['foo']
        mock_code.return_value = 'bar'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = (None, True)
        self.assertEqual((False, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.fqdn_resolve')
    @patch('acme_srv.challenge.sha256_hash')
    @patch('acme_srv.challenge.b64_url_encode')
    @patch('acme_srv.challenge.txt_get')
    def test_036_challenge__validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Challenge.validate_dns_challenge() with invalid but correct fqdn returned - obsolete """
        mock_dns.return_value = ['foo']
        mock_code.return_value = 'foo'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = ('foo', True)
        self.assertEqual((True, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    def test_037_challenge__validate_tkauth_challenge(self):
        """ test Chalölenge.validate_tkauth_challenge() """
        self.assertEqual((True, False), self.challenge._validate_tkauth_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint', 'payload'))

    def test_038_challenge__check(self):
        """ challenge check with incorrect challenge-dictionary """
        # self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.challenge.dbstore.challenge_lookup.return_value = {}
        self.assertEqual((False, False), self.challenge._check('name', 'payload'))

    def test_039_challenge__check(self):
        """ challenge check with without jwk return """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'type', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = None
        self.assertEqual((False, False), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_alpn_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_040_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tls-alpn challenge - for loop returns data during 1st iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tls-alpn-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(False, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))
        self.assertTrue(mock_chall.called)

    @patch('acme_srv.challenge.Challenge._validate_alpn_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_041_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tls-alpn challenge - - for loop returns data during 2nd iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tls-alpn-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(False, False), (False, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))
        self.assertTrue(mock_chall.called)

    @patch('acme_srv.challenge.Challenge._validate_alpn_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_042_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tls-alpn challenge - - for loop returns data during 6th iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tls-alpn-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(False, False), (False, False), (False, False), (False, False), (False, False), (False, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, False), self.challenge._check('name', 'payload'))
        self.assertTrue(mock_chall.called)

    @patch('acme_srv.challenge.Challenge._validate_alpn_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_043_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tls-alpn challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tls-alpn-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))
        self.assertTrue(mock_chall.called)

    @patch('acme_srv.challenge.Challenge._validate_http_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_044_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed http challenge - for loop returns data during 1st iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(False, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_http_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_045_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed http challenge - for loop returns data during 2nd iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(False, False), (False, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_http_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_046_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge - for loop returns data during 1st iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_http_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_047_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge - for loop returns data during 2nd iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(False, False), (True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_dns_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_048_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed dns challenge  - for loop returns data during 1st iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_dns_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_049_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed dns challenge  - for loop returns data during 2nd iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(False, False), (True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_dns_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_050_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge - for loop returns data during 1st iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_dns_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_051_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge  - for loop returns data during 2nd iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(False, False), (True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_052_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tkauth challenge tnauthlist_support not configured """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.side_effect = [(False, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((False, True), self.challenge._check('name', 'payload'))
        self.assertFalse(mock_chall.called)
        self.assertIn('ERROR:test_a2c:unknown challenge type "tkauth-01". Setting check result to False', lcm.output)

    @patch('acme_srv.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_053_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tkauth challenge tnauthlist_support True - for loop returns data during 1st iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.side_effect = [(False, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))
        self.assertTrue(mock_chall.called)

    @patch('acme_srv.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_054_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tkauth challenge tnauthlist_support True - for loop returns data during 2nd iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.side_effect = [(False, False), (False, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))
        self.assertTrue(mock_chall.called)

    @patch('acme_srv.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_055_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist_support unset """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = False
        mock_chall.side_effect = [(True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, True), self.challenge._check('name', 'payload'))
        self.assertFalse(mock_chall.called)

    @patch('acme_srv.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_056_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist support set - for loop returns data during 1st iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.side_effect = [(True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme_srv.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme_srv.challenge.jwk_thumbprint_get')
    def test_057_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist support set - for loop returns data during 2nd iteration """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.side_effect = [(False, False), (True, 'foo')]
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    def test_058_challenge__wcd_manipulate(self):
        """ get fqdn wc manipulation """
        fqdn = 'foo.bar'
        self.assertEqual('foo.bar', self.challenge._wcd_manipulate(fqdn))

    def test_059_challenge__wcd_manipulate(self):
        """ get fqdn wc manipulation """
        fqdn = '*.foo.bar'
        self.assertEqual('foo.bar', self.challenge._wcd_manipulate(fqdn))

    def test_060_challenge__wcd_manipulate(self):
        """ get fqdn wc manipulation """
        fqdn = 'foo*.foo.bar'
        self.assertEqual('foo*.foo.bar', self.challenge._wcd_manipulate(fqdn))

    def test_061_challenge__challengelist_search(self):
        """ test Challenge._challengelist_search - one challenge """
        self.challenge.dbstore.challenges_search.return_value = [{'token': 'token', 'type': 'type', 'name': 'name'}]
        self.challenge.path_dic = {'chall_path': '/chall_path/'}
        self.challenge.server_name = 'server_name'
        result = [{'name': 'name', 'token': 'token', 'type': 'type', 'url': 'server_name/chall_path/name'}]
        self.assertEqual(result, self.challenge._challengelist_search('key', 'value'))

    def test_062_challenge__challengelist_search(self):
        """ test Challenge._challengelist_search - two challenges """
        self.challenge.dbstore.challenges_search.return_value = [{'token': 'token1', 'type': 'type1', 'name': 'name1'}, {'token': 'token2', 'type': 'type2', 'name': 'name2'}]
        self.challenge.path_dic = {'chall_path': '/chall_path/'}
        self.challenge.server_name = 'server_name'
        result = [{'name': 'name1', 'token': 'token1', 'type': 'type1', 'url': 'server_name/chall_path/name1'}, {'name': 'name2', 'token': 'token2', 'type': 'type2', 'url': 'server_name/chall_path/name2'}]
        self.assertEqual(result, self.challenge._challengelist_search('key', 'value'))

    def test_063_challenge__challengelist_search(self):
        """ test Challenge._challengelist_search - one challenge with status field"""
        self.challenge.dbstore.challenges_search.return_value = [{'token': 'token', 'type': 'type', 'name': 'name', 'status__name': 'status'}]
        self.challenge.path_dic = {'chall_path': '/chall_path/'}
        self.challenge.server_name = 'server_name'
        result = [{'name': 'name', 'token': 'token', 'type': 'type', 'url': 'server_name/chall_path/name', 'status': 'status'}]
        self.assertEqual(result, self.challenge._challengelist_search('key', 'value'))

    def test_064_challenge__challengelist_search(self):
        """ test Challenge._challengelist_search - two challenges with status field """
        self.challenge.dbstore.challenges_search.return_value = [{'token': 'token1', 'type': 'type1', 'name': 'name1', 'status__name': 'status'}, {'token': 'token2', 'type': 'type2', 'name': 'name2', 'status__name': 'status'}]
        self.challenge.path_dic = {'chall_path': '/chall_path/'}
        self.challenge.server_name = 'server_name'
        result = [{'name': 'name1', 'token': 'token1', 'type': 'type1', 'url': 'server_name/chall_path/name1', 'status': 'status'}, {'name': 'name2', 'token': 'token2', 'type': 'type2', 'url': 'server_name/chall_path/name2', 'status': 'status'}]
        self.assertEqual(result, self.challenge._challengelist_search('key', 'value'))

    def test_065_challenge__challengelist_search(self):
        """ test Challenge._challengelist_search - dbstore.challenges_search() raises an exception  """
        self.challenge.dbstore.challenges_search.side_effect = Exception('exc_chall_search')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._challengelist_search('key', 'value')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._challengelist_search(): exc_chall_search', lcm.output)

    def test_066_challenge__check(self):
        """ test Challenge._check - dbstore.jwk_load() raises an exception  """
        self.challenge.dbstore.jwk_load.side_effect = Exception('exc_jkw_load')
        self.challenge.dbstore.challenge_lookup.return_value = {'type': 'type', 'authorization__value': 'authorization__value', 'token': 'token', 'authorization__order__account__name': 'authorization__order__account__name'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._check('name', 'payload')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._check() jwk: exc_jkw_load', lcm.output)

    def test_067_challenge__update_authz(self):
        """ test challenge update authz """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization': 'authzname'}
        self.challenge.dbstore.authorization_update.return_value = 'foo'
        self.challenge._update_authz('name', {'foo': 'bar'})

    def test_068_challenge__check(self):
        """ test Challenge._check - dbstore.challenge_lookup() raises an exception  """
        self.challenge.dbstore.challenge_lookup.side_effect = Exception('exc_chall_chk')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._check('name', 'payload')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._check() lookup: exc_chall_chk', lcm.output)

    def test_069_challenge__info(self):
        """ test Challenge._info - dbstore.challenge_lookup() raises an exception  """
        self.challenge.dbstore.challenge_lookup.side_effect = Exception('exc_chall_info')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._info('name')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._info(): exc_chall_info', lcm.output)

    def test_070_challenge__new(self):
        """ test Challenge._new - dbstore.challenge_add() raises an exception  """
        self.challenge.dbstore.challenge_add.side_effect = Exception('exc_chall_add')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._new('authz_name', 'mtype', 'token', 'value')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._new(): exc_chall_add, value:mtype', lcm.output)

    def test_071_challenge__update(self):
        """ test Challenge._update - dbstore.challenge_update() raises an exception  """
        self.challenge.dbstore.challenge_update.side_effect = Exception('exc_chall_upd')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._update({'foo': 'bar'})
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._update(): exc_chall_upd', lcm.output)

    def test_072_challenge__update_authz(self):
        """ test Challenge._update_authz - dbstore.authorization_update() raises an exception  """
        self.challenge.dbstore.authorization_update.side_effect = Exception('exc_chall_autz_upd')
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__name': 'authorization__name', 'authorization': 'authorization'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._update_authz('name', {'foo': 'bar'})
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._update_authz() upd: exc_chall_autz_upd', lcm.output)

    def test_073_challenge__update_authz(self):
        """ test Challenge._update_authz - dbstore.authorization_update() raises an exception  """
        self.challenge.dbstore.challenge_lookup.side_effect = Exception('exc_chall_lookup_foo')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._update_authz('name', {'foo': 'bar'})
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._update_authz() lookup: exc_chall_lookup_foo', lcm.output)

    @patch('acme_srv.challenge.fqdn_resolve')
    def test_074_challenge__validate_alpn_challenge(self, mock_resolve):
        """ test validate_alpn_challenge fqdn_resolve returned Invalid """
        mock_resolve.return_value = (None, True)
        self.assertEqual((False, True), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.servercert_get')
    @patch('acme_srv.challenge.fqdn_resolve')
    def test_075_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv):
        """ test validate_alpn_challenge no certificate returned """
        mock_resolve.return_value = ('foo', False)
        mock_srv.return_value = None
        self.assertEqual((False, False), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.proxy_check')
    @patch('acme_srv.challenge.servercert_get')
    @patch('acme_srv.challenge.fqdn_resolve')
    def test_076_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv, mock_proxy):
        """ test validate_alpn_challenge no certificate returned """
        mock_resolve.return_value = ('foo', False)
        mock_srv.return_value = None
        self.challenge.proxy_server_list = 'proxy_list'
        mock_proxy.return_value = 'proxy'
        self.assertEqual((False, False), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.fqdn_in_san_check')
    @patch('acme_srv.challenge.cert_san_get')
    @patch('acme_srv.challenge.servercert_get')
    @patch('acme_srv.challenge.fqdn_resolve')
    def test_077_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv, mock_sanget, mock_sanchk):
        """ test validate_alpn_challenge sancheck returned false """
        mock_resolve.return_value = ('foo', False)
        mock_sanget.return_value = ['foo', 'bar']
        mock_sanchk.return_value = False
        mock_srv.return_value = 'cert'
        self.assertEqual((False, False), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.cert_extensions_get')
    @patch('acme_srv.challenge.b64_encode')
    @patch('acme_srv.challenge.fqdn_in_san_check')
    @patch('acme_srv.challenge.cert_san_get')
    @patch('acme_srv.challenge.servercert_get')
    @patch('acme_srv.challenge.fqdn_resolve')
    def test_078_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext):
        """ test validate_alpn_challenge extension check failed """
        mock_resolve.return_value = ('foo', False)
        mock_sanget.return_value = ['foo', 'bar']
        mock_sanchk.return_value = True
        mock_srv.return_value = 'cert'
        mock_encode.return_value = 'foo'
        mock_ext.return_value = ['foobar', 'bar', 'foo1']
        self.assertEqual((False, False), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.cert_extensions_get')
    @patch('acme_srv.challenge.b64_encode')
    @patch('acme_srv.challenge.fqdn_in_san_check')
    @patch('acme_srv.challenge.cert_san_get')
    @patch('acme_srv.challenge.servercert_get')
    @patch('acme_srv.challenge.fqdn_resolve')
    def test_079_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext):
        """ test validate_alpn_challenge extension sucessful """
        mock_resolve.return_value = ('foo', False)
        mock_sanget.return_value = ['foo', 'bar']
        mock_sanchk.return_value = True
        mock_srv.return_value = 'cert'
        mock_encode.return_value = 'foo'
        mock_ext.return_value = ['foobar', 'bar', 'foo']
        self.assertEqual((True, False), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme_srv.challenge.Challenge._validate')
    def test_080__existing_challenge_validate(self, mock_validate):
        """ validate challenge with empty challenge list """
        challenge_list = []
        self.challenge._existing_challenge_validate(challenge_list)
        self.assertFalse(mock_validate.called)

    @patch('acme_srv.challenge.Challenge._validate')
    def test_081__existing_challenge_validate(self, mock_validate):
        """ validate challenge with challenge list """
        challenge_list = [{'name': 'foo', 'type': 'http-01'}]
        self.challenge._existing_challenge_validate(challenge_list)
        self.assertTrue(mock_validate.called)

    @patch('acme_srv.challenge.load_config')
    def test_082_config_load(self, mock_load_cfg):
        """ test _config_load empty config """
        parser = configparser.ConfigParser()
        # parser['Account'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list )
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_083_config_load(self, mock_load_cfg):
        """ test _config_load challenge_validation_disable False """
        parser = configparser.ConfigParser()
        parser['Challenge'] = {'challenge_validation_disable': False}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_084_config_load(self, mock_load_cfg):
        """ test _config_load challenge_validation_disable True """
        parser = configparser.ConfigParser()
        parser['Challenge'] = {'challenge_validation_disable': True}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertTrue(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_085_config_load(self, mock_load_cfg):
        """ test _config_load tnauthlist_support False """
        parser = configparser.ConfigParser()
        parser['Order'] = {'tnauthlist_support': False}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_086_config_load(self, mock_load_cfg):
        """ test _config_load tnauthlist_support True """
        parser = configparser.ConfigParser()
        parser['Order'] = {'tnauthlist_support': True}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertTrue(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_087_config_load(self, mock_load_cfg):
        """ test _config_load one DNS """
        parser = configparser.ConfigParser()
        parser['Challenge'] = {'dns_server_list': '["10.10.10.10"]'}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertEqual(['10.10.10.10'], self.challenge.dns_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_088_config_load(self, mock_load_cfg):
        """ test _config_load two DNS """
        parser = configparser.ConfigParser()
        parser['Challenge'] = {'dns_server_list': '["10.10.10.10", "10.0.0.1"]'}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertEqual(['10.10.10.10', '10.0.0.1'], self.challenge.dns_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('json.loads')
    @patch('acme_srv.challenge.load_config')
    def test_089_config_load(self, mock_load_cfg, mock_json):
        """ test _config_load two DNS """
        parser = configparser.ConfigParser()
        parser['Challenge'] = {'dns_server_list': '["10.10.10.10", "10.0.0.1"]'}
        mock_load_cfg.return_value = parser
        mock_json.side_effect = Exception('exc_mock_json')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._config_load()
        self.assertIn('WARNING:test_a2c:Challenge._config_load() dns_server_list failed with error: exc_mock_json', lcm.output)
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_090_config_load(self, mock_load_cfg):
        """ test _config_load tnauthlist_support False """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'url_prefix': 'url_prefix/'}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.dns_server_list)
        self.assertEqual({'authz_path': 'url_prefix//acme/authz/','chall_path': 'url_prefix//acme/chall/'}, self.challenge.path_dic)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_091_config_load(self, mock_load_cfg):
        """ test _config_load one DNS """
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'proxy_server_list': '{"key1.bar.local": "val1.bar.local"}'}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertEqual({'key1.bar.local': 'val1.bar.local'}, self.challenge.proxy_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_092_config_load(self, mock_load_cfg):
        """ test _config_load one DNS """
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'proxy_server_list': '{"key1.bar.local": "val1.bar.local", "key2.bar.local": "val2.bar.local"}'}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertEqual({'key1.bar.local': 'val1.bar.local', 'key2.bar.local': 'val2.bar.local'}, self.challenge.proxy_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('json.loads')
    @patch('acme_srv.challenge.load_config')
    def test_093_config_load(self, mock_load_cfg, mock_json):
        """ test _config_load exception """
        parser = configparser.ConfigParser()
        parser['DEFAULT'] = {'proxy_server_list': '{"key1.bar.local": "val1.bar.local"}'}
        mock_load_cfg.return_value = parser
        mock_json.side_effect = Exception('exc_mock_json')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._config_load()
        self.assertIn('WARNING:test_a2c:Challenge._config_load() proxy_server_list failed with error: exc_mock_json', lcm.output)
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_094_config_load(self, mock_load_cfg):
        """ test _config_load one DNS """
        parser = configparser.ConfigParser()
        parser['Challenge'] = {'challenge_validation_timeout': 5}
        mock_load_cfg.return_value = parser
        self.challenge._config_load()
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertEqual(5, self.challenge.challenge_validation_timeout )

    @patch('acme_srv.challenge.load_config')
    def test_095_config_load(self, mock_load_cfg):
        """ test _config_load exception """
        parser = configparser.ConfigParser()
        parser['Challenge'] = {'challenge_validation_timeout': 'AA'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._config_load()
        self.assertIn("WARNING:test_a2c:Challenge._config_load() failed to load challenge_validation_timeout: invalid literal for int() with base 10: 'AA'", lcm.output)
        self.assertFalse(self.challenge.challenge_validation_disable)
        self.assertFalse(self.challenge.tnauthlist_support)
        self.assertFalse(self.challenge.proxy_server_list)
        self.assertEqual(10, self.challenge.challenge_validation_timeout )

    def test_096__name_get(self):
        """ test name get no touch"""
        url = 'foo'
        self.assertEqual('foo', self.challenge._name_get(url))

    @patch('acme_srv.challenge.parse_url')
    def test_097__name_get(self, mock_parse):
        """ test name get urlparse"""
        mock_parse.return_value = {'path': 'path'}
        url = 'foo'
        self.assertEqual('path', self.challenge._name_get(url))

    @patch('acme_srv.challenge.parse_url')
    def test_098__name_get(self, mock_parse):
        """ test name get challenge_path replace """
        mock_parse.return_value = {'path': 'foo/my_path'}
        self.challenge.path_dic = {'chall_path': 'foo/'}
        url = 'foo'
        self.assertEqual('my_path', self.challenge._name_get(url))

    @patch('acme_srv.challenge.parse_url')
    def test_099__name_get(self, mock_parse):
        """ test name get challenge_path replace """
        mock_parse.return_value = {'path': 'foo/my/path'}
        self.challenge.path_dic = {'chall_path': 'foo/'}
        url = 'foo'
        self.assertEqual('my', self.challenge._name_get(url))

    @patch('acme_srv.challenge.Challenge._update_authz')
    @patch('acme_srv.challenge.Challenge._update')
    def test_100__validate(self, mock_update, mock_aupdate):
        """ test validate """
        challenge_name = 'challenge_name'
        payload = 'payload'
        mock_update.return_value = True
        mock_aupdate.return_value = True
        self.challenge.challenge_validation_disable = True
        self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch('acme_srv.challenge.Challenge._check')
    @patch('acme_srv.challenge.Challenge._update_authz')
    @patch('acme_srv.challenge.Challenge._update')
    def test_101__validate(self, mock_update, mock_aupdate, mock_check):
        """ test validate check returned ch:False/inv:False """
        challenge_name = 'challenge_name'
        payload = 'payload'
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (False, False)
        self.assertFalse(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertFalse(mock_aupdate.called)

    @patch('acme_srv.challenge.Challenge._check')
    @patch('acme_srv.challenge.Challenge._update_authz')
    @patch('acme_srv.challenge.Challenge._update')
    def test_102__validate(self, mock_update, mock_aupdate, mock_check):
        """ test validate check returned ch:False/inv:True """
        challenge_name = 'challenge_name'
        payload = 'payload'
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (False, True)
        self.assertFalse(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch('acme_srv.challenge.Challenge._check')
    @patch('acme_srv.challenge.Challenge._update_authz')
    @patch('acme_srv.challenge.Challenge._update')
    def test_103__validate(self, mock_update, mock_aupdate, mock_check):
        """ test validate check returned ch:True/inv:False """
        challenge_name = 'challenge_name'
        payload = 'payload'
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (True, False)
        self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch('acme_srv.challenge.Challenge._check')
    @patch('acme_srv.challenge.Challenge._update_authz')
    @patch('acme_srv.challenge.Challenge._update')
    def test_104__validate(self, mock_update, mock_aupdate, mock_check):
        """ test validate check returned ch:True/inv:True """
        challenge_name = 'challenge_name'
        payload = 'payload'
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (True, True)
        self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch('acme_srv.challenge.Challenge._check')
    @patch('acme_srv.challenge.Challenge._update_authz')
    @patch('acme_srv.challenge.Challenge._update')
    def test_105__validate(self, mock_update, mock_aupdate, mock_check):
        """ test validate check returned ch:True/inv:False """
        challenge_name = 'challenge_name'
        payload = {'keyAuthorization': 'keyAuthorization'}
        mock_update.return_value = True
        mock_aupdate.return_value = True
        mock_check.return_value = (True, False)
        self.assertTrue(self.challenge._validate(challenge_name, payload))
        self.assertTrue(mock_update.called)
        self.assertTrue(mock_aupdate.called)

    @patch('acme_srv.challenge.Challenge._name_get')
    @patch('acme_srv.challenge.Challenge._info')
    def test_106_get(self, mock_info, mock_name):
        """ test get """
        mock_info.return_value = 'chall_info'
        mock_name.return_value = 'foo'
        self.assertEqual({'code': 200, 'data': 'chall_info'}, self.challenge.get('url'))
        self.assertTrue(mock_name.called)

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.challenge.Challenge._existing_challenge_validate')
    @patch('acme_srv.challenge.Challenge._challengelist_search')
    def test_107_challengeset_get(self, mock_chsearch, mock_val, mock_set):
        """ test challengeset_get - no challenge_list returned """
        mock_chsearch.return_value = []
        mock_val.return_value = True
        mock_set.return_value = 'new_set'
        self.assertEqual('new_set', self.challenge.challengeset_get('authz_name', 'auth_status', 'token', 'tnauth'))
        self.assertTrue(mock_set.called)
        self.assertFalse(mock_val.called)

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.challenge.Challenge._existing_challenge_validate')
    @patch('acme_srv.challenge.Challenge._challengelist_search')
    def test_108_challengeset_get(self, mock_chsearch, mock_val, mock_set):
        """ test challengeset_get - challenge_list returned """
        mock_chsearch.return_value = [{'name': 'name1', 'foo': 'bar'}]
        mock_val.return_value = True
        mock_set.return_value = 'new_set'
        self.assertEqual([{'foo': 'bar'}], self.challenge.challengeset_get('authz_name', 'auth_status', 'token', 'tnauth'))
        self.assertFalse(mock_set.called)
        self.assertFalse(mock_val.called)

    #@patch('acme_srv.challenge.Challenge.new_set')
    #@patch('acme_srv.challenge.Challenge._existing_challenge_validate')
    #@patch('acme_srv.challenge.Challenge._challengelist_search')
    #def test_097_challengeset_get(self, mock_chsearch, mock_val, mock_set):
    #    """ test challengeset_get - challenge_list returned autzstatus pending """
    #    mock_chsearch.return_value = [{'name': 'name1', 'foo': 'bar'}]
    #    mock_val.return_value = True
    #    mock_set.return_value = 'new_set'
    #    self.assertEqual([{'foo': 'bar'}], self.challenge.challengeset_get('authz_name', 'pending', 'token', 'tnauth'))
    #    self.assertFalse(mock_set.called)
    #    self.assertTrue(mock_val.called)

if __name__ == '__main__':
    unittest.main()
