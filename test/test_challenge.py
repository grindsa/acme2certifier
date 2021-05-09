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
        from acme.challenge import Challenge
        self.challenge = Challenge(False, 'http://tester.local', self.logger)

    @patch('acme.challenge.generate_random_string')
    def test_001_challenge__new(self, mock_random):
        """ test challenge generation """
        mock_random.return_value = 'foo'
        # self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'mtype'}, self.challenge._new('authz_name', 'mtype', 'token'))

    @patch('acme.challenge.generate_random_string')
    def test_002_challenge__new(self, mock_random):
        """ test challenge generation for tnauthlist challenge """
        mock_random.return_value = 'foo'
        # self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'tkauth-01', 'tkauth-type': 'atc'}, self.challenge._new('authz_name', 'tkauth-01', 'token'))

    @patch('acme.challenge.Challenge._new')
    def test_003_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token'))

    @patch('acme.challenge.Challenge._new')
    def test_004_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set with tnauth true """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}], self.challenge.new_set('authz_name', 'token', True))

    @patch('acme.challenge.Challenge._new')
    def test_005_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token', False))

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

    @patch('acme.message.Message.check')
    def test_012_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed bcs. message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  {'detail': 'detail', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.message.Message.check')
    def test_013_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'url missing in protected header', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.challenge.Challenge._name_get')
    @patch('acme.message.Message.check')
    def test_014_challenge_parse(self, mock_mcheck, mock_cname):
        """ Challenge.parse() message check returns ok with tnauhlist enabled failed tnauth check """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'url' : 'foo'}, {}, 'account_name')
        mock_cname.return_value = None
        self.assertEqual({'code': 400, 'data' : {'detail': 'could not get challenge', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}, self.challenge.parse('content'))

    @patch('acme.challenge.Challenge._info')
    @patch('acme.challenge.Challenge._name_get')
    @patch('acme.message.Message.check')
    def test_015_challenge_parse(self, mock_mcheck, mock_cname, mock_info):
        """ Challenge.parse() message check returns challenge.info() failed """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'url' : 'foo'}, {}, 'account_name')
        mock_cname.return_value = 'foo'
        mock_info.return_value = {}
        self.assertEqual({'code': 400, 'data' : {'detail': 'invalid challenge: foo', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}, self.challenge.parse('content'))

    @patch('acme.challenge.Challenge._validate_tnauthlist_payload')
    @patch('acme.challenge.Challenge._info')
    @patch('acme.challenge.Challenge._name_get')
    @patch('acme.message.Message.check')
    def test_016_challenge_parse(self, mock_mcheck, mock_cname, mock_info, mock_tnauth):
        """ Challenge.parse() with tnauhlist enabled and failed tnauth check """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'url' : 'foo'}, {}, 'account_name')
        mock_cname.return_value = 'foo'
        mock_info.return_value = {'foo': 'bar'}
        mock_tnauth.return_value = (400, 'foo', 'bar')
        self.assertEqual({'code': 400, 'data' : {'detail': 'bar', 'message': 'foo', 'status': 400}, 'header': {}}, self.challenge.parse('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.challenge.Challenge._validate_tnauthlist_payload')
    @patch('acme.challenge.Challenge._info')
    @patch('acme.challenge.Challenge._name_get')
    @patch('acme.message.Message.check')
    def test_017_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce):
        """ Challenge.parse() successful with TNauthlist enabled """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.return_value = {'challenge_foo' : 'challenge_bar'}
        mock_tnauth.return_value = (200, 'foo', 'bar')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'new_nonce'}, 'data': {'challenge_foo': 'challenge_bar', 'url': 'bar'}}, self.challenge.parse('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.challenge.Challenge._validate_tnauthlist_payload')
    @patch('acme.challenge.Challenge._info')
    @patch('acme.challenge.Challenge._name_get')
    @patch('acme.message.Message.check')
    def test_018_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce):
        """ Challenge.parse() successful with TNauthlist disabled """
        self.challenge.tnauthlist_support = False
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.return_value = {'challenge_foo' : 'challenge_bar'}
        mock_tnauth.return_value = (200, 'foo', 'bar')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'new_nonce'}, 'data': {'challenge_foo': 'challenge_bar', 'url': 'bar'}}, self.challenge.parse('content'))

    def test_019_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty challenge_dic """
        payload = {'foo': 'bar'}
        challenge_dic = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'invalid challenge: {}'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_020_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty challenge_dic """
        payload = {}
        challenge_dic = {'type': 'foo'}
        self.assertEqual((200, None, None), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_021_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload without atc claim """
        payload = {}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'atc claim is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_022_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty atc claim """
        payload = {'atc' : None}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'SPC token is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_023_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with '' atc claim """
        payload = {'atc' : ''}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'SPC token is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_024_challenge__validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with spc token in atc claim """
        payload = {'atc' : 'a'}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((200, None, None), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_025_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() with a wrong challenge """
        mock_url.return_value = 'foo'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((False, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_026_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() with a correct challenge """
        mock_url.return_value = 'token.jwk_thumbprint'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((True, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_027_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() without response """
        mock_url.return_value = None
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((False, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_028_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Challenge.validate_http_challenge() failed with NX-domain error """
        mock_url.return_value = None
        mock_resolve.return_value = (None, True)
        self.assertEqual((False, True), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_029_challenge__validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() failed with NX-domain error - non existing case but to be tested"""
        mock_url.return_value = 'foo'
        mock_resolve.return_value = ('foo', True)
        self.assertEqual((False, True), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_030_challenge__validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Chalölenge.validate_dns_challenge() with incorrect response """
        mock_dns.return_value = ['foo']
        mock_code.return_value = 'bar'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((False, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_031_challenge__validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Chalölenge.validate_dns_challenge() with correct response """
        mock_dns.return_value = ['foo']
        mock_code.return_value = 'foo'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((True, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_032_challenge__validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Challenge.validate_dns_challenge() with invalid response - obsolete """
        mock_dns.return_value = ['foo']
        mock_code.return_value = 'bar'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = (None, True)
        self.assertEqual((False, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_033_challenge__validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Challenge.validate_dns_challenge() with invalid but correct fqdn returned - obsolete """
        mock_dns.return_value = ['foo']
        mock_code.return_value = 'foo'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = ('foo', True)
        self.assertEqual((True, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    def test_034_challenge__validate_tkauth_challenge(self):
        """ test Chalölenge.validate_tkauth_challenge() """
        self.assertEqual((True, False), self.challenge._validate_tkauth_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint', 'payload'))

    def test_035_challenge__check(self):
        """ challenge check with incorrect challenge-dictionary """
        # self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.challenge.dbstore.challenge_lookup.return_value = {}
        self.assertEqual((False, False), self.challenge._check('name', 'payload'))

    def test_036_challenge__check(self):
        """ challenge check with without jwk return """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'type', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = None
        self.assertEqual((False, False), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_http_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_037_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (False, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_http_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_038_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_dns_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_039_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed dns challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_dns_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_040_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_041_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tkauth challenge tnauthlist_support not configured """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (False, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, True), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_042_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tkauth challenge tnauthlist_support True """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.return_value = (False, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_043_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist_support unset """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = False
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, True), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_044_challenge__check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist support set """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    def test_045_challenge__wcd_manipulate(self):
        """ get fqdn wc manipulation """
        fqdn = 'foo.bar'
        self.assertEqual('foo.bar', self.challenge._wcd_manipulate(fqdn))

    def test_046_challenge__wcd_manipulate(self):
        """ get fqdn wc manipulation """
        fqdn = '*.foo.bar'
        self.assertEqual('foo.bar', self.challenge._wcd_manipulate(fqdn))

    def test_047_challenge__wcd_manipulate(self):
        """ get fqdn wc manipulation """
        fqdn = 'foo*.foo.bar'
        self.assertEqual('foo*.foo.bar', self.challenge._wcd_manipulate(fqdn))

    def test_048_challenge__challengelist_search(self):
        """ test Challenge._challengelist_search - dbstore.challenges_search() raises an exception  """
        self.challenge.dbstore.challenges_search.side_effect = Exception('exc_chall_search')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._challengelist_search('key', 'value')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._challengelist_search(): exc_chall_search', lcm.output)

    def test_049_challenge__check(self):
        """ test Challenge._check - dbstore.jwk_load() raises an exception  """
        self.challenge.dbstore.jwk_load.side_effect = Exception('exc_jkw_load')
        self.challenge.dbstore.challenge_lookup.return_value = {'type': 'type', 'authorization__value': 'authorization__value', 'token': 'token', 'authorization__order__account__name': 'authorization__order__account__name'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._check('name', 'payload')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._check() jwk: exc_jkw_load', lcm.output)

    def test_050_challenge__check(self):
        """ test Challenge._check - dbstore.challenge_lookup() raises an exception  """
        self.challenge.dbstore.challenge_lookup.side_effect = Exception('exc_chall_chk')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._check('name', 'payload')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._check() lookup: exc_chall_chk', lcm.output)

    def test_051_challenge__info(self):
        """ test Challenge._info - dbstore.challenge_lookup() raises an exception  """
        self.challenge.dbstore.challenge_lookup.side_effect = Exception('exc_chall_info')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._info('name')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._info(): exc_chall_info', lcm.output)

    def test_052_challenge__new(self):
        """ test Challenge._new - dbstore.challenge_add() raises an exception  """
        self.challenge.dbstore.challenge_add.side_effect = Exception('exc_chall_add')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._new('authz_name', 'mtype', 'token')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._new(): exc_chall_add', lcm.output)

    def test_053_challenge__update(self):
        """ test Challenge._update - dbstore.challenge_update() raises an exception  """
        self.challenge.dbstore.challenge_update.side_effect = Exception('exc_chall_upd')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._update({'foo': 'bar'})
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._update(): exc_chall_upd', lcm.output)

    def test_054_challenge__update_authz(self):
        """ test Challenge._update_authz - dbstore.authorization_update() raises an exception  """
        self.challenge.dbstore.authorization_update.side_effect = Exception('exc_chall_autz_upd')
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__name': 'authorization__name', 'authorization': 'authorization'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._update_authz('name', {'foo': 'bar'})
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._update_authz() upd: exc_chall_autz_upd', lcm.output)

    def test_055_challenge__update_authz(self):
        """ test Challenge._update_authz - dbstore.authorization_update() raises an exception  """
        self.challenge.dbstore.challenge_lookup.side_effect = Exception('exc_chall_lookup_foo')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.challenge._update_authz('name', {'foo': 'bar'})
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Challenge._update_authz() lookup: exc_chall_lookup_foo', lcm.output)

    @patch('acme.challenge.fqdn_resolve')
    def test_056_challenge__validate_alpn_challenge(self, mock_resolve):
        """ test validate_alpn_challenge fqdn_resolve returned Invalid """
        mock_resolve.return_value = (None, True)
        self.assertEqual((False, True), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.servercert_get')
    @patch('acme.challenge.fqdn_resolve')
    def test_057_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv):
        """ test validate_alpn_challenge no certificate returned """
        mock_resolve.return_value = ('foo', False)
        mock_srv.return_value = None
        self.assertEqual((False, False), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_in_san_check')
    @patch('acme.challenge.cert_san_get')
    @patch('acme.challenge.servercert_get')
    @patch('acme.challenge.fqdn_resolve')
    def test_058_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv, mock_sanget, mock_sanchk):
        """ test validate_alpn_challenge sancheck returned false """
        mock_resolve.return_value = ('foo', False)
        mock_sanget.return_value = ['foo', 'bar']
        mock_sanchk.return_value = False
        mock_srv.return_value = 'cert'
        self.assertEqual((False, False), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.cert_extensions_get')
    @patch('acme.challenge.b64_encode')
    @patch('acme.challenge.fqdn_in_san_check')
    @patch('acme.challenge.cert_san_get')
    @patch('acme.challenge.servercert_get')
    @patch('acme.challenge.fqdn_resolve')
    def test_059_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext):
        """ test validate_alpn_challenge extension check failed """
        mock_resolve.return_value = ('foo', False)
        mock_sanget.return_value = ['foo', 'bar']
        mock_sanchk.return_value = True
        mock_srv.return_value = 'cert'
        mock_encode.return_value = 'foo'
        mock_ext.return_value = ['foobar', 'bar', 'foo1']
        self.assertEqual((False, False), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.cert_extensions_get')
    @patch('acme.challenge.b64_encode')
    @patch('acme.challenge.fqdn_in_san_check')
    @patch('acme.challenge.cert_san_get')
    @patch('acme.challenge.servercert_get')
    @patch('acme.challenge.fqdn_resolve')
    def test_060_challenge__validate_alpn_challenge(self, mock_resolve, mock_srv, mock_sanget, mock_sanchk, mock_encode, mock_ext):
        """ test validate_alpn_challenge extension sucessful """
        mock_resolve.return_value = ('foo', False)
        mock_sanget.return_value = ['foo', 'bar']
        mock_sanchk.return_value = True
        mock_srv.return_value = 'cert'
        mock_encode.return_value = 'foo'
        mock_ext.return_value = ['foobar', 'bar', 'foo']
        self.assertEqual((True, False), self.challenge._validate_alpn_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

if __name__ == '__main__':
    unittest.main()
