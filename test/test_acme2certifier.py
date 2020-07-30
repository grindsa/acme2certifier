#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import importlib
import datetime
import requests
import json
import dns.resolver
import sys
try:
    from mock import patch, MagicMock, Mock
except ImportError:
    from unittest.mock import patch, MagicMock, Mock
sys.path.insert(0, '.')
sys.path.insert(1, '..')

class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    # pylint: disable=W0107
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
        from acme.account import Account
        from acme.authorization import Authorization
        from acme.housekeeping import Housekeeping
        from acme.certificate import Certificate
        from acme.challenge import Challenge
        from acme.directory import Directory
        from acme.error import Error
        from acme.nonce import Nonce
        from acme.message import Message
        from acme.order import Order
        from acme.signature import Signature
        from acme.trigger import Trigger
        from acme.helper import b64decode_pad, b64_decode, b64_url_encode, b64_url_recode, ca_handler_get, convert_string_to_byte, convert_byte_to_string, decode_message, decode_deserialize, get_url, generate_random_string, signature_check, validate_email, uts_to_date_utc, date_to_uts_utc, load_config, cert_serial_get, cert_san_get, cert_dates_get, build_pem_file, date_to_datestr, datestr_to_date, dkeys_lower, csr_cn_get, cert_pubkey_get, csr_pubkey_get, url_get, url_get_with_own_dns, dns_server_list_load, csr_san_get, csr_extensions_get, fqdn_resolve
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_acme2certifier')
        self.directory = Directory(False, 'http://tester.local', self.logger)
        self.account = Account(False, 'http://tester.local', self.logger)
        self.authorization = Authorization(False, 'http://tester.local', self.logger)
        self.challenge = Challenge(False, 'http://tester.local', self.logger)
        self.certificate = Certificate(False, 'http://tester.local', self.logger)
        self.message = Message(False, 'http://tester.local', self.logger)
        self.nonce = Nonce(False, self.logger)
        self.error = Error(False, self.logger)
        self.housekeeping = Housekeeping(False, self.logger)
        self.order = Order(False, 'http://tester.local', self.logger)
        self.signature = Signature(False, 'http://tester.local', self.logger)
        self.trigger = Trigger(False, 'http://tester.local', self.logger)
        self.b64decode_pad = b64decode_pad
        self.validate_email = validate_email
        self.signature_check = signature_check
        self.decode_deserialize = decode_deserialize
        self.decode_message = decode_message
        self.uts_to_date_utc = uts_to_date_utc
        self.date_to_uts_utc = date_to_uts_utc
        self.generate_random_string = generate_random_string
        self.b64_url_recode = b64_url_recode
        self.load_config = load_config
        self.cert_serial_get = cert_serial_get
        self.cert_dates_get = cert_dates_get
        self.cert_san_get = cert_san_get
        self.cert_pubkey_get = cert_pubkey_get
        self.csr_pubkey_get = csr_pubkey_get
        self.csr_cn_get = csr_cn_get
        self.build_pem_file = build_pem_file
        self.b64_decode = b64_decode
        self.b64_url_encode = b64_url_encode
        self.date_to_datestr = date_to_datestr
        self.datestr_to_date = datestr_to_date
        self.convert_byte_to_string = convert_byte_to_string
        self.convert_string_to_byte = convert_string_to_byte
        self.get_url = get_url
        self.url_get = url_get
        self.ca_handler_get = ca_handler_get
        self.url_get_with_own_dns = url_get_with_own_dns
        self.dns_server_list_load = dns_server_list_load
        self.dkeys_lower = dkeys_lower
        self.csr_san_get = csr_san_get
        self.csr_extensions_get = csr_extensions_get
        self.fqdn_resolve = fqdn_resolve

    def test_001_servername_new(self):
        """ test Directory.get_server_name() method """
        self.assertEqual('http://tester.local', self.directory.servername_get())

    def test_002_get_dir_newnonce(self):
        """ test Directory.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newNonce': 'http://tester.local/acme/newnonce'}, self.directory.directory_get())

    def test_003_get_dir_newaccount(self):
        """ test Directory.get_directory() method and check for "newnonce" tag in output"""
        self.assertDictContainsSubset({'newAccount': 'http://tester.local/acme/newaccount'}, self.directory.directory_get())

    def test_004_get_dir_meta(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.supress_version = True
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier'}}, self.directory.directory_get())

    def test_005_nonce_new(self):
        """ test Nonce.new() and check if we get something back """
        self.assertIsNotNone(self.nonce._new())

    def test_006_nonce_generate_and_add(self):
        """ test Nonce.nonce_generate_and_add() and check if we get something back """
        self.assertIsNotNone(self.nonce.generate_and_add())

    def test_007_nonce_check_failed(self):
        """ test Nonce.nonce_check_and_delete """
        self.assertEqual((400, 'urn:ietf:params:acme:error:badNonce', 'NONE'), self.nonce.check({'foo':'bar'}))

    def test_008_nonce_check_succ(self):
        """ test Nonce.nonce_check_and_delete """
        self.assertEqual((200, None, None), self.nonce.check({'nonce':'aaa'}))

    def test_009_nonce_check_and_delete(self):
        """ test Nonce.nonce_check_and_delete """
        self.assertEqual((200, None, None), self.nonce._check_and_delete('aaa'))

    def test_010_err_badnonce(self):
        """ test badnonce error message """
        self.assertEqual('JWS has invalid anti-replay nonce', self.error._acme_errormessage('urn:ietf:params:acme:error:badNonce'))

    def test_011_err_invalidcontact(self):
        """ test badnonce error message """
        self.assertEqual('The provided contact URI was invalid', self.error._acme_errormessage('urn:ietf:params:acme:error:invalidContact'))

    def test_012_err_useractionrequired(self):
        """ test badnonce error message """
        self.assertFalse(self.error._acme_errormessage('urn:ietf:params:acme:error:userActionRequired'))

    def test_013_err_malformed(self):
        """ test badnonce error message """
        self.assertFalse(self.error._acme_errormessage('urn:ietf:params:acme:error:malformed'))

    def test_014_b64decode_pad_correct(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-correctly-padded', self.b64decode_pad(self.logger, 'dGhpcy1pcy1mb28tY29ycmVjdGx5LXBhZGRlZA=='))

    def test_015_b64decode_pad_missing(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-with-incorrect-padding', self.b64decode_pad(self.logger, 'dGhpcy1pcy1mb28td2l0aC1pbmNvcnJlY3QtcGFkZGluZw'))

    def test_016_b64decode_failed(self):
        """ test b64 decoding failure """
        self.assertEqual('ERR: b64 decoding error', self.b64decode_pad(self.logger, 'b'))

    def test_017_decode_dser_succ(self):
        """ test successful deserialization of a b64 encoded string """
        self.assertEqual({u'a': u'b', u'c': u'd'}, self.decode_deserialize(self.logger, 'eyJhIiA6ICJiIiwgImMiIDogImQifQ=='))

    def test_018_decode_dser_failed(self):
        """ test failed deserialization of a b64 encoded string """
        self.assertEqual('ERR: Json decoding error', self.decode_deserialize(self.logger, 'Zm9vLXdoaWNoLWNhbm5vdC1iZS1qc29uaXplZA=='))

    def test_019_validate_email_0(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(self.logger, 'foo@example.com'))

    def test_020_validate_email_1(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(self.logger, 'mailto:foo@example.com'))

    def test_021_validate_email_2(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(self.logger, 'mailto: foo@example.com'))

    def test_022_validate_email_3(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(self.logger, ['mailto: foo@example.com', 'mailto: bar@example.com']))

    def test_023_validate_wrong_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(self.logger, 'example.com'))

    def test_024_validate_wrong_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(self.logger, 'me@exam,ple.com'))

    def test_025_validate_wrong_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(self.logger, ['mailto: foo@exa,mple.com', 'mailto: bar@example.com']))

    def test_026_validate_wrong_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(self.logger, ['mailto: foo@example.com', 'mailto: bar@exa,mple.com']))

    def test_027_tos_check_true(self):
        """ test successful tos check """
        self.assertEqual((200, None, None), self.account._tos_check({'termsofserviceagreed': True}))

    def test_028_tos_check_false(self):
        """ test successful tos check """
        self.assertEqual((403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse'), self.account._tos_check({'termsOfServiceAgreed': False}))

    def test_029_tos_check_missing(self):
        """ test successful tos check """
        self.assertEqual((403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse'), self.account._tos_check({'foo': 'bar'}))

    def test_030_contact_check_valid(self):
        """ test successful tos check """
        self.assertEqual((200, None, None), self.account._contact_check({'contact': ['mailto: foo@example.com']}))

    def test_031_contact_check_invalid(self):
        """ test successful tos check """
        self.assertEqual((400, 'urn:ietf:params:acme:error:invalidContact', 'mailto: bar@exa,mple.com'), self.account._contact_check({'contact': ['mailto: bar@exa,mple.com']}))

    def test_032_contact_check_missing(self):
        """ test successful tos check """
        self.assertEqual((400, 'urn:ietf:params:acme:error:invalidContact', 'no contacts specified'), self.account._contact_check({'foo': 'bar'}))

    @patch('acme.account.generate_random_string')
    def test_033_account_add_new(self, mock_name):
        """ test successful account add for a new account"""
        self.account.dbstore.account_add.return_value = (2, True)
        mock_name.return_value = 'randowm_string'
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((201, 'randowm_string', None), self.account._add(dic, 'foo@example.com'))

    @patch('acme.account.generate_random_string')
    def test_034_account_add_existing(self, mock_name):
        """ test successful account add for a new account"""
        self.account.dbstore.account_add.return_value = ('foo', False)
        mock_name.return_value = 'randowm_string'
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((200, 'foo', None), self.account._add(dic, 'foo@example.com'))

    def test_035_account_add_failed1(self):
        """ test account add without ALG """
        dic = {'foo': 'bar', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protected payload'), self.account._add(dic, ['me@example.com']))

    def test_036_account_add_failed2(self):
        """ test account add without jwk """
        dic = {'alg': 'RS256', 'foo': {'foo': u'bar'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protected payload'), self.account._add(dic, ['me@example.com']))

    def test_037_account_add_failed6(self):
        """ test account add without contact """
        self.account.tos_check_disable = False
        self.account.contact_check_disable = False
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protected payload'), self.account._add(dic, None))

    def test_038_get_id_succ(self):
        """ test successfull get_id """
        string = {'kid' : 'http://tester.local/acme/acct/foo'}
        self.assertEqual('foo', self.account._name_get(string))

    def test_039_get_id_failed(self):
        """ test failed get_id bcs of suffix """
        string = 'http://tester.local/acme/acct/bar/foo'
        self.assertFalse(self.account._name_get(string))

    def test_040_get_id_failed(self):
        """ test failed get_id bcs wrong servername """
        string = {'kid' : 'http://test.local/acme/acct/foo'}
        self.assertFalse(self.account._name_get(string))

    def test_041_get_id_failed(self):
        """ test failed get_id bcs of wrong path """
        string = {'kid' : 'http://tester.local/acct/foo'}
        self.assertFalse(self.account._name_get(string))

    def test_042_validate_sig_succ(self):
        """ successful validation of singature """
        mkey = {
            'alg' : 'RS256',
            'e' : 'AQAB',
            'kty' : 'RSA',
            'n' : '2CFMV4MK6Uo_2GQWa0KVWlzffgSDiLwur4ujSZkCRzbA3w5p1ABJgr7l_P84HpRv8R8rGL67hqmDJuT52mGD6fMVAhHPX5pSdtyZlQQuzpXonzNmHbG1DbMSiXrxg5jWVXchCxHx82wAt9Kf13O5ATxD0WOBB5FffpqQHh8zTf29jTL4vBd8N57ce17ZgNWl_EcoByjigqNFJcO0rrvrf6xyNaO9nbun4PAMJTLbfVa6CiEqjnjYMX80VYLH4fCqsAZgxIoli_D2j9P5Kq6KZZUL_bZ2QQV4UuwWZvh6tcA393YQLeMARnhWI6dqlZVdcU74NXi9NhSxcMkM8nZZ8Q',
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((True, None), self.signature_check(self.logger, message, mkey))

    def test_043_validate_sig_fail(self):
        """ failed validatio of singature  wrong key"""
        mkey = {
            'alg' : 'rs256',
            'e' : 'AQAB',
            'kty' : 'RSA',
            'n' : 'zncgRHCp22-29g9FO4Hn02iyS1Fo4Y1tB-6cucH1yKSxM6bowjAaVa4HkAnIxgF6Zj9qLROgQR84YjMPeNkq8woBRz1aziDiTIOc0D2aXvLgZbuFGesvxoSGd6uyxjyyV7ONwZEpB8QtDW0I3shlhosKB3Ni1NFu55bPUP9RvxUdPzRRuhxUMHc1CXre1KR0eQmQdNZT6tgQVxpv2lb-iburBADjivBRyrI3k3NmXkYknBggAu8JInaFY4T8pVK0jTwP-f3-0eAV1bg99Rm7uXNXl7SKpQ3oGihwy2OK-XAc59v6C3n4Wq9QpzGkFWsOOlp4zEf13L3_UKugeExEqw',
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'

        if int('%i%i' % (sys.version_info[0], sys.version_info[1])) <= 36:
            result = (False, 'Verification failed for all signatures["Failed: [InvalidJWSSignature(\'Verification failed {InvalidSignature()}\',)]"]')
        else:
            result = (False, 'Verification failed for all signatures["Failed: [InvalidJWSSignature(\'Verification failed {InvalidSignature()}\')]"]')

        self.assertEqual(result, self.signature_check(self.logger, message, mkey))

    def test_044_validate_sig_fail(self):
        """ failed validatio of singature  faulty key"""
        mkey = {
            'alg' : 'rs256',
            'e' : 'AQAB',
            'n' : 'zncgRHCp22-29g9FO4Hn02iyS1Fo4Y1tB-6cucH1yKSxM6bowjAaVa4HkAnIxgF6Zj9qLROgQR84YjMPeNkq8woBRz1aziDiTIOc0D2aXvLgZbuFGesvxoSGd6uyxjyyV7ONwZEpB8QtDW0I3shlhosKB3Ni1NFu55bPUP9RvxUdPzRRuhxUMHc1CXre1KR0eQmQdNZT6tgQVxpv2lb-iburBADjivBRyrI3k3NmXkYknBggAu8JInaFY4T8pVK0jTwP-f3-0eAV1bg99Rm7uXNXl7SKpQ3oGihwy2OK-XAc59v6C3n4Wq9QpzGkFWsOOlp4zEf13L3_UKugeExEqw',
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        if sys.version_info[0] < 3:
            self.assertEqual((False, 'Unknown type "None", valid types are: [\'RSA\', \'EC\', \'oct\']'), self.signature_check(self.logger, message, mkey))
        else:
            self.assertEqual((False, 'Unknown type "None", valid types are: [\'EC\', \'RSA\', \'oct\', \'OKP\']'), self.signature_check(self.logger, message, mkey))

    def test_045_validate_sig_fail(self):
        """ failed validatio of singature  no key"""
        mkey = {}
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((False, 'No key specified.'), self.signature_check(self.logger, message, mkey))

    def test_046_jwk_load(self):
        """ test jwk load """
        self.signature.dbstore.jwk_load.return_value = 'foo'
        self.assertEqual('foo', self.signature._jwk_load(1))

    @patch('acme.message.Message.check')
    def test_047_account_new(self, mock_mcheck):
        """ Account.new() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.account.new(message))

    @patch('acme.account.Account._tos_check')
    @patch('acme.message.Message.check')
    def test_048_account_new(self, mock_mcheck, mock_tos):
        """ Account.new() failed bcs failed tos check """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', None)
        mock_tos.return_value = (403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse')
        message = {'foo' : 'bar'}
        self.account.tos_url = 'foo'
        e_result = {'code': 403, 'data': {'detail': 'Terms of service must be accepted', 'message': 'urn:ietf:params:acme:error:userActionRequired', 'status': 403}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.account.Account._contact_check')
    @patch('acme.account.Account._tos_check')
    @patch('acme.message.Message.check')
    def test_049_account_new(self, mock_mcheck, mock_tos, mock_contact):
        """ Account.new() failed bcs failed contact check """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (400, 'urn:ietf:params:acme:error:invalidContact', 'no contacts specified')
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': 'The provided contact URI was invalid: no contacts specified', 'message': 'urn:ietf:params:acme:error:invalidContact', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.account.Account._add')
    @patch('acme.account.Account._contact_check')
    @patch('acme.account.Account._tos_check')
    @patch('acme.message.Message.check')
    def test_050_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad):
        """ Account.new() failed bcs of failed add """
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : 'foo@bar.com'}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key')
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': 'incomplete JSON Web Key', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account._add')
    @patch('acme.account.Account._contact_check')
    @patch('acme.account.Account._tos_check')
    @patch('acme.message.Message.check')
    def test_051_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad, mock_nnonce):
        """ Account.new() successful for a new account"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (201, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 201, 'data': {'contact': [u'mailto: foo@bar.com'], 'orders': 'http://tester.local/acme/acct/1/orders', 'status': 'valid'}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account._add')
    @patch('acme.account.Account._contact_check')
    @patch('acme.account.Account._tos_check')
    @patch('acme.message.Message.check')
    def test_052_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad, mock_nnonce):
        """ Account.new() successful for an existing account"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.account.Account._onlyreturnexisting')
    @patch('acme.message.Message.check')
    def test_053_account_new(self, mock_mcheck, mock_existing):
        """ Account.new() onlyReturnExisting for a non existing account """
        mock_mcheck.return_value = (200, None, None, 'protected', {"onlyreturnexisting": 'true'}, None)
        mock_existing.return_value = (400, 'urn:ietf:params:acme:error:accountDoesNotExist', None)
        message = {'foo': 'bar'}
        e_result = {'code': 400, 'data': {'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account._onlyreturnexisting')
    @patch('acme.message.Message.check')
    def test_054_account_new(self, mock_mcheck, mock_existing, mock_nnonce):
        """ Account.new() onlyReturnExisting for an existing account """
        mock_mcheck.return_value = (200, None, None, 'protected', {"onlyreturnexisting": 'true'}, None)
        mock_existing.return_value = (200, 100, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/100', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    def test_055_get_id_failed(self):
        """ test failed get_id bcs of wrong data """
        string = {'foo' : 'bar'}
        self.assertFalse(self.account._name_get(string))

    def test_056_signature_check(self):
        """ test Signature.check() without having content """
        self.assertEqual((False, 'urn:ietf:params:acme:error:malformed', None), self.signature.check('foo', None))

    @patch('acme.signature.Signature._jwk_load')
    def test_057_signature_check(self, mock_jwk):
        """ test Signature.check() while pubkey lookup failed """
        mock_jwk.return_value = {}
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check('foo', 1))

    @patch('acme.signature.signature_check')
    @patch('acme.signature.Signature._jwk_load')
    def test_058_signature_check(self, mock_jwk, mock_sig):
        """ test successful Signature.check()  """
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None, None), self.signature.check('foo', 1))

    def test_059_signature_check(self):
        """ test successful Signature.check() without account_name and use_emb_key False"""
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check(None, 1, False))

    def test_060_signature_check(self):
        """ test successful Signature.check() without account_name and use_emb_key True but having a corrupted protected header"""
        protected = {'foo': 'foo'}
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check(None, 1, True, protected))

    @patch('acme.signature.signature_check')
    def test_061_signature_check(self, mock_sig):
        """ test successful Signature.check() with account_name and use_emb_key True, sigcheck returns something"""
        mock_sig.return_value = ('result', 'error')
        self.assertEqual(('result', 'error', None), self.signature.check('foo', 1, True))

    @patch('acme.signature.signature_check')
    def test_062_signature_check(self, mock_sig):
        """ test successful Signature.check() without account_name and use_emb_key True, sigcheck returns something"""
        mock_sig.return_value = ('result', 'error')
        protected = {'url' : 'url', 'jwk': 'jwk'}
        self.assertEqual(('result', 'error', None), self.signature.check(None, 1, True, protected))

    @patch('acme.message.decode_message')
    def test_063_message_check(self, mock_decode):
        """ message_check failed bcs of decoding error """
        message = '{"foo" : "bar"}'
        mock_decode.return_value = (False, 'detail', None, None, None)
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'detail', None, None, None), self.message.check(message))

    @patch('acme.nonce.Nonce.check')
    @patch('acme.message.decode_message')
    def test_064_message_check(self, mock_decode, mock_nonce_check):
        """ message_check nonce check failed """
        message = '{"foo" : "bar"}'
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        self.assertEqual((400, 'badnonce', None, 'protected', 'payload', None), self.message.check(message))

    @patch('acme.nonce.Nonce.check')
    @patch('acme.message.decode_message')
    def test_065_message_check(self, mock_decode, mock_nonce_check):
        """ message check failed bcs account id lookup failed """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual((403, 'urn:ietf:params:acme:error:accountDoesNotExist', None, 'protected', 'payload', None), self.message.check(message))

    @patch('acme.signature.Signature.check')
    @patch('acme.message.Message._name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.message.decode_message')
    def test_066_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check failed bcs signature_check_failed """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (False, 'error', 'detail')
        message = '{"foo" : "bar"}'
        self.assertEqual((403, 'error', 'detail', 'protected', 'payload', 'account_name'), self.message.check(message))

    @patch('acme.signature.Signature.check')
    @patch('acme.message.Message._name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.message.decode_message')
    def test_067_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check successful """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message))

    @patch('acme.signature.Signature.check')
    @patch('acme.message.Message._name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.message.decode_message')
    def test_068_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check successful as nonce check is disabled """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message, skip_nonce_check=True))

    @patch('acme.message.Message.check')
    def test_069_accout_parse(self, mock_mcheck):
        """ Account.parse() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.account.parse(message))

    @patch('acme.message.Message.check')
    def test_070_accout_parse(self, mock_mcheck):
        """ test failed account parse for request which does not has a "status" field in payload """
        mock_mcheck.return_value = (200, None, None, 'protected', {"foo" : "bar"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'dont know what to do with this request'}}, self.account.parse(message))

    @patch('acme.message.Message.check')
    def test_071_accout_parse(self, mock_mcheck):
        """ test failed account parse for reqeust with a "status" field other than "deactivated" """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'status attribute without sense'}}, self.account.parse(message))

    @patch('acme.account.Account._delete')
    @patch('acme.message.Message.check')
    def test_072_accout_parse(self, mock_mcheck, mock_del):
        """ test failed account parse for reqeust with failed deletion """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "deactivated"}, 'account_name')
        mock_del.return_value = (400, 'urn:ietf:params:acme:error:accountDoesNotExist', 'deletion failed')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'detail': 'deletion failed'}}, self.account.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account._delete')
    @patch('acme.message.Message.check')
    def test_073_accout_parse(self, mock_mcheck, mock_del, mock_nnonce):
        """ test succ account parse for reqeust with succ deletion """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "deactivated"}, 'account_name')
        mock_del.return_value = (200, None, None)
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'status': 'deactivated'}, 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))

    def test_074_onlyreturnexisting(self):
        """ test onlyReturnExisting with False """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyreturnexisting' : False}
        self.assertEqual((400, 'urn:ietf:params:acme:error:userActionRequired', 'onlyReturnExisting must be true'), self.account._onlyreturnexisting(protected, payload))

    def test_075_onlyreturnexisting(self):
        """ test onlyReturnExisting without jwk structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyreturnexisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'jwk structure missing'), self.account._onlyreturnexisting(protected, payload))

    def test_076_onlyreturnexisting(self):
        """ test onlyReturnExisting fucntion without onlyReturnExisting structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {}
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'onlyReturnExisting without payload'), self.account._onlyreturnexisting(protected, payload))

    def test_077_onlyreturnexisting(self):
        """ test onlyReturnExisting for existing account """
        self.signature.dbstore.account_lookup.return_value = {'name' : 'foo', 'alg' : 'RS256'}
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyreturnexisting' : True}
        self.assertEqual((200, 'foo', None), self.account._onlyreturnexisting(protected, payload))

    def test_078_onlyreturnexisting(self):
        """ test onlyReturnExisting for non existing account """
        self.signature.dbstore.account_lookup.return_value = False
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyreturnexisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.account._onlyreturnexisting(protected, payload))

    def test_079_utstodate_utc(self):
        """ test uts_to_date_utc for a given format """
        self.assertEqual('2018-12-01', self.uts_to_date_utc(1543640400, '%Y-%m-%d'))

    def test_080_utstodate_utc(self):
        """ test uts_to_date_utc without format """
        self.assertEqual('2018-12-01T05:00:00Z', self.uts_to_date_utc(1543640400))

    def test_081_utstodate_utc(self):
        """ test date_to_uts_utc for a given format """
        self.assertEqual(1543622400, self.date_to_uts_utc('2018-12-01', '%Y-%m-%d'))

    def test_082_utstodate_utc(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(1543640400, self.date_to_uts_utc('2018-12-01T05:00:00'))

    def test_083_generaterandomstring(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(5, len(self.generate_random_string(self.logger, 5)))

    def test_084_generaterandomstring(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(15, len(self.generate_random_string(self.logger, 15)))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_085_order_add(self, mock_name, mock_uts):
        """ test Oder.add() without identifier in payload """
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        message = {}
        e_result = ('urn:ietf:params:acme:error:unsupportedIdentifier', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_086_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with empty identifier in payload dbstore-add returns None"""
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        self.signature.dbstore.order_add.return_value = False
        message = {'identifiers' : {}}
        e_result = ('urn:ietf:params:acme:error:malformed', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_087_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with single identifier in payload dbstore-add returns something real"""
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        self.order.dbstore.order_add.return_value = 1
        self.order.dbstore.authorization_add.return_value = True
        message = {'identifiers' : [{"type": "dns", "value": "example.com"}]}
        e_result = (None, 'aaaaa', {'aaaaa': {'type': 'dns', 'value': 'example.com'}}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_088_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with multiple identifier in payload dbstore-add returns something real"""
        mock_name.side_effect = ['order', 'identifier1', 'identifier2']
        mock_uts.return_value = 1543640400
        self.order.dbstore.order_add.return_value = 1
        self.order.dbstore.authorization_add.return_value = True
        message = {'identifiers' : [{"type": "dns", "value": "example1.com"}, {"type": "dns", "value": "example2.com"}]}
        e_result = (None, 'order', {'identifier1': {'type': 'dns', 'value': 'example1.com'}, 'identifier2': {'type': 'dns', 'value': 'example2.com'}}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme.message.Message.check')
    def test_089_order_new(self, mock_mcheck):
        """ Order.new() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.order.new(message))

    @patch('acme.order.Order._add')
    @patch('acme.message.Message.check')
    def test_090_order_new(self, mock_mcheck, mock_orderadd):
        """ Order.new() failed bcs of db_add failed """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = ('urn:ietf:params:acme:error:malformed', None, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'could not process order'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._add')
    @patch('acme.message.Message.check')
    def test_091_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order with a single identifier """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = (None, 'foo_order', {'foo_auth': {u'type': u'dns', u'value': u'acme.nclm-samba.local'}}, 'expires')
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{u'type': u'dns', u'value': u'acme.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._add')
    @patch('acme.message.Message.check')
    def test_092_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order with multiple identifiers """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = (None, 'foo_order', {'foo_auth1': {u'type': u'dns', u'value': u'acme1.nclm-samba.local'}, 'foo_auth2': {u'type': u'dns', u'value': u'acme2.nclm-samba.local'}}, 'expires')
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        if sys.version_info[0] < 3:
            self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{'type': 'dns', 'value': 'acme2.nclm-samba.local'}, {'type': 'dns', 'value': 'acme1.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth2', 'http://tester.local/acme/authz/foo_auth1'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))
        else:
            self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{'type': 'dns', 'value': 'acme1.nclm-samba.local'}, {'type': 'dns', 'value': 'acme2.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth1', 'http://tester.local/acme/authz/foo_auth2'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._add')
    @patch('acme.message.Message.check')
    def test_093_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order without identifiers """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_nnonce.return_value = 'new_nonce'
        mock_orderadd.return_value = (None, 'foo_order', {}, 'expires')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [], 'authorizations': [], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.challenge.generate_random_string')
    def test_094_challenge_new(self, mock_random):
        """ test challenge generation """
        mock_random.return_value = 'foo'
        # self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'mtype'}, self.challenge._new('authz_name', 'mtype', 'token'))

    @patch('acme.challenge.generate_random_string')
    def test_095_challenge_new(self, mock_random):
        """ test challenge generation for tnauthlist challenge """
        mock_random.return_value = 'foo'
        # self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'tkauth-01', 'tkauth-type': 'atc'}, self.challenge._new('authz_name', 'tkauth-01', 'token'))

    @patch('acme.challenge.Challenge._new')
    def test_096_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token'))

    @patch('acme.challenge.Challenge._new')
    def test_097_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set with tnauth true """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}], self.challenge.new_set('authz_name', 'token', True))

    @patch('acme.challenge.Challenge._new')
    def test_098_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token', False))

    @patch('acme.challenge.Challenge.new_set')
    @patch('acme.authorization.uts_now')
    @patch('acme.authorization.generate_random_string')
    def test_099_authorization_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = [{'type' : 'identifier_type', 'value' : 'identifier_value', 'status__name' : 'foo'}]
        self.assertEqual({'status': 'foo', 'expires': '2018-12-02T05:00:00Z', 'identifier': {'type': 'identifier_type', 'value': 'identifier_value'}, 'challenges': [{'key2': 'value2', 'key1': 'value1'}]}, self.authorization._authz_info('http://tester.local/acme/authz/foo'))

    def test_100_challenge_info(self):
        """ test challenge.info() """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.assertEqual({'status': 'pending', 'token': 'token', 'type': 'http-01'}, self.challenge._info('foo'))

    @patch('acme.message.Message.check')
    def test_101_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed bcs. message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  {'detail': 'detail', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.message.Message.check')
    def test_102_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'url missing in protected header', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.challenge.Challenge._name_get')
    @patch('acme.message.Message.check')
    def test_103_challenge_parse(self, mock_mcheck, mock_cname):
        """ Challenge.parse() message check returns ok with tnauhlist enabled failed tnauth check """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'url' : 'foo'}, {}, 'account_name')
        mock_cname.return_value = None
        self.assertEqual({'code': 400, 'data' : {'detail': 'could not get challenge', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}, self.challenge.parse('content'))

    @patch('acme.challenge.Challenge._info')
    @patch('acme.challenge.Challenge._name_get')
    @patch('acme.message.Message.check')
    def test_104_challenge_parse(self, mock_mcheck, mock_cname, mock_info):
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
    def test_105_challenge_parse(self, mock_mcheck, mock_cname, mock_info, mock_tnauth):
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
    def test_106_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce):
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
    def test_107_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce):
        """ Challenge.parse() successful with TNauthlist disabled """
        self.challenge.tnauthlist_support = False
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.return_value = {'challenge_foo' : 'challenge_bar'}
        mock_tnauth.return_value = (200, 'foo', 'bar')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'new_nonce'}, 'data': {'challenge_foo': 'challenge_bar', 'url': 'bar'}}, self.challenge.parse('content'))

    def test_108_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty challenge_dic """
        payload = {'foo': 'bar'}
        challenge_dic = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'invalid challenge: {}'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_109_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty challenge_dic """
        payload = {}
        challenge_dic = {'type': 'foo'}
        self.assertEqual((200, None, None), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_110_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload without atc claim """
        payload = {}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'atc claim is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_111_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty atc claim """
        payload = {'atc' : None}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'SPC token is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_112_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with '' atc claim """
        payload = {'atc' : ''}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'SPC token is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_113_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with spc token in atc claim """
        payload = {'atc' : 'a'}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((200, None, None), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    @patch('acme.order.Order._info')
    def test_114_order_lookup(self, mock_oinfo):
        """ test order lookup with empty hash """
        mock_oinfo.return_value = {}
        self.assertEqual({}, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_115_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and wrong authorization hash"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': []}, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_116_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and correct authorization hash"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz/name']}, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_117_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and authorization hash having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2']}, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_118_order_lookup(self, mock_oinfo):
        """ test order lookup status in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2']}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_119_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_120_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore (0) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_121_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (0) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 0, 'notafter' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_122_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_123_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_124_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and worng authorization"""
        self.authorization.dbstore.authorization_lookup.return_value = 'foo'
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': [], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order._lookup('foo'))

    def test_125_base64_recode(self):
        """ test base64url recode to base64 - add padding for 1 char"""
        self.assertEqual('fafafaf=', self.b64_url_recode(self.logger, 'fafafaf'))

    def test_126_base64_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(self.logger, 'fafafa'))

    def test_127_base64_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(self.logger, 'fafaf'))

    def test_128_base64_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(self.logger, 'fafafafa'))

    def test_129_base64_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(self.logger, 'fafa-f'))

    def test_130_base64_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, 'fafa_f'))

    def test_131_base64_recode(self):
        """ test base64url recode to base64 - add padding for 1 char"""
        self.assertEqual('fafafaf=', self.b64_url_recode(self.logger, b'fafafaf'))

    def test_132_base64_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(self.logger, b'fafafa'))

    def test_133_base64_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(self.logger, b'fafaf'))

    def test_134_base64_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(self.logger, b'fafafafa'))

    def test_135_base64_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(self.logger, b'fafa-f'))

    def test_136_base64_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, b'fafa_f'))

    @patch('acme.order.Order._info')
    def test_137_csr_process(self, mock_oinfo):
        """ test order prcoess_csr with empty order_dic """
        mock_oinfo.return_value = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized', 'order: order_name not found'), self.order._csr_process('order_name', 'csr'))

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.Order._info')
    def test_138_csr_process(self, mock_oinfo, mock_certname, mock_import):
        """ test order prcoess_csr with failed csr dbsave"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = None
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'CSR processing failed'), self.order._csr_process('order_name', 'csr'))

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.enroll_and_store')
    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.Order._info')
    def test_139_csr_process(self, mock_oinfo, mock_certname, mock_enroll, mock_import):
        """ test order prcoess_csr with failed cert enrollment"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = 'foo'
        mock_enroll.return_value = ('error', 'detail')
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual((400, 'error', 'detail'), self.order._csr_process('order_name', 'csr'))

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.enroll_and_store')
    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.Order._info')
    def test_140_csr_process(self, mock_oinfo, mock_certname, mock_enroll, mock_import):
        """ test order prcoess_csr with successful cert enrollment"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = 'foo'
        mock_enroll.return_value = (None, None)
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual((200, 'foo', None), self.order._csr_process('order_name', 'csr'))

    def test_141_decode_message(self):
        """ decode message with empty payload - certbot issue"""
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        e_result = (True, None, {u'nonce': u'26e6a46efadd477d908d7c2014e49b34', u'url': u'http://laptop.nclm-samba.local/acme/authz/PG189FFzfao1', u'alg': u'RS256', u'kid': u'http://laptop.nclm-samba.local/acme/acct/yuZ1GUJb76Zk'}, {}, b'encoded_signature')
        self.assertEqual(e_result, self.decode_message(self.logger, data_dic))

    @patch('acme.certificate.generate_random_string')
    def test_142_store_csr(self, mock_name):
        """ test Certificate.store_csr() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'foo'
        mock_name.return_value = 'bar'
        self.assertEqual('bar', self.certificate.store_csr('order_name', 'csr'))

    def test_143_store_cert(self):
        """ test Certificate.store_cert() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'bar'
        self.assertEqual('bar', self.certificate._store_cert('cert_name', 'cert', 'raw'))

    def test_144_info(self):
        """ test Certificate.new_get() """
        self.certificate.dbstore.certificate_lookup.return_value = 'foo'
        self.assertEqual('foo', self.certificate._info('cert_name'))

    @patch('acme.certificate.Certificate._info')
    def test_145_new_get(self, mock_info):
        """ test Certificate.new_get() without certificate"""
        mock_info.return_value = {}
        self.assertEqual({'code': 500, 'data': 'urn:ietf:params:acme:error:serverInternal'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_146_new_get(self, mock_info):
        """ test Certificate.new_get() without unknown order_status_id"""
        mock_info.return_value = {'order__status_id': 'foo'}
        self.assertEqual({'code': 403, 'data': 'urn:ietf:params:acme:error:orderNotReady'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_147_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 4 (processing)"""
        mock_info.return_value = {'order__status_id': 4}
        self.assertEqual({'code': 403, 'data': 'urn:ietf:params:acme:error:rateLimited', 'header': {'Retry-After': '600'}}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_148_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) but no certificate in"""
        mock_info.return_value = {'order__status_id': 5}
        self.assertEqual({'code': 500, 'data': 'urn:ietf:params:acme:error:serverInternal'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_149_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) and empty certificate field"""
        mock_info.return_value = {'order__status_id': 5, 'cert': None}
        self.assertEqual({'code': 500, 'data': 'urn:ietf:params:acme:error:serverInternal'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_150_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) but no certificate in"""
        mock_info.return_value = {'order__status_id': 5, 'cert': 'foo-bar'}
        self.assertEqual({'code': 200, 'data': 'foo-bar', 'header': {'Content-Type': 'application/pem-certificate-chain'}}, self.certificate.new_get('url'))

    @patch('acme.message.Message.check')
    def test_151_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  json.dumps({'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'detail'})}, self.certificate.new_post('content'))

    @patch('acme.message.Message.check')
    def test_152_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': json.dumps({'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'url missing in protected header'})}, self.certificate.new_post('content'))

    @patch('acme.message.Message.prepare_response')
    @patch('acme.certificate.Certificate.new_get')
    @patch('acme.message.Message.check')
    def test_153_new_post(self, mock_mcheck, mock_certget, mock_response):
        """ test Certificate.new_post() message check returns ok  """
        mock_mcheck.return_value = (200, None, None, {'url' : 'example.com'}, 'payload', 'account_name')
        mock_certget.return_value = {'code': 403, 'data': 'foo'}
        mock_response.return_value = {'data': 'foo'}
        self.assertEqual({'data': 'foo'}, self.certificate.new_post('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_154_prepare_response(self, mock_nnonce):
        """ Message.prepare_respons for code 200 and complete data """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header', 'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.error.Error.enrich_error')
    @patch('acme.nonce.Nonce.generate_and_add')
    def test_155_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_respons for code 200 without header tag in response_dic """
        data_dic = {'data' : {'foo_data' : 'bar_bar'},}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_156_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without code key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'http status code missing', 'message': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_157_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without message key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'detail', 'message': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_158_prepare_response(self, mock_nnonce):
        """ Message.repare_response for config_dic without detail key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 400, 'message': 'message'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'message': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.error.Error.enrich_error')
    @patch('acme.nonce.Nonce.generate_and_add')
    def test_159_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_response for response_dic without data key """
        data_dic = {'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'message': 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'mock_error', 'message': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    def test_160_acme_errormessage(self):
        """ Error.acme_errormessage for existing value with content """
        self.assertEqual('JWS has invalid anti-replay nonce', self.error._acme_errormessage('urn:ietf:params:acme:error:badNonce'))

    def test_161_acme_errormessage(self):
        """ Error.acme_errormessage for existing value without content """
        self.assertFalse(self.error._acme_errormessage('urn:ietf:params:acme:error:unauthorized'))

    def test_162_acme_errormessage(self):
        """ Error.acme_errormessage for message None """
        self.assertFalse(self.error._acme_errormessage(None))

    def test_163_acme_errormessage(self):
        """ Error.acme_errormessage for not unknown message """
        self.assertFalse(self.error._acme_errormessage('unknown'))

    def test_164_enrich_error(self):
        """ Error.enrich_error for valid message and detail """
        self.assertEqual('JWS has invalid anti-replay nonce: detail', self.error.enrich_error('urn:ietf:params:acme:error:badNonce', 'detail'))

    def test_165_enrich_error(self):
        """ Error.enrich_error for valid message, detail and None in error_hash hash """
        self.assertEqual('detail', self.error.enrich_error('urn:ietf:params:acme:error:badCSR', 'detail'))

    def test_166_enrich_error(self):
        """ Error.enrich_error for valid message, no detail and someting in error_hash hash """
        self.assertEqual('JWS has invalid anti-replay nonce: None', self.error.enrich_error('urn:ietf:params:acme:error:badNonce', None))

    def test_167_enrich_error(self):
        """ Error.enrich_error for valid message, no detail and nothing in error_hash hash """
        self.assertFalse(self.error.enrich_error('urn:ietf:params:acme:error:badCSR', None))

    def test_168_name_get(self):
        """ Order.name_get() http"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo'))

    def test_169_name_get(self):
        """ Order.name_get() http with further path (finalize)"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo/bar'))

    def test_170_name_get(self):
        """ Order.name_get() http with parameters"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo?bar'))

    def test_171_name_get(self):
        """ Order.name_get() http with key/value parameters"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo?key=value'))

    def test_172_name_get(self):
        """ Order.name_get() https with key/value parameters"""
        self.assertEqual('foo', self.order._name_get('https://tester.local/acme/order/foo?key=value'))

    @patch('acme.message.Message.check')
    def test_173_order_parse(self, mock_mcheck):
        """ Order.parse() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.order.parse(message))

    @patch('acme.message.Message.check')
    def test_174_order_parse(self, mock_mcheck):
        """ Order.parse() failed bcs. no url key in protected """
        mock_mcheck.return_value = (200, None, None, {'foo_protected' : 'bar_protected'}, {"foo_payload" : "bar_payload"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'url is missing in protected', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.order.parse(message))

    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_175_order_parse(self, mock_mcheck, mock_oname):
        """ Order.parse() name_get failed """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = None
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'order name is missing', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.order.parse(message))

    @patch('acme.order.Order._lookup')
    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_176_order_parse(self, mock_mcheck, mock_oname, mock_lookup):
        """ Order.parse() failed as order lookup failed """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = None
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 403, 'data': {'detail': 'order not found', 'message': 'urn:ietf:params:acme:error:orderNotReady', 'status': 403}}, self.order.parse(message))

    @patch('acme.order.Order._process')
    @patch('acme.order.Order._lookup')
    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_177_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process):
        """ Order.parse() succ, oder process returned non 200 """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = 'foo'
        mock_process.return_value = (400, 'message', 'detail', None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.order.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._process')
    @patch('acme.order.Order._lookup')
    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_178_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and no certname """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar'}
        mock_process.return_value = (200, 'message', 'detail', None)
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce'}}, self.order.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._process')
    @patch('acme.order.Order._lookup')
    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_179_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname and valid status """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar', 'status': 'valid'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'certificate': 'http://tester.local/acme/cert/certname', 'foo': 'bar', 'status': 'valid'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce'}}, self.order.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._process')
    @patch('acme.order.Order._lookup')
    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_180_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname without status """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce'}}, self.order.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._process')
    @patch('acme.order.Order._lookup')
    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_181_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname and non-valid status """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar', 'status': 'foobar'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar', 'status': 'foobar'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce'}}, self.order.parse(message))

    @patch('acme.message.Message.check')
    def test_182_authorization_post(self, mock_mcheck):
        """ Authorization.new_post() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.authorization.new_post(message))

    @patch('acme.authorization.Authorization._authz_info')
    @patch('acme.message.Message.check')
    def test_183_authorization_post(self, mock_mcheck, mock_authzinfo):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', 'account_name')
        mock_authzinfo.return_value = {'authz_foo': 'authz_bar'}
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'url is missing in protected', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.authorization.new_post(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.authorization.Authorization._authz_info')
    @patch('acme.message.Message.check')
    def test_184_authorization_post(self, mock_mcheck, mock_authzinfo, mock_nnonce):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, {'url' : 'foo_url'}, 'payload', 'account_name')
        mock_authzinfo.return_value = {'authz_foo': 'authz_bar'}
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'authz_foo': 'authz_bar'}}, self.authorization.new_post(message))

    def test_185_cert_serial_get(self):
        """ test cert_serial_get """
        cert = """MIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u
                ZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw
                FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
                ggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq
                HVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC
                7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y
                dpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er
                1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+
                FyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z
                zuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7
                LjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB
                AANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02
                5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm
                TW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h
                bta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR
                fxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H
                t+eRUDECE+0UnjyeCjTn3EU="""
        self.assertEqual(10, self.cert_serial_get(self.logger, cert))

    def test_186_cert_san_get(self):
        """ test cert_san_get for a single SAN """
        cert = """MIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u
                ZXhhbXBsZS5jb20wHhcNMTkwMTIwMTY1OTIwWhcNMTkwMjE5MTY1OTIwWjAaMRgw
                FgYDVQQDEw9mb28uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
                ggEKAoIBAQCqUeNzDyBVugUKZq597ishYAdMPgus5Nw5pWE/Jw7PP0koeFE2wODq
                HVb+XNFFEX4IOyiE2Pi4ilzfXYGKchhP3wHgnkxGNIwt/cDNZgyTiUpITV/ciFaC
                7avkvQS6ScCYUYrhby7QnvcU02mAyhNcSVGI5TW7HhFdtWrEAK3N8H6yhxHLSi2y
                dpQ3kCJyJylqt/Rv3uKNjCvTv867K6A1QSsXoAxtPK9P0UOTRvgHkFf8T32Bn/Er
                1bjkX9Ms8rqDQmicCWJk260lUHzN6vxaeiEg7Kz3TA8Ik3DMIcvwJrE168G1APo+
                FyOIKyx+t78HWOlNINIqZMj5e2DpulV7AgMBAAGjXjBcMB8GA1UdIwQYMBaAFK1Z
                zuGt0Pe+NLerCXqQBYmVV7suMB0GA1UdDgQWBBStWc7hrdD3vjS3qwl6kAWJlVe7
                LjAaBgNVHREEEzARgg9mb28uZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB
                AANW0DD4Xp7LH/Rzf2jVLwiFlbtR6iazyn9S/pH2Gwqjkscv/27/dqJb7CfPdD02
                5ItQcYkZPJhDOsj63kvUaD89QU31RnYQrXrbXFqYOIAq6kxfZUoQmpfEBxbB4Wxm
                TW0OWS+FMqNw/SuGs6EQjTRA+gBOeGzj4H9yOFOg0PpadBayZ7UT4lm1LOiFHh8h
                bta75ocePrurdNxsxKJhLlXbnKD6lurCb4khRhrmLmpK8JxhuaevEVklSQX0gqlR
                fxAH4XQsaqcaedPNI+W5OUITMz40ezDCbUqxS9KEMCGPoOTXNRAjbr72sc4Vkw7H
                t+eRUDECE+0UnjyeCjTn3EU="""
        self.assertEqual(['DNS:foo.example.com'], self.cert_san_get(self.logger, cert))

    def test_187_cert_san_get(self):
        """ test cert_san_get for a multiple SAN of type DNS"""
        cert = """MIIDIzCCAgugAwIBAgICBZgwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPZm9v
                LmV4YW1wbGUuY29tMB4XDTE5MDEyMDE3MDkxMVoXDTE5MDIxOTE3MDkxMVowGjEY
                MBYGA1UEAxMPZm9vLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
                MIIBCgKCAQEA+EM+gzAyjegQSRbJI+qZJhuAGM9i48xvIfuOQHleXoJPjV+8VZRV
                KDljZNXdNT5Zi7K6HY9C622NOV7QefB6zTtm6mSY08ypNsaeorhIvJdnpaJ9gAGH
                YeQqJ04fL099kiRXJAv8gT8wdpiekg2KEU4wlXMIRfSHiiB37yjcqUzXl6XYYKGe
                2USMpDfliXL3o8TW2KByGUdCzXUdNbMgzRXwYxkX2+xV2f0vn8NyXHiHg9yJRof2
                HTjyvAcXN5Nr987slq/Ex5lXLtpB861Ov3ZbwxyzREjmreZBlze7KTfP5IY66XuN
                Mvhi7AAs0cLTd3SNjpppE/yvUi5q5gfhXQIDAQABo3MwcTAfBgNVHSMEGDAWgBSl
                YnpKQw12MmEMpvsTEeQi17UsnDAdBgNVHQ4EFgQUpWJ6SkMNdjJhDKb7ExHkIte1
                LJwwLwYDVR0RBCgwJoIRZm9vLTIuZXhhbXBsZS5jb22CEWZvby0xLmV4YW1wbGUu
                Y29tMA0GCSqGSIb3DQEBCwUAA4IBAQASA20TtMPXIHH10dikLhFuI14EOtZzXvCx
                kGlJw9/5JuvVKLsL1wd8BC9o/lg8apDqsrDZ/+0Nc8g3Z9HRN99vcLsVDdT27DkM
                BslfXdN/qBhKAp3m7jw29uijX5fss+Wz9iHfHciUjVyMJ4DoFxHYPbMWQG8XEUKR
                TP6Gp79DzCiPKFt52Y8yVikIET4fnyRzU8kGKLuPoIt+EQQzpG26qWAjeNHAASEM
                keiA+tedMWzydX52B+tGg+l2svxg34apIBDjK8pF+8ZxTt5yjVUa10GbpffJuiEh
                NWQddOR8IHg+v6lWc9BtuuKK5ubsg6XOiEjhhr42AKViKalX1i4+"""
        self.assertEqual(['DNS:foo-2.example.com', 'DNS:foo-1.example.com'], self.cert_san_get(self.logger, cert))

    def test_188_cert_serial_get(self):
        """ test cert_serial for a multiple SAN of different types"""
        cert = """MIIDIzCCAgugAwIBAgICBZgwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAxMPZm9v
                LmV4YW1wbGUuY29tMB4XDTE5MDEyMDE3MDkxMVoXDTE5MDIxOTE3MDkxMVowGjEY
                MBYGA1UEAxMPZm9vLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
                MIIBCgKCAQEA+EM+gzAyjegQSRbJI+qZJhuAGM9i48xvIfuOQHleXoJPjV+8VZRV
                KDljZNXdNT5Zi7K6HY9C622NOV7QefB6zTtm6mSY08ypNsaeorhIvJdnpaJ9gAGH
                YeQqJ04fL099kiRXJAv8gT8wdpiekg2KEU4wlXMIRfSHiiB37yjcqUzXl6XYYKGe
                2USMpDfliXL3o8TW2KByGUdCzXUdNbMgzRXwYxkX2+xV2f0vn8NyXHiHg9yJRof2
                HTjyvAcXN5Nr987slq/Ex5lXLtpB861Ov3ZbwxyzREjmreZBlze7KTfP5IY66XuN
                Mvhi7AAs0cLTd3SNjpppE/yvUi5q5gfhXQIDAQABo3MwcTAfBgNVHSMEGDAWgBSl
                YnpKQw12MmEMpvsTEeQi17UsnDAdBgNVHQ4EFgQUpWJ6SkMNdjJhDKb7ExHkIte1
                LJwwLwYDVR0RBCgwJoIRZm9vLTIuZXhhbXBsZS5jb22CEWZvby0xLmV4YW1wbGUu
                Y29tMA0GCSqGSIb3DQEBCwUAA4IBAQASA20TtMPXIHH10dikLhFuI14EOtZzXvCx
                kGlJw9/5JuvVKLsL1wd8BC9o/lg8apDqsrDZ/+0Nc8g3Z9HRN99vcLsVDdT27DkM
                BslfXdN/qBhKAp3m7jw29uijX5fss+Wz9iHfHciUjVyMJ4DoFxHYPbMWQG8XEUKR
                TP6Gp79DzCiPKFt52Y8yVikIET4fnyRzU8kGKLuPoIt+EQQzpG26qWAjeNHAASEM
                keiA+tedMWzydX52B+tGg+l2svxg34apIBDjK8pF+8ZxTt5yjVUa10GbpffJuiEh
                NWQddOR8IHg+v6lWc9BtuuKK5ubsg6XOiEjhhr42AKViKalX1i4+"""
        self.assertEqual(1432, self.cert_serial_get(self.logger, cert))

    def test_189_revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with allowed reason"""
        rev_reason = 0
        self.assertEqual('unspecified', self.certificate._revocation_reason_check(rev_reason))

    def test_190_revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with non-allowed reason"""
        rev_reason = 8
        self.assertFalse(self.certificate._revocation_reason_check(rev_reason))

    @patch('acme.certificate.cert_san_get')
    def test_191_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans but failed order lookup"""
        self.account.dbstore.order_lookup.return_value = {}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_192_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order returning wrong values (no 'identifiers' key) """
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_193_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order lookup returning identifiers without json structure) """
        self.account.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_194_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with wrong sans) """
        self.account.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_195_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with SAN entry which is not in the identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_196_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with single SAN entry and correct entry in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_197_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with multiple SAN entries and correct entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_198_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with one SAN entry and multiple entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_199_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with uppercase SAN entries and lowercase entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:SAN1.EXAMPLE.COM', 'DNS:SAN2.EXAMPLE.COM']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_200_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lowercase SAN entries and uppercase entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"TYPE": "DNS", "VALUE": "SAN1.EXAMPLE.COM"}, {"TYPE": "DNS", "VALUE": "SAN2.EXAMPLE.COM"}]'}
        mock_san.return_value = ['dns:san1.example.com', 'dns:san2.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_201_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lSAN entries (return none) and entries in identifier containing None"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "None", "value": "None"}]'}
        mock_san.return_value = ['san1.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_202_revocation_request_validate(self):
        """ test Certificate.revocation_request_validate empty payload"""
        payload = {}
        self.assertEqual((400, 'unspecified'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_203_revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns None"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:badRevocationReason'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_204_revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns a reason"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = 'revrcheck'
        self.assertEqual((400, 'revrcheck'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._authorization_check')
    @patch('acme.certificate.Certificate._account_check')
    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_205_revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check failed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._authorization_check')
    @patch('acme.certificate.Certificate._account_check')
    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_206_revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check succeed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = True
        self.assertEqual((200, 'revrcheck'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.message.Message.check')
    def test_207_revoke(self, mock_mcheck):
        """ test Certificate.revoke with failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'message', 'detail': 'detail'}}, self.certificate.revoke('content'))

    @patch('acme.message.Message.check')
    def test_208_revoke(self, mock_mcheck):
        """ test Certificate.revoke with incorrect payload """
        mock_mcheck.return_value = (200, 'message', 'detail', None, {}, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'certificate not found'}}, self.certificate.revoke('content'))

    @patch('acme.certificate.Certificate._revocation_request_validate')
    @patch('acme.message.Message.check')
    def test_209_revoke(self, mock_mcheck, mock_validate):
        """ test Certificate.revoke with failed request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (400, 'error')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'error'}}, self.certificate.revoke('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.certificate.Certificate._revocation_request_validate')
    @patch('acme.message.Message.check')
    def test_210_revoke(self, mock_mcheck, mock_validate, mock_nnonce):
        """ test Certificate.revoke with sucessful request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (200, 'reason')
        mock_nnonce.return_value = 'new_nonce'
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.certificate.cahandler = ca_handler_module.CAhandler
        self.certificate.cahandler.revoke = Mock(return_value=(200, 'message', 'detail'))
        self.assertEqual({'code': 200, 'header': {'Replay-Nonce': 'new_nonce'}}, self.certificate.revoke('content'))

    def test_211_name_get(self):
        """ test Message.name_get() with empty content"""
        protected = {}
        self.assertFalse(self.message._name_get(protected))

    def test_212_name_get(self):
        """ test Message.name_get() with kid with nonsens in content"""
        protected = {'kid' : 'foo'}
        self.assertEqual('foo', self.message._name_get(protected))

    def test_213_name_get(self):
        """ test Message.name_get() with wrong kid in content"""
        protected = {'kid' : 'http://tester.local/acme/account/account_name'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_214_name_get(self):
        """ test Message.name_get() with correct kid in content"""
        protected = {'kid' : 'http://tester.local/acme/acct/account_name'}
        self.assertEqual('account_name', self.message._name_get(protected))

    def test_215_name_get(self):
        """ test Message.name_get() with 'jwk' in content but without URL"""
        protected = {'jwk' : 'jwk'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_216_name_get(self):
        """ test Message.name_get() with 'jwk' and 'url' in content but url is wrong"""
        protected = {'jwk' : 'jwk', 'url' : 'url'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_217_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' in content but no 'n' in jwk """
        protected = {'jwk' : 'jwk', 'url' : 'http://tester.local/acme/revokecert'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_218_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' but account lookup failed """
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {}
        self.assertEqual(None, self.message._name_get(protected))

    def test_219_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'bar' : 'foo'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_220_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'name' : 'foo'}
        self.assertEqual('foo', self.message._name_get(protected))

    def test_221_revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with a valid revocation reason"""
        self.assertEqual('unspecified', self.certificate._revocation_reason_check(0))

    def test_222_revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with an invalid revocation reason"""
        self.assertFalse(self.certificate._revocation_reason_check(2))

    def test_223_build_pem_file(self):
        """ test build_pem_file without exsting content """
        existing = None
        cert = 'cert'
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_224_build_pem_file(self):
        """ test build_pem_file with exsting content """
        existing = 'existing'
        cert = 'cert'
        self.assertEqual('existing-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_225_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_226_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, False))

    def test_227_build_pem_file(self):
        """ test build_pem_file for CSR """
        existing = None
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=='
        result = """-----BEGIN CERTIFICATE REQUEST-----
MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CT
ZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDg
WlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4
FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZb
eI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY
9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3
BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJh
ci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7
n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAt
iUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYu
tUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9I
NJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQs
KxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A==
-----END CERTIFICATE REQUEST-----
"""
        self.assertEqual(result, self.build_pem_file(self.logger, existing, csr, False, True))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_228_validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() with a wrong challenge """
        mock_url.return_value = 'foo'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((False, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_229_validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() with a correct challenge """
        mock_url.return_value = 'token.jwk_thumbprint'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((True, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_230_validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() without response """
        mock_url.return_value = None
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((False, False), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_231_validate_http_challenge(self, mock_url, mock_resolve):
        """ test Challenge.validate_http_challenge() failed with NX-domain error """
        mock_url.return_value = None
        mock_resolve.return_value = (None, True)
        self.assertEqual((False, True), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.url_get')
    def test_232_validate_http_challenge(self, mock_url, mock_resolve):
        """ test Chalölenge.validate_http_challenge() failed with NX-domain error - non existing case but to be tested"""
        mock_url.return_value = 'foo'
        mock_resolve.return_value = ('foo', True)
        self.assertEqual((False, True), self.challenge._validate_http_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_233_validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Chalölenge.validate_dns_challenge() with incorrect response """
        mock_dns.return_value = 'foo'
        mock_code.return_value = 'bar'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((False, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_234_validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Chalölenge.validate_dns_challenge() with correct response """
        mock_dns.return_value = 'foo'
        mock_code.return_value = 'foo'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = ('foo', False)
        self.assertEqual((True, False), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_235_validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Challenge.validate_dns_challenge() with invalid response """
        mock_dns.return_value = 'foo'
        mock_code.return_value = 'bar'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = (None, True)
        self.assertEqual((False, True), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.fqdn_resolve')
    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_236_validate_dns_challenge(self, mock_dns, mock_code, mock_hash, mock_resolve):
        """ test Challenge.validate_dns_challenge() with invalid but correct fqdn returned """
        mock_dns.return_value = 'foo'
        mock_code.return_value = 'foo'
        mock_hash.return_value = 'hash'
        mock_resolve.return_value = ('foo', True)
        self.assertEqual((False, True), self.challenge._validate_dns_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint'))

    def test_237_validate_tkauth_challenge(self):
        """ test Chalölenge.validate_tkauth_challenge() """
        self.assertEqual((True, False), self.challenge._validate_tkauth_challenge('cert_name', 'fqdn', 'token', 'jwk_thumbprint', 'payload'))

    def test_238_challenge_check(self):
        """ challenge check with incorrect challenge-dictionary """
        # self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.challenge.dbstore.challenge_lookup.return_value = {}
        self.assertEqual((False, False), self.challenge._check('name', 'payload'))

    def test_239_challenge_check(self):
        """ challenge check with without jwk return """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'type', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = None
        self.assertEqual((False, False), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_http_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_240_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (False, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_http_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_241_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_dns_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_242_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed dns challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_dns_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_243_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_244_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tkauth challenge tnauthlist_support not configured """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = (False, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, True), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_245_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tkauth challenge tnauthlist_support True """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.return_value = (False, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, 'foo'), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_246_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist_support unset """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = False
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((False, True), self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_247_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist support set """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.return_value = (True, 'foo')
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertEqual((True, 'foo'), self.challenge._check('name', 'payload'))

    def test_248_order_identifier_check(self):
        """ order identifers check with empty identifer list"""
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check([]))

    def test_249_order_identifier_check(self):
        """ order identifers check with string identifier """
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check('foo'))

    def test_250_order_identifier_check(self):
        """ order identifers check with dictionary identifier """
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check({'type': 'dns', 'value': 'foo.bar'}))

    def test_251_order_identifier_check(self):
        """ order identifers check with correct identifer but case-insensitive """
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check([{'Type': 'dns', 'value': 'value'}]))

    def test_252_order_identifier_check(self):
        """ order identifers check with wrong identifer in list"""
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'foo', 'value': 'value'}]))

    def test_253_order_identifier_check(self):
        """ order identifers check with correct identifer in list"""
        self.assertEqual(None, self.order._identifiers_check([{'type': 'dns', 'value': 'value'}]))

    def test_254_order_identifier_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'dns', 'value': 'value'}, {'type': 'foo', 'value': 'value'}]))

    def test_255_order_identifier_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'foo', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_256_order_identifier_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual(None, self.order._identifiers_check([{'type': 'dns', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_257_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier and support false """
        self.order.tnauthlist_support = False
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_258_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier and support True """
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_259_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier and support True """
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}]))

    def test_260_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier a wrong identifer and support True """
        self.order.tnauthlist_support = True
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'type', 'value': 'value'}]))

    def test_261_order_identifier_check(self):
        """ order identifers check with wrong identifer in list and tnauthsupport true"""
        self.order.tnauthlist_support = True
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'foo', 'value': 'value'}]))

    def test_262_order_identifier_check(self):
        """ order identifers check with correct identifer in list and tnauthsupport true"""
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order._identifiers_check([{'type': 'dns', 'value': 'value'}]))

    def test_263_b64_decode(self):
        """ test bas64 decoder for string value"""
        self.assertEqual('test', self.b64_decode(self.logger, 'dGVzdA=='))

    def test_264_b64_decode(self):
        """ test bas64 decoder for byte value """
        self.assertEqual('test', self.b64_decode(self.logger, b'dGVzdA=='))

    @patch('acme.challenge.Challenge.new_set')
    @patch('acme.authorization.uts_now')
    @patch('acme.authorization.generate_random_string')
    def test_265_authorization_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() in case auth_lookup failed """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = []
        self.assertEqual({}, self.authorization._authz_info('http://tester.local/acme/authz/foo'))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.authorization.Authorization._authz_info')
    @patch('acme.message.Message.check')
    def test_266_authorization_post(self, mock_mcheck, mock_authzinfo, mock_nnonce):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, {'url' : 'foo_url'}, 'payload', 'account_name')
        mock_authzinfo.return_value = {}
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 403, 'data': {'detail': 'authorizations lookup failed', 'message': 'urn:ietf:params:acme:error:unauthorized', 'status': 403}}, self.authorization.new_post(message))

    @patch('acme.account.Account._contact_check')
    def test_267_account_contact_update(self, mock_contact_chk,):
        """ Account.contact_update() failed contact_check failed """
        mock_contact_chk.return_value = (400, 'message', 'detail')
        payload = '{"foo" : "bar"}'
        aname = 'aname'
        self.assertEqual((400, 'message', 'detail'), self.account._contacts_update(aname, payload))

    @patch('acme.account.Account._contact_check')
    def test_268_account_contact_update(self, mock_contact_chk,):
        """ Account.contact_update() failed bcs account update failed """
        mock_contact_chk.return_value = (200, 'message', 'detail')
        self.account.dbstore.account_update.return_value = None
        payload = {"contact" : "foo"}
        aname = 'aname'
        self.assertEqual((400, 'urn:ietf:params:acme:error:accountDoesNotExist', 'update failed'), self.account._contacts_update(aname, payload))

    @patch('acme.account.Account._contact_check')
    def test_269_account_contact_update(self, mock_contact_chk,):
        """ Account.contact_update() succ """
        mock_contact_chk.return_value = (200, 'message', 'detail')
        self.account.dbstore.account_update.return_value = 'foo'
        payload = {"contact" : "foo"}
        aname = 'aname'
        self.assertEqual((200, 'message', 'detail'), self.account._contacts_update(aname, payload))

    @patch('acme.account.Account._contacts_update')
    @patch('acme.message.Message.check')
    def test_270_accout_parse(self, mock_mcheck, mock_contact_upd):
        """ test failed account parse for contacts update as contact updated failed """
        mock_mcheck.return_value = (200, None, None, 'protected', {"contact" : "deactivated"}, 'account_name')
        mock_contact_upd.return_value = (400, 'message', 'detail')
        message = 'message'
        self.assertEqual({'code': 400, 'data': {'detail': 'update failed', 'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'status': 400}, 'header': {}}, self.account.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.date_to_datestr')
    @patch('acme.account.Account._lookup')
    @patch('acme.account.Account._contacts_update')
    @patch('acme.message.Message.check')
    def test_271_accout_parse(self, mock_mcheck, mock_contact_upd, mock_account_lookup, mock_datestr, mock_nnonce):
        """ test succ account parse for reqeust with succ contacts update """
        mock_mcheck.return_value = (200, None, None, 'protected', {"contact" : "deactivated"}, 'account_name')
        mock_contact_upd.return_value = (200, None, None)
        mock_nnonce.return_value = 'new_nonce'
        mock_account_lookup.return_value = {'jwk': '{"foo1": "bar1", "foo2": "bar2"}', 'contact': '["foo@bar", "foo1@bar"]', 'created_at': 'foo'}
        mock_datestr.return_value = 'foo_date'
        message = 'message'
        self.assertEqual({'code': 200, 'data': {'contact': [u'foo@bar', u'foo1@bar'], 'createdAt': 'foo_date', 'key': {u'foo1': u'bar1', u'foo2': u'bar2'}, 'status': 'valid'}, 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))

    def test_272_date_to_datestr(self):
        """ convert dateobj to date-string with default format"""
        self.assertEqual('2019-10-27T00:00:00Z', self.date_to_datestr(datetime.date(2019, 10, 27)))

    def test_273_date_to_datestr(self):
        """ convert dateobj to date-string with a predefined format"""
        self.assertEqual('2019.10.27', self.date_to_datestr(datetime.date(2019, 10, 27), '%Y.%m.%d'))

    def test_274_date_to_datestr(self):
        """ convert dateobj to date-string for an knvalid date"""
        self.assertEqual(None, self.date_to_datestr('foo', '%Y.%m.%d'))

    def test_275_datestr_to_date(self):
        """ convert datestr to date with default format"""
        self.assertEqual(datetime.datetime(2019, 11, 27, 0, 1, 2), self.datestr_to_date('2019-11-27T00:01:02'))

    def test_276_datestr_to_date(self):
        """ convert datestr to date with predefined format"""
        self.assertEqual(datetime.datetime(2019, 11, 27, 0, 0, 0), self.datestr_to_date('2019.11.27', '%Y.%m.%d'))

    def test_277_datestr_to_date(self):
        """ convert datestr to date with invalid format"""
        self.assertEqual(None, self.datestr_to_date('foo', '%Y.%m.%d'))

    def test_278_dkeys_lower(self):
        """ dkeys_lower with a simple string """
        tree = 'fOo'
        self.assertEqual('fOo', self.dkeys_lower(tree))

    def test_279_dkeys_lower(self):
        """ dkeys_lower with a simple list """
        tree = ['fOo', 'bAr']
        self.assertEqual(['fOo', 'bAr'], self.dkeys_lower(tree))

    def test_280_dkeys_lower(self):
        """ dkeys_lower with a simple dictionary """
        tree = {'kEy': 'vAlUe'}
        self.assertEqual({'key': 'vAlUe'}, self.dkeys_lower(tree))

    def test_281_dkeys_lower(self):
        """ dkeys_lower with a nested dictionary containg strings, list and dictionaries"""
        tree = {'kEy1': 'vAlUe2', 'keys2': ['lIsT2', {'kEyS3': 'vAlUe3', 'kEyS4': 'vAlUe3'}], 'keys4': {'kEyS4': 'vAluE5', 'kEyS5': 'vAlUE6'}}
        self.assertEqual({'key1': 'vAlUe2', 'keys2': ['lIsT2', {'keys3': 'vAlUe3', 'keys4': 'vAlUe3'}], 'keys4': {'keys5': 'vAlUE6', 'keys4': 'vAluE5'}}, self.dkeys_lower(tree))

    def test_282_key_compare(self):
        """ Account.key_compare() with two empty dictionaries"""
        self.account.dbstore.jwk_load.return_value = {}
        aname = 'foo'
        okey = {}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_283_key_compare(self):
        """ Account.key_compare() with empty pub_key and existing old_key"""
        self.account.dbstore.jwk_load.return_value = {}
        aname = 'foo'
        okey = {'foo': 'bar'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_284_key_compare(self):
        """ Account.key_compare() with existing pub_key and empty old_key"""
        self.account.dbstore.jwk_load.return_value = {'foo': 'bar'}
        aname = 'foo'
        okey = {}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_285_key_compare(self):
        """ Account.key_compare() with similar pub_key empty old_key"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': None}
        aname = 'foo'
        okey = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': None}
        self.assertEqual((200, None, None), self.account._key_compare(aname, okey))

    def test_286_key_compare(self):
        """ Account.key_compare() with similar pub_key empty old_key but different order"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': None}
        aname = 'foo'
        okey = {'foo3': None, 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((200, None, None), self.account._key_compare(aname, okey))

    def test_287_key_compare(self):
        """ Account.key_compare() pub_key alg rewrite"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'ESfoo'}
        aname = 'foo'
        okey = {'alg': 'ECDSA', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((200, None, None), self.account._key_compare(aname, okey))

    def test_288_key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'foo'}
        aname = 'foo'
        okey = {'alg': 'ECDSA', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_289_key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'ESfoo'}
        aname = 'foo'
        okey = {'alg': 'rsa', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_290_key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite no alg statement in old_key"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'ESfoo'}
        aname = 'foo'
        okey = {'foo3': None, 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_291_key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite no alg statement in pub_key"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': 'bar3'}
        aname = 'foo'
        okey = {'alg': 'ECDSA', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_292_inner_jws_check(self):
        """ Account.inner_jws_check() no jwk in inner header"""
        outer = {}
        inner = {'foo': 'bar'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner jws is missing jwk'), self.account._inner_jws_check(outer, inner))

    def test_293_inner_jws_check(self):
        """ Account.inner_jws_check() no url in inner header """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner or outer jws is missing url header parameter'), self.account._inner_jws_check(outer, inner))

    def test_294_inner_jws_check(self):
        """ Account.inner_jws_check() no url in outer header """
        outer = {'foo' : 'bar'}
        inner = {'jwk': 'jwk', 'url': 'url'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner or outer jws is missing url header parameter'), self.account._inner_jws_check(outer, inner))

    def test_295_inner_jws_check(self):
        """ Account.inner_jws_check() different url string in inner and outer header """
        outer = {'url' : 'url_'}
        inner = {'jwk': 'jwk', 'url': 'url'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'url parameter differ in inner and outer jws'), self.account._inner_jws_check(outer, inner))

    def test_296_inner_jws_check(self):
        """ Account.inner_jws_check() same url string in inner and outer header """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk', 'url': 'url'}
        self.assertEqual((200, None, None), self.account._inner_jws_check(outer, inner))

    def test_297_inner_jws_check(self):
        """ Account.inner_jws_check() nonce in inner header """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk', 'url': 'url', 'nonce': 'nonce'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner jws must omit nonce header'), self.account._inner_jws_check(outer, inner))

    def test_298_inner_jws_check(self):
        """ Account.inner_jws_check() nonce in inner header and inner_header_nonce_allow True """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk', 'url': 'url', 'nonce': 'nonce'}
        self.account.inner_header_nonce_allow = True
        self.assertEqual((200, None, None), self.account._inner_jws_check(outer, inner))

    def test_299_inner_payload_check(self):
        """ Account.inner_payload_check() without kid in outer protected """
        outer_protected = {}
        inner_payload = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'kid is missing in outer header'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_300_inner_payload_check(self):
        """ Account.inner_payload_check() with kid in outer protected but without account object in inner_payload """
        outer_protected = {'kid': 'kid'}
        inner_payload = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'account object is missing on inner payload'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_301_inner_payload_check(self):
        """ Account.inner_payload_check() with different kid and account values """
        outer_protected = {'kid': 'kid'}
        inner_payload = {'account': 'account'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'kid and account objects do not match'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_302_inner_payload_check(self):
        """ Account.inner_payload_check() with same kid and account values but no old_key"""
        outer_protected = {'kid': 'kid'}
        inner_payload = {'account': 'kid'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'old key is missing'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    @patch('acme.account.Account._key_compare')
    def test_303_inner_payload_check(self, mock_cmp):
        """ Account.inner_payload_check() with same kid and account values but no old_key"""
        outer_protected = {'kid': 'kid'}
        inner_payload = {'account': 'kid', 'oldkey': 'oldkey'}
        mock_cmp.return_value = ('code', 'message', 'detail')
        self.assertEqual(('code', 'message', 'detail'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_304_key_change_validate(self):
        """ Account.key_change_validate() without JWK in inner_protected """
        inner_protected = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner jws is missing jwk'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    @patch('acme.account.Account._lookup')
    def test_305_key_change_validate(self, mock_lup):
        """ Account.key_change_validate() for existing key """
        inner_protected = {'jwk': 'jwk'}
        mock_lup.return_value = True
        self.assertEqual((400, 'urn:ietf:params:acme:error:badPublicKey', 'public key does already exists'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    @patch('acme.account.Account._inner_jws_check')
    @patch('acme.account.Account._lookup')
    def test_306_key_change_validate(self, mock_lup, mock_jws_chk):
        """ Account.key_change_validate() inner_jws_check returns 400 """
        inner_protected = {'jwk': 'jwk'}
        mock_lup.return_value = False
        mock_jws_chk.return_value = (400, 'message1', 'detail1')
        self.assertEqual((400, 'message1', 'detail1'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    @patch('acme.account.Account._inner_payload_check')
    @patch('acme.account.Account._inner_jws_check')
    @patch('acme.account.Account._lookup')
    def test_307_key_change_validate(self, mock_lup, mock_jws_chk, mock_pl_chk):
        """ Account.key_change_validate() inner_jws_check returns 200 """
        inner_protected = {'jwk': 'jwk'}
        mock_lup.return_value = False
        mock_jws_chk.return_value = (200, 'message1', 'detail1')
        mock_pl_chk.return_value = ('code2', 'message2', 'detail2')
        self.assertEqual(('code2', 'message2', 'detail2'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    def test_308_key_change(self):
        """ Account.key_change() without URL in protected """
        protected = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'malformed request'), self.account._key_change('aname', {}, protected))

    def test_309_key_change(self):
        """ Account.key_change() with URL in protected without key-change in url"""
        protected = {'url': 'url'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'malformed request. not a key-change'), self.account._key_change('aname', {}, protected))

    @patch('acme.message.Message.check')
    def test_310_key_change(self, mock_mcheck):
        """ Account.key_change() message.check() returns non-200"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = ('code1', 'message1', 'detail1', 'prot', 'payload', 'aname')
        self.assertEqual(('code1', 'message1', 'detail1'), self.account._key_change('aname', {}, protected))

    @patch('acme.account.Account._key_change_validate')
    @patch('acme.message.Message.check')
    def test_311_key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() with URL in protected without key-change in url"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', 'prot', 'payload', 'aname')
        moch_kchval.return_value = ('code2', 'message2', 'detail2')
        self.assertEqual(('code2', 'message2', 'detail2'), self.account._key_change('aname', {}, protected))

    @patch('acme.account.Account._key_change_validate')
    @patch('acme.message.Message.check')
    def test_312_key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() - account_update returns nothing"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', {'jwk': {'h1': 'h1a', 'h2': 'h2a', 'h3': 'h3a'}}, 'payload', 'aname')
        moch_kchval.return_value = (200, 'message2', 'detail2')
        self.account.dbstore.account_update.return_value = None
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'key rollover failed'), self.account._key_change('aname', {}, protected))

    @patch('acme.account.Account._key_change_validate')
    @patch('acme.message.Message.check')
    def test_313_key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() - account_update returns nothing"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', {'jwk': {'h1': 'h1a', 'h2': 'h2a', 'h3': 'h3a'}}, 'payload', 'aname')
        moch_kchval.return_value = (200, 'message2', 'detail2')
        self.account.dbstore.account_update.return_value = True
        self.assertEqual((200, None, None), self.account._key_change('aname', {}, protected))

    def test_314_order_process(self):
        """ Order.prcoess() without url in protected header """
        order_name = 'order_name'
        protected = 'protected'
        payload = 'payload'
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'url is missing in protected', None), self.order._process(order_name, protected, payload))

    def test_315_order_process(self):
        """ Order.prcoess() polling request with failed certificate lookup """
        order_name = 'order_name'
        protected = {'url': 'foo'}
        payload = 'payload'
        self.order.dbstore.certificate_lookup.return_value = {}
        self.assertEqual((200, None, None, None), self.order._process(order_name, protected, payload))

    def test_316_order_process(self):
        """ Order.prcoess() polling request with successful certificate lookup """
        order_name = 'order_name'
        protected = {'url': 'foo'}
        payload = 'payload'
        self.order.dbstore.certificate_lookup.return_value = {'name': 'cert_name'}
        self.assertEqual((200, None, None, 'cert_name'), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._info')
    def test_317_order_process(self, mock_info):
        """ Order.prcoess() finalize request with empty orderinfo """
        mock_info.return_value = {}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:orderNotReady', 'Order is not ready', None), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._info')
    def test_318_order_process(self, mock_info):
        """ Order.prcoess() finalize request with orderinfo without status"""
        mock_info.return_value = {'foo': 'bar'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:orderNotReady', 'Order is not ready', None), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._info')
    def test_319_order_process(self, mock_info):
        """ Order.prcoess() finalize request with orderinfo with wrong status"""
        mock_info.return_value = {'status': 'bar'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:orderNotReady', 'Order is not ready', None), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._info')
    def test_320_order_process(self, mock_info):
        """ Order.prcoess() finalize request without CSR """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((400, 'urn:ietf:params:acme:error:badCSR', 'csr is missing in payload', None), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._csr_process')
    @patch('acme.order.Order._info')
    def test_321_order_process(self, mock_info, mock_process_csr):
        """ Order.prcoess() finalize request with CSR but csr_process failed """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = {'csr': 'csr'}
        mock_process_csr.return_value = (400, 'cert_name', 'detail')
        self.assertEqual((400, 'cert_name', 'enrollment failed', 'cert_name'), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._update')
    @patch('acme.order.Order._csr_process')
    @patch('acme.order.Order._info')
    def test_322_order_process(self, mock_info, mock_process_csr, mock_update):
        """ Order.prcoess() finalize request with CSR but csr_process failed """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = {'csr': 'csr'}
        mock_process_csr.return_value = (200, 'cert_name', 'detail')
        mock_update.return_value = None
        self.assertEqual((200, None, 'detail', 'cert_name'), self.order._process(order_name, protected, payload))

    def test_323_cert_pubkey_get(self):
        """ test get public_key from certificate """
        cert = """
-----BEGIN X509 CERTIFICATE-----
MIIE2zCCAsOgAwIBAgIPAXI102H4bCWEkhD2SaLsMA0GCSqGSIb3DQEBDQUAMDIx
CzAJBgNVBAYTAkRFMQ4wDAYDVQQKEwVOb2tpYTETMBEGA1UEAwwKbmNtX3N1Yl9j
YTAeFw0yMDA1MjEwNTMyMjVaFw0yMDA2MjAyMzU5NTlaMBkxFzAVBgNVBAMTDmZv
bzEuYmFyLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+
z+9wsEewBf1hnk3yAy5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN
+lx6nQCXIqCZSN97hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOL
hjTlN2f7Z081XWIgkikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MF
o+tLu0toAc0nm9v8Otme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgba
j94e1uznsyni7CYw/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xo
aygpd9+UHCREhcOu/wIDAQABo4IBBTCCAQEwHwYDVR0jBBgwFoAUEZ+5Dp2l8KCZ
zHhwr3965P6xxsswHQYDVR0OBBYEFKsuSjgZZMl9vZeBB0wks4Wbg4PhMAsGA1Ud
DwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDBUBgNVHR8ETTBLMEmg
R6BFhkNodHRwOi8vc3J2Lm5jbG0tc2FtYmEubG9jYWw6ODA4MC9jcmwtYXMtZGVy
L2N1cnJlbnRjcmwtODcuY3JsP2lkPTg3MEEGCCsGAQUFBwEBBDUwMzAxBggrBgEF
BQcwAYYlaHR0cDovL3Nydi5uY2xtLXNhbWJhLmxvY2FsOjgwOTAvY2EyLzANBgkq
hkiG9w0BAQ0FAAOCAgEAgpfWOM8fWlkwSbWtgnAKnu8GNMteOckWS1gMydOhokhY
PZdkpL8uoMWRahyjhmAH85TtHdydVaQ9NNBUTsbiOqkN2jPurDdzgfUs2gAwoR05
MkHVWI1+C3lHAVlqPWYld+6Kl3lnEjy3jFSMugTuq5h79f0KxGle7W568Xg+zI3R
Ry1dRggR6W2G9L+7Ez8Y+H/8P/gjbTO1GGYoXI4ISQl3EinL/X7XpYnQ3o14uDLb
m/h+YyLfi03m8tLJQPM7soDAZx6qI/1V4H/VT1VEKBCiec8w580rIH6GSrjUkddp
wd0p74B8xwmt9zA+gBV3Js72PBy9mdcMIvYIO3otmN2jQL8PC1B8VNEmf0l8a5wq
07qftQEI82vcrLG8Dgy7R9AxrIxd1xnZOTrcOo3dU+blAehAJZWT2B0B8XyoGk2/
CiMCwOQijMgp97tjnuQ3dkRhu50kUN5LCa9jU2ongXj0+28mEKZ5rAQUBQmAMITR
hTkTB1OxdpFMxyg83OZdYu/xit9YfVB0AAyarqjTst/y79UkExfEf0sAARBiffkx
PZwtZpoz736yvIqanX6u2zUHLDzSRZXOZHY6pxANqoH6howxqGkI3FMjeDbDUln7
/TEtRju77ONV1X+8iPYrnQqTRoR3a3IwT8Cz/HErNM6aNCvPVPqakZXZrcpXILY=
-----END X509 CERTIFICATE-----"""

        pub_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+z+9wsEewBf1hnk3y
Ay5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN+lx6nQCXIqCZSN97
hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOLhjTlN2f7Z081XWIg
kikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo+tLu0toAc0nm9v8
Otme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw
/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xoaygpd9+UHCREhcOu
/wIDAQAB
-----END PUBLIC KEY-----
"""
        self.assertEqual(pub_key, self.cert_pubkey_get(self.logger, cert))

    def test_324_csr_pubkey_get(self):
        """ test get public_key from certificate """
        csr = """MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBvH7P73CwR7AF/WGeTfIDLlMWD6VZV3CTZBF0AwNMTFU/zbdAX8r63pzElX/5C5ZVsc36XHqdAJcioJlI33uE3RhOSvDyOcDgWlnPK9gj2soQ7enizGqd1u7hf6C3IwFtc4uGNOU3Z/tnTzVdYiCSKS+5lTZfMxn4FtEUN+w90NHBvC+AlTo3Gl0gqbYOZgg/UwWj60u7S2gBzSeb2/w62Z7bz+SknGZbeI4ySo30ET6oCSCAUN42jE+1dHI/Y+tGBtqP3h7W7OezKeLsJjD9r07U0+uMoVCY9oKTyT0gK8+gsde0tpt6QKa93HJGUPAP9ehrKCl335QcJESFw67/AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAf4cdGpYHLqX+06BFF7+NqXLmKvc7n66vAfevLN75eu/pCXhhRSdpXvcYm+mAVEXJCPaG2kFGt6wfBvVWoVX/91d+OuAtiUHmhY95Oi7g3RF3ThCrvT2mR4zsNiKgC34jXbl9489iIiFRBQXkq2fLwN5JwBYutUENwkDIeApRRbmUzTDbar1xoBAQ3GjVtOAEjHc/3S1yyKkCpM6Qkg8uWOJAXw9INJqH6x55nMZrvTUuXkURc/mvhV+bp2vdKoigGvfa3VVfoAI0BZLQMohQ9QLKoNQsKxEs3JidvpZrl3o23LMGEPoJs3zIuowTa217PHwdBw4UwtD7KxJK/+344A=="""

        pub_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx+z+9wsEewBf1hnk3y
Ay5TFg+lWVdwk2QRdAMDTExVP823QF/K+t6cxJV/+QuWVbHN+lx6nQCXIqCZSN97
hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X+gtyMBbXOLhjTlN2f7Z081XWIg
kikvuZU2XzMZ+BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo+tLu0toAc0nm9v8
Otme28/kpJxmW3iOMkqN9BE+qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw
/a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD/Xoaygpd9+UHCREhcOu
/wIDAQAB
-----END PUBLIC KEY-----
"""
        self.assertEqual(pub_key, self.csr_pubkey_get(self.logger, csr))

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_325_trigger_certname_lookup(self, mock_cert_pub, mock_search_list, mock_import):
        """ trigger._certname_lookup() failed bcs. of empty certificate list """
        mock_cert_pub.return_value = 'foo'
        mock_search_list.return_value = []
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_326_trigger_certname_lookup(self, mock_cert_pub, mock_search_list, mock_import):
        """ trigger._certname_lookup() failed bcs. of wrong certificate list """
        mock_cert_pub.return_value = 'foo'
        mock_search_list.return_value = [{'foo': 'bar'}]
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_327_trigger_certname_lookup(self, mock_cert_pub, mock_search_list, mock_import):
        """ trigger._certname_lookup() failed bcs. of emty csr field """
        mock_cert_pub.return_value = 'foo'
        mock_search_list.return_value = [{'csr': None}]
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('importlib.import_module')
    @patch('acme.trigger.csr_pubkey_get')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_328_trigger_certname_lookup(self, mock_cert_pub, mock_search_list, mock_csr_pub, mock_import):
        """ trigger._certname_lookup() failed bcs. of emty csr field """
        mock_cert_pub.return_value = 'foo'
        mock_csr_pub.return_value = 'foo1'
        mock_search_list.return_value = [{'csr': None}]
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('importlib.import_module')
    @patch('acme.trigger.csr_pubkey_get')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_329_trigger_certname_lookup(self, mock_cert_pub, mock_search_list, mock_csr_pub, mock_import):
        """ trigger._certname_lookup() failed bcs. of emty csr field """
        mock_cert_pub.return_value = 'foo'
        mock_csr_pub.return_value = 'foo'
        mock_search_list.return_value = [{'csr': 'csr', 'name': 'cert_name', 'order__name': 'order_name'}]
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.assertEqual([{'cert_name': 'cert_name', 'order_name': 'order_name'}], self.trigger._certname_lookup('cert_pem'))

    def test_330_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertEqual('foo', self.convert_byte_to_string('foo'))

    def test_331_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertEqual('foo', self.convert_byte_to_string('foo'))

    def test_332_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertNotEqual('foo', self.convert_byte_to_string('foobar'))

    def test_333_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertNotEqual('foo', self.convert_byte_to_string(b'foobar'))

    def test_334_parse(self):
        """ Trigger.parse() with empty payload """
        payload = ""
        result = {'header': {}, 'code': 400, 'data': {'detail': 'payload missing', 'message': 'malformed', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    def test_335_parse(self):
        """ Trigger.parse() with wrong payload """
        payload = '{"foo": "bar"}'
        result = {'header': {}, 'code': 400, 'data': {'detail': 'payload missing', 'message': 'malformed', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    def test_336_parse(self):
        """ Trigger.parse() with empty payload key"""
        payload = '{"payload": ""}'
        result = {'header': {}, 'code': 400, 'data': {'detail': 'payload empty', 'message': 'malformed', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    @patch('acme.trigger.Trigger._payload_process')
    def test_337_parse(self, mock_process):
        """ Trigger.parse() with payload mock result 400"""
        payload = '{"payload": "foo"}'
        mock_process.return_value = (400, 'message', 'detail')
        result = {'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    @patch('acme.trigger.Trigger._payload_process')
    def test_338_parse(self, mock_process):
        """ Trigger.parse() with payload mock result 200"""
        payload = '{"payload": "foo"}'
        mock_process.return_value = (200, 'message', 'detail')
        result = {'header': {}, 'code': 200, 'data': {'detail': 'detail', 'message': 'message', 'status': 200}}
        self.assertEqual(result, self.trigger.parse(payload))

    def test_339__payload_process(self):
        """ Trigger._payload_process() without payload"""
        payload = {}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', None, None))
        self.assertEqual((400, 'payload malformed', None), self.trigger._payload_process(payload))

    def test_340__payload_process(self):
        """ Trigger._payload_process() without certbunde and cert_raw"""
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', None, None))
        self.assertEqual((400, 'error', None), self.trigger._payload_process(payload))

    def test_341__payload_process(self):
        """ Trigger._payload_process() with bundle and without cart_raw"""
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', None))
        self.assertEqual((400, 'error', None), self.trigger._payload_process(payload))

    def test_342__payload_process(self):
        """ Trigger._payload_process() with bundle and without cart_raw"""
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', None, 'raw'))
        self.assertEqual((400, 'error', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    def test_343__payload_process(self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() with certificae_name"""
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', 'raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name', 'order_name': None}]
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    def test_344__payload_process(self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() without certificate_name """
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', 'raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': None, 'order_name': 'order_name'}]
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    def test_345__payload_process(self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() without certificate_name """
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', 'raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name', 'order_name': 'order_name'}]
        self.order.dbstore.order_update.return_value = None
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    def test_346__payload_process(self, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() without certificate_name """
        payload = {'payload': 'foo'}
        ca_handler_module = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        self.trigger.cahandler = ca_handler_module.CAhandler
        self.trigger.cahandler.trigger = Mock(return_value=('error', 'bundle', 'raw'))
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value = 'b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name1', 'order_name': 'order_name1'}, {'cert_name': 'certificate_name2', 'order_name': 'order_name2'}]
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    def test_347_b64encode(self):
        """ test b64_url_encode of string """
        self.assertEqual(b'c3RyaW5n', self.b64_url_encode(self.logger, 'string'))

    def test_348_b64encode(self):
        """ test b64_url_encode of byte """
        self.assertEqual(b'Ynl0ZQ', self.b64_url_encode(self.logger, b'byte'))

    def test_349_csr_cn_get(self):
        """ get cn of csr """
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0lk4lyEIa0VL/u5ic01Zo/o+gyYqFpU7xe+nbFgiKA+R1rqrzP/sR6xjHqS0Rkv/BcBXf81sp/+iDmwIQLVlBTkKdimqVHCJMAbTL8ZNpcLDaRUce4liyX1cmczPTSqI/kcyEr8tKpYN+KzvKZZsNx2Pbgu7y7/70P2uSywiW+sqYZ+X28KGFxq6wwENzJtweDVsbWql9LLtw6daF41UQg10auNlRL1nhW0SlWZh1zPPW/0sa6C3xX28jjVh843b4ekkRNLXSEYQMTi0qYR2LomQ5aTlQ/hellf17UknfN2aA2RH5D7Ek+mndj/rH21bxQg26KRmHlaJld9K1IfvJAgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAl3egrkO3I94IpxxfSJmVetd7s9uW3lSBqh9OiypFevQO7ZgUxau+k05NKTUNpSq3W9H/lRr5AG5x3/VX8XZVbcLKXQ0d6e38uXBAUFQQJmjBVYqd8KcMfqLeFFUBsLcG04yek2tNIbhXZfBtw9UYO27Y5ktMgWjAz2VskIXl3E2L0b8tGnSKDoMB07IVpYB9bHfHX4o+ccIgq1HxyYT1d+eVIQuSHHxR7j7Wkgb8RG9bCWpVWaYWKWU0Inh3gMnP06kPBJ9nOB4adgC3Hz37ab/0KpmBuQBEgmMfINwV/OpJVv2Su1FYK+uX7E1qUGae6QDsfg0Yor9uP0Vkv4b1NA=='
        self.assertEqual('foo1.bar.local', self.csr_cn_get(self.logger, csr))

    def test_350_csr_cn_get(self):
        """ get cn of csr """
        csr = b'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0lk4lyEIa0VL/u5ic01Zo/o+gyYqFpU7xe+nbFgiKA+R1rqrzP/sR6xjHqS0Rkv/BcBXf81sp/+iDmwIQLVlBTkKdimqVHCJMAbTL8ZNpcLDaRUce4liyX1cmczPTSqI/kcyEr8tKpYN+KzvKZZsNx2Pbgu7y7/70P2uSywiW+sqYZ+X28KGFxq6wwENzJtweDVsbWql9LLtw6daF41UQg10auNlRL1nhW0SlWZh1zPPW/0sa6C3xX28jjVh843b4ekkRNLXSEYQMTi0qYR2LomQ5aTlQ/hellf17UknfN2aA2RH5D7Ek+mndj/rH21bxQg26KRmHlaJld9K1IfvJAgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAl3egrkO3I94IpxxfSJmVetd7s9uW3lSBqh9OiypFevQO7ZgUxau+k05NKTUNpSq3W9H/lRr5AG5x3/VX8XZVbcLKXQ0d6e38uXBAUFQQJmjBVYqd8KcMfqLeFFUBsLcG04yek2tNIbhXZfBtw9UYO27Y5ktMgWjAz2VskIXl3E2L0b8tGnSKDoMB07IVpYB9bHfHX4o+ccIgq1HxyYT1d+eVIQuSHHxR7j7Wkgb8RG9bCWpVWaYWKWU0Inh3gMnP06kPBJ9nOB4adgC3Hz37ab/0KpmBuQBEgmMfINwV/OpJVv2Su1FYK+uX7E1qUGae6QDsfg0Yor9uP0Vkv4b1NA=='
        self.assertEqual('foo1.bar.local', self.csr_cn_get(self.logger, csr))

    def test_351_wcd_manipulate(self):
        """ get fqdn wc manipulation """
        fqdn = 'foo.bar'
        self.assertEqual('foo.bar', self.challenge._wcd_manipulate(fqdn))

    def test_352_wcd_manipulate(self):
        """ get fqdn wc manipulation """
        fqdn = '*.foo.bar'
        self.assertEqual('foo.bar', self.challenge._wcd_manipulate(fqdn))

    def test_353_wcd_manipulate(self):
        """ get fqdn wc manipulation """
        fqdn = 'foo*.foo.bar'
        self.assertEqual('foo*.foo.bar', self.challenge._wcd_manipulate(fqdn))

    def test_354_convert_string_to_byte(self):
        """ convert string value to byte """
        value = 'foo.bar'
        self.assertEqual(b'foo.bar', self.convert_string_to_byte(value))

    def test_355_convert_string_to_byte(self):
        """ convert string value to byte """
        value = b'foo.bar'
        self.assertEqual(b'foo.bar', self.convert_string_to_byte(value))

    def test_356_convert_string_to_byte(self):
        """ convert string value to byte """
        value = b''
        self.assertEqual(b'', self.convert_string_to_byte(value))

    def test_357_convert_string_to_byte(self):
        """ convert string value to byte """
        value = ''
        self.assertEqual(b'', self.convert_string_to_byte(value))

    def test_358_convert_string_to_byte(self):
        """ convert string value to byte """
        value = None
        self.assertFalse(self.convert_string_to_byte(value))

    def test_359_get_url(self):
        """ get_url https """
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 443, 'PATH_INFO': 'path_info'}
        self.assertEqual('https://http_host', self.get_url(data_dic, False))

    def test_360_get_url(self):
        """ get_url http """
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 80, 'PATH_INFO': 'path_info'}
        self.assertEqual('http://http_host', self.get_url(data_dic, False))

    def test_361_get_url(self):
        """ get_url http wsgi.scheme """
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 80, 'PATH_INFO': 'path_info', 'wsgi.url_scheme': 'wsgi.url_scheme'}
        self.assertEqual('wsgi.url_scheme://http_host', self.get_url(data_dic, False))

    def test_362_get_url(self):
        """ get_url https include_path true bot no pathinfo"""
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 443}
        self.assertEqual('https://http_host', self.get_url(data_dic, True))

    def test_363_get_url(self):
        """ get_url https and path info"""
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 443, 'PATH_INFO': 'path_info'}
        self.assertEqual('https://http_hostpath_info', self.get_url(data_dic, True))

    def test_364_get_url(self):
        """ get_url wsgi.url and pathinfo """
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 80, 'PATH_INFO': 'path_info', 'wsgi.url_scheme': 'wsgi.url_scheme'}
        self.assertEqual('wsgi.url_scheme://http_hostpath_info', self.get_url(data_dic, True))

    def test_365_get_url(self):
        """ get_url http and pathinfo"""
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 80, 'PATH_INFO': 'path_info'}
        self.assertEqual('http://http_hostpath_info', self.get_url(data_dic, True))

    def test_366_get_url(self):
        """ get_url without hostinfo """
        data_dic = {'SERVER_PORT': 80, 'PATH_INFO': 'path_info'}
        self.assertEqual('http://localhost', self.get_url(data_dic, False))

    def test_367_get_url(self):
        """ get_url without SERVER_PORT """
        data_dic = {'HTTP_HOST': 'http_host'}
        self.assertEqual('http://http_host', self.get_url(data_dic, True))

    @patch('acme.helper.requests.get')
    def test_368_url_get(self, mock_request):
        """ successful url get without dns servers """
        mock_request.return_value.text = 'foo'
        self.assertEqual('foo', self.url_get(self.logger, 'url'))

    @patch('acme.helper.requests.get')
    def test_369_url_get(self, mock_request):
        """ unsuccessful url get without dns servers """
        # this is stupid but triggrs an expeption
        mock_request.return_value = {'foo': 'foo'}
        self.assertEqual(None, self.url_get(self.logger, 'url'))

    @patch('acme.helper.url_get_with_own_dns')
    def test_370_url_get(self, mock_request):
        """ successful url get with dns servers """
        mock_request.return_value = 'foo'
        self.assertEqual('foo', self.url_get(self.logger, 'url', 'dns'))

    @patch('acme.helper.requests.get')
    def test_371_url_get(self, mock_request):
        """ successful url_get_with_own_dns get with dns servers """
        mock_request.return_value.text = 'foo'
        self.assertEqual('foo', self.url_get_with_own_dns(self.logger, 'url'))

    @patch('acme.helper.requests.get')
    def test_372_url_get(self, mock_request):
        """ successful url_get_with_own_dns get with dns servers """
        mock_request.return_value = {'foo': 'foo'}
        self.assertEqual(None, self.url_get_with_own_dns(self.logger, 'url'))

    @patch('acme.helper.load_config')
    def test_373_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with empty config file """
        mock_load_config.return_value = {}
        self.assertEqual(['9.9.9.9', '8.8.8.8'], self.dns_server_list_load())

    @patch('acme.helper.load_config')
    def test_374_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with empty Challenge section """
        mock_load_config.return_value = {'Challenge': {}}
        self.assertEqual(['9.9.9.9', '8.8.8.8'], self.dns_server_list_load())

    @patch('acme.helper.load_config')
    def test_375_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with wrong Challenge section """
        mock_load_config.return_value = {'Challenge': {'foo': 'bar'}}
        self.assertEqual(['9.9.9.9', '8.8.8.8'], self.dns_server_list_load())

    @patch('acme.helper.load_config')
    def test_376_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with wrong json format """
        mock_load_config.return_value = {'Challenge': {'dns_server_list': 'bar'}}
        self.assertEqual(['9.9.9.9', '8.8.8.8'], self.dns_server_list_load())

    @patch('acme.helper.load_config')
    def test_377_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with wrong json format """
        mock_load_config.return_value = {'Challenge': {'dns_server_list': '["foo", "bar"]'}}
        self.assertEqual(['foo', 'bar'], self.dns_server_list_load())

    @patch('acme.account.generate_random_string')
    def test_378_account_add_new(self, mock_name):
        """ test failed account add due to ecc mandated """
        # self.account.dbstore.account_add.return_value = (2, True)
        self.account.ecc_only = True
        mock_name.return_value = 'randowm_string'
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((403, 'urn:ietf:params:acme:error:badPublicKey', 'Only ECC keys are supported'), self.account._add(dic, 'foo@example.com'))

    @patch('acme.account.generate_random_string')
    def test_379_account_add_new(self, mock_name):
        """ test successful account add for a new account"""
        self.account.dbstore.account_add.return_value = (2, True)
        self.account.ecc_only = True
        mock_name.return_value = 'randowm_string'
        dic = {'alg': 'ES256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((201, 'randowm_string', None), self.account._add(dic, 'foo@example.com'))

    @patch('acme.account.generate_random_string')
    def test_380_account_add_new(self, mock_name):
        """ test account add without contact """
        self.account.contact_check_disable = True
        self.account.dbstore.account_add.return_value = ('foo', False)
        mock_name.return_value = 'randowm_string'
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((200, 'foo', None), self.account._add(dic, None))

    @patch('acme.message.Message.check')
    def test_381_account_new(self, mock_mcheck):
        """ Account.new() tos required"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        self.account.tos_check_disable = False
        self.account.tos_url = 'foo'
        message = {'foo' : 'bar'}
        e_result = {'code': 403, 'data': {'detail': 'Terms of service must be accepted', 'message': 'urn:ietf:params:acme:error:userActionRequired', 'status': 403}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account._add')
    @patch('acme.account.Account._contact_check')
    @patch('acme.message.Message.check')
    def test_382_account_new(self, mock_mcheck, mock_contact, mock_aad, mock_nnonce):
        """ Account.new() successful tos disabled no tos url configured"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        self.account.tos_check_disable = True
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account._add')
    @patch('acme.account.Account._contact_check')
    @patch('acme.message.Message.check')
    def test_383_account_new(self, mock_mcheck, mock_contact, mock_aad, mock_nnonce):
        """ Account.new() successful tos disabled tos url configured"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        self.account.tos_check_disable = True
        self.account.tos_url = 'foo'
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account._add')
    @patch('acme.message.Message.check')
    def test_384_account_new(self, mock_mcheck, mock_aad, mock_nnonce):
        """ Account.new() successful tos/email checks_disabled"""
        mock_mcheck.return_value = (200, None, None, 'protected', {}, None)
        self.account.tos_check_disable = True
        self.account.contact_check_disable = True
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.account.Account._tos_check')
    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account._add')
    @patch('acme.message.Message.check')
    def test_385_account_new(self, mock_mcheck, mock_aad, mock_nnonce, mock_tos):
        """ Account.new() successful email checks_disabled"""
        mock_mcheck.return_value = (200, None, None, 'protected', {}, None)
        self.account.contact_check_disable = True
        mock_tos.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    def test_386_get_dir_meta(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.tos_url = 'foo'
        self.directory.supress_version = True
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'termsOfService': 'foo'}}, self.directory.directory_get())

    def test_387_get_dir_meta(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.version = '0.1'
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'version': '0.1'}}, self.directory.directory_get())

    def test_388_get_dir_meta(self):
        """ test Directory.get_directory() method and check for "meta" tag in output"""
        self.directory.version = '0.1'
        self.directory.tos_url = 'foo'
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>', 'name': 'acme2certifier', 'version': '0.1', 'termsOfService': 'foo'}}, self.directory.directory_get())

    @patch('acme.message.Message.check')
    def test_389_account_new(self, mock_mcheck):
        """ Account.new() tos check skipped as no tos """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', None)
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': 'The provided contact URI was invalid: no contacts specified', 'message': 'urn:ietf:params:acme:error:invalidContact', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    def test_390_tnauth_identifier_check(self):
        """ identifier check empty """
        identifier_dic = []
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_391_tnauth_identifier_check(self):
        """ identifier check none input"""
        identifier_dic = None
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_392_tnauth_identifier_check(self):
        """ identifier check none input"""
        identifier_dic = 'foo'
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_393_tnauth_identifier_check(self):
        """ identifier check one identifier """
        identifier_dic = [{'foo': 'bar'}]
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_394_tnauth_identifier_check(self):
        """ identifier check two identifiers """
        identifier_dic = [{'foo': 'bar'}, {'foo': 'bar'}]
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_395_tnauth_identifier_check(self):
        """ identifier check hit first identifiers """
        identifier_dic = [{'type': 'bar'}, {'foo': 'bar'}]
        self.assertFalse(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_396_tnauth_identifier_check(self):
        """ identifier check hit first identifiers """
        identifier_dic = [{'type': 'TNAUTHLIST'}, {'foo': 'bar'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_397_tnauth_identifier_check(self):
        """ identifier check hit first identifiers """
        identifier_dic = [{'type': 'tnauthlist'}, {'foo': 'bar'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_398_tnauth_identifier_check(self):
        """ identifier check hit 2nd identifiers """
        identifier_dic = [{'type': 'bar'}, {'type': 'tnauthlist'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_399_tnauth_identifier_check(self):
        """ identifier check hit 2nd identifiers """
        identifier_dic = [{'type': 'bar'}, {'type': 'TNAUTHLIST'}]
        self.assertTrue(self.certificate._tnauth_identifier_check(identifier_dic))

    def test_400__identifer_status_list(self):
        """ failed check identifiers against san """
        identifier_dic = [{'foo': 'bar'}, {'foo': 'bar'}]
        san_list = ['foo:bar', 'foo:bar']
        self.assertEqual([False, False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_401__identifer_status_list(self):
        """ failed check no sans """
        identifier_dic = [{'foo': 'bar'}]
        san_list = []
        self.assertEqual([], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_402__identifer_status_list(self):
        """ failed check no identifiers """
        identifier_dic = []
        san_list = ['foo:bar']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_403__identifer_status_list(self):
        """ failed check no identifiers """
        identifier_dic = []
        san_list = ['bar']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_404__identifer_status_list(self):
        """ succ check no identifiers """
        identifier_dic = [{'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar']
        self.assertEqual([True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_405__identifer_status_list(self):
        """ failed check san in identifier """
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}]
        san_list = ['dns:bar']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_406__identifer_status_list(self):
        """ failed check identifier in san """
        identifier_dic = [{'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar1']
        self.assertEqual([False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_407__identifer_status_list(self):
        """ failed check identifier one identifier two sans"""
        identifier_dic = [{'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar', 'dns:bar2']
        self.assertEqual([True, False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_408__identifer_status_list(self):
        """ failed check identifier two identifier one san"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar1']
        self.assertEqual([True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_409__identifer_status_list(self):
        """ failed check identifier both ok"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar1', 'dns:bar2']
        self.assertEqual([True, True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_410__identifer_status_list(self):
        """ failed check identifier both ok - wrong order"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar2', 'dns:bar1']
        self.assertEqual([True, True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_411__identifer_status_list(self):
        """ failed check identifier first ok 2nd nok"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar'}]
        san_list = ['dns:bar1', 'dns:bar2']
        self.assertEqual([True, False], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_412__identifer_status_list(self):
        """ failed check identifier first nook 2nd ok"""
        identifier_dic = [{'type': 'dns', 'value': 'bar1'}, {'type': 'dns', 'value': 'bar2'}]
        san_list = ['dns:bar', 'dns:bar2']
        self.assertEqual([False, True], self.certificate._identifer_status_list(identifier_dic, san_list))

    def test_413_csr_san_get(self):
        """ get sans but no csr """
        csr = None
        self.assertEqual([], self.csr_san_get(self.logger, csr))

    def test_414_csr_san_get(self):
        """ get sans but one san with == """
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ=='
        self.assertEqual(['DNS:foo1.bar.local'], self.csr_san_get(self.logger, csr))

    def test_415_csr_san_get(self):
        """ get sans but one san without == """
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ'
        self.assertEqual(['DNS:foo1.bar.local'], self.csr_san_get(self.logger, csr))

    def test_416_csr_san_get(self):
        """ get sans but two sans """
        csr = 'MIICpzCCAY8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgSTBHBgkqhkiG9w0BCQ4xOjA4MAsGA1UdDwQEAwIF4DApBgNVHREEIjAggg5mb28xLmJhci5sb2NhbIIOZm9vMi5iYXIubG9jYWwwDQYJKoZIhvcNAQELBQADggEBADeuf4J8Xziw2OuvLNnLOSgHQl2HdMFtRdgJoun7zPobsP3L3qyXLvvhJcQsIJggu5ZepnHGrCxroSbtRSO65GtLQA0Rq3DCGcPIC1fe9AYrqoynx8bWt2Hd+PyDrBppHVoQzj6yNCt6XNSDs04BMtjs9Pu4DD6DDHmxFMVNdHXea2Rms7C5nLQvXgw7yOF3Zk1vEu7Kue7d3zZMhN+HwwrNEA7RGAEzHHlCv5LL4Mw+kf6OJ8nf/WDiLDKEQIh6bnOuB42Y2wUMpzui8Uur0VJO+twY46MvjiVMMBZE3aPJU33eNPAQVC7GinStn+zQIJA5AADdcO8Lk1qdtaDiGp8'
        self.assertEqual(['DNS:foo1.bar.local', 'DNS:foo2.bar.local'], self.csr_san_get(self.logger, csr))

    def test_417_csr_san_get(self):
        """ get sans but three sans """
        csr = 'MIICtzCCAZ8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgWTBXBgkqhkiG9w0BCQ4xSjBIMAsGA1UdDwQEAwIF4DA5BgNVHREEMjAwgg5mb28xLmJhci5sb2NhbIIOZm9vMi5iYXIubG9jYWyCDmZvbzMuYmFyLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQAQRkub6G4uijaXOYpCkoz40I+SVRsbRDgnMNjsooZz1+7DVglFjrr6Pb0PPTOvOxtmbHP2KK0WokDn4LqOD2t0heuI+KPQy7m/ROpOB/YZOzTWEB8yS4vjkf/RFiJ7fnCAc8vA+3K/mBVb+89F8w/KlyPmpg1GK7UNgjEa5bnznTox8q12CocCJVykPEiC8AT/VPWUOPfg6gs+V6LO8R73VRPMVy0ttYKGX80ob+KczDTMUhoxXg8OG+G+bXXU+4Tu4l+nQWf2lFejECi/vNKzUT90IbcGJwyk7rc4Q7BJ/t/5nMo+vuV9f+2HI7qakHcw6u9RGylL4OYDf1CrqF1R'
        self.assertEqual(['DNS:foo1.bar.local', 'DNS:foo2.bar.local', 'DNS:foo3.bar.local'], self.csr_san_get(self.logger, csr))

    def test_418_csr_extensions_get(self):
        """ get sns in hex """
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ'
        self.assertEqual(['AwIF4A==', 'MBCCDmZvbzEuYmFyLmxvY2Fs'], self.csr_extensions_get(self.logger, csr))

    def test_419_csr_extensions_get(self):
        """ get tnauth identifier """
        csr = 'MIICuzCCAaMCAQAwHjEcMBoGA1UEAwwTY2VydC5zdGlyLmJhci5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALsLm4zgkl2lEx2EHy1ENfh3cYB79Xb5sD3ehkY+1pXphIWoM9KYVqHKOurModjsh75YjRBSilRfTFSk6kCUahTJyeCbM6Vzl75CcZy7poUxiK+u80JMU/xymUsrqY4GZlh2/XtFMxXHUSf3bhKZAIjBNugsvR/sHtEvJ6RJiuYqHMWUzZ/Vby5L0ywNl+LPSY7AVTUAZ0lKrnUCP4dHnbjwjf+nPi7vT6G0yrEg0qPOYXtJOXdf7vvjLi8J+ap758NtG2qapLdbToIPr0uOEvMO6zs8z1bIyjOHU3kzlpKHzDsPYy8txxKC/3Rae7sKB9gWm8WUxFBmuA7gaFDGQAECAwEAAaBYMFYGCSqGSIb3DQEJDjFJMEcwCwYDVR0PBAQDAgXgMB4GA1UdEQQXMBWCE2NlcnQuc3Rpci5iYXIubG9jYWwwGAYIKwYBBQUHARoEDDAKoAgWBjEyMzQ1NjANBgkqhkiG9w0BAQsFAAOCAQEAjyhJfgb/zJBMYp6ylRtEXgtBpsX9ePUL/iLgIDMcGtwaFm3pkQOSBr4xiTxftnqN77SlC8UEu7PDR73JX6iqLNJWucPlhAXVrr367ygO8GGLrtGddClZmo0lhRBRErgpagWB/jFkbL8afPGJwgQQXF0KWFMcajAPiIl1l6M0w11KqJ23Pwrmi7VJHzIgh4ys0D2UrX7KuV4PIOOmG0s7jTfBSB+yUH2zwVzOAzbr3wrD1WubD7hRaHDUi4bn4DRbquQOzbqfTI6QhetUcNpq4DwhBRcnZwUMJUIcxLAsFnDgGSW+dmJe6JH8MsS+8ZmOLllyQxWzYEVquQQvxFVTZA'
        self.assertEqual(['AwIF4A==', 'MBWCE2NlcnQuc3Rpci5iYXIubG9jYWw=', 'MAqgCBYGMTIzNDU2'], self.csr_extensions_get(self.logger, csr))

    def test_420_identifer_tnauth_list(self):
        """ empty identifier dic but tnauth exists """
        identifier_dic = []
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_421_identifer_tnauth_list(self):
        """ identifier dic but no tnauth """
        identifier_dic = {'foo': 'bar'}
        tnauthlist = None
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_422_identifer_tnauth_list(self):
        """ wrong identifier """
        identifier_dic = {'identifiers': '[{"foo": "bar"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_423_identifer_tnauth_list(self):
        """ wrong type """
        identifier_dic = {'identifiers': '[{"type": "bar"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_424_identifer_tnauth_list(self):
        """ correct type but no value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_425_identifer_tnauth_list(self):
        """ correct type but wrong value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt", "value": "bar"}]'}
        tnauthlist = 'foo'
        self.assertEqual([False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_426_identifer_tnauth_list(self):
        """ correct type but wrong value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt", "value": "foo"}]'}
        tnauthlist = 'foo'
        self.assertEqual([True], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    def test_427_identifer_tnauth_list(self):
        """ correct type but wrong value"""
        identifier_dic = {'identifiers': '[{"type": "TnAuThLiSt", "value": "foo"}, {"type": "dns", "value": "foo"}]'}
        tnauthlist = 'foo'
        self.assertEqual([True, False], self.certificate._identifer_tnauth_list(identifier_dic, tnauthlist))

    @patch('acme.certificate.Certificate._info')
    def test_428_csr_check(self, mock_certinfo):
        """ csr-check certname lookup failed """
        mock_certinfo.return_value = {}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.Certificate._info')
    def test_429_csr_check(self, mock_certinfo):
        """ csr-check order lookup failed """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.return_value = {}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.Certificate._info')
    def test_430_csr_check(self, mock_certinfo):
        """ csr-check order lookup returns rubbish """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.Certificate._info')
    def test_431_csr_check(self, mock_certinfo):
        """ csr-check order lookup returns an identifier """
        mock_certinfo.return_value = {'order': 'order'}
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_432_csr_check(self, mock_certinfo, mock_tnauthin):
        """ csr-check no tnauth """
        mock_certinfo.return_value = {'order': 'order'}
        mock_tnauthin.return_value = False
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    @patch('acme.certificate.csr_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    @patch('acme.certificate.Certificate._info')
    def test_433_csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
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
    def test_434_csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
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
    def test_435_csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
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
    def test_436_csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
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
    def test_437_csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
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
    def test_438_csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
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
    def test_439_csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
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
    def test_440_csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
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
    def test_441_csr_check(self, mock_certinfo, mock_tnauthin, mock_status, mock_san):
        """ csr-check tnauth  but tnauthlist_support on and returns True, False  """
        mock_certinfo.return_value = {'order': 'order'}
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False, True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._csr_check('cert_name', 'csr'))

    def test_442_authorization_check(self):
        """ _authorization_check order lookup failed """
        self.certificate.dbstore.order_lookup.return_value = {}
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_443_authorization_check(self):
        """ _authorization_check order lookup returns rubbish """
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar'}
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_444_authorization_check(self):
        """ _authorization_check order lookup returns an identifier """
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_445_authorization_check(self, mock_tnauthin):
        """ _authorization_check no tnauth """
        mock_tnauthin.return_value = False
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_446_authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status true """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_447_authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status true """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertTrue(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_448_authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status False """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_449_authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status True, False """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_status_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_450_authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check no tnauth  status True, False, True """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = False
        mock_status.return_value = [True, False, True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_451_authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support off  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True]
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    @patch('acme.certificate.cert_extensions_get')
    @patch('acme.certificate.Certificate._identifer_tnauth_list')
    @patch('acme.certificate.Certificate._tnauth_identifier_check')
    def test_452_authorization_check(self, mock_tnauthin, mock_status, mock_san):
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
    def test_453_authorization_check(self, mock_tnauthin, mock_status, mock_san):
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
    def test_454_authorization_check(self, mock_tnauthin, mock_status, mock_san):
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
    def test_455_authorization_check(self, mock_tnauthin, mock_status, mock_san):
        """ _authorization_check tnauth  but tnauthlist_support on and returns True, False  """
        mock_san.return_value = ['foo']
        mock_tnauthin.return_value = True
        mock_status.return_value = [True, False, True]
        self.certificate.tnauthlist_support = True
        self.certificate.dbstore.order_lookup.return_value = {'foo': 'bar', 'identifiers': 'bar'}
        self.assertFalse(self.certificate._authorization_check('cert_name', 'cert'))

    def test_456_validate_email(self):
        """ validate email containing "-" in domain """
        self.assertTrue(self.validate_email(self.logger, 'foo@example-example.com'))

    def test_457_validate_email(self):
        """ validate email containing "-" in user"""
        self.assertTrue(self.validate_email(self.logger, 'foo-foo@example.com'))

    @patch('importlib.import_module')
    @patch('acme.certificate.Certificate.enroll_and_store')
    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.Order._info')
    def test_458_csr_process(self, mock_oinfo, mock_certname, mock_enroll, mock_import):
        """ test order prcoess_csr with failed cert enrollment with internal error (response code must be corrected by 500)"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = 'foo'
        mock_import.return_value = importlib.import_module('examples.ca_handler.skeleton_ca_handler')
        mock_enroll.return_value = ('urn:ietf:params:acme:error:serverInternal', 'detail')
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'detail'), self.order._csr_process('order_name', 'csr'))

    def test_459_get_url(self):
        """ get_url with xforwarded https """
        data_dic = {'HTTP_X_FORWARDED_PROTO': 'https', 'HTTP_HOST': 'http_host', 'SERVER_PORT': 443, 'PATH_INFO': 'path_info'}
        self.assertEqual('https://http_host', self.get_url(data_dic, False))

    def test_460_get_url(self):
        """ get_url with xforwarded http """
        data_dic = {'HTTP_X_FORWARDED_PROTO': 'http', 'HTTP_HOST': 'http_host', 'SERVER_PORT': 443, 'PATH_INFO': 'path_info'}
        self.assertEqual('http://http_host', self.get_url(data_dic, False))

    def test_461_validate_email(self):
        """ validate email containing first letter of domain cannot be a number"""
        self.assertFalse(self.validate_email(self.logger, 'foo@1example.com'))

    def test_462_validate_email(self):
        """ validate email containing last letter of domain cannot - """
        self.assertFalse(self.validate_email(self.logger, 'foo@example-.com'))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._process')
    @patch('acme.order.Order._lookup')
    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_463_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname processing status default retry after-header """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar', 'status': 'processing'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar', 'status': 'processing'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce',  'Retry-After': '600'}}, self.order.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._process')
    @patch('acme.order.Order._lookup')
    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_464_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname processing status configurable retry after-header """
        self.order.retry_after = 60
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar', 'status': 'processing'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar', 'status': 'processing'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce',  'Retry-After': '60'}}, self.order.parse(message))

    def test_465_cert_dates_get(self):
        """ get issuing and expiration date from rsa certificate """
        cert = 'MIIElTCCAn2gAwIBAgIRAKD_ulfqPUn-ggOUHOxjp40wDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEXMBUGA1UECgwOQWNtZTJDZXJ0aWZpZXIxDzANBgNVBAMMBnN1Yi1jYTAeFw0yMDA1MjcxMjMwMjNaFw0yMDA2MjYxMjMwMjNaMBkxFzAVBgNVBAMMDmZvbzEuYmFyLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx-z-9wsEewBf1hnk3yAy5TFg-lWVdwk2QRdAMDTExVP823QF_K-t6cxJV_-QuWVbHN-lx6nQCXIqCZSN97hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X-gtyMBbXOLhjTlN2f7Z081XWIgkikvuZU2XzMZ-BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo-tLu0toAc0nm9v8Otme28_kpJxmW3iOMkqN9BE-qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw_a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD_Xoaygpd9-UHCREhcOu_wIDAQABo4GoMIGlMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDAdBgNVHQ4EFgQUqy5KOBlkyX29l4EHTCSzhZuDg-EwDgYDVR0PAQH_BAQDAgWgMB8GA1UdIwQYMBaAFBs0P896R0FUZHfnxMJL52ftKQOkMAwGA1UdEwEB_wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4ICAQB7pQpILzxqcU2RKlr17rcne6NSJTUJnNXALeUFy5PrnjjJY1_B1cKaWluk3p7AMFvUjBpcucGCfEDudW290AQxYjrvl8_ePkzRzEkAo76L7ZqED5upYBZVn_3lA5Alr8L67UC0bDMhKTsy8WJzhWHQlMb37_YFUvtNPoI_MI09Q842VXeNQz5UDZmW9qhyeDIkf6fwOAO66VnGTLuUm2LGQZ-St2GauxR0ZUcRtMJoc-c7WOdHs8DlUCoFtglrzVH98501Sx749CG4nkJr4QNDpkw2hAhlo4Cxzp6PlljPNSgM9MsqqVdrgqDteDM_n-yrVFGezCik4QexDkWARPutRLQtpbhudExVnoFM68ihZ0y3oeDjgUBLybBQpcBAsBqiJ66Q8HTZRSqO9zlKW5Vm1KwAVDh_qgELxvqd0wIVkyxBKPta2l1fvb5YBiVqo4JyNcCTnoBS1emO4vk8XjroKijwLnU0cEXwHrY4JF1uU_kOtoZMGPul5EuBMcODLs7JJ3_IqJd8quI7Vf5zSsaB6nSzQ8XmiQiVogKflBeLl7AWmYCiL-FLP_q4dSJmvdr6fPMNy4-cfDO4Awc8RNfv-VjF5Mq57X1IXJrWKkat4lCEoPMq5WRJV8uVm6XNdwvUJxgCYR9mfol7T6imODDd7BNV4dKYvyteoS0auC0iww'
        self.assertEqual((1590582623, 1593174623), self.cert_dates_get(self.logger, cert))

    def test_466_cert_dates_get(self):
        """ get issuing and expiration date no certificate """
        cert = None
        self.assertEqual((0, 0), self.cert_dates_get(self.logger, cert))

    def test_467_cert_dates_get(self):
        """ get issuing and expiration date damaged certificate """
        cert = 'foo'
        self.assertEqual((0, 0), self.cert_dates_get(self.logger, cert))

    def test_468_cert_dates_get(self):
        """ get issuing and expiration date ecc certificate """
        cert = 'MIIDozCCAYugAwIBAgIIMMxkE7mRR+YwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMDA3MTEwNDUzMTFaFw0yMTA3MTEwNDUzMTFaMBkxFzAVBgNVBAMMDmZvbzEuYmFyLmxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER/KMoV5+zQgegqYue2ztPK2nZVpK2vxb02UzwyHw4ebhJ2gBobI23lSBRa1so1ug0kej7U+ohm5aGFdNxLM0G6OBqDCBpTALBgNVHQ8EBAMCBeAwGQYDVR0RBBIwEIIOZm9vMS5iYXIubG9jYWwwHQYDVR0OBBYEFCSaU743wU8jMETIO381r13tVLdMMA4GA1UdDwEB/wQEAwIFoDAfBgNVHSMEGDAWgBS/3o6OBiIiq61DyN3UT6irSEE+1TAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAgEAmmhHuBhXNM2Azv53rCKY72yTQIoDVHjYrAvTmS6NsJzYflEOMkI7FCes64dWp54BerSD736Yax67b4XmLXc/+T41d7QAcnhY5xvLJiMpSsW37icHcLZpjlOrYDoRmny2U7n6t1aQ03nwgV+BgdaUQYLkUZuczs4kdqH1c9Ot9CCRTHpqSWlmWzGeRgt2uT4gKhFESP9lzx37YwKBHulBGthv1kcAaz8w8iPXBg01OEDiraXCBZFoYDEpDi2w2Y6ChCr7sNsY7aJ3a+2iHGYlktXEntk78S+g00HW61G9oLoRgeqEH3L6qVIpnswPAU/joub0YhNBIUFenCj8c3HMBgMcczzdZL+qStdymhpVkZetzXtMTKtgmxhkRzAOQUBBcHFc+wM97FqC0S4HJAuoHQ4EJ46MxwZH0jBVqcqCPMSaJ88uV902+VGGXrnxMR8RbGWLoCmsYb1ISmBUt+31PjMCYbXKwLmzvbRpO7XAQimvtOqoufl5yeRUJRLcUS6Let0QzU196/nZ789d7Etep7RjDYQm7/QhiWH197yKZ5/mUxqfyHDQ3hk5iX7S/gbo1jQXElEv5tB8Ozs+zVQmB2bXpN8c+8XUaZnwvYC2y+0LAQN4z7xilReCaasxQSsEOLCrlsannkGV704HYnnaKBS2tI948QotHnADHdfHl3o'
        self.assertEqual((1594443191, 1625979191), self.cert_dates_get(self.logger, cert))

    def test_469_ca_handler_get(self):
        """ identifier check none input"""
        file_name = 'foo'
        self.assertEqual('foo', self.ca_handler_get(self.logger, file_name))

    def test_470_ca_handler_get(self):
        """ identifier check none input"""
        file_name = 'foo.py'
        self.assertEqual('foo', self.ca_handler_get(self.logger, file_name))

    def test_471_ca_handler_get(self):
        """ identifier check none input"""
        file_name = 'foo/foo.py'
        self.assertEqual('foo.foo', self.ca_handler_get(self.logger, file_name))

    def test_472_ca_handler_get(self):
        """ identifier check none input"""
        file_name = 'foo\\foo.py'
        self.assertEqual('foo.foo', self.ca_handler_get(self.logger, file_name))

    @patch('acme.certificate.Certificate._csr_check')
    def test_473_enroll_and_store(self, mock_csr):
        """ Certificate.enroll_and_store() csr_check failed """
        mock_csr.return_value = False
        certificate_name = 'cert_name'
        csr = 'csr'
        self.assertEqual(('urn:ietf:params:acme:badCSR', 'CSR validation failed'), self.certificate.enroll_and_store(certificate_name, csr))

    @patch('acme.certificate.Certificate._store_cert_error')
    @patch('acme.certificate.Certificate._csr_check')
    def test_474_enroll_and_store(self, mock_csr, mock_store):
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
    def test_475_enroll_and_store(self, mock_csr, mock_store):
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
    def test_476_enroll_and_store(self, mock_csr, mock_store, mock_dates):
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

    @patch('dns.resolver.Resolver')
    def test_477_fqdn_resolve(self, mock_resolve):
        """ successful dns-query returning one value """
        mock_resolve.return_value.query.return_value = ['foo']
        self.assertEqual(('foo', False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver')
    def test_478_fqdn_resolve(self, mock_resolve):
        """ successful dns-query returning two values """
        mock_resolve.return_value.query.return_value = ['bar', 'foo']
        self.assertEqual(('bar', False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=Mock(side_effect=dns.resolver.NXDOMAIN))
    def test_479_fqdn_resolve(self, mock_resolve):
        """ catch NXDOMAIN """
        self.assertEqual((None, True), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=Mock(side_effect=dns.resolver.NoAnswer))
    def test_480_fqdn_resolve(self, mock_resolve):
        """ catch NoAnswer """
        self.assertEqual((None, True), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=Mock(side_effect=dns.resolver.NoNameservers))
    def test_481_fqdn_resolve(self, mock_resolve):
        """ catch other dns related execption """
        self.assertEqual((None, False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=Mock(side_effect=Exception('foo')))
    def test_482_fqdn_resolve(self, mock_resolve):
        """ catch other execption """
        self.assertEqual((None, False), self.fqdn_resolve('foo.bar.local'))

    def test_483_certificatelist_get(self):
       """ test Housekeeping._certificatelist_get() """
       self.housekeeping.dbstore.certificatelist_get.return_value = 'foo'
       self.assertEqual('foo', self.housekeeping._certificatelist_get())

    def test_484_convert_data(self):
       """ test Housekeeping._convert_data() - empty list"""
       cert_list = []
       self.assertEqual([], self.housekeeping._convert_data(cert_list))

    def test_485_convert_data(self):
       """ test Housekeeping._convert_data() - orders__expire to convert """
       cert_list = [{'foo': 'bar', 'order.expires': 1577840461}]
       self.assertEqual([{'foo': 'bar', 'order.expires': '2020-01-01 01:01:01', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.expire_date': '', 'certificate.issue_date': ''}], self.housekeeping._convert_data(cert_list))

    def test_472_convert_data(self):
       """ test Housekeeping._convert_data() - orders__expires and authentication__expires to convert (not in list) """
       cert_list = [{'foo': 'bar', 'order.expires': 1577840461, 'authentication.expires': 1577840462}]
       self.assertEqual([{'authentication.expires': 1577840462, 'foo': 'bar', 'order.expires': '2020-01-01 01:01:01', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.expire_date': '', 'certificate.issue_date': ''}], self.housekeeping._convert_data(cert_list))

    def test_473_convert_data(self):
       """ test Housekeeping._convert_data() - orders__expires and authorization__expires to convert (not in list) """
       cert_list = [{'foo': 'bar', 'order.expires': 1577840461, 'authorization.expires': 1577840462}]
       self.assertEqual([{'authorization.expires': '2020-01-01 01:01:02', 'foo': 'bar', 'order.expires': '2020-01-01 01:01:01', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.expire_date': '', 'certificate.issue_date': ''}], self.housekeeping._convert_data(cert_list))

    def test_486_convert_data(self):
       """ test Housekeeping._convert_data() - list containing bogus values"""
       cert_list = [{'foo': 'bar'}]
       self.assertEqual([{'foo': 'bar', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.expire_date': '', 'certificate.issue_date': ''}], self.housekeeping._convert_data(cert_list))

    def test_487_convert_data(self):
       """ test Housekeeping._convert_data() - list contains only issue_uts """
       cert_list = [{'foo': 'bar', 'certificate.issue_uts': 0}]
       self.assertEqual([{'foo': 'bar', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.expire_date': '', 'certificate.issue_date': ''}], self.housekeeping._convert_data(cert_list))

    def test_488_convert_data(self):
       """ test Housekeeping._convert_data() - list contains only expire_uts """
       cert_list = [{'foo': 'bar', 'certificate.expire_uts': 0}]
       self.assertEqual([{'foo': 'bar', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.expire_date': '', 'certificate.issue_date': ''}], self.housekeeping._convert_data(cert_list))

    def test_489_convert_data(self):
       """ test Housekeeping._convert_data() - list contains both issue_uts and expire_uts """
       cert_list = [{'foo': 'bar', 'certificate.expire_uts': 1577840461, 'certificate.issue_uts': 1577840462}]
       self.assertEqual([{'foo': 'bar', 'certificate.expire_uts': 1577840461, 'certificate.expire_date': '2020-01-01 01:01:01', 'certificate.issue_date': '2020-01-01 01:01:02', 'certificate.issue_uts': 1577840462}], self.housekeeping._convert_data(cert_list))

    def test_490_convert_data(self):
       """ test Housekeeping._convert_data() - list contains both uts with 0 """
       cert_list = [{'foo': 'bar', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0}]
       self.assertEqual([{'foo': 'bar', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.expire_date': '', 'certificate.issue_date': ''}], self.housekeeping._convert_data(cert_list))

    def test_491_convert_data(self):
       """ test Housekeeping._convert_data() - list contains both uts with 0 and a bogus cert_raw """
       cert_list = [{'foo': 'bar', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.cert_raw': 'cert_raw'}]
       self.assertEqual([{'foo': 'bar', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.expire_date': '', 'certificate.issue_date': '', 'certificate.cert_raw': 'cert_raw', 'certificate.serial': ''}], self.housekeeping._convert_data(cert_list))

    @patch('acme.housekeeping.cert_serial_get')
    @patch('acme.housekeeping.cert_dates_get')
    def test_492_convert_data(self, mock_dates, mock_serial):
       """ test Housekeeping._convert_data() - list contains both uts with 0 and a bogus cert_raw """
       cert_list = [{'foo': 'bar', 'certificate.expire_uts': 0, 'certificate.issue_uts': 0, 'certificate.cert_raw': 'cert_raw'}]
       mock_dates.return_value = (1577840461, 1577840462)
       mock_serial.return_value = 'serial'
       self.assertEqual([{'foo': 'bar', 'certificate.expire_uts': 1577840462, 'certificate.issue_uts': 1577840461, 'certificate.serial': 'serial', 'certificate.expire_date': '2020-01-01 01:01:02', 'certificate.issue_date': '2020-01-01 01:01:01', 'certificate.cert_raw': 'cert_raw'}], self.housekeeping._convert_data(cert_list))

    def test_493_to_list(self):
        """ test Housekeeping._to_list() - both lists are empty """
        field_list = []
        cert_list = []
        self.assertEqual([], self.housekeeping._to_list(field_list, cert_list))

    def test_494_to_list(self):
        """ test Housekeeping._to_list() - cert_list is empty """
        field_list = ['foo', 'bar']
        cert_list = []
        self.assertEqual([['foo', 'bar']], self.housekeeping._to_list(field_list, cert_list))

    def test_495_to_list(self):
        """ test Housekeeping._to_list() - one cert in list """
        field_list = ['foo', 'bar']
        cert_list = [{'foo': 'foo1', 'bar': 'bar1'}]
        self.assertEqual([['foo', 'bar'], ['foo1', 'bar1']], self.housekeeping._to_list(field_list, cert_list))

    def test_496_to_list(self):
        """ test Housekeeping._to_list() - one incomplete cert in list """
        field_list = ['foo', 'bar']
        cert_list = [{'foo': 'foo1'}]
        self.assertEqual([['foo', 'bar'], ['foo1', '']], self.housekeeping._to_list(field_list, cert_list))

    def test_497_to_list(self):
        """ test Housekeeping._to_list() - two certs in list """
        field_list = ['foo', 'bar']
        cert_list = [{'foo': 'foo1', 'bar': 'bar1'}, {'foo': 'foo2', 'bar': 'bar2'}]
        self.assertEqual([['foo', 'bar'], ['foo1', 'bar1'], ['foo2', 'bar2']], self.housekeeping._to_list(field_list, cert_list))

    def test_498_to_list(self):
        """ test Housekeeping._to_list() - two certs in list but on bogus """
        field_list = ['foo', 'bar']
        cert_list = [{'foo': 'foo1', 'bar': 'bar1'}, {'foo': 'foo2'}]
        self.assertEqual([['foo', 'bar'], ['foo1', 'bar1'], ['foo2', '']], self.housekeeping._to_list(field_list, cert_list))

    def test_499_to_list(self):
        """ test Housekeeping._to_list() - one line contains LF """
        field_list = ['foo', 'bar']
        cert_list = [{'foo': 'fo\no1', 'bar': 'bar1'}, {'foo': 'foo2'}]
        self.assertEqual([['foo', 'bar'], ['foo1', 'bar1'], ['foo2', '']], self.housekeeping._to_list(field_list, cert_list))

    def test_500_to_list(self):
        """ test Housekeeping._to_list() - one line contains CRLF """
        field_list = ['foo', 'bar']
        cert_list = [{'foo': 'fo\r\no1', 'bar': 'bar1'}, {'foo': 'foo2'}]
        self.assertEqual([['foo', 'bar'], ['foo1', 'bar1'], ['foo2', '']], self.housekeeping._to_list(field_list, cert_list))

    def test_501_to_list(self):
        """ test Housekeeping._to_list() - one line contains CR """
        field_list = ['foo', 'bar']
        cert_list = [{'foo': 'fo\ro1', 'bar': 'bar1'}, {'foo': 'foo2'}]
        self.assertEqual([['foo', 'bar'], ['foo1', 'bar1'], ['foo2', '']], self.housekeeping._to_list(field_list, cert_list))

    def test_502_to_list(self):
        """ test Housekeeping._to_list() - integer in dictionary """
        field_list = ['foo', 'bar']
        cert_list = [{'foo': 'fo\ro1', 'bar': 100}]
        self.assertEqual([['foo', 'bar'], ['foo1', 100]], self.housekeeping._to_list(field_list, cert_list))

    def test_503_to_list(self):
        """ test Housekeeping._to_list() - float in dictionary """
        field_list = ['foo', 'bar']
        cert_list = [{'foo': 'fo\ro1', 'bar': 10.23}]
        self.assertEqual([['foo', 'bar'], ['foo1', 10.23]], self.housekeeping._to_list(field_list, cert_list))

    def test_504_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - empty list """
        account_list = []
        self.assertEqual([], self.housekeeping._to_acc_json(account_list))

    def test_505_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - bogus list """
        account_list = [{'foo': 'bar'}]
        self.assertEqual([{'error_list': [{'foo': 'bar'}]}], self.housekeeping._to_acc_json(account_list))

    def test_506_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - bogus list """
        account_list = [{'account.name': 'account.name'}]
        self.assertEqual([{'error_list': [{'account.name': 'account.name'}]}], self.housekeeping._to_acc_json(account_list))

    def test_507_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - bogus list """
        account_list = [{'account.name': 'account.name01', 'order.name': 'order.name01'}]
        self.assertEqual([{'error_list': [{'account.name': 'account.name01', 'order.name': 'order.name01'}]}], self.housekeeping._to_acc_json(account_list))

    def test_508_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - bogus list """
        account_list = [{'account.name': 'account.name01', 'order.name': 'order.name01', 'authorization.name': 'authorization.name01'}]
        self.assertEqual([{'error_list': [{'account.name': 'account.name01', 'authorization.name': 'authorization.name01', 'order.name': 'order.name01'}]}], self.housekeeping._to_acc_json(account_list))

    def test_509_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - complete list """
        account_list = [
            {'account.name': 'account.name01', 'order.name': 'order.name01', 'authorization.name': 'authorization.name01', 'challenge.name': 'challenge.name01'}
            ]
        result_list = [{'account.name': 'account.name01', 'orders': [{'order.name': 'order.name01', 'authorizations': [{'authorization.name': 'authorization.name01', 'challenges': [{'challenge.name': 'challenge.name01'}]}]}]}]
        self.assertEqual(result_list, self.housekeeping._to_acc_json(account_list))

    def test_510_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - two challenges """
        account_list = [
            {'account.name': 'account.name01', 'order.name': 'order.name01', 'authorization.name': 'authorization.name01', 'challenge.name': 'challenge.name01'},
            {'account.name': 'account.name01', 'order.name': 'order.name01', 'authorization.name': 'authorization.name01', 'challenge.name': 'challenge.name02'}
            ]
        result_list = [{'account.name': 'account.name01', 'orders': [{'order.name': 'order.name01', 'authorizations': [{'authorization.name': 'authorization.name01', 'challenges': [{'challenge.name': 'challenge.name01'},  {'challenge.name': 'challenge.name02'}]}]}]}]
        self.assertEqual(result_list, self.housekeeping._to_acc_json(account_list))

    def test_511_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - two authorizations """
        account_list = [
            {'account.name': 'account.name01', 'order.name': 'order.name01', 'authorization.name': 'authorization.name01', 'challenge.name': 'challenge.name01'},
            {'account.name': 'account.name01', 'order.name': 'order.name01', 'authorization.name': 'authorization.name02', 'challenge.name': 'challenge.name02'}
            ]
        result_list = [{'account.name': 'account.name01', 'orders': [{'order.name': 'order.name01', 'authorizations': [{'authorization.name': 'authorization.name01', 'challenges': [{'challenge.name': 'challenge.name01'}]}, {'authorization.name': 'authorization.name02', 'challenges': [{'challenge.name': 'challenge.name02'}]}]}]}]
        self.assertEqual(result_list, self.housekeeping._to_acc_json(account_list))

    def test_512_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - two orders """
        account_list = [
            {'account.name': 'account.name01', 'order.name': 'order.name01', 'authorization.name': 'authorization.name01', 'challenge.name': 'challenge.name01'},
            {'account.name': 'account.name01', 'order.name': 'order.name02', 'authorization.name': 'authorization.name02', 'challenge.name': 'challenge.name02'}
            ]
        result_list = [{'account.name': 'account.name01', 'orders': [{'order.name': 'order.name01', 'authorizations': [{'authorization.name': 'authorization.name01', 'challenges': [{'challenge.name': 'challenge.name01'}]}]}, {'order.name': 'order.name02', 'authorizations': [{'authorization.name': 'authorization.name02', 'challenges': [{'challenge.name': 'challenge.name02'}]}]}]}]
        self.assertEqual(result_list, self.housekeeping._to_acc_json(account_list))

    def test_513_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - two accounts """
        account_list = [
            {'account.name': 'account.name01', 'order.name': 'order.name01', 'authorization.name': 'authorization.name01', 'challenge.name': 'challenge.name01'},
            {'account.name': 'account.name02', 'order.name': 'order.name02', 'authorization.name': 'authorization.name02', 'challenge.name': 'challenge.name02'}
            ]
        result_list = [{'account.name': 'account.name01', 'orders': [{'order.name': 'order.name01', 'authorizations': [{'authorization.name': 'authorization.name01', 'challenges': [{'challenge.name': 'challenge.name01'}]}]}]}, {'account.name': 'account.name02', 'orders': [{'order.name': 'order.name02', 'authorizations': [{'authorization.name': 'authorization.name02', 'challenges': [{'challenge.name': 'challenge.name02'}]}]}]}]
        self.assertEqual(result_list, self.housekeeping._to_acc_json(account_list))

    def test_514_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - complete list with subkeys"""
        account_list = [
            {'account.name': 'account.name01', 'account.foo': 'account.foo', 'order.name': 'order.name01', 'order.foo': 'order.foo', 'authorization.name': 'authorization.name01', 'authorization.foo': 'authorization.foo', 'challenge.name': 'challenge.name01', 'challenge.foo': 'challenge.foo'}
            ]
        result_list = [{'account.name': 'account.name01', 'account.foo': 'account.foo', 'orders': [{'order.name': 'order.name01', 'order.foo': 'order.foo', 'authorizations': [{'authorization.name': 'authorization.name01', 'authorization.foo': 'authorization.foo', 'challenges': [{'challenge.name': 'challenge.name01', 'challenge.foo': 'challenge.foo'}]}]}]}]
        self.assertEqual(result_list, self.housekeeping._to_acc_json(account_list))

    def test_515_to_acc_json(self):
        """ test Housekeeping._to_acc_list() - complete list """
        account_list = [
            {'account.name': 'account.name01', 'order.name': 'order.name01', 'authorization.name': 'authorization.name01', 'challenge.name': 'challenge.name01'},
            {'foo': 'bar'}]
        result_list = [{'account.name': 'account.name01', 'orders': [{'order.name': 'order.name01', 'authorizations': [{'authorization.name': 'authorization.name01', 'challenges': [{'challenge.name': 'challenge.name01'}]}]}]}, {'error_list': [{'foo': 'bar'}]}]
        self.assertEqual(result_list, self.housekeeping._to_acc_json(account_list))


if __name__ == '__main__':
    unittest.main()
