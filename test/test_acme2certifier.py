#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
import unittest
import datetime
import json
import sys
try:
    from mock import patch, MagicMock
except ImportError:
    from unittest.mock import patch, MagicMock
import sys
sys.path.insert(0, '..')

class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    pass

class TestACMEHandler(unittest.TestCase):
    """ test class for ACMEHandler """
    acme = None
    def setUp(self):
        """ setup unittest """
        models_mock = MagicMock()
        models_mock.acme.db_handler.DBstore.return_value = FakeDBStore
        # models_mock.acme.ca_handler.CAhandler.return_value = FakeDBStore
        # modules = {'acme.db_handler': models_mock, 'acme.ca_handler': models_mock}
        modules = {'acme.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        from acme.account import Account
        from acme.authorization import Authorization
        from acme.certificate import Certificate
        from acme.challenge import Challenge
        from acme.directory import Directory
        from acme.error import Error
        from acme.nonce import Nonce
        from acme.message import Message
        from acme.order import Order
        from acme.signature import Signature
        from acme.trigger import Trigger
        from acme.helper import b64decode_pad, b64_decode, b64_url_encode, b64_url_recode, decode_message, decode_deserialize, generate_random_string, signature_check, validate_email, uts_to_date_utc, date_to_uts_utc, load_config, cert_serial_get, cert_san_get, build_pem_file, date_to_datestr, datestr_to_date, dkeys_lower, cert_pubkey_get, csr_pubkey_get, convert_byte_to_string
        import logging
        logging.basicConfig(
            # format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            format='%(asctime)s - acme2certifier - %(levelname)s - %(message)s',
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.INFO)
        self.logger = logging.getLogger('test_acme2certifier')
        self.directory = Directory(False, 'http://tester.local', self.logger)
        self.account = Account(False, 'http://tester.local', self.logger)
        self.authorization = Authorization(False, 'http://tester.local', self.logger)
        self.challenge = Challenge(False, 'http://tester.local', self.logger)
        self.certificate = Certificate(False, 'http://tester.local', self.logger)
        self.message = Message(False, 'http://tester.local', self.logger)
        self.nonce = Nonce(False, self.logger)
        self.error = Error(False, self.logger)
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
        self.cert_san_get = cert_san_get
        self.cert_pubkey_get = cert_pubkey_get
        self.csr_pubkey_get = csr_pubkey_get
        self.build_pem_file = build_pem_file
        self.b64_decode = b64_decode
        self.b64_url_encode = b64_url_encode
        self.date_to_datestr = date_to_datestr
        self.datestr_to_date = datestr_to_date
        self.convert_byte_to_string = convert_byte_to_string
        self.dkeys_lower = dkeys_lower
        self.maxDiff = None

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
        self.assertEqual((False, 'Verification failed for all signatures["Failed: [InvalidJWSSignature(\'Verification failed {InvalidSignature()}\')]"]'), self.signature_check(self.logger, message, mkey))

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
        """ Account.new() failed bcs filed tos check """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', None)
        mock_tos.return_value = (403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse')
        message = {'foo' : 'bar'}
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
        message = {'foo' : 'bar'}
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
        protected = {'jwk' : 'jwk'}
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

    @patch('acme.message.Message.check')
    def test_068_accout_parse(self, mock_mcheck):
        """ Account.parse() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.account.parse(message))

    @patch('acme.message.Message.check')
    def test_069_accout_parse(self, mock_mcheck):
        """ test failed account parse for request which does not has a "status" field in payload """
        mock_mcheck.return_value = (200, None, None, 'protected', {"foo" : "bar"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'dont know what to do with this request'}}, self.account.parse(message))

    @patch('acme.message.Message.check')
    def test_070_accout_parse(self, mock_mcheck):
        """ test failed account parse for reqeust with a "status" field other than "deactivated" """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'status attribute without sense'}}, self.account.parse(message))

    @patch('acme.account.Account._delete')
    @patch('acme.message.Message.check')
    def test_071_accout_parse(self, mock_mcheck, mock_del):
        """ test failed account parse for reqeust with failed deletion """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "deactivated"}, 'account_name')
        mock_del.return_value = (400, 'urn:ietf:params:acme:error:accountDoesNotExist', 'deletion failed')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'detail': 'deletion failed'}}, self.account.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account._delete')
    @patch('acme.message.Message.check')
    def test_072_accout_parse(self, mock_mcheck, mock_del, mock_nnonce):
        """ test succ account parse for reqeust with succ deletion """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "deactivated"}, 'account_name')
        mock_del.return_value = (200, None, None)
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'status': 'deactivated'}, 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))

    def test_073_onlyreturnexisting(self):
        """ test onlyReturnExisting with False """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyreturnexisting' : False}
        self.assertEqual((400, 'urn:ietf:params:acme:error:userActionRequired', 'onlyReturnExisting must be true'), self.account._onlyreturnexisting(protected, payload))

    def test_074_onlyreturnexisting(self):
        """ test onlyReturnExisting without jwk structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyreturnexisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'jwk structure missing'), self.account._onlyreturnexisting(protected, payload))

    def test_075_onlyreturnexisting(self):
        """ test onlyReturnExisting fucntion without onlyReturnExisting structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {}
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'onlyReturnExisting without payload'), self.account._onlyreturnexisting(protected, payload))

    def test_076_onlyreturnexisting(self):
        """ test onlyReturnExisting for existing account """
        self.signature.dbstore.account_lookup.return_value = {'name' : 'foo', 'alg' : 'RS256'}
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyreturnexisting' : True}
        self.assertEqual((200, 'foo', None), self.account._onlyreturnexisting(protected, payload))

    def test_077_onlyreturnexisting(self):
        """ test onlyReturnExisting for non existing account """
        self.signature.dbstore.account_lookup.return_value = False
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyreturnexisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.account._onlyreturnexisting(protected, payload))

    def test_078_utstodate_utc(self):
        """ test uts_to_date_utc for a given format """
        self.assertEqual('2018-12-01', self.uts_to_date_utc(1543640400, '%Y-%m-%d'))

    def test_079_utstodate_utc(self):
        """ test uts_to_date_utc without format """
        self.assertEqual('2018-12-01T05:00:00Z', self.uts_to_date_utc(1543640400))

    def test_080_utstodate_utc(self):
        """ test date_to_uts_utc for a given format """
        self.assertEqual(1543622400, self.date_to_uts_utc('2018-12-01', '%Y-%m-%d'))

    def test_081_utstodate_utc(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(1543640400, self.date_to_uts_utc('2018-12-01T05:00:00'))

    def test_082_generaterandomstring(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(5, len(self.generate_random_string(self.logger, 5)))

    def test_083_generaterandomstring(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(15, len(self.generate_random_string(self.logger, 15)))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_084_order_add(self, mock_name, mock_uts):
        """ test Oder.add() without identifier in payload """
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        message = {}
        e_result = ('urn:ietf:params:acme:error:unsupportedIdentifier', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_085_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with empty identifier in payload dbstore-add returns None"""
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        self.signature.dbstore.order_add.return_value = False
        message = {'identifiers' : {}}
        e_result = ('urn:ietf:params:acme:error:malformed', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_086_order_add(self, mock_name, mock_uts):
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
    def test_087_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with multiple identifier in payload dbstore-add returns something real"""
        mock_name.side_effect = ['order', 'identifier1', 'identifier2']
        mock_uts.return_value = 1543640400
        self.order.dbstore.order_add.return_value = 1
        self.order.dbstore.authorization_add.return_value = True
        message = {'identifiers' : [{"type": "dns", "value": "example1.com"}, {"type": "dns", "value": "example2.com"}]}
        e_result = (None, 'order', {'identifier1': {'type': 'dns', 'value': 'example1.com'}, 'identifier2': {'type': 'dns', 'value': 'example2.com'}}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order._add(message, 1))

    @patch('acme.message.Message.check')
    def test_088_order_new(self, mock_mcheck):
        """ Order.new() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.order.new(message))

    @patch('acme.order.Order._add')
    @patch('acme.message.Message.check')
    def test_089_order_new(self, mock_mcheck, mock_orderadd):
        """ Order.new() failed bcs of db_add failed """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = ('urn:ietf:params:acme:error:malformed', None, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'could not process order'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._add')
    @patch('acme.message.Message.check')
    def test_090_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order with a single identifier """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = (None, 'foo_order', {'foo_auth': {u'type': u'dns', u'value': u'acme.nclm-samba.local'}}, 'expires')
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{u'type': u'dns', u'value': u'acme.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order._add')
    @patch('acme.message.Message.check')
    def test_091_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
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
    def test_092_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order without identifiers """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_nnonce.return_value = 'new_nonce'
        mock_orderadd.return_value = (None, 'foo_order', {}, 'expires')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [], 'authorizations': [], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.challenge.generate_random_string')
    def test_093_challenge_new(self, mock_random):
        """ test challenge generation """
        mock_random.return_value = 'foo'
        self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'mtype'}, self.challenge._new('authz_name', 'mtype', 'token'))

    @patch('acme.challenge.generate_random_string')
    def test_094_challenge_new(self, mock_random):
        """ test challenge generation for tnauthlist challenge """
        mock_random.return_value = 'foo'
        self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'tkauth-01', 'tkauth-type': 'atc'}, self.challenge._new('authz_name', 'tkauth-01', 'token'))

    @patch('acme.challenge.Challenge._new')
    def test_095_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token'))

    @patch('acme.challenge.Challenge._new')
    def test_096_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set with tnauth true """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}], self.challenge.new_set('authz_name', 'token', True))

    @patch('acme.challenge.Challenge._new')
    def test_097_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token', False))

    @patch('acme.challenge.Challenge.new_set')
    @patch('acme.authorization.uts_now')
    @patch('acme.authorization.generate_random_string')
    def test_098_authorization_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = [{'type' : 'identifier_type', 'value' : 'identifier_value', 'status__name' : 'foo'}]
        self.assertEqual({'status': 'foo', 'expires': '2018-12-02T05:00:00Z', 'identifier': {'type': 'identifier_type', 'value': 'identifier_value'}, 'challenges': [{'key2': 'value2', 'key1': 'value1'}]}, self.authorization._authz_info('http://tester.local/acme/authz/foo'))

    def test_099_challenge_info(self):
        """ test challenge.info() """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.assertEqual({'status': 'pending', 'token': 'token', 'type': 'http-01'}, self.challenge._info('foo'))

    @patch('acme.message.Message.check')
    def test_100_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed bcs. message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  {'detail': 'detail', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.message.Message.check')
    def test_101_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'url missing in protected header', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.challenge.Challenge._name_get')
    @patch('acme.message.Message.check')
    def test_102_challenge_parse(self, mock_mcheck, mock_cname):
        """ Challenge.parse() message check returns ok with tnauhlist enabled failed tnauth check """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'url' : 'foo'}, {}, 'account_name')
        mock_cname.return_value = None
        self.assertEqual({'code': 400, 'data' : {'detail': 'could not get challenge', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}, self.challenge.parse('content'))

    @patch('acme.challenge.Challenge._info')
    @patch('acme.challenge.Challenge._name_get')
    @patch('acme.message.Message.check')
    def test_103_challenge_parse(self, mock_mcheck, mock_cname, mock_info):
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
    def test_104_challenge_parse(self, mock_mcheck, mock_cname, mock_info, mock_tnauth):
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
    def test_105_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce):
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
    def test_106_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_tnauth, mock_nnonce):
        """ Challenge.parse() successful with TNauthlist disabled """
        self.challenge.tnauthlist_support = False
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.return_value = {'challenge_foo' : 'challenge_bar'}
        mock_tnauth.return_value = (200, 'foo', 'bar')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'new_nonce'}, 'data': {'challenge_foo': 'challenge_bar', 'url': 'bar'}}, self.challenge.parse('content'))

    def test_107_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty challenge_dic """
        payload = {'foo': 'bar'}
        challenge_dic = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'invalid challenge: {}'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_108_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty challenge_dic """
        payload = {}
        challenge_dic = {'type': 'foo'}
        self.assertEqual((200, None, None), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_109_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload without atc claim """
        payload = {}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'atc claim is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_110_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with empty atc claim """
        payload = {'atc' : None}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'SPC token is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_111_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with '' atc claim """
        payload = {'atc' : ''}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'SPC token is missing'), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    def test_112_challenge_validate_tnauthlist_payload(self):
        """ Challenge.validate_tnauthlist_payload with spc token in atc claim """
        payload = {'atc' : 'a'}
        challenge_dic = {'type': 'tkauth-01'}
        self.assertEqual((200, None, None), self.challenge._validate_tnauthlist_payload(payload, challenge_dic))

    @patch('acme.order.Order._info')
    def test_113_order_lookup(self, mock_oinfo):
        """ test order lookup with empty hash """
        mock_oinfo.return_value = {}
        self.assertEqual({}, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_114_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and wrong authorization hash"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': []}, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_115_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and correct authorization hash"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz/name']}, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_116_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and authorization hash having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2']}, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_117_order_lookup(self, mock_oinfo):
        """ test order lookup status in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2']}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_118_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_119_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore (0) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_120_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (0) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 0, 'notafter' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_121_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_122_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz/name', 'http://tester.local/acme/authz/name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order._lookup('foo'))

    @patch('acme.order.Order._info')
    def test_123_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and worng authorization"""
        self.authorization.dbstore.authorization_lookup.return_value = 'foo'
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': [], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order._lookup('foo'))

    def test_124_base64_recode(self):
        """ test base64url recode to base64 - add padding for 1 char"""
        self.assertEqual('fafafaf=', self.b64_url_recode(self.logger, 'fafafaf'))

    def test_125_base64_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(self.logger, 'fafafa'))

    def test_126_base64_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(self.logger, 'fafaf'))

    def test_127_base64_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(self.logger, 'fafafafa'))

    def test_128_base64_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(self.logger, 'fafa-f'))

    def test_129_base64_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, 'fafa_f'))

    def test_130_base64_recode(self):
        """ test base64url recode to base64 - add padding for 1 char"""
        self.assertEqual('fafafaf=', self.b64_url_recode(self.logger, b'fafafaf'))

    def test_131_base64_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(self.logger, b'fafafa'))

    def test_132_base64_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(self.logger, b'fafaf'))

    def test_133_base64_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(self.logger, b'fafafafa'))

    def test_134_base64_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(self.logger, b'fafa-f'))

    def test_135_base64_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, b'fafa_f'))

    @patch('acme.order.Order._info')
    def test_136_csr_process(self, mock_oinfo):
        """ test order prcoess_csr with empty order_dic """
        mock_oinfo.return_value = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized', 'order: order_name not found'), self.order._csr_process('order_name', 'csr'))

    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.Order._info')
    def test_137_csr_process(self, mock_oinfo, mock_certname):
        """ test order prcoess_csr with failed csr dbsave"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = None
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'CSR processing failed'), self.order._csr_process('order_name', 'csr'))

    @patch('acme.certificate.Certificate.enroll_and_store')
    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.Order._info')
    def test_138_csr_process(self, mock_oinfo, mock_certname, mock_enroll):
        """ test order prcoess_csr with failed cert enrollment"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = 'foo'
        mock_enroll.return_value = ('error', 'detail')
        self.assertEqual((400, 'error', 'detail'), self.order._csr_process('order_name', 'csr'))

    @patch('acme.certificate.Certificate.enroll_and_store')
    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.Order._info')
    def test_139_csr_process(self, mock_oinfo, mock_certname, mock_enroll):
        """ test order prcoess_csr with successful cert enrollment"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_certname.return_value = 'foo'
        mock_enroll.return_value = (None, None)
        self.assertEqual((200, 'foo', None), self.order._csr_process('order_name', 'csr'))

    def test_140_decode_message(self):
        """ decode message with empty payload - certbot issue"""
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        e_result = (True, None, {u'nonce': u'26e6a46efadd477d908d7c2014e49b34', u'url': u'http://laptop.nclm-samba.local/acme/authz/PG189FFzfao1', u'alg': u'RS256', u'kid': u'http://laptop.nclm-samba.local/acme/acct/yuZ1GUJb76Zk'}, {}, b'encoded_signature')
        self.assertEqual(e_result, self.decode_message(self.logger, data_dic))

    @patch('acme.certificate.generate_random_string')
    def test_141_store_csr(self, mock_name):
        """ test Certificate.store_csr() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'foo'
        mock_name.return_value = 'bar'
        self.assertEqual('bar', self.certificate.store_csr('order_name', 'csr'))

    def test_142_store_cert(self):
        """ test Certificate.store_cert() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'bar'
        self.assertEqual('bar', self.certificate._store_cert('cert_name', 'cert', 'raw'))

    def test_143_info(self):
        """ test Certificate.new_get() """
        self.certificate.dbstore.certificate_lookup.return_value = 'foo'
        self.assertEqual('foo', self.certificate._info('cert_name'))

    @patch('acme.certificate.Certificate._info')
    def test_144_new_get(self, mock_info):
        """ test Certificate.new_get() without certificate"""
        mock_info.return_value = {}
        self.assertEqual({'code': 403, 'data': 'NotFound'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_145_new_get(self, mock_info):
        """ test Certificate.new_get() without unknown order_status_id"""
        mock_info.return_value = {'order__status_id': 'foo'}
        self.assertEqual({'code': 403, 'data': 'urn:ietf:params:acme:error:orderNotReady'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_146_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 4 (processing)"""
        mock_info.return_value = {'order__status_id': 4}
        self.assertEqual({'code': 403, 'data': 'urn:ietf:params:acme:error:rateLimited', 'header': {'Retry-After': '600'}}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_147_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) but no certificate in"""
        mock_info.return_value = {'order__status_id': 5}
        self.assertEqual({'code': 403, 'data': 'NotFound'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate._info')
    def test_148_new_get(self, mock_info):
        """ test Certificate.new_get() without order_status_id 5 (valid) but no certificate in"""
        mock_info.return_value = {'order__status_id': 5, 'cert': 'foo-bar'}
        self.assertEqual({'code': 200, 'data': 'foo-bar', 'header': {'Content-Type': 'application/pem-certificate-chain'}}, self.certificate.new_get('url'))

    @patch('acme.message.Message.check')
    def test_149_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  json.dumps({'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'detail'})}, self.certificate.new_post('content'))

    @patch('acme.message.Message.check')
    def test_150_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': json.dumps({'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'url missing in protected header'})}, self.certificate.new_post('content'))

    @patch('acme.message.Message.prepare_response')
    @patch('acme.certificate.Certificate.new_get')
    @patch('acme.message.Message.check')
    def test_151_new_post(self, mock_mcheck, mock_certget, mock_response):
        """ test Certificate.new_post() message check returns ok  """
        mock_mcheck.return_value = (200, None, None, {'url' : 'example.com'}, 'payload', 'account_name')
        mock_certget.return_value = {'code': 403, 'data': 'foo'}
        mock_response.return_value = {'data': 'foo'}
        self.assertEqual({'data': 'foo'}, self.certificate.new_post('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_152_prepare_response(self, mock_nnonce):
        """ Message.prepare_respons for code 200 and complete data """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header', 'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.error.Error.enrich_error')
    @patch('acme.nonce.Nonce.generate_and_add')
    def test_153_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_respons for code 200 without header tag in response_dic """
        data_dic = {'data' : {'foo_data' : 'bar_bar'},}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_154_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without code key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'http status code missing', 'message': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_155_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without message key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'detail', 'message': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_156_prepare_response(self, mock_nnonce):
        """ Message.repare_response for config_dic without detail key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 400, 'message': 'message'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'message': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.error.Error.enrich_error')
    @patch('acme.nonce.Nonce.generate_and_add')
    def test_157_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_response for response_dic without data key """
        data_dic = {'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'message': 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'mock_error', 'message': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    def test_158_acme_errormessage(self):
        """ Error.acme_errormessage for existing value with content """
        self.assertEqual('JWS has invalid anti-replay nonce', self.error._acme_errormessage('urn:ietf:params:acme:error:badNonce'))

    def test_159_acme_errormessage(self):
        """ Error.acme_errormessage for existing value without content """
        self.assertFalse(self.error._acme_errormessage('urn:ietf:params:acme:error:unauthorized'))

    def test_160_acme_errormessage(self):
        """ Error.acme_errormessage for message None """
        self.assertFalse(self.error._acme_errormessage(None))

    def test_161_acme_errormessage(self):
        """ Error.acme_errormessage for not unknown message """
        self.assertFalse(self.error._acme_errormessage('unknown'))

    def test_162_enrich_error(self):
        """ Error.enrich_error for valid message and detail """
        self.assertEqual('JWS has invalid anti-replay nonce: detail', self.error.enrich_error('urn:ietf:params:acme:error:badNonce', 'detail'))

    def test_163_enrich_error(self):
        """ Error.enrich_error for valid message, detail and None in error_hash hash """
        self.assertEqual('detail', self.error.enrich_error('urn:ietf:params:acme:error:badCSR', 'detail'))

    def test_164_enrich_error(self):
        """ Error.enrich_error for valid message, no detail and someting in error_hash hash """
        self.assertEqual('JWS has invalid anti-replay nonce: None', self.error.enrich_error('urn:ietf:params:acme:error:badNonce', None))

    def test_165_enrich_error(self):
        """ Error.enrich_error for valid message, no detail and nothing in error_hash hash """
        self.assertFalse(self.error.enrich_error('urn:ietf:params:acme:error:badCSR', None))

    def test_166_name_get(self):
        """ Order.name_get() http"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo'))

    def test_167_name_get(self):
        """ Order.name_get() http with further path (finalize)"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo/bar'))

    def test_168_name_get(self):
        """ Order.name_get() http with parameters"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo?bar'))

    def test_169_name_get(self):
        """ Order.name_get() http with key/value parameters"""
        self.assertEqual('foo', self.order._name_get('http://tester.local/acme/order/foo?key=value'))

    def test_170_name_get(self):
        """ Order.name_get() https with key/value parameters"""
        self.assertEqual('foo', self.order._name_get('https://tester.local/acme/order/foo?key=value'))

    @patch('acme.message.Message.check')
    def test_171_order_parse(self, mock_mcheck):
        """ Order.parse() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.order.parse(message))

    @patch('acme.message.Message.check')
    def test_172_order_parse(self, mock_mcheck):
        """ Order.parse() failed bcs. no url key in protected """
        mock_mcheck.return_value = (200, None, None, {'foo_protected' : 'bar_protected'}, {"foo_payload" : "bar_payload"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'url is missing in protected', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.order.parse(message))

    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_173_order_parse(self, mock_mcheck, mock_oname):
        """ Order.parse() name_get failed """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = None
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'order name is missing', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.order.parse(message))

    @patch('acme.order.Order._lookup')
    @patch('acme.order.Order._name_get')
    @patch('acme.message.Message.check')
    def test_174_order_parse(self, mock_mcheck, mock_oname, mock_lookup):
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
    def test_175_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process):
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
    def test_176_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
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
    def test_177_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
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
    def test_178_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
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
    def test_179_order_parse(self, mock_mcheck, mock_oname, mock_lookup, mock_process, mock_nnonce):
        """ Order.parse() succ, oder process returned 200 and certname and non-valid status """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'foo'
        mock_lookup.return_value = {'foo': 'bar', 'status': 'foobar'}
        mock_process.return_value = (200, 'message', 'detail', 'certname')
        mock_nnonce.return_value = 'nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'finalize': 'http://tester.local/acme/order/foo/finalize', 'foo': 'bar', 'status': 'foobar'}, 'header': {'Location': 'http://tester.local/acme/order/foo', 'Replay-Nonce': 'nonce'}}, self.order.parse(message))

    @patch('acme.message.Message.check')
    def test_180_authorization_post(self, mock_mcheck):
        """ Authorization.new_post() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.authorization.new_post(message))

    @patch('acme.authorization.Authorization._authz_info')
    @patch('acme.message.Message.check')
    def test_181_authorization_post(self, mock_mcheck, mock_authzinfo):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', 'account_name')
        mock_authzinfo.return_value = {'authz_foo': 'authz_bar'}
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'url is missing in protected', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.authorization.new_post(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.authorization.Authorization._authz_info')
    @patch('acme.message.Message.check')
    def test_182_authorization_post(self, mock_mcheck, mock_authzinfo, mock_nnonce):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, {'url' : 'foo_url'}, 'payload', 'account_name')
        mock_authzinfo.return_value = {'authz_foo': 'authz_bar'}
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'authz_foo': 'authz_bar'}}, self.authorization.new_post(message))

    def test_183_cert_serial_get(self):
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

    def test_184_cert_san_get(self):
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

    def test_185_cert_san_get(self):
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

    def test_186_cert_serial_get(self):
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

    def test_187_revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with allowed reason"""
        rev_reason = 0
        self.assertEqual('unspecified', self.certificate._revocation_reason_check(rev_reason))

    def test_188_revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with non-allowed reason"""
        rev_reason = 8
        self.assertFalse(self.certificate._revocation_reason_check(rev_reason))

    @patch('acme.certificate.cert_san_get')
    def test_189_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans but failed order lookup"""
        self.account.dbstore.order_lookup.return_value = {}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_190_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order returning wrong values (no 'identifiers' key) """
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_191_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order lookup returning identifiers without json structure) """
        self.account.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_192_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with wrong sans) """
        self.account.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_193_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with SAN entry which is not in the identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_194_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with single SAN entry and correct entry in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_195_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with multiple SAN entries and correct entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_196_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with one SAN entry and multiple entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_197_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with uppercase SAN entries and lowercase entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:SAN1.EXAMPLE.COM', 'DNS:SAN2.EXAMPLE.COM']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_198_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lowercase SAN entries and uppercase entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"TYPE": "DNS", "VALUE": "SAN1.EXAMPLE.COM"}, {"TYPE": "DNS", "VALUE": "SAN2.EXAMPLE.COM"}]'}
        mock_san.return_value = ['dns:san1.example.com', 'dns:san2.example.com']
        self.assertTrue(self.certificate._authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_199_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lSAN entries (return none) and entries in identifier containing None"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "None", "value": "None"}]'}
        mock_san.return_value = ['san1.example.com']
        self.assertFalse(self.certificate._authorization_check('order_name', 'cert'))

    def test_200_revocation_request_validate(self):
        """ test Certificate.revocation_request_validate empty payload"""
        payload = {}
        self.assertEqual((400, 'unspecified'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_201_revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns None"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:badRevocationReason'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_202_revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns a reason"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = 'revrcheck'
        self.assertEqual((400, 'revrcheck'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._authorization_check')
    @patch('acme.certificate.Certificate._account_check')
    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_203_revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check failed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate._authorization_check')
    @patch('acme.certificate.Certificate._account_check')
    @patch('acme.certificate.Certificate._revocation_reason_check')
    def test_204_revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check succeed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = True
        self.assertEqual((200, 'revrcheck'), self.certificate._revocation_request_validate('account_name', payload))

    @patch('acme.message.Message.check')
    def test_205_revoke(self, mock_mcheck):
        """ test Certificate.revoke with failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'message', 'detail': 'detail'}}, self.certificate.revoke('content'))

    @patch('acme.message.Message.check')
    def test_206_revoke(self, mock_mcheck):
        """ test Certificate.revoke with incorrect payload """
        mock_mcheck.return_value = (200, 'message', 'detail', None, {}, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'certificate not found'}}, self.certificate.revoke('content'))

    @patch('acme.certificate.Certificate._revocation_request_validate')
    @patch('acme.message.Message.check')
    def test_207_revoke(self, mock_mcheck, mock_validate):
        """ test Certificate.revoke with failed request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (400, 'error')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'error'}}, self.certificate.revoke('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.ca_handler.CAhandler.revoke')
    @patch('acme.certificate.Certificate._revocation_request_validate')
    @patch('acme.message.Message.check')
    def test_208_revoke(self, mock_mcheck, mock_validate, mock_ca_handler, mock_nnonce):
        """ test Certificate.revoke with sucessful request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (200, 'reason')
        mock_ca_handler.return_value = (200, 'message', 'detail')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Replay-Nonce': 'new_nonce'}}, self.certificate.revoke('content'))

    def test_209_name_get(self):
        """ test Message.name_get() with empty content"""
        protected = {}
        self.assertFalse(self.message._name_get(protected))

    def test_210_name_get(self):
        """ test Message.name_get() with kid with nonsens in content"""
        protected = {'kid' : 'foo'}
        self.assertEqual('foo', self.message._name_get(protected))

    def test_211_name_get(self):
        """ test Message.name_get() with wrong kid in content"""
        protected = {'kid' : 'http://tester.local/acme/account/account_name'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_212_name_get(self):
        """ test Message.name_get() with correct kid in content"""
        protected = {'kid' : 'http://tester.local/acme/acct/account_name'}
        self.assertEqual('account_name', self.message._name_get(protected))

    def test_213_name_get(self):
        """ test Message.name_get() with 'jwk' in content but without URL"""
        protected = {'jwk' : 'jwk'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_214_name_get(self):
        """ test Message.name_get() with 'jwk' and 'url' in content but url is wrong"""
        protected = {'jwk' : 'jwk', 'url' : 'url'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_215_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' in content but no 'n' in jwk """
        protected = {'jwk' : 'jwk', 'url' : 'http://tester.local/acme/revokecert'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_216_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' but account lookup failed """
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {}
        self.assertEqual(None, self.message._name_get(protected))

    def test_217_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'bar' : 'foo'}
        self.assertEqual(None, self.message._name_get(protected))

    def test_218_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'name' : 'foo'}
        self.assertEqual('foo', self.message._name_get(protected))

    def test_219_revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with a valid revocation reason"""
        self.assertEqual('unspecified', self.certificate._revocation_reason_check(0))

    def test_220_revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with an invalid revocation reason"""
        self.assertFalse(self.certificate._revocation_reason_check(2))

    def test_221_build_pem_file(self):
        """ test build_pem_file without exsting content """
        existing = None
        cert = 'cert'
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_222_build_pem_file(self):
        """ test build_pem_file with exsting content """
        existing = 'existing'
        cert = 'cert'
        self.assertEqual('existing-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_223_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_224_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, False))

    def test_225_build_pem_file(self):
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

    @patch('acme.challenge.url_get')
    def test_226_validate_http_challenge(self, mock_url):
        """ test Chalölenge.validate_http_challenge() with a wrong challenge """
        mock_url.return_value = 'foo'
        self.assertFalse(self.challenge._validate_http_challenge('fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.url_get')
    def test_227_validate_http_challenge(self, mock_url):
        """ test Chalölenge.validate_http_challenge() with a correct challenge """
        mock_url.return_value = 'token.jwk_thumbprint'
        self.assertTrue(self.challenge._validate_http_challenge('fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.url_get')
    def test_228_validate_http_challenge(self, mock_url):
        """ test Chalölenge.validate_http_challenge() without response """
        mock_url.return_value = None
        self.assertFalse(self.challenge._validate_http_challenge('fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_229_validate_dns_challenge(self, mock_dns, mock_code, mock_hash):
        """ test Chalölenge.validate_dns_challenge() with incorrect response """
        mock_dns.return_value = 'foo'
        mock_code.return_value = 'bar'
        mock_hash.return_value = 'hash'
        self.assertFalse(self.challenge._validate_dns_challenge('fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_230_validate_dns_challenge(self, mock_dns, mock_code, mock_hash):
        """ test Chalölenge.validate_dns_challenge() with correct response """
        mock_dns.return_value = 'foo'
        mock_code.return_value = 'foo'
        mock_hash.return_value = 'hash'
        self.assertTrue(self.challenge._validate_dns_challenge('fqdn', 'token', 'jwk_thumbprint'))

    def test_231_validate_tkauth_challenge(self):
        """ test Chalölenge.validate_tkauth_challenge() """
        self.assertTrue(self.challenge._validate_tkauth_challenge('fqdn', 'token', 'jwk_thumbprint', 'payload'))

    def test_232_challenge_check(self):
        """ challenge check with incorrect challenge-dictionary """
        # self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.challenge.dbstore.challenge_lookup.return_value = {}
        self.assertFalse(self.challenge._check('name', 'payload'))

    def test_233_challenge_check(self):
        """ challenge check with without jwk return """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'type', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = None
        self.assertFalse(self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_http_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_234_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = False
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertFalse(self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_http_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_235_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = True
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue(self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_dns_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_236_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed dns challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = False
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertFalse(self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_dns_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_237_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = True
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue(self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_238_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tkauth challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = False
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertFalse(self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_239_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist_support unset """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = False
        mock_chall.return_value = True
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertFalse(self.challenge._check('name', 'payload'))

    @patch('acme.challenge.Challenge._validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_240_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist support set """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.return_value = True
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue(self.challenge._check('name', 'payload'))

    def test_241_order_identifier_check(self):
        """ order identifers check with empty identifer list"""
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check([]))

    def test_242_order_identifier_check(self):
        """ order identifers check with string identifier """
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check('foo'))

    def test_243_order_identifier_check(self):
        """ order identifers check with dictionary identifier """
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check({'type': 'dns', 'value': 'foo.bar'}))

    def test_244_order_identifier_check(self):
        """ order identifers check with correct identifer but case-insensitive """
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order._identifiers_check([{'Type': 'dns', 'value': 'value'}]))

    def test_245_order_identifier_check(self):
        """ order identifers check with wrong identifer in list"""
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'foo', 'value': 'value'}]))

    def test_246_order_identifier_check(self):
        """ order identifers check with correct identifer in list"""
        self.assertEqual(None, self.order._identifiers_check([{'type': 'dns', 'value': 'value'}]))

    def test_247_order_identifier_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'dns', 'value': 'value'}, {'type': 'foo', 'value': 'value'}]))

    def test_248_order_identifier_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'foo', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_249_order_identifier_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual(None, self.order._identifiers_check([{'type': 'dns', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_250_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier and support false """
        self.order.tnauthlist_support = False
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_251_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier and support True """
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_252_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier and support True """
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}]))

    def test_253_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier a wrong identifer and support True """
        self.order.tnauthlist_support = True
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'type', 'value': 'value'}]))

    def test_254_order_identifier_check(self):
        """ order identifers check with wrong identifer in list and tnauthsupport true"""
        self.order.tnauthlist_support = True
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order._identifiers_check([{'type': 'foo', 'value': 'value'}]))

    def test_255_order_identifier_check(self):
        """ order identifers check with correct identifer in list and tnauthsupport true"""
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order._identifiers_check([{'type': 'dns', 'value': 'value'}]))

    def test_256_b64_decode(self):
        """ test bas64 decoder for string value"""
        self.assertEqual('test', self.b64_decode(self.logger, 'dGVzdA=='))

    def test_257_b64_decode(self):
        """ test bas64 decoder for byte value """
        self.assertEqual('test', self.b64_decode(self.logger, b'dGVzdA=='))

    @patch('acme.challenge.Challenge.new_set')
    @patch('acme.authorization.uts_now')
    @patch('acme.authorization.generate_random_string')
    def test_258_authorization_info(self, mock_name, mock_uts, mock_challengeset):
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
    def test_259_authorization_post(self, mock_mcheck, mock_authzinfo, mock_nnonce):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, {'url' : 'foo_url'}, 'payload', 'account_name')
        mock_authzinfo.return_value = {}
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 403, 'data': {'detail': 'authorizations lookup failed', 'message': 'urn:ietf:params:acme:error:unauthorized', 'status': 403}}, self.authorization.new_post(message))

    @patch('acme.account.Account._contact_check')
    def test_260_account_contact_update(self, mock_contact_chk,):
        """ Account.contact_update() failed contact_check failed """
        mock_contact_chk.return_value = (400, 'message', 'detail')
        payload = '{"foo" : "bar"}'
        aname = 'aname'
        self.assertEqual((400,'message', 'detail'), self.account._contacts_update(aname, payload))

    @patch('acme.account.Account._contact_check')
    def test_261_account_contact_update(self, mock_contact_chk,):
        """ Account.contact_update() failed bcs account update failed """
        mock_contact_chk.return_value = (200, 'message', 'detail')
        self.account.dbstore.account_update.return_value = None
        payload = {"contact" : "foo"}
        aname = 'aname'
        self.assertEqual((400, 'urn:ietf:params:acme:error:accountDoesNotExist', 'update failed'), self.account._contacts_update(aname, payload))

    @patch('acme.account.Account._contact_check')
    def test_262_account_contact_update(self, mock_contact_chk,):
        """ Account.contact_update() succ """
        mock_contact_chk.return_value = (200, 'message', 'detail')
        self.account.dbstore.account_update.return_value = 'foo'
        payload = {"contact" : "foo"}
        aname = 'aname'
        self.assertEqual((200, 'message', 'detail'), self.account._contacts_update(aname, payload))

    @patch('acme.account.Account._contacts_update')
    @patch('acme.message.Message.check')
    def test_263_accout_parse(self, mock_mcheck, mock_contact_upd):
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
    def test_264_accout_parse(self, mock_mcheck, mock_contact_upd, mock_account_lookup, mock_datestr, mock_nnonce):
        """ test succ account parse for reqeust with succ contacts update """
        mock_mcheck.return_value = (200, None, None, 'protected', {"contact" : "deactivated"}, 'account_name')
        mock_contact_upd.return_value = (200, None, None)
        mock_nnonce.return_value = 'new_nonce'
        mock_account_lookup.return_value = {'contact': ['foo@bar', 'foo1@bar'], 'jwk': '{"foo1": "bar1", "foo2": "bar2"}', 'contact': '["foo@bar", "foo1@bar"]', 'created_at': 'foo'}
        mock_datestr.return_value = 'foo_date'
        message = 'message'
        self.assertEqual({'code': 200, 'data': {'contact': [u'foo@bar', u'foo1@bar'], 'createdAt': 'foo_date', 'key': {u'foo1': u'bar1', u'foo2': u'bar2'}, 'status': 'valid'}, 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))

    def test_265_date_to_datestr(self):
        """ convert dateobj to date-string with default format"""
        self.assertEqual('2019-10-27T00:00:00Z', self.date_to_datestr(datetime.date(2019, 10, 27)))

    def test_266_date_to_datestr(self):
        """ convert dateobj to date-string with a predefined format"""
        self.assertEqual('2019.10.27', self.date_to_datestr(datetime.date(2019, 10, 27), '%Y.%m.%d'))

    def test_267_date_to_datestr(self):
        """ convert dateobj to date-string for an knvalid date"""
        self.assertEqual(None, self.date_to_datestr('foo', '%Y.%m.%d'))

    def test_268_datestr_to_date(self):
        """ convert datestr to date with default format"""
        self.assertEqual(datetime.datetime(2019, 11, 27, 0, 1, 2), self.datestr_to_date('2019-11-27T00:01:02'))

    def test_269_datestr_to_date(self):
        """ convert datestr to date with predefined format"""
        self.assertEqual(datetime.datetime(2019, 11, 27, 0, 0, 0), self.datestr_to_date('2019.11.27', '%Y.%m.%d'))

    def test_270_datestr_to_date(self):
        """ convert datestr to date with invalid format"""
        self.assertEqual(None, self.datestr_to_date('foo', '%Y.%m.%d'))

    def test_271_dkeys_lower(self):
        """ dkeys_lower with a simple string """
        tree = 'fOo'
        self.assertEqual('fOo', self.dkeys_lower(tree))

    def test_272_dkeys_lower(self):
        """ dkeys_lower with a simple list """
        tree = ['fOo', 'bAr']
        self.assertEqual(['fOo', 'bAr'], self.dkeys_lower(tree))

    def test_273_dkeys_lower(self):
        """ dkeys_lower with a simple dictionary """
        tree = {'kEy': 'vAlUe'}
        self.assertEqual({'key': 'vAlUe'}, self.dkeys_lower(tree))

    def test_274_dkeys_lower(self):
        """ dkeys_lower with a nested dictionary containg strings, list and dictionaries"""
        tree = {'kEy1': 'vAlUe2', 'keys2': ['lIsT2', {'kEyS3': 'vAlUe3', 'kEyS4': 'vAlUe3'}], 'keys4': {'kEyS4': 'vAluE5', 'kEyS5': 'vAlUE6'}}
        self.assertEqual({'key1': 'vAlUe2', 'keys2': ['lIsT2', {'keys3': 'vAlUe3', 'keys4': 'vAlUe3'}], 'keys4': {'keys5': 'vAlUE6', 'keys4': 'vAluE5'}}, self.dkeys_lower(tree))

    def test_275_key_compare(self):
        """ Account.key_compare() with two empty dictionaries"""
        self.account.dbstore.jwk_load.return_value = {}
        aname = 'foo'
        okey = {}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_276_key_compare(self):
        """ Account.key_compare() with empty pub_key and existing old_key"""
        self.account.dbstore.jwk_load.return_value = {}
        aname = 'foo'
        okey = {'foo': 'bar'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_277_key_compare(self):
        """ Account.key_compare() with existing pub_key and empty old_key"""
        self.account.dbstore.jwk_load.return_value = {'foo': 'bar'}
        aname = 'foo'
        okey = {}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_278_key_compare(self):
        """ Account.key_compare() with similar pub_key empty old_key"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': None}
        aname = 'foo'
        okey = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': None}
        self.assertEqual((200, None, None), self.account._key_compare(aname, okey))

    def test_279_key_compare(self):
        """ Account.key_compare() with similar pub_key empty old_key but different order"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': None}
        aname = 'foo'
        okey = {'foo3': None, 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((200, None, None), self.account._key_compare(aname, okey))

    def test_280_key_compare(self):
        """ Account.key_compare() pub_key alg rewrite"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'ESfoo'}
        aname = 'foo'
        okey = {'alg': 'ECDSA', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((200, None, None), self.account._key_compare(aname, okey))

    def test_281_key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'foo'}
        aname = 'foo'
        okey = {'alg': 'ECDSA', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_282_key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'ESfoo'}
        aname = 'foo'
        okey = {'alg': 'rsa', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_283_key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite no alg statement in old_key"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'alg': 'ESfoo'}
        aname = 'foo'
        okey = {'foo3': None, 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_284_key_compare(self):
        """ Account.key_compare() pub_key failed alg rewrite no alg statement in pub_key"""
        self.account.dbstore.jwk_load.return_value = {'foo1': 'bar1', 'foo2': 'bar2', 'foo3': 'bar3'}
        aname = 'foo'
        okey = {'alg': 'ECDSA', 'foo2': 'bar2', 'foo1': 'bar1'}
        self.assertEqual((401, 'urn:ietf:params:acme:error:unauthorized', 'wrong public key'), self.account._key_compare(aname, okey))

    def test_285_inner_jws_check(self):
        """ Account.inner_jws_check() no jwk in inner header"""
        outer = {}
        inner = {'foo': 'bar'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner jws is missing jwk'), self.account._inner_jws_check(outer, inner))

    def test_286_inner_jws_check(self):
        """ Account.inner_jws_check() no url in inner header """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner or outer jws is missing url header parameter'), self.account._inner_jws_check(outer, inner))

    def test_287_inner_jws_check(self):
        """ Account.inner_jws_check() no url in outer header """
        outer = {'foo' : 'bar'}
        inner = {'jwk': 'jwk', 'url': 'url'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner or outer jws is missing url header parameter'), self.account._inner_jws_check(outer, inner))

    def test_288_inner_jws_check(self):
        """ Account.inner_jws_check() different url string in inner and outer header """
        outer = {'url' : 'url_'}
        inner = {'jwk': 'jwk', 'url': 'url'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'url parameter differ in inner and outer jws'), self.account._inner_jws_check(outer, inner))

    def test_289_inner_jws_check(self):
        """ Account.inner_jws_check() same url string in inner and outer header """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk', 'url': 'url'}
        self.assertEqual((200, None, None), self.account._inner_jws_check(outer, inner))

    def test_290_inner_jws_check(self):
        """ Account.inner_jws_check() nonce in inner header """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk', 'url': 'url', 'nonce': 'nonce'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner jws must omit nonce header'), self.account._inner_jws_check(outer, inner))

    def test_291_inner_jws_check(self):
        """ Account.inner_jws_check() nonce in inner header and inner_header_nonce_allow True """
        outer = {'url' : 'url'}
        inner = {'jwk': 'jwk', 'url': 'url', 'nonce': 'nonce'}
        self.account.inner_header_nonce_allow = True
        self.assertEqual((200, None, None), self.account._inner_jws_check(outer, inner))

    def test_292_inner_payload_check(self):
        """ Account.inner_payload_check() without kid in outer protected """
        outer_protected = {}
        inner_payload = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'kid is missing in outer header'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_293_inner_payload_check(self):
        """ Account.inner_payload_check() with kid in outer protected but without account object in inner_payload """
        outer_protected = {'kid': 'kid'}
        inner_payload = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'account object is missing on inner payload'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_294_inner_payload_check(self):
        """ Account.inner_payload_check() with different kid and account values """
        outer_protected = {'kid': 'kid'}
        inner_payload = {'account': 'account'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'kid and account objects do not match'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_295_inner_payload_check(self):
        """ Account.inner_payload_check() with same kid and account values but no old_key"""
        outer_protected = {'kid': 'kid'}
        inner_payload = {'account': 'kid'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'old key is missing'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    @patch('acme.account.Account._key_compare')
    def test_296_inner_payload_check(self, mock_cmp):
        """ Account.inner_payload_check() with same kid and account values but no old_key"""
        outer_protected = {'kid': 'kid'}
        inner_payload = {'account': 'kid', 'oldkey': 'oldkey'}
        mock_cmp.return_value = ('code', 'message', 'detail')
        self.assertEqual(('code', 'message', 'detail'), self.account._inner_payload_check('aname', outer_protected, inner_payload))

    def test_297_key_change_validate(self):
        """ Account.key_change_validate() without JWK in inner_protected """
        inner_protected = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'inner jws is missing jwk'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    @patch('acme.account.Account._lookup')
    def test_298_key_change_validate(self, mock_lup):
        """ Account.key_change_validate() for existing key """
        inner_protected = {'jwk': 'jwk'}
        mock_lup.return_value = True
        self.assertEqual((400, 'urn:ietf:params:acme:error:badPublicKey', 'public key does already exists'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    @patch('acme.account.Account._inner_jws_check')
    @patch('acme.account.Account._lookup')
    def test_299_key_change_validate(self, mock_lup, mock_jws_chk):
        """ Account.key_change_validate() inner_jws_check returns 400 """
        inner_protected = {'jwk': 'jwk'}
        mock_lup.return_value = False
        mock_jws_chk.return_value = (400, 'message1', 'detail1')
        self.assertEqual((400, 'message1', 'detail1'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    @patch('acme.account.Account._inner_payload_check')
    @patch('acme.account.Account._inner_jws_check')
    @patch('acme.account.Account._lookup')
    def test_300_key_change_validate(self, mock_lup, mock_jws_chk, mock_pl_chk):
        """ Account.key_change_validate() inner_jws_check returns 200 """
        inner_protected = {'jwk': 'jwk'}
        mock_lup.return_value = False
        mock_jws_chk.return_value = (200, 'message1', 'detail1')
        mock_pl_chk.return_value = ('code2', 'message2', 'detail2')
        self.assertEqual(('code2', 'message2', 'detail2'), self.account._key_change_validate('aname', {}, inner_protected, {}))

    def test_301_key_change(self):
        """ Account.key_change() without URL in protected """
        protected = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'malformed request'), self.account._key_change('aname', {}, protected))

    def test_302_key_change(self):
        """ Account.key_change() with URL in protected without key-change in url"""
        protected = {'url': 'url'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'malformed request. not a key-change'), self.account._key_change('aname', {}, protected))

    @patch('acme.message.Message.check')
    def test_303_key_change(self, mock_mcheck):
        """ Account.key_change() message.check() returns non-200"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = ('code1', 'message1', 'detail1', 'prot', 'payload', 'aname')
        self.assertEqual(('code1', 'message1', 'detail1'), self.account._key_change('aname', {}, protected))

    @patch('acme.account.Account._key_change_validate')
    @patch('acme.message.Message.check')
    def test_304_key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() with URL in protected without key-change in url"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', 'prot', 'payload', 'aname')
        moch_kchval.return_value = ('code2', 'message2', 'detail2')
        self.assertEqual(('code2', 'message2', 'detail2'), self.account._key_change('aname', {}, protected))

    @patch('acme.account.Account._key_change_validate')
    @patch('acme.message.Message.check')
    def test_305_key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() - account_update returns nothing"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', {'jwk': {'h1': 'h1a', 'h2': 'h2a', 'h3': 'h3a'}}, 'payload', 'aname')
        moch_kchval.return_value = (200, 'message2', 'detail2')
        self.account.dbstore.account_update.return_value = None
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'key rollover failed'), self.account._key_change('aname', {}, protected))

    @patch('acme.account.Account._key_change_validate')
    @patch('acme.message.Message.check')
    def test_306_key_change(self, mock_mcheck, moch_kchval):
        """ Account.key_change() - account_update returns nothing"""
        protected = {'url': 'url/key-change'}
        mock_mcheck.return_value = (200, 'message1', 'detail1', {'jwk': {'h1': 'h1a', 'h2': 'h2a', 'h3': 'h3a'}}, 'payload', 'aname')
        moch_kchval.return_value = (200, 'message2', 'detail2')
        self.account.dbstore.account_update.return_value = True
        self.assertEqual((200, None, None), self.account._key_change('aname', {}, protected))

    def test_307_order_process(self):
        """ Order.prcoess() without url in protected header """
        order_name = 'order_name'
        protected = 'protected'
        payload = 'payload'
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'url is missing in protected', None), self.order._process(order_name, protected, payload))

    def test_308_order_process(self):
        """ Order.prcoess() polling request with failed certificate lookup """
        order_name = 'order_name'
        protected = {'url': 'foo'}
        payload = 'payload'
        self.order.dbstore.certificate_lookup.return_value = {}
        self.assertEqual((200, None, None, None), self.order._process(order_name, protected, payload))

    def test_309_order_process(self):
        """ Order.prcoess() polling request with successful certificate lookup """
        order_name = 'order_name'
        protected = {'url': 'foo'}
        payload = 'payload'
        self.order.dbstore.certificate_lookup.return_value = {'name': 'cert_name'}
        self.assertEqual((200, None, None, 'cert_name'), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._info')
    def test_310_order_process(self, mock_info):
        """ Order.prcoess() finalize request with empty orderinfo """
        mock_info.return_value = {}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:orderNotReady', 'Order is not ready', None), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._info')
    def test_311_order_process(self, mock_info):
        """ Order.prcoess() finalize request with orderinfo without status"""
        mock_info.return_value = {'foo': 'bar'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:orderNotReady', 'Order is not ready', None), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._info')
    def test_312_order_process(self, mock_info):
        """ Order.prcoess() finalize request with orderinfo with wrong status"""
        mock_info.return_value = {'status': 'bar'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((403, 'urn:ietf:params:acme:error:orderNotReady', 'Order is not ready', None), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._info')
    def test_313_order_process(self, mock_info):
        """ Order.prcoess() finalize request without CSR """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = 'payload'
        self.assertEqual((400, 'urn:ietf:params:acme:error:badCSR', 'csr is missing in payload', None), self.order._process(order_name, protected, payload))

    @patch('acme.order.Order._csr_process')
    @patch('acme.order.Order._info')
    def test_314_order_process(self, mock_info, mock_process_csr):
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
    def test_315_order_process(self, mock_info, mock_process_csr, mock_update):
        """ Order.prcoess() finalize request with CSR but csr_process failed """
        mock_info.return_value = {'status': 'ready'}
        order_name = 'order_name'
        protected = {'url': {'finalize': 'foo', 'foo': 'bar'}}
        payload = {'csr': 'csr'}
        mock_process_csr.return_value = (200, 'cert_name', 'detail')
        mock_update.return_value = None
        self.assertEqual((200, None, 'detail', 'cert_name'), self.order._process(order_name, protected, payload))

    def test_316_cert_pubkey_get(self):
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

    def test_317_csr_pubkey_get(self):
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

    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_318_trigger_certname_lookup(self, mock_cert_pub, mock_search_list):
        """ trigger._certname_lookup() failed bcs. of empty certificate list """
        mock_cert_pub.return_value = 'foo'
        mock_search_list = []
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_319_trigger_certname_lookup(self, mock_cert_pub, mock_search_list):
        """ trigger._certname_lookup() failed bcs. of wrong certificate list """
        mock_cert_pub.return_value = 'foo'
        mock_search_list.return_value = [{'foo': 'bar'}]
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_320_trigger_certname_lookup(self, mock_cert_pub, mock_search_list):
        """ trigger._certname_lookup() failed bcs. of emty csr field """
        mock_cert_pub.return_value = 'foo'
        mock_search_list.return_value = [{'csr': None}]
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('acme.trigger.csr_pubkey_get')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_321_trigger_certname_lookup(self, mock_cert_pub, mock_search_list, mock_csr_pub):
        """ trigger._certname_lookup() failed bcs. of emty csr field """
        mock_cert_pub.return_value = 'foo'
        mock_csr_pub.return_value = 'foo1'
        mock_search_list.return_value = [{'csr': None}]
        self.assertEqual([], self.trigger._certname_lookup('cert_pem'))

    @patch('acme.trigger.csr_pubkey_get')
    @patch('acme.certificate.Certificate.certlist_search')
    @patch('acme.trigger.cert_pubkey_get')
    def test_322_trigger_certname_lookup(self, mock_cert_pub, mock_search_list, mock_csr_pub):
        """ trigger._certname_lookup() failed bcs. of emty csr field """
        mock_cert_pub.return_value = 'foo'
        mock_csr_pub.return_value = 'foo'
        mock_search_list.return_value = [{'csr': 'csr', 'name': 'cert_name', 'order__name': 'order_name'}]
        self.assertEqual([{'cert_name': 'cert_name', 'order_name': 'order_name'}], self.trigger._certname_lookup('cert_pem'))

    def test_323_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertEqual('foo', self.convert_byte_to_string('foo'))

    def test_324_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertEqual('foo', self.convert_byte_to_string('foo'))

    def test_325_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertNotEqual('foo', self.convert_byte_to_string('foobar'))

    def test_326_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertNotEqual('foo', self.convert_byte_to_string(b'foobar'))

    def test_327_parse(self):
        """ Trigger.parse() with empty payload """
        payload = ""
        result = {'header': {}, 'code': 400, 'data': {'detail': 'payload missing', 'message': 'malformed', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    def test_328_parse(self):
        """ Trigger.parse() with wrong payload """
        payload = '{"foo": "bar"}'
        result = {'header': {}, 'code': 400, 'data': {'detail': 'payload missing', 'message': 'malformed', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    def test_329_parse(self):
        """ Trigger.parse() with empty payload key"""
        payload = '{"payload": ""}'
        result = {'header': {}, 'code': 400, 'data': {'detail': 'payload empty', 'message': 'malformed', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    @patch('acme.trigger.Trigger._payload_process')
    def test_330_parse(self, mock_process):
        """ Trigger.parse() with payload mock result 400"""
        payload = '{"payload": "foo"}'
        mock_process.return_value = (400, 'message', 'detail')
        result = {'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}
        self.assertEqual(result, self.trigger.parse(payload))

    @patch('acme.trigger.Trigger._payload_process')
    def test_331_parse(self, mock_process):
        """ Trigger.parse() with payload mock result 200"""
        payload = '{"payload": "foo"}'
        mock_process.return_value = (200, 'message', 'detail')
        result = {'header': {}, 'code': 200, 'data': {'detail': 'detail', 'message': 'message', 'status': 200}}
        self.assertEqual(result, self.trigger.parse(payload))

    def test_332__payload_process(self):
        """ Trigger._payload_process() without payload"""
        payload = {}
        self.assertEqual((400, 'payload malformed', None), self.trigger._payload_process(payload))

    @patch('acme.ca_handler.CAhandler.trigger')
    def test_333__payload_process(self, mock_cat_trigger):
        """ Trigger._payload_process() without certbunde and cert_raw"""
        payload = {'payload': 'foo'}
        mock_cat_trigger.return_value = ('error', None, None)
        self.assertEqual((400, 'error', None), self.trigger._payload_process(payload))

    @patch('acme.ca_handler.CAhandler.trigger')
    def test_334__payload_process(self, mock_cat_trigger):
        """ Trigger._payload_process() with bundle and without cart_raw"""
        payload = {'payload': 'foo'}
        mock_cat_trigger.return_value = ('error', 'bundle', None)
        self.assertEqual((400, 'error', None), self.trigger._payload_process(payload))

    @patch('acme.ca_handler.CAhandler.trigger')
    def test_335__payload_process(self, mock_cat_trigger):
        """ Trigger._payload_process() with bundle and without cart_raw"""
        payload = {'payload': 'foo'}
        mock_cat_trigger.return_value = ('error', None, 'raw')
        self.assertEqual((400, 'error', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    @patch('acme.ca_handler.CAhandler.trigger')
    def test_336__payload_process(self, mock_cat_trigger, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() with certificae_name"""
        payload = {'payload': 'foo'}
        mock_cat_trigger.return_value = ('error', 'bundle', 'raw')
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value ='b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name', 'order_name': None}]
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    @patch('acme.ca_handler.CAhandler.trigger')
    def test_337__payload_process(self, mock_cat_trigger, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() without certificate_name """
        payload = {'payload': 'foo'}
        mock_cat_trigger.return_value = ('error', 'bundle', 'raw')
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value ='b64dec'
        mock_lookup.return_value = [{'cert_name': None, 'order_name': 'order_name'}]
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    @patch('acme.ca_handler.CAhandler.trigger')
    def test_338__payload_process(self, mock_cat_trigger, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() without certificate_name """
        payload = {'payload': 'foo'}
        mock_cat_trigger.return_value = ('error', 'bundle', 'raw')
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value ='b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name', 'order_name': 'order_name'}]
        self.order.dbstore.order_update.return_value = None
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    @patch('acme.trigger.Trigger._certname_lookup')
    @patch('acme.trigger.b64_decode')
    @patch('acme.trigger.cert_der2pem')
    @patch('acme.trigger.convert_byte_to_string')
    @patch('acme.ca_handler.CAhandler.trigger')
    def test_339__payload_process(self, mock_cat_trigger, mock_cobystr, mock_der2pem, mock_b64dec, mock_lookup):
        """ Trigger._payload_process() without certificate_name """
        payload = {'payload': 'foo'}
        mock_cat_trigger.return_value = ('error', 'bundle', 'raw')
        mock_der2pem.return_value = 'der2pem'
        mock_cobystr.return_value = 'cert_pem'
        mock_b64dec.return_value ='b64dec'
        mock_lookup.return_value = [{'cert_name': 'certificate_name1', 'order_name': 'order_name1'}, {'cert_name': 'certificate_name2', 'order_name': 'order_name2'}]
        self.order.dbstore.order_update.return_value = None
        self.assertEqual((200, 'OK', None), self.trigger._payload_process(payload))

    def test_340_b64encode(self):
        """ test b64_url_encode of string """
        self.assertEqual(b'c3RyaW5n', self.b64_url_encode(self.logger, 'string'))

    def test_341_b64encode(self):
        """ test b64_url_encode of byte """
        self.assertEqual(b'Ynl0ZQ', self.b64_url_encode(self.logger, b'byte'))

if __name__ == '__main__':
    unittest.main()
