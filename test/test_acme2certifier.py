#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
import unittest
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
        from acme.helper import b64decode_pad, b64_url_recode, decode_message, decode_deserialize, generate_random_string, signature_check, validate_email, uts_to_date_utc, date_to_uts_utc, load_config, cert_serial_get, cert_san_get, build_pem_file
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
        self.build_pem_file = build_pem_file

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
        self.assertDictContainsSubset({'meta': {'home': 'https://github.com/grindsa/acme2certifier', 'author': 'grindsa <grindelsack@gmail.com>'}}, self.directory.directory_get())

    def test_005_nonce_new(self):
        """ test Nonce.new() and check if we get something back """
        self.assertIsNotNone(self.nonce.new())

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
        self.assertEqual((200, None, None), self.nonce.check_and_delete('aaa'))

    def test_010_err_badnonce(self):
        """ test badnonce error message """
        self.assertEqual('JWS has invalid anti-replay nonce', self.error.acme_errormessage('urn:ietf:params:acme:error:badNonce'))

    def test_011_err_invalidcontact(self):
        """ test badnonce error message """
        self.assertEqual('The provided contact URI was invalid', self.error.acme_errormessage('urn:ietf:params:acme:error:invalidContact'))

    def test_012_err_useractionrequired(self):
        """ test badnonce error message """
        self.assertFalse(self.error.acme_errormessage('urn:ietf:params:acme:error:userActionRequired'))

    def test_013_err_malformed(self):
        """ test badnonce error message """
        self.assertFalse(self.error.acme_errormessage('urn:ietf:params:acme:error:malformed'))

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
        self.assertEqual((200, None, None), self.account.tos_check({'termsOfServiceAgreed': True}))

    def test_028_tos_check_false(self):
        """ test successful tos check """
        self.assertEqual((403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse'), self.account.tos_check({'termsOfServiceAgreed': False}))

    def test_029_tos_check_missing(self):
        """ test successful tos check """
        self.assertEqual((403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse'), self.account.tos_check({'foo': 'bar'}))

    def test_030_contact_check_valid(self):
        """ test successful tos check """
        self.assertEqual((200, None, None), self.account.contact_check({'contact': ['mailto: foo@example.com']}))

    def test_031_contact_check_invalid(self):
        """ test successful tos check """
        self.assertEqual((400, 'urn:ietf:params:acme:error:invalidContact', 'mailto: bar@exa,mple.com'), self.account.contact_check({'contact': ['mailto: bar@exa,mple.com']}))

    def test_032_contact_check_missing(self):
        """ test successful tos check """
        self.assertEqual((400, 'urn:ietf:params:acme:error:invalidContact', 'no contacts specified'), self.account.contact_check({'foo': 'bar'}))

    @patch('acme.account.generate_random_string')
    def test_033_account_add_new(self, mock_name):
        """ test successful account add for a new account"""
        self.account.dbstore.account_add.return_value = (2, True)
        mock_name.return_value = 'randowm_string'
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((201, 'randowm_string', None), self.account.add(dic, 'foo@example.com'))

    @patch('acme.account.generate_random_string')
    def test_034_account_add_existing(self, mock_name):
        """ test successful account add for a new account"""
        self.account.dbstore.account_add.return_value = ('foo', False)
        mock_name.return_value = 'randowm_string'
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((200, 'foo', None), self.account.add(dic, 'foo@example.com'))

    def test_035_account_add_failed1(self):
        """ test account add without ALG """
        dic = {'foo': 'bar', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protectedpayload'), self.account.add(dic, ['me@example.com']))

    def test_036_account_add_failed2(self):
        """ test account add without jwk """
        dic = {'alg': 'RS256', 'foo': {'foo': u'bar'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protectedpayload'), self.account.add(dic, ['me@example.com']))

    def test_037_account_add_failed3(self):
        """ test account add without jwk e """
        dic = {'alg': 'RS256', 'jwk': {'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key'), self.account.add(dic, ['me@example.com']))

    def test_038_account_add_failed4(self):
        """ test account add without jwk kty """
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key'), self.account.add(dic, ['me@example.com']))

    def test_039_account_add_failed5(self):
        """ test account add without jwk n """
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key'), self.account.add(dic, ['me@example.com']))

    def test_040_account_add_failed6(self):
        """ test account add without contact """
        dic = {'alg': 'RS256', 'jwk': {'e': u'AQAB', 'kty': u'RSA', 'n': u'foo'}, 'nonce': u'bar', 'url': u'acme.srv/acme/newaccount'}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'incomplete protectedpayload'), self.account.add(dic, None))

    def test_041_get_id_succ(self):
        """ test successfull get_id """
        string = {'kid' : 'http://tester.local/acme/acct/foo'}
        self.assertEqual('foo', self.account.name_get(string))

    def test_042_get_id_failed(self):
        """ test failed get_id bcs of suffix """
        string = 'http://tester.local/acme/acct/bar/foo'
        self.assertFalse(self.account.name_get(string))

    def test_043_get_id_failed(self):
        """ test failed get_id bcs wrong servername """
        string = {'kid' : 'http://test.local/acme/acct/foo'}
        self.assertFalse(self.account.name_get(string))

    def test_044_get_id_failed(self):
        """ test failed get_id bcs of wrong path """
        string = {'kid' : 'http://tester.local/acct/foo'}
        self.assertFalse(self.account.name_get(string))

    def test_045_validate_sig_succ(self):
        """ successful validation of singature """
        mkey = {
            'alg' : 'RS256',
            'e' : 'AQAB',
            'kty' : 'RSA',
            'n' : '2CFMV4MK6Uo_2GQWa0KVWlzffgSDiLwur4ujSZkCRzbA3w5p1ABJgr7l_P84HpRv8R8rGL67hqmDJuT52mGD6fMVAhHPX5pSdtyZlQQuzpXonzNmHbG1DbMSiXrxg5jWVXchCxHx82wAt9Kf13O5ATxD0WOBB5FffpqQHh8zTf29jTL4vBd8N57ce17ZgNWl_EcoByjigqNFJcO0rrvrf6xyNaO9nbun4PAMJTLbfVa6CiEqjnjYMX80VYLH4fCqsAZgxIoli_D2j9P5Kq6KZZUL_bZ2QQV4UuwWZvh6tcA393YQLeMARnhWI6dqlZVdcU74NXi9NhSxcMkM8nZZ8Q',
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((True, None), self.signature_check(self.logger, message, mkey))

    def test_046_validate_sig_fail(self):
        """ failed validatio of singature  wrong key"""
        mkey = {
            'alg' : 'rs256',
            'e' : 'AQAB',
            'kty' : 'RSA',
            'n' : 'zncgRHCp22-29g9FO4Hn02iyS1Fo4Y1tB-6cucH1yKSxM6bowjAaVa4HkAnIxgF6Zj9qLROgQR84YjMPeNkq8woBRz1aziDiTIOc0D2aXvLgZbuFGesvxoSGd6uyxjyyV7ONwZEpB8QtDW0I3shlhosKB3Ni1NFu55bPUP9RvxUdPzRRuhxUMHc1CXre1KR0eQmQdNZT6tgQVxpv2lb-iburBADjivBRyrI3k3NmXkYknBggAu8JInaFY4T8pVK0jTwP-f3-0eAV1bg99Rm7uXNXl7SKpQ3oGihwy2OK-XAc59v6C3n4Wq9QpzGkFWsOOlp4zEf13L3_UKugeExEqw',
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((False, 'Verification failed for all signatures["Failed: [InvalidJWSSignature(\'Verification failed {InvalidSignature()}\',)]"]'), self.signature_check(self.logger, message, mkey))

    def test_047_validate_sig_fail(self):
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
            self.assertEqual((False, 'Unknown type "None", valid types are: [\'EC\', \'RSA\', \'oct\']'), self.signature_check(self.logger, message, mkey))
            
    def test_048_validate_sig_fail(self):
        """ failed validatio of singature  no key"""
        mkey = {}
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((False, 'No key specified.'), self.signature_check(self.logger, message, mkey))

    def test_049_jwk_load(self):
        """ test jwk load """
        self.signature.dbstore.jwk_load.return_value = 'foo'
        self.assertEqual('foo', self.signature.jwk_load(1))

    @patch('acme.message.Message.check')
    def test_050_account_new(self, mock_mcheck):
        """ Account.new() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.account.new(message))

    @patch('acme.account.Account.tos_check')
    @patch('acme.message.Message.check')
    def test_051_account_new(self, mock_mcheck, mock_tos):
        """ Account.new() failed bcs filed tos check """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', None)
        mock_tos.return_value = (403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse')
        message = {'foo' : 'bar'}
        e_result = {'code': 403, 'data': {'detail': 'Terms of service must be accepted', 'message': 'urn:ietf:params:acme:error:userActionRequired', 'status': 403}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.account.Account.contact_check')
    @patch('acme.account.Account.tos_check')
    @patch('acme.message.Message.check')
    def test_052_account_new(self, mock_mcheck, mock_tos, mock_contact):
        """ Account.new() failed bcs failed contact check """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (400, 'urn:ietf:params:acme:error:invalidContact', 'no contacts specified')
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': 'The provided contact URI was invalid: no contacts specified', 'message': 'urn:ietf:params:acme:error:invalidContact', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.account.Account.add')
    @patch('acme.account.Account.contact_check')
    @patch('acme.account.Account.tos_check')
    @patch('acme.message.Message.check')
    def test_053_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad):
        """ Account.new() failed bcs of failed add """
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : 'foo@bar.com'}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key')
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': 'incomplete JSON Web Key', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account.add')
    @patch('acme.account.Account.contact_check')
    @patch('acme.account.Account.tos_check')
    @patch('acme.message.Message.check')
    def test_054_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad, mock_nnonce):
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
    @patch('acme.account.Account.add')
    @patch('acme.account.Account.contact_check')
    @patch('acme.account.Account.tos_check')
    @patch('acme.message.Message.check')
    def test_055_account_new(self, mock_mcheck, mock_tos, mock_contact, mock_aad, mock_nnonce):
        """ Account.new() successful for an existing account"""
        mock_mcheck.return_value = (200, None, None, 'protected', {'contact' : [u'mailto: foo@bar.com']}, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.account.Account.onlyreturnexisting')
    @patch('acme.message.Message.check')
    def test_056_account_new(self, mock_mcheck, mock_existing):
        """ Account.new() onlyReturnExisting for a non existing account """
        mock_mcheck.return_value = (200, None, None, 'protected', {"onlyReturnExisting": 'true'}, None)
        mock_existing.return_value = (400, 'urn:ietf:params:acme:error:accountDoesNotExist', None)
        message = {'foo' : 'bar'}
        e_result = {'code': 400, 'data': {'detail': None, 'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'status': 400}, 'header': {}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account.onlyreturnexisting')
    @patch('acme.message.Message.check')
    def test_057_account_new(self, mock_mcheck, mock_existing, mock_nnonce):
        """ Account.new() onlyReturnExisting for an existing account """
        mock_mcheck.return_value = (200, None, None, 'protected', {"onlyReturnExisting": 'true'}, None)
        mock_existing.return_value = (200, 100, None)
        mock_nnonce.return_value = 'new_nonce'
        message = {'foo' : 'bar'}
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/100', 'Replay-Nonce': 'new_nonce'}}
        self.assertEqual(e_result, self.account.new(message))

    def test_058_get_id_failed(self):
        """ test failed get_id bcs of wrong data """
        string = {'foo' : 'bar'}
        self.assertFalse(self.account.name_get(string))

    def test_059_signature_check(self):
        """ test Signature.check() without having a kid """
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check('foo', None))

    @patch('acme.signature.Signature.jwk_load')
    def test_060_signature_check(self, mock_jwk):
        """ test Signature.check() while pubkey lookup failed """
        mock_jwk.return_value = {}
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check('foo', 1))

    @patch('acme.signature.signature_check')
    @patch('acme.signature.Signature.jwk_load')
    def test_061_signature_check(self, mock_jwk, mock_sig):
        """ test successful Signature.check()  """
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None, None), self.signature.check('foo', 1))

    @patch('acme.signature.signature_check')
    @patch('acme.signature.Signature.jwk_load')
    def test_062_signature_check(self, mock_jwk, mock_sig):
        """ test successful Signature.check() without account_name but having a corrupted protected header"""
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = (True, None)
        protected = 'foo'
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check('foo', None, protected))

    @patch('acme.signature.signature_check')
    @patch('acme.signature.Signature.jwk_load')
    def test_063_signature_check(self, mock_jwk, mock_sig):
        """ test successful Signature.check() without account_name but having url in protected header"""
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = (True, None)
        protected = {'url' : 'url'}
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check('foo', None, protected))

    @patch('acme.signature.signature_check')
    @patch('acme.signature.Signature.jwk_load')
    def test_064_signature_check(self, mock_jwk, mock_sig):
        """ test successful Signature.check() without account_name but having url (wrong) and jwk in protected header"""
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = (True, None)
        protected = {'url' : 'url', 'jwk': 'jwk'}
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check('foo', None, protected))

    @patch('acme.signature.signature_check')
    @patch('acme.signature.Signature.jwk_load')
    def test_065_signature_check(self, mock_jwk, mock_sig):
        """ test successful Signature.check() without account_name but having url (correct) and jwk in protected header"""
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = (True, None)
        protected = {'url' : 'http://tester.local/acme/revokecert', 'jwk': 'jwk'}
        self.assertEqual((True, None, None), self.signature.check('foo', None, protected))

    @patch('acme.message.decode_message')
    def test_066_message_check(self, mock_decode):
        """ message_check failed bcs of decoding error """
        message = '{"foo" : "bar"}'
        mock_decode.return_value = (False, 'detail', None, None, None)
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'detail', None, None, None), self.message.check(message))

    @patch('acme.nonce.Nonce.check')
    @patch('acme.message.decode_message')
    def test_067_message_check(self, mock_decode, mock_nonce_check):
        """ message_check nonce check failed """
        message = '{"foo" : "bar"}'
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (400, 'badnonce', None)
        self.assertEqual((400, 'badnonce', None, 'protected', 'payload', None), self.message.check(message))

    @patch('acme.nonce.Nonce.check')
    @patch('acme.message.decode_message')
    def test_068_message_check(self, mock_decode, mock_nonce_check):
        """ message check failed bcs account id lookup failed """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual((403, 'urn:ietf:params:acme:error:accountDoesNotExist', None, 'protected', 'payload', None), self.message.check(message))

    @patch('acme.signature.Signature.check')
    @patch('acme.message.Message.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.message.decode_message')
    def test_069_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check failed bcs signature_check_failed """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (False, 'error', 'detail')
        message = '{"foo" : "bar"}'
        self.assertEqual((403, 'error', 'detail', 'protected', 'payload', 'account_name'), self.message.check(message))

    @patch('acme.signature.Signature.check')
    @patch('acme.message.Message.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.message.decode_message')
    def test_070_message_check(self, mock_decode, mock_nonce_check, mock_aname, mock_sig):
        """ message check successful """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_nonce_check.return_value = (200, None, None)
        mock_aname.return_value = 'account_name'
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual((200, None, None, 'protected', 'payload', 'account_name'), self.message.check(message))

    @patch('acme.message.Message.check')
    def test_071_accout_parse(self, mock_mcheck):
        """ Account.parse() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.account.parse(message))

    @patch('acme.message.Message.check')
    def test_072_accout_parse(self, mock_mcheck):
        """ test failed account parse for request which does not has a "status" field in payload """
        mock_mcheck.return_value = (200, None, None, 'protected', {"foo" : "bar"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'dont know what to do with this request'}}, self.account.parse(message))

    @patch('acme.message.Message.check')
    def test_073_accout_parse(self, mock_mcheck):
        """ test failed account parse for reqeust with a "status" field other than "deactivated" """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'status attribute without sense'}}, self.account.parse(message))

    @patch('acme.account.Account.delete')
    @patch('acme.message.Message.check')
    def test_074_accout_parse(self, mock_mcheck, mock_del):
        """ test failed account parse for reqeust with failed deletion """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "deactivated"}, 'account_name')
        mock_del.return_value = (400, 'urn:ietf:params:acme:error:accountDoesNotExist', 'deletion failed')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'detail': 'deletion failed'}}, self.account.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account.delete')
    @patch('acme.message.Message.check')
    def test_075_accout_parse(self, mock_mcheck, mock_del, mock_nnonce):
        """ test succ account parse for reqeust with succ deletion """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "deactivated"}, 'account_name')
        mock_del.return_value = (200, None, None)
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'status': 'deactivated'}, 'header': {'Replay-Nonce': 'new_nonce'}}, self.account.parse(message))

    def test_076_onlyreturnexisting(self):
        """ test onlyReturnExisting with False """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyReturnExisting' : False}
        self.assertEqual((400, 'urn:ietf:params:acme:error:userActionRequired', 'onlyReturnExisting must be true'), self.account.onlyreturnexisting(protected, payload))

    def test_077_onlyreturnexisting(self):
        """ test onlyReturnExisting without jwk structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyReturnExisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'jwk structure missing'), self.account.onlyreturnexisting(protected, payload))

    def test_078_onlyreturnexisting(self):
        """ test onlyReturnExisting without jwk[n] structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {'jwk' : {}}
        payload = {'onlyReturnExisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'n value missing'), self.account.onlyreturnexisting(protected, payload))

    def test_079_onlyreturnexisting(self):
        """ test onlyReturnExisting for existing account """
        self.signature.dbstore.account_lookup.return_value = {'name' : 'foo', 'alg' : 'RS256'}
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyReturnExisting' : True}
        self.assertEqual((200, 'foo', None), self.account.onlyreturnexisting(protected, payload))

    def test_080_onlyreturnexisting(self):
        """ test onlyReturnExisting for non existing account """
        self.signature.dbstore.account_lookup.return_value = False
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyReturnExisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.account.onlyreturnexisting(protected, payload))

    def test_081_utstodate_utc(self):
        """ test uts_to_date_utc for a given format """
        self.assertEqual('2018-12-01', self.uts_to_date_utc(1543640400, '%Y-%m-%d'))

    def test_082_utstodate_utc(self):
        """ test uts_to_date_utc without format """
        self.assertEqual('2018-12-01T05:00:00Z', self.uts_to_date_utc(1543640400))

    def test_083_utstodate_utc(self):
        """ test date_to_uts_utc for a given format """
        self.assertEqual(1543618800, self.date_to_uts_utc('2018-12-01', '%Y-%m-%d'))

    def test_084_utstodate_utc(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(1543636800, self.date_to_uts_utc('2018-12-01T05:00:00'))

    def test_085_generaterandomstring(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(5, len(self.generate_random_string(self.logger, 5)))

    def test_086_generaterandomstring(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(15, len(self.generate_random_string(self.logger, 15)))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_087_order_add(self, mock_name, mock_uts):
        """ test Oder.add() without identifier in payload """
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        message = {}
        e_result = ('urn:ietf:params:acme:error:unsupportedIdentifier', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order.add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_088_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with empty identifier in payload dbstore-add returns None"""
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        self.signature.dbstore.order_add.return_value = False
        message = {'identifiers' : {}}
        e_result = ('urn:ietf:params:acme:error:malformed', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order.add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_089_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with single identifier in payload dbstore-add returns something real"""
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        self.order.dbstore.order_add.return_value = 1
        self.order.dbstore.authorization_add.return_value = True
        message = {'identifiers' : [{"type": "dns", "value": "example.com"}]}
        e_result = (None, 'aaaaa', {'aaaaa': {'type': 'dns', 'value': 'example.com'}}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order.add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_090_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with multiple identifier in payload dbstore-add returns something real"""
        mock_name.side_effect = ['order', 'identifier1', 'identifier2']
        mock_uts.return_value = 1543640400
        self.order.dbstore.order_add.return_value = 1
        self.order.dbstore.authorization_add.return_value = True
        message = {'identifiers' : [{"type": "dns", "value": "example1.com"}, {"type": "dns", "value": "example2.com"}]}
        e_result = (None, 'order', {'identifier1': {'type': 'dns', 'value': 'example1.com'}, 'identifier2': {'type': 'dns', 'value': 'example2.com'}}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order.add(message, 1))

    @patch('acme.message.Message.check')
    def test_091_order_new(self, mock_mcheck):
        """ Order.new() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.order.new(message))

    @patch('acme.order.Order.add')
    @patch('acme.message.Message.check')
    def test_092_order_new(self, mock_mcheck, mock_orderadd):
        """ Order.new() failed bcs of db_add failed """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = ('urn:ietf:params:acme:error:malformed', None, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'could not process order'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order.add')
    @patch('acme.message.Message.check')
    def test_093_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order with a single identifier """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_orderadd.return_value = (None, 'foo_order', {'foo_auth': {u'type': u'dns', u'value': u'acme.nclm-samba.local'}}, 'expires')
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{u'type': u'dns', u'value': u'acme.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order.add')
    @patch('acme.message.Message.check')
    def test_094_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
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
    @patch('acme.order.Order.add')
    @patch('acme.message.Message.check')
    def test_095_order_new(self, mock_mcheck, mock_orderadd, mock_nnonce):
        """ test successful order without identifiers """
        mock_mcheck.return_value = (200, None, None, 'protected', {"status" : "foo"}, 'account_name')
        mock_nnonce.return_value = 'new_nonce'
        mock_orderadd.return_value = (None, 'foo_order', {}, 'expires')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'new_nonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [], 'authorizations': [], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.challenge.generate_random_string')
    def test_096_challenge_new(self, mock_random):
        """ test challenge generation """
        mock_random.return_value = 'foo'
        self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'mtype'}, self.challenge.new('authz_name', 'mtype', 'token'))

    @patch('acme.challenge.generate_random_string')
    def test_097_challenge_new(self, mock_random):
        """ test challenge generation for tnauthlist challenge """
        mock_random.return_value = 'foo'
        self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'tkauth-01', 'tkauth-type': 'atc'}, self.challenge.new('authz_name', 'tkauth-01', 'token'))

    @patch('acme.challenge.Challenge.new')
    def test_098_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token'))

    @patch('acme.challenge.Challenge.new')
    def test_099_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set with tnauth true """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}], self.challenge.new_set('authz_name', 'token', True))

    @patch('acme.challenge.Challenge.new')
    def test_100_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token', False))

    @patch('acme.challenge.Challenge.new_set')
    @patch('acme.authorization.uts_now')
    @patch('acme.authorization.generate_random_string')
    def test_101_authorization_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = [{'type' : 'identifier_type', 'value' : 'identifier_value', 'status__name' : 'foo'}]
        self.assertEqual({'status': 'foo', 'expires': '2018-12-02T05:00:00Z', 'identifier': {'type': 'identifier_type', 'value': 'identifier_value'}, 'challenges': [{'key2': 'value2', 'key1': 'value1'}]}, self.authorization.authz_info('http://tester.local/acme/authz/foo'))

    def test_102_challenge_info(self):
        """ test challenge.info() """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.assertEqual({'status': 'pending', 'token': 'token', 'type': 'http-01'}, self.challenge.info('foo'))

    @patch('acme.message.Message.check')
    def test_103_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed bcs. message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  {'detail': 'detail', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.message.Message.check')
    def test_104_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() failed message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'url missing in protected header', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.message.Message.check')
    def test_105_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() message check returns ok with tnauhlist enabled but no atc claim """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'foo' : 'bar'}, {}, 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'atc claim is missing', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.message.Message.check')
    def test_106_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() message check returns ok with tnauhlist enabled but empty atc claim """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'foo' : 'bar'}, {'atc' : ''}, 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'SPC token is missing', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.message.Message.check')
    def test_107_challenge_parse(self, mock_mcheck):
        """ Challenge.parse() message check returns ok with tnauhlist enabled but empty atc claim """
        self.challenge.tnauthlist_support = True
        mock_mcheck.return_value = (200, 'message', 'detail', {'foo' : 'bar'}, {'atc' : 'foo'}, 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'url missing in protected header', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.challenge.Challenge.name_get')
    @patch('acme.message.Message.check')
    def test_108_challenge_parse(self, mock_mcheck, mock_cname):
        """ Challenge.parse() failed message check returns ok challenge name could not get obtained """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = None
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'could not get challenge', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.challenge.Challenge.info')
    @patch('acme.challenge.Challenge.name_get')
    @patch('acme.message.Message.check')
    def test_109_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo):
        """ Challenge.parse() failed bcs of empty challenge_dic """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.return_value = {}
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'invalid challenge: foo', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.challenge.parse('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.challenge.Challenge.info')
    @patch('acme.challenge.Challenge.name_get')
    @patch('acme.message.Message.check')
    def test_110_challenge_parse(self, mock_mcheck, mock_cname, mock_cinfo, mock_nnonce):
        """ Challenge.parse() successful """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'url' : 'bar'}, 'payload', 'account_name')
        mock_cname.return_value = 'foo'
        mock_cinfo.return_value = {'challenge_foo' : 'challenge_bar'}
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'new_nonce'}, 'data': {'challenge_foo': 'challenge_bar', 'url': 'bar'}}, self.challenge.parse('content'))

    @patch('acme.order.Order.info')
    def test_111_order_lookup(self, mock_oinfo):
        """ test order lookup with empty hash """
        mock_oinfo.return_value = {}
        self.assertEqual({}, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_112_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and wrong authorization hash"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': []}, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_113_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and correct authorization hash"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz//name']}, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_114_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and authorization hash having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2']}, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_115_order_lookup(self, mock_oinfo):
        """ test order lookup status in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2']}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_116_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_117_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore (0) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_118_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (0) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 0, 'notafter' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_119_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_120_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_121_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and worng authorization"""
        self.authorization.dbstore.authorization_lookup.return_value = 'foo'
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400, 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': [], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order.lookup('foo'))

    def test_122_base64_recode(self):
        """ test base64url recode to base64 - add padding for 1 char"""
        self.assertEqual('fafafaf=', self.b64_url_recode(self.logger, 'fafafaf'))

    def test_123_base64_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(self.logger, 'fafafa'))

    def test_124_base64_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(self.logger, 'fafaf'))

    def test_125_base64_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(self.logger, 'fafafafa'))

    def test_126_base64_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(self.logger, 'fafa-f'))

    def test_127_base64_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, 'fafa_f'))

    @patch('acme.order.Order.info')
    def test_128_process_csr(self, mock_oinfo):
        """ test order prcoess_csr with empty order_dic """
        mock_oinfo.return_value = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized', 'order: order_name not found'), self.order.process_csr('order_name', 'csr'))

    @patch('acme.order.validate_csr')
    @patch('acme.order.Order.info')
    def test_129_process_csr(self, mock_oinfo, mock_csrchk):
        """ test order prcoess_csr with failed csr check"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_csrchk.return_value = False
        self.assertEqual((403, 'urn:ietf:params:acme:badCSR', 'CSR validation failed'), self.order.process_csr('order_name', 'csr'))

    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.validate_csr')
    @patch('acme.order.Order.info')
    def test_130_process_csr(self, mock_oinfo, mock_csrchk, mock_certname):
        """ test order prcoess_csr with failed csr dbsave"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_csrchk.return_value = True
        mock_certname.return_value = None
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'CSR processing failed'), self.order.process_csr('order_name', 'csr'))

    @patch('acme.certificate.Certificate.enroll_and_store')
    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.validate_csr')
    @patch('acme.order.Order.info')
    def test_131_process_csr(self, mock_oinfo, mock_csrchk, mock_certname, mock_enroll):
        """ test order prcoess_csr with failed cert enrollment"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_csrchk.return_value = True
        mock_certname.return_value = 'foo'
        mock_enroll.return_value = (None, 'error')
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'error'), self.order.process_csr('order_name', 'csr'))

    @patch('acme.certificate.Certificate.enroll_and_store')
    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.validate_csr')
    @patch('acme.order.Order.info')
    def test_132_process_csr(self, mock_oinfo, mock_csrchk, mock_certname, mock_enroll):
        """ test order prcoess_csr with successful cert enrollment"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_csrchk.return_value = True
        mock_certname.return_value = 'foo'
        mock_enroll.return_value = ('bar', None)
        self.assertEqual((200, 'foo', None), self.order.process_csr('order_name', 'csr'))

    def test_133_decode_message(self):
        """ decode message with empty payload - certbot issue"""
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        e_result = (True, None, {u'nonce': u'26e6a46efadd477d908d7c2014e49b34', u'url': u'http://laptop.nclm-samba.local/acme/authz/PG189FFzfao1', u'alg': u'RS256', u'kid': u'http://laptop.nclm-samba.local/acme/acct/yuZ1GUJb76Zk'}, None, b'encoded_signature')
        self.assertEqual(e_result, self.decode_message(self.logger, data_dic))

    @patch('acme.certificate.generate_random_string')
    def test_134_store_csr(self, mock_name):
        """ test Certificate.store_csr() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'foo'
        mock_name.return_value = 'bar'
        self.assertEqual('bar', self.certificate.store_csr('order_name', 'csr'))

    def test_135_store_cert(self):
        """ test Certificate.store_cert() and check if we get something back """
        self.certificate.dbstore.certificate_add.return_value = 'bar'
        self.assertEqual('bar', self.certificate.store_cert('cert_name', 'cert', 'raw'))

    def test_136_info(self):
        """ test Certificate.new_get() """
        self.certificate.dbstore.certificate_lookup.return_value = 'foo'
        self.assertEqual('foo', self.certificate.info('cert_name'))

    @patch('acme.certificate.Certificate.info')
    def test_137_new_get(self, mock_info):
        """ test Certificate.new_get() with not existing cert_name"""
        mock_info.return_value = {}
        self.assertEqual({'code': 403, 'data': 'NotFound'}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate.info')
    def test_138_new_get(self, mock_info):
        """ test Certificate.new_get() with with exiting data without padding"""
        mock_info.return_value = {'cert' : 'ZGVjb2RlZF9jZXJ0aWZpY2F0ZQ=='}
        self.assertEqual({'code': 200, 'data': 'decoded_certificate', 'header': {'Content-Type': 'application/pem-certificate-chain'}}, self.certificate.new_get('url'))

    @patch('acme.certificate.Certificate.info')
    def test_139_new_get(self, mock_info):
        """ test Certificate.new_get() with with exiting data with padding"""
        mock_info.return_value = {'cert' : 'ZGVjb2RlZF9jZXJ0aWZpY2F0ZQ'}
        self.assertEqual({'code': 200, 'data': 'decoded_certificate', 'header': {'Content-Type': 'application/pem-certificate-chain'}}, self.certificate.new_get('url'))

    @patch('acme.message.Message.check')
    def test_140_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns an error """
        mock_mcheck.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'detail', 'protected', 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data':  {'detail': 'detail', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.certificate.new_post('content'))

    @patch('acme.message.Message.check')
    def test_141_new_post(self, mock_mcheck):
        """ test Certificate.new_post() message check returns ok but no url in protected """
        mock_mcheck.return_value = (200, 'urn:ietf:params:acme:error:malformed', 'detail', {'foo' : 'bar'}, 'payload', 'account_name')
        self.assertEqual({'code': 400, 'header': {}, 'data': {'detail': 'url missing in protected header', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.certificate.new_post('content'))

    @patch('acme.message.Message.prepare_response')
    @patch('acme.certificate.Certificate.new_get')
    @patch('acme.message.Message.check')
    def test_142_new_post(self, mock_mcheck, mock_certget, mock_response):
        """ test Certificate.new_post() message check returns ok  """
        mock_mcheck.return_value = (200, None, None, {'url' : 'example.com'}, 'payload', 'account_name')
        mock_certget.return_value = 'foo'
        mock_response.return_value = {'foo', 'bar'}
        self.assertEqual(set(['foo', 'bar']), self.certificate.new_post('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_143_prepare_response(self, mock_nnonce):
        """ Message.prepare_respons for code 200 and complete data """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header', 'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.error.Error.enrich_error')
    @patch('acme.nonce.Nonce.generate_and_add')
    def test_144_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_respons for code 200 without header tag in response_dic """
        data_dic = {'data' : {'foo_data' : 'bar_bar'},}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 200, 'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'foo_data': 'bar_bar'}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_145_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without code key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'message' : 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'http status code missing', 'message': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_146_prepare_response(self, mock_nnonce):
        """ Message.prepare_response for config_dic without message key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        # mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'detail', 'message': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_147_prepare_response(self, mock_nnonce):
        """ Message.repare_response for config_dic without detail key """
        data_dic = {'data' : {'foo_data' : 'bar_bar'}, 'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        config_dic = {'code' : 400, 'message': 'message'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': None, 'message': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    @patch('acme.error.Error.enrich_error')
    @patch('acme.nonce.Nonce.generate_and_add')
    def test_148_prepare_response(self, mock_nnonce, mock_error):
        """ Message.prepare_response for response_dic without data key """
        data_dic = {'header': {'foo_header' : 'bar_header'}}
        mock_nnonce.return_value = 'new_nonce'
        mock_error.return_value = 'mock_error'
        config_dic = {'code' : 400, 'message': 'message', 'detail' : 'detail'}
        self.assertEqual({'header': {'foo_header': 'bar_header'}, 'code': 400, 'data': {'detail': 'mock_error', 'message': 'message', 'status': 400}}, self.message.prepare_response(data_dic, config_dic))

    def test_149_acme_errormessage(self):
        """ Error.acme_errormessage for existing value with content """
        self.assertEqual('JWS has invalid anti-replay nonce', self.error.acme_errormessage('urn:ietf:params:acme:error:badNonce'))

    def test_150_acme_errormessage(self):
        """ Error.acme_errormessage for existing value without content """
        self.assertFalse(self.error.acme_errormessage('urn:ietf:params:acme:error:unauthorized'))

    def test_151_acme_errormessage(self):
        """ Error.acme_errormessage for message None """
        self.assertFalse(self.error.acme_errormessage(None))

    def test_152_acme_errormessage(self):
        """ Error.acme_errormessage for not unknown message """
        self.assertFalse(self.error.acme_errormessage('unknown'))

    def test_153_enrich_error(self):
        """ Error.enrich_error for valid message and detail """
        self.assertEqual('JWS has invalid anti-replay nonce: detail', self.error.enrich_error('urn:ietf:params:acme:error:badNonce', 'detail'))

    def test_154_enrich_error(self):
        """ Error.enrich_error for valid message, detail and None in error_hash hash """
        self.assertEqual('detail', self.error.enrich_error('urn:ietf:params:acme:error:badCSR', 'detail'))

    def test_155_enrich_error(self):
        """ Error.enrich_error for valid message, no detail and someting in error_hash hash """
        self.assertEqual('JWS has invalid anti-replay nonce: None', self.error.enrich_error('urn:ietf:params:acme:error:badNonce', None))

    def test_156_enrich_error(self):
        """ Error.enrich_error for valid message, no detail and nothing in error_hash hash """
        self.assertFalse(self.error.enrich_error('urn:ietf:params:acme:error:badCSR', None))

    def test_157_name_get(self):
        """ Order.name_get() http"""
        self.assertEqual('foo', self.order.name_get('http://tester.local/acme/order/foo'))

    def test_158_name_get(self):
        """ Order.name_get() http with further path (finalize)"""
        self.assertEqual('foo', self.order.name_get('http://tester.local/acme/order/foo/bar'))

    def test_159_name_get(self):
        """ Order.name_get() http with parameters"""
        self.assertEqual('foo', self.order.name_get('http://tester.local/acme/order/foo?bar'))

    def test_160_name_get(self):
        """ Order.name_get() http with key/value parameters"""
        self.assertEqual('foo', self.order.name_get('http://tester.local/acme/order/foo?key=value'))

    def test_161_name_get(self):
        """ Order.name_get() https with key/value parameters"""
        self.assertEqual('foo', self.order.name_get('https://tester.local/acme/order/foo?key=value'))

    @patch('acme.message.Message.check')
    def test_162_order_parse(self, mock_mcheck):
        """ Order.parse() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.order.parse(message))

    @patch('acme.message.Message.check')
    def test_163_order_parse(self, mock_mcheck):
        """ Order.parse() failed bcs. no url key in protected """
        mock_mcheck.return_value = (200, None, None, {'foo_protected' : 'bar_protected'}, {"foo_payload" : "bar_payload"}, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'url is missing in protected', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.order.parse(message))

    @patch('acme.order.Order.name_get')
    @patch('acme.message.Message.check')
    def test_164_order_parse(self, mock_mcheck, mock_oname):
        """ Order.parse() finalized failed bcs. no csr in payload """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'order_name'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'csr is missing in payload', 'message': 'urn:ietf:params:acme:error:badCSR', 'status': 400}}, self.order.parse(message))

    @patch('acme.order.Order.process_csr')
    @patch('acme.order.Order.name_get')
    @patch('acme.message.Message.check')
    def test_165_order_parse(self, mock_mcheck, mock_oname, mock_csr):
        """ Order.parse() finalized failed bcs. enrollment failure """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"csr" : "csr_payload"}, 'account_name')
        mock_oname.return_value = 'order_name'
        mock_csr.return_value = (400, 'cert_name', 'detail')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'enrollment failed', 'message': 'urn:ietf:params:acme:error:badCSR', 'status': 400}}, self.order.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order.update')
    @patch('acme.order.Order.process_csr')
    @patch('acme.order.Order.name_get')
    @patch('acme.message.Message.check')
    def test_166_order_parse(self, mock_mcheck, mock_oname, mock_csr, mock_update, mock_nnonce):
        """ Order.parse() finalized sucessful """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url/finalize'}, {"csr" : "csr_payload"}, 'account_name')
        mock_oname.return_value = 'order_name'
        mock_csr.return_value = (200, 'cert_name', 'detail')
        mock_update.return_value = True
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        e_result = {'header': {'Location': 'http://tester.local/acme/order/order_name', 'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'authorizations': [], 'certificate': 'http://tester.local/acme/cert/cert_name', 'finalize': 'http://tester.local/acme/order/order_name/finalize'}}
        self.assertEqual(e_result, self.order.parse(message))

    @patch('acme.order.Order.name_get')
    @patch('acme.message.Message.check')
    def test_167_order_parse(self, mock_mcheck, mock_oname):
        """ Order.parse() polling failed bcs. certificate not found """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'order_name'
        message = '{"foo" : "bar"}'
        self.order.dbstore.certificate_lookup.return_value = {}
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'no certificate for order: order_name found', 'message': 'urn:ietf:params:acme:error:serverInternal', 'status': 400}}, self.order.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order.name_get')
    @patch('acme.message.Message.check')
    def test_168_order_parse(self, mock_mcheck, mock_oname, mock_nnonce):
        """ Order.parse() polling successful """
        mock_mcheck.return_value = (200, None, None, {'url' : 'bar_url'}, {"foo_payload" : "bar_payload"}, 'account_name')
        mock_oname.return_value = 'order_name'
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.order.dbstore.certificate_lookup.return_value = {'name' : 'cert_name'}
        e_result = {'header': {'Location': 'http://tester.local/acme/order/order_name', 'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'authorizations': [], 'certificate': 'http://tester.local/acme/cert/cert_name', 'finalize': 'http://tester.local/acme/order/order_name/finalize'}}
        self.assertEqual(e_result, self.order.parse(message))

    @patch('acme.message.Message.check')
    def test_169_authorization_post(self, mock_mcheck):
        """ Authorization.new_post() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'message': 'message', 'status': 400}}, self.authorization.new_post(message))

    @patch('acme.authorization.Authorization.authz_info')
    @patch('acme.message.Message.check')
    def test_170_authorization_post(self, mock_mcheck, mock_authzinfo):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', 'account_name')
        mock_authzinfo.return_value = {'authz_foo': 'authz_bar'}
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'url is missing in protected', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.authorization.new_post(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.authorization.Authorization.authz_info')
    @patch('acme.message.Message.check')
    def test_171_authorization_post(self, mock_mcheck, mock_authzinfo, mock_nnonce):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, {'url' : 'foo_url'}, 'payload', 'account_name')
        mock_authzinfo.return_value = {'authz_foo': 'authz_bar'}
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'authz_foo': 'authz_bar'}}, self.authorization.new_post(message))

    def test_172_cert_serial_get(self):
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

    def test_173_cert_san_get(self):
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

    def test_174_cert_san_get(self):
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

    def test_175_cert_serial_get(self):
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

    def test_176_revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with allowed reason"""
        rev_reason = 0
        self.assertEqual('unspecified', self.certificate.revocation_reason_check(rev_reason))

    def test_177_revocation_reason_check(self):
        """ test Certificate.revocation_reason_check with non-allowed reason"""
        rev_reason = 8
        self.assertFalse(self.certificate.revocation_reason_check(rev_reason))

    @patch('acme.certificate.cert_san_get')
    def test_178_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans but failed order lookup"""
        self.account.dbstore.order_lookup.return_value = {}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_179_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order returning wrong values (no 'identifiers' key) """
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_180_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with some sans and order lookup returning identifiers without json structure) """
        self.account.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_181_authorization_check(self, mock_san):
        """ test Certificate.authorization_check  with wrong sans) """
        self.account.dbstore.order_lookup.return_value = {'identifiers' : 'test'}
        mock_san.return_value = ['san1.example.com', 'san2.example.com']
        self.assertFalse(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_182_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with SAN entry which is not in the identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertFalse(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_183_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with single SAN entry and correct entry in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_184_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with multiple SAN entries and correct entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com', 'DNS:san2.example.com']
        self.assertTrue(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_185_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with one SAN entry and multiple entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:san1.example.com']
        self.assertTrue(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_186_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with uppercase SAN entries and lowercase entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "dns", "value": "san1.example.com"}, {"type": "dns", "value": "san2.example.com"}]'}
        mock_san.return_value = ['DNS:SAN1.EXAMPLE.COM', 'DNS:SAN2.EXAMPLE.COM']
        self.assertTrue(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_187_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lowercase SAN entries and uppercase entries in identifier list"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"TYPE": "DNS", "VALUE": "SAN1.EXAMPLE.COM"}, {"TYPE": "DNS", "VALUE": "SAN2.EXAMPLE.COM"}]'}
        mock_san.return_value = ['dns:san1.example.com', 'dns:san2.example.com']
        self.assertTrue(self.certificate.authorization_check('order_name', 'cert'))

    @patch('acme.certificate.cert_san_get')
    def test_188_authorization_check(self, mock_san):
        """ test Certificate.authorization_check with lSAN entries (return none) and entries in identifier containing None"""
        self.account.dbstore.order_lookup.return_value = {'identifiers' : '[{"type": "None", "value": "None"}]'}
        mock_san.return_value = ['san1.example.com']
        self.assertFalse(self.certificate.authorization_check('order_name', 'cert'))

    def test_189_revocation_request_validate(self):
        """ test Certificate.revocation_request_validate empty payload"""
        payload = {}
        self.assertEqual((400, 'unspecified'), self.certificate.revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate.revocation_reason_check')
    def test_190_revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns None"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:badRevocationReason'), self.certificate.revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate.revocation_reason_check')
    def test_191_revocation_request_validate(self, mock_revrcheck):
        """ test Certificate.revocation_request_validate reason_check returns a reason"""
        payload = {'reason' : 0}
        mock_revrcheck.return_value = 'revrcheck'
        self.assertEqual((400, 'revrcheck'), self.certificate.revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate.authorization_check')
    @patch('acme.certificate.Certificate.account_check')
    @patch('acme.certificate.Certificate.revocation_reason_check')
    def test_192_revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check failed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = False
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized'), self.certificate.revocation_request_validate('account_name', payload))

    @patch('acme.certificate.Certificate.authorization_check')
    @patch('acme.certificate.Certificate.account_check')
    @patch('acme.certificate.Certificate.revocation_reason_check')
    def test_193_revocation_request_validate(self, mock_revrcheck, mock_account, mock_authz):
        """ test Certificate.revocation_request_validate authz_check succeed"""
        payload = {'reason' : 0, 'certificate': 'certificate'}
        mock_revrcheck.return_value = 'revrcheck'
        mock_account.return_value = 'account_name'
        mock_authz.return_value = True
        self.assertEqual((200, 'revrcheck'), self.certificate.revocation_request_validate('account_name', payload))

    @patch('acme.message.Message.check')
    def test_194_revoke(self, mock_mcheck):
        """ test Certificate.revoke with failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'message', 'detail': 'detail'}}, self.certificate.revoke('content'))

    @patch('acme.message.Message.check')
    def test_195_revoke(self, mock_mcheck):
        """ test Certificate.revoke with incorrect payload """
        mock_mcheck.return_value = (200, 'message', 'detail', None, {}, 'account_name')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'certificate not found'}}, self.certificate.revoke('content'))

    @patch('acme.certificate.Certificate.revocation_request_validate')
    @patch('acme.message.Message.check')
    def test_196_revoke(self, mock_mcheck, mock_validate):
        """ test Certificate.revoke with failed request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (400, 'error')
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'error', 'detail': None}}, self.certificate.revoke('content'))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.ca_handler.CAhandler.revoke')
    @patch('acme.certificate.Certificate.revocation_request_validate')
    @patch('acme.message.Message.check')
    def test_197_revoke(self, mock_mcheck, mock_validate, mock_ca_handler, mock_nnonce):
        """ test Certificate.revoke with sucessful request validation """
        mock_mcheck.return_value = (200, None, None, None, {'certificate' : 'certificate'}, 'account_name')
        mock_validate.return_value = (200, 'reason')
        mock_ca_handler.return_value = (200, 'message', 'detail')
        mock_nnonce.return_value = 'new_nonce'
        self.assertEqual({'code': 200, 'header': {'Replay-Nonce': 'new_nonce'}}, self.certificate.revoke('content'))

    def test_198_name_get(self):
        """ test Message.name_get() with empty content"""
        protected = {}
        self.assertFalse(self.message.name_get(protected))

    def test_199_name_get(self):
        """ test Message.name_get() with kid with nonsens in content"""
        protected = {'kid' : 'foo'}
        self.assertEqual('foo', self.message.name_get(protected))

    def test_200_name_get(self):
        """ test Message.name_get() with wrong kid in content"""
        protected = {'kid' : 'http://tester.local/acme/account/account_name'}
        self.assertEqual(None, self.message.name_get(protected))

    def test_201_name_get(self):
        """ test Message.name_get() with correct kid in content"""
        protected = {'kid' : 'http://tester.local/acme/acct/account_name'}
        self.assertEqual('account_name', self.message.name_get(protected))

    def test_202_name_get(self):
        """ test Message.name_get() with 'jwk' in content but without URL"""
        protected = {'jwk' : 'jwk'}
        self.assertEqual(None, self.message.name_get(protected))

    def test_203_name_get(self):
        """ test Message.name_get() with 'jwk' and 'url' in content but url is wrong"""
        protected = {'jwk' : 'jwk', 'url' : 'url'}
        self.assertEqual(None, self.message.name_get(protected))

    def test_204_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' in content but no 'n' in jwk """
        protected = {'jwk' : 'jwk', 'url' : 'http://tester.local/acme/revokecert'}
        self.assertEqual(None, self.message.name_get(protected))

    def test_205_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' but account lookup failed """
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {}
        self.assertEqual(None, self.message.name_get(protected))

    def test_206_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'bar' : 'foo'}
        self.assertEqual(None, self.message.name_get(protected))

    def test_207_name_get(self):
        """ test Message.name_get() with 'jwk' and correct 'url' and wrong account lookup data"""
        protected = {'jwk' : {'n' : 'n'}, 'url' : 'http://tester.local/acme/revokecert'}
        self.message.dbstore.account_lookup.return_value = {'name' : 'foo'}
        self.assertEqual('foo', self.message.name_get(protected))

    def test_208_revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with a valid revocation reason"""
        self.assertEqual('unspecified', self.certificate.revocation_reason_check(0))

    def test_209_revocation_reason_check(self):
        """ test Certicate.revocation_reason_check() with an invalid revocation reason"""
        self.assertFalse(self.certificate.revocation_reason_check(2))

    def test_210_build_pem_file(self):
        """ test build_pem_file without exsting content """
        existing = None
        cert = 'cert'
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_211_build_pem_file(self):
        """ test build_pem_file with exsting content """
        existing = 'existing'
        cert = 'cert'
        self.assertEqual('existing-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_212_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_213_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, False))

    @patch('acme.challenge.url_get')
    def test_214_validate_http_challenge(self, mock_url):
        """ test Chalölenge.validate_http_challenge() with a wrong challenge """
        mock_url.return_value = 'foo'
        self.assertFalse(self.challenge.validate_http_challenge('fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.url_get')
    def test_215_validate_http_challenge(self, mock_url):
        """ test Chalölenge.validate_http_challenge() with a correct challenge """
        mock_url.return_value = 'token.jwk_thumbprint'
        self.assertTrue(self.challenge.validate_http_challenge('fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.url_get')
    def test_216_validate_http_challenge(self, mock_url):
        """ test Chalölenge.validate_http_challenge() without response """
        mock_url.return_value = None
        self.assertFalse(self.challenge.validate_http_challenge('fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_217_validate_dns_challenge(self, mock_dns, mock_code, mock_hash):
        """ test Chalölenge.validate_dns_challenge() with incorrect response """
        mock_dns.return_value = 'foo'
        mock_code.return_value = 'bar'
        mock_hash.return_value = 'hash'
        self.assertFalse(self.challenge.validate_dns_challenge('fqdn', 'token', 'jwk_thumbprint'))

    @patch('acme.challenge.sha256_hash')
    @patch('acme.challenge.b64_url_encode')
    @patch('acme.challenge.txt_get')
    def test_218_validate_dns_challenge(self, mock_dns, mock_code, mock_hash):
        """ test Chalölenge.validate_dns_challenge() with correct response """
        mock_dns.return_value = 'foo'
        mock_code.return_value = 'foo'
        mock_hash.return_value = 'hash'
        self.assertTrue(self.challenge.validate_dns_challenge('fqdn', 'token', 'jwk_thumbprint'))

    def test_219_validate_tkauth_challenge(self):
        """ test Chalölenge.validate_tkauth_challenge() """
        self.assertTrue(self.challenge.validate_tkauth_challenge('fqdn', 'token', 'jwk_thumbprint', 'payload'))

    def test_220_challenge_check(self):
        """ challenge check with incorrect challenge-dictionary """
        # self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.challenge.dbstore.challenge_lookup.return_value = {}
        self.assertFalse(self.challenge.check('name', 'payload'))

    def test_221_challenge_check(self):
        """ challenge check with without jwk return """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'type', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = None
        self.assertFalse(self.challenge.check('name', 'payload'))

    @patch('acme.challenge.Challenge.validate_http_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_222_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = False
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertFalse(self.challenge.check('name', 'payload'))

    @patch('acme.challenge.Challenge.validate_http_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_223_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'http-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = True
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue(self.challenge.check('name', 'payload'))

    @patch('acme.challenge.Challenge.validate_dns_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_224_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed dns challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = False
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertFalse(self.challenge.check('name', 'payload'))

    @patch('acme.challenge.Challenge.validate_dns_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_225_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ http challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'dns-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = True
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue(self.challenge.check('name', 'payload'))

    @patch('acme.challenge.Challenge.validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_226_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with failed tkauth challenge """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        mock_chall.return_value = False
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertFalse(self.challenge.check('name', 'payload'))

    @patch('acme.challenge.Challenge.validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_227_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist_support unset """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = False
        mock_chall.return_value = True
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertFalse(self.challenge.check('name', 'payload'))

    @patch('acme.challenge.Challenge.validate_tkauth_challenge')
    @patch('acme.challenge.jwk_thumbprint_get')
    def test_228_challenge_check(self, mock_jwk, mock_chall):
        """ challenge check with with succ tkauth challenge and tnauthlist support set """
        self.challenge.dbstore.challenge_lookup.return_value = {'authorization__value' : 'authorization__value', 'type' : 'tkauth-01', 'token' : 'token', 'authorization__order__account__name' : 'authorization__order__account__name'}
        self.challenge.dbstore.jwk_load.return_value = 'pub_key'
        self.challenge.tnauthlist_support = True
        mock_chall.return_value = True
        mock_jwk.return_value = 'jwk_thumbprint'
        self.assertTrue(self.challenge.check('name', 'payload'))

    def test_229_order_identifier_check(self):
        """ order identifers check with empty identifer list"""
        self.assertEqual('urn:ietf:params:acme:error:malformed', self.order.identifiers_check([]))

    def test_230_order_identifier_check(self):
        """ order identifers check with wrong identifer in list"""
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order.identifiers_check([{'type': 'foo', 'value': 'value'}]))

    def test_231_order_identifier_check(self):
        """ order identifers check with correct identifer in list"""
        self.assertEqual(None, self.order.identifiers_check([{'type': 'dns', 'value': 'value'}]))

    def test_232_order_identifier_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order.identifiers_check([{'type': 'dns', 'value': 'value'}, {'type': 'foo', 'value': 'value'}]))

    def test_233_order_identifier_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order.identifiers_check([{'type': 'foo', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_234_order_identifier_check(self):
        """ order identifers check with two identifers in list (one wrong) """
        self.assertEqual(None, self.order.identifiers_check([{'type': 'dns', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_235_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier and support false """
        self.order.tnauthlist_support = False
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order.identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_236_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier and support True """
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order.identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'dns', 'value': 'value'}]))

    def test_237_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier and support True """
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order.identifiers_check([{'type': 'TNAuthList', 'value': 'value'}]))

    def test_238_order_identifier_check(self):
        """ order identifers check with tnauthlist identifier a wrong identifer and support True """
        self.order.tnauthlist_support = True
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order.identifiers_check([{'type': 'TNAuthList', 'value': 'value'}, {'type': 'type', 'value': 'value'}]))

    def test_239_order_identifier_check(self):
        """ order identifers check with wrong identifer in list and tnauthsupport true"""
        self.order.tnauthlist_support = True
        self.assertEqual('urn:ietf:params:acme:error:unsupportedIdentifier', self.order.identifiers_check([{'type': 'foo', 'value': 'value'}]))

    def test_240_order_identifier_check(self):
        """ order identifers check with correct identifer in list and tnauthsupport true"""
        self.order.tnauthlist_support = True
        self.assertEqual(None, self.order.identifiers_check([{'type': 'dns', 'value': 'value'}]))

if __name__ == '__main__':
    unittest.main()
