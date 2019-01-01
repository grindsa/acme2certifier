#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
import unittest
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
        models_mock.acme.cgi_handler.DBstore.return_value = FakeDBStore
        modules = {'acme.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        from acme.account import Account
        from acme.authorization import Authorization
        from acme.certificate import Certificate
        from acme.challenge import Challenge
        from acme.directory import Directory
        from acme.nonce import Nonce
        from acme.error import Error
        from acme.order import Order
        from acme.signature import Signature
        from acme.helper import b64decode_pad, b64_url_recode, decode_message, decode_deserialize, generate_random_string, signature_check, validate_email, uts_to_date_utc, date_to_uts_utc, load_config
        self.directory = Directory(False, 'http://tester.local')
        self.account = Account(False, 'http://tester.local')
        self.authorization = Authorization(False, 'http://tester.local')
        self.challenge = Challenge(False, 'http://tester.local')
        self.certificate = Certificate(False, 'http://tester.local')
        self.nonce = Nonce(False)
        self.error = Error(False)
        self.order = Order(False, 'http://tester.local')
        self.signature = Signature(False)
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
        self.assertEqual('', self.error.acme_errormessage('urn:ietf:params:acme:error:userActionRequired'))

    def test_013_err_malformed(self):
        """ test badnonce error message """
        self.assertEqual('', self.error.acme_errormessage('urn:ietf:params:acme:error:malformed'))

    def test_014_b64decode_pad_correct(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-correctly-padded', self.b64decode_pad(False, 'dGhpcy1pcy1mb28tY29ycmVjdGx5LXBhZGRlZA=='))

    def test_015_b64decode_pad_missing(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-with-incorrect-padding', self.b64decode_pad(False, 'dGhpcy1pcy1mb28td2l0aC1pbmNvcnJlY3QtcGFkZGluZw'))

    def test_016_b64decode_failed(self):
        """ test b64 decoding failure """
        self.assertEqual('ERR: b64 decoding error', self.b64decode_pad(False, 'b'))

    def test_017_decode_dser_succ(self):
        """ test successful deserialization of a b64 encoded string """
        self.assertEqual({u'a': u'b', u'c': u'd'}, self.decode_deserialize(False, 'eyJhIiA6ICJiIiwgImMiIDogImQifQ=='))

    def test_018_decode_dser_failed(self):
        """ test failed deserialization of a b64 encoded string """
        self.assertEqual('ERR: Json decoding error', self.decode_deserialize(False, 'Zm9vLXdoaWNoLWNhbm5vdC1iZS1qc29uaXplZA=='))

    def test_019_validate_email_0(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(False, 'foo@example.com'))

    def test_020_validate_email_1(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(False, 'mailto:foo@example.com'))

    def test_021_validate_email_2(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(False, 'mailto: foo@example.com'))

    def test_022_validate_email_3(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(False, ['mailto: foo@example.com', 'mailto: bar@example.com']))

    def test_023_validate_wrong_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(False, 'example.com'))

    def test_024_validate_wrong_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(False, 'me@exam,ple.com'))

    def test_025_validate_wrong_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(False, ['mailto: foo@exa,mple.com', 'mailto: bar@example.com']))

    def test_026_validate_wrong_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(False, ['mailto: foo@example.com', 'mailto: bar@exa,mple.com']))

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
        self.assertEqual((True, None), self.signature_check(False, message, mkey))

    def test_046_validate_sig_fail(self):
        """ failed validatio of singature  wrong key"""
        mkey = {
            'alg' : 'rs256',
            'e' : 'AQAB',
            'kty' : 'RSA',
            'n' : 'zncgRHCp22-29g9FO4Hn02iyS1Fo4Y1tB-6cucH1yKSxM6bowjAaVa4HkAnIxgF6Zj9qLROgQR84YjMPeNkq8woBRz1aziDiTIOc0D2aXvLgZbuFGesvxoSGd6uyxjyyV7ONwZEpB8QtDW0I3shlhosKB3Ni1NFu55bPUP9RvxUdPzRRuhxUMHc1CXre1KR0eQmQdNZT6tgQVxpv2lb-iburBADjivBRyrI3k3NmXkYknBggAu8JInaFY4T8pVK0jTwP-f3-0eAV1bg99Rm7uXNXl7SKpQ3oGihwy2OK-XAc59v6C3n4Wq9QpzGkFWsOOlp4zEf13L3_UKugeExEqw',
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((False, 'Verification failed for all signatures["Failed: [InvalidJWSSignature(\'Verification failed {InvalidSignature()}\',)]"]'), self.signature_check(False, message, mkey))

    def test_047_validate_sig_fail(self):
        """ failed validatio of singature  faulty key"""
        mkey = {
            'alg' : 'rs256',
            'e' : 'AQAB',
            'n' : 'zncgRHCp22-29g9FO4Hn02iyS1Fo4Y1tB-6cucH1yKSxM6bowjAaVa4HkAnIxgF6Zj9qLROgQR84YjMPeNkq8woBRz1aziDiTIOc0D2aXvLgZbuFGesvxoSGd6uyxjyyV7ONwZEpB8QtDW0I3shlhosKB3Ni1NFu55bPUP9RvxUdPzRRuhxUMHc1CXre1KR0eQmQdNZT6tgQVxpv2lb-iburBADjivBRyrI3k3NmXkYknBggAu8JInaFY4T8pVK0jTwP-f3-0eAV1bg99Rm7uXNXl7SKpQ3oGihwy2OK-XAc59v6C3n4Wq9QpzGkFWsOOlp4zEf13L3_UKugeExEqw',
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((False, 'Unknown type "None", valid types are: [\'RSA\', \'EC\', \'oct\']'), self.signature_check(False, message, mkey))

    def test_048_validate_sig_fail(self):
        """ failed validatio of singature  no key"""
        mkey = {}
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((False, 'No key specified.'), self.signature_check(False, message, mkey))

    def test_049_jwk_load(self):
        """ test jwk load """
        self.signature.dbstore.jwk_load.return_value = 'foo'
        self.assertEqual('foo', self.signature.jwk_load(1))

    @patch('acme.nonce.Nonce.generate_and_add')
    def test_050_account_new(self, mock_nonce):
        """ failed account add bcs of incomplete json file """
        mock_nonce.return_value = 'foo'
        dic = '{"foo" : "bar"}'
        e_result = {'header': {'Replay-Nonce': 'foo'}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': "Invalid JWS Object [Invalid format] {KeyError('signature',)}"}}
        self.assertEqual(e_result, self.account.new(dic))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.nonce.Nonce.check')
    def test_051_account_new(self, mock_ncheck, mock_nnonce):
        """ failed account add bcs failed nonce check """
        mock_nnonce.return_value = 'foo'
        mock_ncheck.return_value = (400, 'urn:ietf:params:acme:error:badNonce', None)
        message = '{"protected": "eyJub25jZSI6ICI3NzAwZTcwMTExYmY0OThjOTA0YmUyOTgwNGUyMDNiZiIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvbmV3YWNjb3VudCIsICJhbGciOiAiUlMyNTYiLCAiandrIjogeyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIjJDRk1WNE1LNlVvXzJHUVdhMEtWV2x6ZmZnU0RpTHd1cjR1alNaa0NSemJBM3c1cDFBQkpncjdsX1A4NEhwUnY4UjhyR0w2N2hxbURKdVQ1Mm1HRDZmTVZBaEhQWDVwU2R0eVpsUVF1enBYb256Tm1IYkcxRGJNU2lYcnhnNWpXVlhjaEN4SHg4MndBdDlLZjEzTzVBVHhEMFdPQkI1RmZmcHFRSGg4elRmMjlqVEw0dkJkOE41N2NlMTdaZ05XbF9FY29CeWppZ3FORkpjTzBycnZyZjZ4eU5hTzluYnVuNFBBTUpUTGJmVmE2Q2lFcWpuallNWDgwVllMSDRmQ3FzQVpneElvbGlfRDJqOVA1S3E2S1paVUxfYloyUVFWNFV1d1dadmg2dGNBMzkzWVFMZU1BUm5oV0k2ZHFsWlZkY1U3NE5YaTlOaFN4Y01rTThuWlo4USJ9fQ", "payload": "eyJjb250YWN0IjogWyJtYWlsdG86IGpvZXJuLm1ld2VzQGdtYWlsLmNvbSJdLCAidGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlfQ", "signature": "RSAYnxHCJLRmEUixPN4p8yEO359XLckPllGjR4ICcg16JdmNSfjI3fL7SlgbFC-SAQaVVI1texo2kOu8aU128PrzyOoTH_IsbeGKxpc9j2gEqt2gQ2DkWhL57wTFH-nkmE0a10soO06hs_uqQPlH9wEm78InA-nzGRVKzrvw0ggO-ymrOqxkoTvlMDWGGqkiPtN2hO9zphAarIa-gACoqX1nXvyIeRDWm9yxu3Ry1ZAndAjfXA8wLmSIICK3RvwDeKqB6GBPLSCaAzGWwBWBACoPj46M9FKn0ZQchuNiJ3-4jp-OnSPWk6POE-Vzl8krjPVnInmrRpqKDyRKbAvogQ"}'
        e_result = {'code': 400, 'data': {'detail': None, 'message': 'urn:ietf:params:acme:error:badNonce', 'status': 400}, 'header': {'Replay-Nonce': 'foo'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account.tos_check')
    @patch('acme.nonce.Nonce.check')
    def test_052_account_new(self, mock_ncheck, mock_tos, mock_nnonce):
        """ failed account add bcs filed tos check """
        mock_nnonce.return_value = 'foo'
        mock_ncheck.return_value = (200, None, None)
        mock_tos.return_value = (403, 'urn:ietf:params:acme:error:userActionRequired', 'tosfalse')
        message = '{"protected": "eyJub25jZSI6ICI3NzAwZTcwMTExYmY0OThjOTA0YmUyOTgwNGUyMDNiZiIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvbmV3YWNjb3VudCIsICJhbGciOiAiUlMyNTYiLCAiandrIjogeyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIjJDRk1WNE1LNlVvXzJHUVdhMEtWV2x6ZmZnU0RpTHd1cjR1alNaa0NSemJBM3c1cDFBQkpncjdsX1A4NEhwUnY4UjhyR0w2N2hxbURKdVQ1Mm1HRDZmTVZBaEhQWDVwU2R0eVpsUVF1enBYb256Tm1IYkcxRGJNU2lYcnhnNWpXVlhjaEN4SHg4MndBdDlLZjEzTzVBVHhEMFdPQkI1RmZmcHFRSGg4elRmMjlqVEw0dkJkOE41N2NlMTdaZ05XbF9FY29CeWppZ3FORkpjTzBycnZyZjZ4eU5hTzluYnVuNFBBTUpUTGJmVmE2Q2lFcWpuallNWDgwVllMSDRmQ3FzQVpneElvbGlfRDJqOVA1S3E2S1paVUxfYloyUVFWNFV1d1dadmg2dGNBMzkzWVFMZU1BUm5oV0k2ZHFsWlZkY1U3NE5YaTlOaFN4Y01rTThuWlo4USJ9fQ", "payload": "eyJjb250YWN0IjogWyJtYWlsdG86IGpvZXJuLm1ld2VzQGdtYWlsLmNvbSJdLCAidGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlfQ", "signature": "RSAYnxHCJLRmEUixPN4p8yEO359XLckPllGjR4ICcg16JdmNSfjI3fL7SlgbFC-SAQaVVI1texo2kOu8aU128PrzyOoTH_IsbeGKxpc9j2gEqt2gQ2DkWhL57wTFH-nkmE0a10soO06hs_uqQPlH9wEm78InA-nzGRVKzrvw0ggO-ymrOqxkoTvlMDWGGqkiPtN2hO9zphAarIa-gACoqX1nXvyIeRDWm9yxu3Ry1ZAndAjfXA8wLmSIICK3RvwDeKqB6GBPLSCaAzGWwBWBACoPj46M9FKn0ZQchuNiJ3-4jp-OnSPWk6POE-Vzl8krjPVnInmrRpqKDyRKbAvogQ"}'
        e_result = {'code': 403, 'data': {'detail': 'Terms of service must be accepted', 'message': 'urn:ietf:params:acme:error:userActionRequired', 'status': 403}, 'header': {'Replay-Nonce': 'foo'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account.contact_check')
    @patch('acme.account.Account.tos_check')
    @patch('acme.nonce.Nonce.check')
    def test_053_account_new(self, mock_ncheck, mock_tos, mock_contact, mock_nnonce):
        """ failed account add bcs failed contact check """
        mock_nnonce.return_value = 'foo'
        mock_ncheck.return_value = (200, None, None)
        mock_tos.return_value = (200, None, None)
        mock_contact.return_value = (400, 'urn:ietf:params:acme:error:invalidContact', 'no contacts specified')
        message = '{"protected": "eyJub25jZSI6ICI3NzAwZTcwMTExYmY0OThjOTA0YmUyOTgwNGUyMDNiZiIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvbmV3YWNjb3VudCIsICJhbGciOiAiUlMyNTYiLCAiandrIjogeyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIjJDRk1WNE1LNlVvXzJHUVdhMEtWV2x6ZmZnU0RpTHd1cjR1alNaa0NSemJBM3c1cDFBQkpncjdsX1A4NEhwUnY4UjhyR0w2N2hxbURKdVQ1Mm1HRDZmTVZBaEhQWDVwU2R0eVpsUVF1enBYb256Tm1IYkcxRGJNU2lYcnhnNWpXVlhjaEN4SHg4MndBdDlLZjEzTzVBVHhEMFdPQkI1RmZmcHFRSGg4elRmMjlqVEw0dkJkOE41N2NlMTdaZ05XbF9FY29CeWppZ3FORkpjTzBycnZyZjZ4eU5hTzluYnVuNFBBTUpUTGJmVmE2Q2lFcWpuallNWDgwVllMSDRmQ3FzQVpneElvbGlfRDJqOVA1S3E2S1paVUxfYloyUVFWNFV1d1dadmg2dGNBMzkzWVFMZU1BUm5oV0k2ZHFsWlZkY1U3NE5YaTlOaFN4Y01rTThuWlo4USJ9fQ", "payload": "eyJjb250YWN0IjogWyJtYWlsdG86IGpvZXJuLm1ld2VzQGdtYWlsLmNvbSJdLCAidGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlfQ", "signature": "RSAYnxHCJLRmEUixPN4p8yEO359XLckPllGjR4ICcg16JdmNSfjI3fL7SlgbFC-SAQaVVI1texo2kOu8aU128PrzyOoTH_IsbeGKxpc9j2gEqt2gQ2DkWhL57wTFH-nkmE0a10soO06hs_uqQPlH9wEm78InA-nzGRVKzrvw0ggO-ymrOqxkoTvlMDWGGqkiPtN2hO9zphAarIa-gACoqX1nXvyIeRDWm9yxu3Ry1ZAndAjfXA8wLmSIICK3RvwDeKqB6GBPLSCaAzGWwBWBACoPj46M9FKn0ZQchuNiJ3-4jp-OnSPWk6POE-Vzl8krjPVnInmrRpqKDyRKbAvogQ"}'
        e_result = {'code': 400, 'data': {'detail': 'The provided contact URI was invalid no contacts specified', 'message': 'urn:ietf:params:acme:error:invalidContact', 'status': 400}, 'header': {'Replay-Nonce': 'foo'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account.add')
    @patch('acme.account.Account.contact_check')
    @patch('acme.account.Account.tos_check')
    @patch('acme.nonce.Nonce.check')
    def test_054_account_new(self, mock_ncheck, mock_tos, mock_contact, mock_aad, mock_nnonce):
        """ failed Account.add() bcs of failed add """
        mock_nnonce.return_value = 'foo'
        mock_ncheck.return_value = (200, None, None)
        mock_tos.return_value = (200, None, None)
        mock_aad.return_value = (400, 'urn:ietf:params:acme:error:malformed', 'incomplete JSON Web Key')
        mock_contact.return_value = (200, None, None)
        message = '{"protected": "eyJub25jZSI6ICI3NzAwZTcwMTExYmY0OThjOTA0YmUyOTgwNGUyMDNiZiIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvbmV3YWNjb3VudCIsICJhbGciOiAiUlMyNTYiLCAiandrIjogeyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIjJDRk1WNE1LNlVvXzJHUVdhMEtWV2x6ZmZnU0RpTHd1cjR1alNaa0NSemJBM3c1cDFBQkpncjdsX1A4NEhwUnY4UjhyR0w2N2hxbURKdVQ1Mm1HRDZmTVZBaEhQWDVwU2R0eVpsUVF1enBYb256Tm1IYkcxRGJNU2lYcnhnNWpXVlhjaEN4SHg4MndBdDlLZjEzTzVBVHhEMFdPQkI1RmZmcHFRSGg4elRmMjlqVEw0dkJkOE41N2NlMTdaZ05XbF9FY29CeWppZ3FORkpjTzBycnZyZjZ4eU5hTzluYnVuNFBBTUpUTGJmVmE2Q2lFcWpuallNWDgwVllMSDRmQ3FzQVpneElvbGlfRDJqOVA1S3E2S1paVUxfYloyUVFWNFV1d1dadmg2dGNBMzkzWVFMZU1BUm5oV0k2ZHFsWlZkY1U3NE5YaTlOaFN4Y01rTThuWlo4USJ9fQ", "payload": "eyJjb250YWN0IjogWyJtYWlsdG86IGpvZXJuLm1ld2VzQGdtYWlsLmNvbSJdLCAidGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlfQ", "signature": "RSAYnxHCJLRmEUixPN4p8yEO359XLckPllGjR4ICcg16JdmNSfjI3fL7SlgbFC-SAQaVVI1texo2kOu8aU128PrzyOoTH_IsbeGKxpc9j2gEqt2gQ2DkWhL57wTFH-nkmE0a10soO06hs_uqQPlH9wEm78InA-nzGRVKzrvw0ggO-ymrOqxkoTvlMDWGGqkiPtN2hO9zphAarIa-gACoqX1nXvyIeRDWm9yxu3Ry1ZAndAjfXA8wLmSIICK3RvwDeKqB6GBPLSCaAzGWwBWBACoPj46M9FKn0ZQchuNiJ3-4jp-OnSPWk6POE-Vzl8krjPVnInmrRpqKDyRKbAvogQ"}'
        e_result = {'code': 400, 'data': {'detail': 'incomplete JSON Web Key', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {'Replay-Nonce': 'foo'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account.add')
    @patch('acme.account.Account.contact_check')
    @patch('acme.account.Account.tos_check')
    @patch('acme.nonce.Nonce.check')
    def test_055_account_new(self, mock_ncheck, mock_tos, mock_contact, mock_aad, mock_nnonce):
        """ successful Account.add() of new account"""
        mock_nnonce.return_value = 'foo'
        mock_ncheck.return_value = (200, None, None)
        mock_tos.return_value = (200, None, None)
        mock_aad.return_value = (201, 1, None)
        mock_contact.return_value = (200, None, None)
        message = '{"protected": "eyJub25jZSI6ICI3NzAwZTcwMTExYmY0OThjOTA0YmUyOTgwNGUyMDNiZiIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvbmV3YWNjb3VudCIsICJhbGciOiAiUlMyNTYiLCAiandrIjogeyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIjJDRk1WNE1LNlVvXzJHUVdhMEtWV2x6ZmZnU0RpTHd1cjR1alNaa0NSemJBM3c1cDFBQkpncjdsX1A4NEhwUnY4UjhyR0w2N2hxbURKdVQ1Mm1HRDZmTVZBaEhQWDVwU2R0eVpsUVF1enBYb256Tm1IYkcxRGJNU2lYcnhnNWpXVlhjaEN4SHg4MndBdDlLZjEzTzVBVHhEMFdPQkI1RmZmcHFRSGg4elRmMjlqVEw0dkJkOE41N2NlMTdaZ05XbF9FY29CeWppZ3FORkpjTzBycnZyZjZ4eU5hTzluYnVuNFBBTUpUTGJmVmE2Q2lFcWpuallNWDgwVllMSDRmQ3FzQVpneElvbGlfRDJqOVA1S3E2S1paVUxfYloyUVFWNFV1d1dadmg2dGNBMzkzWVFMZU1BUm5oV0k2ZHFsWlZkY1U3NE5YaTlOaFN4Y01rTThuWlo4USJ9fQ", "payload": "eyJjb250YWN0IjogWyJtYWlsdG86IGpvZXJuLm1ld2VzQGdtYWlsLmNvbSJdLCAidGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlfQ", "signature": "RSAYnxHCJLRmEUixPN4p8yEO359XLckPllGjR4ICcg16JdmNSfjI3fL7SlgbFC-SAQaVVI1texo2kOu8aU128PrzyOoTH_IsbeGKxpc9j2gEqt2gQ2DkWhL57wTFH-nkmE0a10soO06hs_uqQPlH9wEm78InA-nzGRVKzrvw0ggO-ymrOqxkoTvlMDWGGqkiPtN2hO9zphAarIa-gACoqX1nXvyIeRDWm9yxu3Ry1ZAndAjfXA8wLmSIICK3RvwDeKqB6GBPLSCaAzGWwBWBACoPj46M9FKn0ZQchuNiJ3-4jp-OnSPWk6POE-Vzl8krjPVnInmrRpqKDyRKbAvogQ"}'
        e_result = {'code': 201, 'data': {'contact': [u'mailto: joern.mewes@gmail.com'], 'orders': 'http://tester.local/acme/acct/1/orders', 'status': 'valid'}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'foo'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account.add')
    @patch('acme.account.Account.contact_check')
    @patch('acme.account.Account.tos_check')
    @patch('acme.nonce.Nonce.check')
    def test_056_account_new(self, mock_ncheck, mock_tos, mock_contact, mock_aad, mock_nnonce):
        """ successful Account.add() existing account"""
        mock_nnonce.return_value = 'foo'
        mock_ncheck.return_value = (200, None, None)
        mock_tos.return_value = (200, None, None)
        mock_aad.return_value = (200, 1, None)
        mock_contact.return_value = (200, None, None)
        message = '{"protected": "eyJub25jZSI6ICI3NzAwZTcwMTExYmY0OThjOTA0YmUyOTgwNGUyMDNiZiIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvbmV3YWNjb3VudCIsICJhbGciOiAiUlMyNTYiLCAiandrIjogeyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIjJDRk1WNE1LNlVvXzJHUVdhMEtWV2x6ZmZnU0RpTHd1cjR1alNaa0NSemJBM3c1cDFBQkpncjdsX1A4NEhwUnY4UjhyR0w2N2hxbURKdVQ1Mm1HRDZmTVZBaEhQWDVwU2R0eVpsUVF1enBYb256Tm1IYkcxRGJNU2lYcnhnNWpXVlhjaEN4SHg4MndBdDlLZjEzTzVBVHhEMFdPQkI1RmZmcHFRSGg4elRmMjlqVEw0dkJkOE41N2NlMTdaZ05XbF9FY29CeWppZ3FORkpjTzBycnZyZjZ4eU5hTzluYnVuNFBBTUpUTGJmVmE2Q2lFcWpuallNWDgwVllMSDRmQ3FzQVpneElvbGlfRDJqOVA1S3E2S1paVUxfYloyUVFWNFV1d1dadmg2dGNBMzkzWVFMZU1BUm5oV0k2ZHFsWlZkY1U3NE5YaTlOaFN4Y01rTThuWlo4USJ9fQ", "payload": "eyJjb250YWN0IjogWyJtYWlsdG86IGpvZXJuLm1ld2VzQGdtYWlsLmNvbSJdLCAidGVybXNPZlNlcnZpY2VBZ3JlZWQiOiB0cnVlfQ", "signature": "RSAYnxHCJLRmEUixPN4p8yEO359XLckPllGjR4ICcg16JdmNSfjI3fL7SlgbFC-SAQaVVI1texo2kOu8aU128PrzyOoTH_IsbeGKxpc9j2gEqt2gQ2DkWhL57wTFH-nkmE0a10soO06hs_uqQPlH9wEm78InA-nzGRVKzrvw0ggO-ymrOqxkoTvlMDWGGqkiPtN2hO9zphAarIa-gACoqX1nXvyIeRDWm9yxu3Ry1ZAndAjfXA8wLmSIICK3RvwDeKqB6GBPLSCaAzGWwBWBACoPj46M9FKn0ZQchuNiJ3-4jp-OnSPWk6POE-Vzl8krjPVnInmrRpqKDyRKbAvogQ"}'
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/1', 'Replay-Nonce': 'foo'}}
        self.assertEqual(e_result, self.account.new(message))

    def test_057_get_id_failed(self):
        """ test failed get_id bcs of wrong data """
        string = {'foo' : 'bar'}
        self.assertFalse(self.account.name_get(string))

    def test_058_signature_check_failed(self):
        """ test Signature.check() without having a kid """
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check('foo', None))

    @patch('acme.signature.Signature.jwk_load')
    def test_059_signature_check_failed(self, mock_jwk):
        """ test Signature.check() while pubkey lookup failed """
        mock_jwk.return_value = {}
        self.assertEqual((False, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.signature.check('foo', 1))

    @patch('acme.signature.signature_check')
    @patch('acme.signature.Signature.jwk_load')
    def test_060_signature_check_failed(self, mock_jwk, mock_sig):
        """ test successful Signature.check()  """
        mock_jwk.return_value = {'foo' : 'bar'}
        mock_sig.return_value = (True, None)
        self.assertEqual((True, None, None), self.signature.check('foo', 1))

    def test_061_accout_parse(self):
        """ test failed account parse """
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': "Invalid JWS Object [Invalid format] {KeyError('signature',)}"}}, self.account.parse(message))

    @patch('acme.account.decode_message')
    def test_062_accout_parse(self, mock_decode):
        """ test failed account parse without getting an account id """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 403, 'data': {'status': 403, 'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'detail': None}}, self.account.parse(message))

    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.account.decode_message')
    def test_063_accout_parse(self, mock_decode, mock_id, mock_sig):
        """ test failed account parse for request which does not has a "status" field in payload """
        mock_decode.return_value = (True, None, 'protected', 'payload', 'signature')
        mock_id.return_value = 1
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'dont know what to do with this request'}}, self.account.parse(message))

    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.account.decode_message')
    def test_064_accout_parse(self, mock_decode, mock_id, mock_sig):
        """ test failed account parse for reqeust with a "status" field other than "deactivated" """
        mock_decode.return_value = (True, None, 'protected', {'status' : 'foo'}, 'signature')
        mock_id.return_value = 1
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'status attribute without sense'}}, self.account.parse(message))

    @patch('acme.account.Account.delete')
    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.account.decode_message')
    def test_065_accout_parse(self, mock_decode, mock_id, mock_sig, mock_del):
        """ test failed account parse for reqeust with failed deletion """
        mock_decode.return_value = (True, None, 'protected', {'status' : 'deactivated'}, 'signature')
        mock_id.return_value = 1
        mock_sig.return_value = (True, None, None)
        mock_del.return_value = (400, 'urn:ietf:params:acme:error:accountDoesNotExist', 'deletion failed')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'detail': 'deletion failed'}}, self.account.parse(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.account.Account.delete')
    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.account.decode_message')
    def test_066_accout_parse(self, mock_decode, mock_id, mock_sig, mock_del, mock_nnonce):
        """ test succ account parse for reqeust with succ deletion """
        mock_decode.return_value = (True, None, 'protected', {'status' : 'deactivated'}, 'signature')
        mock_id.return_value = 1
        mock_sig.return_value = (True, None, None)
        mock_del.return_value = (200, None, None)
        mock_nnonce.return_value = 'newnonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'status': 'deactivated'}, 'header': {'Replay-Nonce': 'newnonce'}}, self.account.parse(message))

    def test_067_onlyreturnexisting(self):
        """ test onlyReturnExisting with False """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyReturnExisting' : False}
        self.assertEqual((400, 'urn:ietf:params:acme:error:userActionRequired', 'onlyReturnExisting must be true'), self.account.onlyreturnexisting(protected, payload))

    def test_068_onlyreturnexisting(self):
        """ test onlyReturnExisting without jwk structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {}
        payload = {'onlyReturnExisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'jwk structure missing'), self.account.onlyreturnexisting(protected, payload))

    def test_069_onlyreturnexisting(self):
        """ test onlyReturnExisting without jwk[n] structure """
        # self.signature.dbstore.jwk_load.return_value = 1
        protected = {'jwk' : {}}
        payload = {'onlyReturnExisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:malformed', 'n value missing'), self.account.onlyreturnexisting(protected, payload))

    def test_070_onlyreturnexisting(self):
        """ test onlyReturnExisting for existing account """
        self.signature.dbstore.account_lookup.return_value = {'name' : 'foo', 'alg' : 'RS256'}
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyReturnExisting' : True}
        self.assertEqual((200, 'foo', None), self.account.onlyreturnexisting(protected, payload))

    def test_071_onlyreturnexisting(self):
        """ test onlyReturnExisting for non existing account """
        self.signature.dbstore.account_lookup.return_value = False
        protected = {'jwk' : {'n' : 'foo'}}
        payload = {'onlyReturnExisting' : True}
        self.assertEqual((400, 'urn:ietf:params:acme:error:accountDoesNotExist', None), self.account.onlyreturnexisting(protected, payload))

    @patch('acme.account.Account.onlyreturnexisting')
    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.nonce.Nonce.check')
    def test_072_account_new(self, mock_ncheck, mock_nnonce, mock_existing):
        """ test onlyReturnExisting for non existing account """
        mock_nnonce.return_value = 'foo'
        mock_ncheck.return_value = (200, None, None)
        mock_existing.return_value = (400, 'urn:ietf:params:acme:error:accountDoesNotExist', None)
        message = '{"protected": "eyJub25jZSI6ICIxNWVmNTczNGNjNGQ0ZDY4YWQ5ODM2ZjVlMTcwYzJhYyIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvbmV3YWNjb3VudCIsICJhbGciOiAiUlMyNTYiLCAiandrIjogeyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm1aZDcyNGxVWVBySXJsRjBYVnVBV3ByUWZtTm05WEdNZ2djUEN0eThhME1MTXptQ2FQWlFzdTl0aDRWWnBSRXRNY0t3aXJfZEJiRTFRRVZNSHJOREIzUWNFbkZka0RSRTFrZU4zMl9oVGowWDBXX2FadDVDeENzZ3loOURxWllRZENDNVV4NEtCSU1sVzA4MjhWTDdSazduMzU2N2VJeUotMHo2aE5hSk1MX2hvR2hhYklmNm1mZUlRai1uWHUyR2dhZzNuaXV5TFNZdTU0TVlEME9YNVU2OHV5cGptbkJzV3RVWGxYM2lLUjhZNFgtejdXM0tqRDMtYk9pSUNJcTNuYy13T2dobFI1ekJSdVhncEh2N2NoMHJSX21LWDdxYlFSS2RONEY5NE0xY3QzTnBycnQtU1ItZE1aNHR6ZzB6bXVXZl9xMDdHZUJWdERPT1o5Nkx1dyJ9fQ", "payload": "eyJjb250YWN0IjogWyJtYWlsdG86IGpvZXJuLm1ld2VzQGdtYWlsLmNvbSJdLCAib25seVJldHVybkV4aXN0aW5nIjogdHJ1ZX0", "signature": "Y8XHbZLoI3bDNa9YmHc2WINSonZmBdLCpOCFrWyClWCUD5BFbAUpo12zgzEmf4kBYNN0L8AV2NM5QwG59zC8nN5mmuPy9b3DX12J0q6n9UF4PM6Wl1WWGTAZ-lmS-G27_MHHSnTrt7kGlq-PGf4eRPjYCmIyCK8Jl-3TOht61kyGB4IP_Z3fF95oDAE57POora6zl5OYTHoL5RAl0Oic3i8UAiFDMbKa0N8o4Gc6l3y-uT-JxYTLzAHMOaPOXetrX5RUx-4Qpc1IZQ4BiLzNvEA-0vHQ9-NoCARyj2kufG7UqGi_eRQ8y6SGPZMzljO9yMJDTtfLug80Zb4GUJrEFA"}'
        e_result = {'code': 400, 'data': {'detail': None, 'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'status': 400}, 'header': {'Replay-Nonce': 'foo'}}
        self.assertEqual(e_result, self.account.new(message))

    @patch('acme.account.Account.onlyreturnexisting')
    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.nonce.Nonce.check')
    def test_073_account_new(self, mock_ncheck, mock_nnonce, mock_existing):
        """ test onlyReturnExisting for an existing account """
        mock_nnonce.return_value = 'foo'
        mock_ncheck.return_value = (200, None, None)
        mock_existing.return_value = (200, 100, None)
        message = '{"protected": "eyJub25jZSI6ICIxNWVmNTczNGNjNGQ0ZDY4YWQ5ODM2ZjVlMTcwYzJhYyIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvbmV3YWNjb3VudCIsICJhbGciOiAiUlMyNTYiLCAiandrIjogeyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm1aZDcyNGxVWVBySXJsRjBYVnVBV3ByUWZtTm05WEdNZ2djUEN0eThhME1MTXptQ2FQWlFzdTl0aDRWWnBSRXRNY0t3aXJfZEJiRTFRRVZNSHJOREIzUWNFbkZka0RSRTFrZU4zMl9oVGowWDBXX2FadDVDeENzZ3loOURxWllRZENDNVV4NEtCSU1sVzA4MjhWTDdSazduMzU2N2VJeUotMHo2aE5hSk1MX2hvR2hhYklmNm1mZUlRai1uWHUyR2dhZzNuaXV5TFNZdTU0TVlEME9YNVU2OHV5cGptbkJzV3RVWGxYM2lLUjhZNFgtejdXM0tqRDMtYk9pSUNJcTNuYy13T2dobFI1ekJSdVhncEh2N2NoMHJSX21LWDdxYlFSS2RONEY5NE0xY3QzTnBycnQtU1ItZE1aNHR6ZzB6bXVXZl9xMDdHZUJWdERPT1o5Nkx1dyJ9fQ", "payload": "eyJjb250YWN0IjogWyJtYWlsdG86IGpvZXJuLm1ld2VzQGdtYWlsLmNvbSJdLCAib25seVJldHVybkV4aXN0aW5nIjogdHJ1ZX0", "signature": "Y8XHbZLoI3bDNa9YmHc2WINSonZmBdLCpOCFrWyClWCUD5BFbAUpo12zgzEmf4kBYNN0L8AV2NM5QwG59zC8nN5mmuPy9b3DX12J0q6n9UF4PM6Wl1WWGTAZ-lmS-G27_MHHSnTrt7kGlq-PGf4eRPjYCmIyCK8Jl-3TOht61kyGB4IP_Z3fF95oDAE57POora6zl5OYTHoL5RAl0Oic3i8UAiFDMbKa0N8o4Gc6l3y-uT-JxYTLzAHMOaPOXetrX5RUx-4Qpc1IZQ4BiLzNvEA-0vHQ9-NoCARyj2kufG7UqGi_eRQ8y6SGPZMzljO9yMJDTtfLug80Zb4GUJrEFA"}'
        e_result = {'code': 200, 'data': {}, 'header': {'Location': 'http://tester.local/acme/acct/100', 'Replay-Nonce': 'foo'}}
        self.assertEqual(e_result, self.account.new(message))

    def test_074_utstodate_utc(self):
        """ test uts_to_date_utc for a given format """
        self.assertEqual('2018-12-01', self.uts_to_date_utc(1543640400, '%Y-%m-%d'))

    def test_075_utstodate_utc(self):
        """ test uts_to_date_utc without format """
        self.assertEqual('2018-12-01T05:00:00Z', self.uts_to_date_utc(1543640400))

    def test_076_utstodate_utc(self):
        """ test date_to_uts_utc for a given format """
        self.assertEqual(1543622400, self.date_to_uts_utc('2018-12-01', '%Y-%m-%d'))

    def test_077_utstodate_utc(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(1543640400, self.date_to_uts_utc('2018-12-01T05:00:00'))

    def test_078_generaterandomstring(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(5, len(self.generate_random_string(False, 5)))

    def test_079_generaterandomstring(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(15, len(self.generate_random_string(False, 15)))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_080_order_add(self, mock_name, mock_uts):
        """ test Oder.add() without identifier in payload """
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        message = {}
        e_result = ('urn:ietf:params:acme:error:unsupportedIdentifier', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order.add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_081_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with empty identifier in payload dbstore-add returns None"""
        mock_name.return_value = 'aaaaa'
        mock_uts.return_value = 1543640400
        self.signature.dbstore.order_add.return_value = False
        message = {'identifiers' : {}}
        e_result = ('urn:ietf:params:acme:error:malformed', 'aaaaa', {}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order.add(message, 1))

    @patch('acme.order.uts_now')
    @patch('acme.order.generate_random_string')
    def test_082_order_add(self, mock_name, mock_uts):
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
    def test_083_order_add(self, mock_name, mock_uts):
        """ test Oder.add() with multiple identifier in payload dbstore-add returns something real"""
        mock_name.side_effect = ['order', 'identifier1', 'identifier2']
        mock_uts.return_value = 1543640400
        self.order.dbstore.order_add.return_value = 1
        self.order.dbstore.authorization_add.return_value = True
        message = {'identifiers' : [{"type": "dns", "value": "example1.com"}, {"type": "dns", "value": "example2.com"}]}
        e_result = (None, 'order', {'identifier1': {'type': 'dns', 'value': 'example1.com'}, 'identifier2': {'type': 'dns', 'value': 'example2.com'}}, '2018-12-02T05:00:00Z')
        self.assertEqual(e_result, self.order.add(message, 1))

    @patch('acme.order.decode_message')
    def test_084_order_new(self, mock_decode):
        """ test failed order new without getting an account id """
        mock_decode.return_value = (None, 'detail', 'protected', 'payload', 'sig')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'detail'}}, self.order.new(message))

    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.order.decode_message')
    def test_085_order_new(self, mock_decode, mock_ncheck, mock_id, mock_sig):
        """ test failed order new bcs of nonce check failed """
        mock_decode.return_value = (True, 'detail', 'protected', 'payload', 'sig')
        mock_ncheck.return_value = (400, 'urn:ietf:params:acme:error:badNonce', None)
        mock_id.return_value = 1
        mock_sig.return_value = (True, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:badNonce', 'detail': None}}, self.order.new(message))

    @patch('acme.error.Error.enrich_error')
    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.order.decode_message')
    def test_086_order_new(self, mock_decode, mock_ncheck, mock_id, mock_sig, mock_err):
        """ test failed order new bcs of sig check failed """
        mock_decode.return_value = (True, 'detail', 'protected', 'payload', 'sig')
        mock_ncheck.return_value = (200, None, None)
        mock_err.return_value = 'detail'
        mock_id.return_value = 1
        mock_sig.return_value = (False, 'message', 'detail')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 403, 'data': {'status': 403, 'message': 'message', 'detail': 'detail'}}, self.order.new(message))

    @patch('acme.order.Order.add')
    @patch('acme.error.Error.enrich_error')
    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.order.decode_message')
    def test_087_order_new(self, mock_decode, mock_ncheck, mock_id, mock_sig, mock_err, mock_orderadd):
        """ test failed order new bcs of db_add failed """
        mock_decode.return_value = (True, 'detail', 'protected', 'payload', 'sig')
        mock_ncheck.return_value = (200, None, None)
        mock_sig.return_value = (True, None, None)
        mock_err.return_value = 'detail'
        mock_orderadd.return_value = ('urn:ietf:params:acme:error:malformed', None, None, None)
        mock_id.return_value = 1
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'status': 400, 'message': 'urn:ietf:params:acme:error:malformed', 'detail': 'detail'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order.add')
    @patch('acme.error.Error.enrich_error')
    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.order.decode_message')
    def test_088_order_new(self, mock_decode, mock_ncheck, mock_id, mock_sig, mock_err, mock_orderadd, mock_nnonce):
        """ test successful order with a single identifier """
        mock_decode.return_value = (True, 'detail', 'protected', 'payload', 'sig')
        mock_ncheck.return_value = (200, None, None)
        mock_sig.return_value = (True, None, None)
        mock_err.return_value = 'detail'
        mock_nnonce.return_value = 'newnonce'
        mock_orderadd.return_value = (None, 'foo_order', {'foo_auth': {u'type': u'dns', u'value': u'acme.nclm-samba.local'}}, 'expires')
        mock_id.return_value = 1
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'newnonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{u'type': u'dns', u'value': u'acme.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order.add')
    @patch('acme.error.Error.enrich_error')
    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.order.decode_message')
    def test_089_order_new(self, mock_decode, mock_ncheck, mock_id, mock_sig, mock_err, mock_orderadd, mock_nnonce):
        """ test successful order with multiple identifiers """
        mock_decode.return_value = (True, 'detail', 'protected', 'payload', 'sig')
        mock_ncheck.return_value = (200, None, None)
        mock_sig.return_value = (True, None, None)
        mock_err.return_value = 'detail'
        mock_nnonce.return_value = 'newnonce'
        mock_orderadd.return_value = (None, 'foo_order', {'foo_auth1': {u'type': u'dns', u'value': u'acme1.nclm-samba.local'}, 'foo_auth2': {u'type': u'dns', u'value': u'acme2.nclm-samba.local'}}, 'expires')
        mock_id.return_value = 1
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'newnonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [{u'type': u'dns', u'value': u'acme2.nclm-samba.local'}, {u'type': u'dns', u'value': u'acme1.nclm-samba.local'}], 'authorizations': ['http://tester.local/acme/authz/foo_auth2', 'http://tester.local/acme/authz/foo_auth1'], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.order.Order.add')
    @patch('acme.error.Error.enrich_error')
    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.order.decode_message')
    def test_090_order_new(self, mock_decode, mock_ncheck, mock_id, mock_sig, mock_err, mock_orderadd, mock_nnonce):
        """ test successful order without identifiers """
        mock_decode.return_value = (True, 'detail', 'protected', 'payload', 'sig')
        mock_ncheck.return_value = (200, None, None)
        mock_sig.return_value = (True, None, None)
        mock_err.return_value = 'detail'
        mock_nnonce.return_value = 'newnonce'
        mock_orderadd.return_value = (None, 'foo_order', {}, 'expires')
        mock_id.return_value = 1
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Location': 'http://tester.local/acme/order/foo_order', 'Replay-Nonce': 'newnonce'}, 'code': 201, 'data': {'status': 'pending', 'identifiers': [], 'authorizations': [], 'finalize': 'http://tester.local/acme/order/foo_order/finalize', 'expires': 'expires'}}, self.order.new(message))

    @patch('acme.challenge.generate_random_string')
    def test_091_challenge_new(self, mock_random):
        """ test challenge generation """
        mock_random.return_value = 'foo'
        self.order.dbstore.challenge_new.return_value = 1
        self.assertEqual({'url': 'http://tester.local/acme/chall/foo', 'token': 'token', 'type': 'mtype'}, self.challenge.new('authz_name', 'mtype', 'token'))

    @patch('acme.challenge.Challenge.new')
    def test_092_challenge_new_set(self, mock_challenge):
        """ test generation of a challenge set """
        mock_challenge.return_value = {'foo' : 'bar'}
        self.assertEqual([{'foo': 'bar'}, {'foo': 'bar'}], self.challenge.new_set('authz_name', 'token'))

    @patch('acme.challenge.Challenge.new_set')
    @patch('acme.authorization.uts_now')
    @patch('acme.authorization.generate_random_string')
    def test_093_authorization_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = [{'identifier_key' : 'identifier_value'}]
        self.assertEqual({'status': 'pending', 'expires': '2018-12-02T05:00:00Z', 'identifier': {'identifier_key': 'identifier_value'}, 'challenges': [{'key2': 'value2', 'key1': 'value1'}]}, self.authorization.authz_info('http://tester.local/acme/authz/foo'))

    def test_094_challenge_info(self):
        """ test challenge.info() """
        self.challenge.dbstore.challenge_lookup.return_value = {'token' : 'token', 'type' : 'http-01', 'status' : 'pending'}
        self.assertEqual({'status': 'pending', 'token': 'token', 'type': 'http-01'}, self.challenge.info('foo'))

    @patch('acme.challenge.decode_message')
    def test_095_challenge_parse(self, mock_decode):
        """ test challenge.parse() - failed message decoding """
        mock_decode.return_value = (False, 'foo', None, None, None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 400, 'data': {'detail': 'foo', 'message': 'urn:ietf:params:acme:error:malformed', 'status': 400}, 'header': {}}, self.challenge.parse('url', message))

    @patch('acme.nonce.Nonce.check')
    @patch('acme.challenge.decode_message')
    def test_096_challenge_parse(self, mock_decode, mock_ncheck):
        """ test challenge.parse() - failed nonce check """
        mock_decode.return_value = (True, None, 'protected', {'keyAuthorization' : 'abcdefghijk'}, 'signature')
        mock_ncheck.return_value = (400, 'urn:ietf:params:acme:error:badNonce', None)
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 400, 'data': {'detail': None, 'message': 'urn:ietf:params:acme:error:badNonce', 'status': 400}, 'header': {}}, self.challenge.parse('url', message))

    @patch('acme.account.Account.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.challenge.decode_message')
    def test_097_challenge_parse(self, mock_decode, mock_ncheck, mock_name):
        """ test challenge.parse() - failed account lookup """
        mock_decode.return_value = (True, None, 'protected', {'keyAuthorization' : 'abcdefghijk'}, 'signature')
        mock_ncheck.return_value = (200, None, None)
        mock_name.return_value = None
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 403, 'data': {'detail': None, 'message': 'urn:ietf:params:acme:error:accountDoesNotExist', 'status': 403}, 'header': {}}, self.challenge.parse('url', message))

    @patch('acme.error.Error.enrich_error')
    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.challenge.decode_message')
    def test_098_challenge_parse(self, mock_decode, mock_ncheck, mock_name, mock_sig, mock_err):
        """ test challenge.parse() - failed signature check """
        mock_decode.return_value = (True, None, 'protected', {'keyAuthorization' : 'abcdefghijk'}, 'signature')
        mock_ncheck.return_value = (200, None, None)
        mock_name.return_value = 'aaa'
        mock_sig.return_value = (False, 'message', 'detail')
        mock_err.return_value = 'detail'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 403, 'data': {'status': 403, 'message': 'message', 'detail': 'detail'}, 'header': {}}, self.challenge.parse('url', message))

    @patch('acme.nonce.Nonce.generate_and_add')
    @patch('acme.challenge.Challenge.info')
    @patch('acme.signature.Signature.check')
    @patch('acme.account.Account.name_get')
    @patch('acme.nonce.Nonce.check')
    @patch('acme.challenge.decode_message')
    def test_099_challenge_parse(self, mock_decode, mock_ncheck, mock_name, mock_sig, mock_info, mock_nnonce):
        """ test challenge.parse() - successful """
        mock_decode.return_value = (True, None, 'protected', {'keyAuthorization' : 'abcdefghijk'}, 'signature')
        mock_ncheck.return_value = (200, None, None)
        mock_name.return_value = 'aaa'
        mock_sig.return_value = (True, None, None)
        mock_info.return_value = {'challenge_foo': 'challenge_bar'}
        mock_nnonce.return_value = 'aaaaa'
        message = '{"foo" : "bar"}'
        self.assertEqual({'code': 200, 'data': {'challenge_foo': 'challenge_bar', 'url': 'url'}, 'header': {'Link': '<http://tester.local/acme/authz/>;rel="up"', 'Replay-Nonce': 'aaaaa'}}, self.challenge.parse('url', message))

    @patch('acme.order.Order.info')
    def test_100_order_lookup(self, mock_oinfo):
        """ test order lookup with empty hash """
        mock_oinfo.return_value = {}
        self.assertEqual({}, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_101_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and wrong authorization hash"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': []}, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_102_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and correct authorization hash"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz//name']}, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_103_order_lookup(self, mock_oinfo):
        """ test order lookup with wrong hash and authorization hash having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status_key' : 'status_value'}
        self.assertEqual({'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2']}, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_104_order_lookup(self, mock_oinfo):
        """ test order lookup status in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2']}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_105_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_106_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore (0) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400 , 'notbefore' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_107_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (0) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400 , 'notbefore' : 0, 'notafter' : 0}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z'}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_108_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid) in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400 , 'notbefore' : 1543640400, 'notafter' : 1543640400}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_109_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and authorization dict having multiple entries"""
        self.authorization.dbstore.authorization_lookup.return_value = [{'name' : 'name', 'identifier_key' : 'identifier_value'}, {'name' : 'name2', 'identifier_key' : 'identifier_value2'}]
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400 , 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': ['http://tester.local/acme/authz//name', 'http://tester.local/acme/authz//name2'], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order.lookup('foo'))

    @patch('acme.order.Order.info')
    def test_110_order_lookup(self, mock_oinfo):
        """ test order lookup status, expires, notbefore and notafter (valid), identifier, in dict and worng authorization"""
        self.authorization.dbstore.authorization_lookup.return_value = 'foo'
        mock_oinfo.return_value = {'status' : 'status_value', 'expires' : 1543640400 , 'notbefore' : 1543640400, 'notafter' : 1543640400, 'identifier': '"{"foo" : "bar"}"'}
        e_result = {'status': 'status_value', 'authorizations': [], 'expires': '2018-12-01T05:00:00Z', 'notAfter': '2018-12-01T05:00:00Z', 'notBefore': '2018-12-01T05:00:00Z',}
        self.assertEqual(e_result, self.order.lookup('foo'))

    def test_111_base64_recode(self):
        """ test base64url recode to base64 - add padding for 1 char"""
        self.assertEqual('fafafaf=', self.b64_url_recode(False, 'fafafaf'))

    def test_112_base64_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(False, 'fafafa'))

    def test_113_base64_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(False, 'fafaf'))

    def test_114_base64_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(False, 'fafafafa'))

    def test_115_base64_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(False, 'fafa-f'))

    def test_116_base64_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(False, 'fafa_f'))

    @patch('acme.order.Order.info')
    def test_117_process_csr(self, mock_oinfo):
        """ test order prcoess_csr with empty order_dic """
        mock_oinfo.return_value = {}
        self.assertEqual((400, 'urn:ietf:params:acme:error:unauthorized', 'order: order_name not found'), self.order.process_csr('order_name', 'csr'))

    @patch('acme.order.validate_csr')
    @patch('acme.order.Order.info')
    def test_118_process_csr(self, mock_oinfo, mock_csrchk):
        """ test order prcoess_csr with failed csr check"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_csrchk.return_value = False
        self.assertEqual((403, 'urn:ietf:params:acme:badCSR', 'CSR validation failed'), self.order.process_csr('order_name', 'csr'))

    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.validate_csr')
    @patch('acme.order.Order.info')
    def test_119_process_csr(self, mock_oinfo, mock_csrchk, mock_certname):
        """ test order prcoess_csr with failed csr dbsave"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_csrchk.return_value = True
        mock_certname.return_value = None
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'CSR processing failed'), self.order.process_csr('order_name', 'csr'))

    @patch('acme.certificate.Certificate.enroll_and_store')
    @patch('acme.certificate.Certificate.store_csr')
    @patch('acme.order.validate_csr')
    @patch('acme.order.Order.info')
    def test_120_process_csr(self, mock_oinfo, mock_csrchk, mock_certname, mock_enroll):
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
    def test_121_process_csr(self, mock_oinfo, mock_csrchk, mock_certname, mock_enroll):
        """ test order prcoess_csr with successful cert enrollment"""
        mock_oinfo.return_value = {'foo', 'bar'}
        mock_csrchk.return_value = True
        mock_certname.return_value = 'foo'
        mock_enroll.return_value = ('bar', None)
        self.assertEqual((200, 'foo', None), self.order.process_csr('order_name', 'csr'))

    def test_122_decode_message(self):
        """ decode message with empty payload - certbot issue"""
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        e_result = (True, None, {u'nonce': u'26e6a46efadd477d908d7c2014e49b34', u'url': u'http://laptop.nclm-samba.local/acme/authz/PG189FFzfao1', u'alg': u'RS256', u'kid': u'http://laptop.nclm-samba.local/acme/acct/yuZ1GUJb76Zk'}, None, 'encoded_signature')
        self.assertEqual(e_result, self.decode_message(False, data_dic))


if __name__ == '__main__':
    unittest.main()
