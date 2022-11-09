7#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for account.py """
# pylint: disable=C0302, C0415, R0904, R0913, R0914, R0915, W0212
import unittest
import configparser
import sys
import datetime
import socket
from unittest.mock import patch, MagicMock, Mock
import dns.resolver

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
        from acme_srv.helper import b64decode_pad, b64_decode, b64_encode, b64_url_encode, b64_url_recode, convert_string_to_byte, convert_byte_to_string, decode_message, decode_deserialize, get_url, generate_random_string, signature_check, validate_email, uts_to_date_utc, date_to_uts_utc, load_config, cert_serial_get, cert_san_get, cert_dates_get, build_pem_file, date_to_datestr, datestr_to_date, dkeys_lower, csr_cn_get, cert_pubkey_get, csr_pubkey_get, url_get, url_get_with_own_dns,  dns_server_list_load, csr_san_get, csr_extensions_get, fqdn_resolve, fqdn_in_san_check, sha256_hash, sha256_hash_hex, cert_der2pem, cert_pem2der, cert_extensions_get, csr_dn_get, logger_setup, logger_info, print_debug, jwk_thumbprint_get, allowed_gai_family, patched_create_connection, validate_csr, servercert_get, txt_get, proxystring_convert, proxy_check, handle_exception, ca_handler_load, eab_handler_load, hooks_load, error_dic_get, _logger_nonce_modify, _logger_certificate_modify, _logger_token_modify, _logger_challenges_modify
        self.logger = logging.getLogger('test_a2c')
        self.allowed_gai_family = allowed_gai_family
        self.b64_decode = b64_decode
        self.b64_encode = b64_encode
        self.b64_url_encode = b64_url_encode
        self.b64_url_recode = b64_url_recode
        self.b64decode_pad = b64decode_pad
        self.build_pem_file = build_pem_file
        self.ca_handler_load = ca_handler_load
        self.cert_dates_get = cert_dates_get
        self.cert_extensions_get = cert_extensions_get
        self.cert_pubkey_get = cert_pubkey_get
        self.cert_san_get = cert_san_get
        self.cert_serial_get = cert_serial_get
        self.cert_pem2der = cert_pem2der
        self.cert_der2pem = cert_der2pem
        self.convert_byte_to_string = convert_byte_to_string
        self.convert_string_to_byte = convert_string_to_byte
        self.csr_cn_get = csr_cn_get
        self.csr_dn_get = csr_dn_get
        self.csr_extensions_get = csr_extensions_get
        self.csr_pubkey_get = csr_pubkey_get
        self.csr_san_get = csr_san_get
        self.date_to_datestr = date_to_datestr
        self.date_to_uts_utc = date_to_uts_utc
        self.datestr_to_date = datestr_to_date
        self.decode_deserialize = decode_deserialize
        self.decode_message = decode_message
        self.dkeys_lower = dkeys_lower
        self.dns_server_list_load = dns_server_list_load
        self.eab_handler_load = eab_handler_load
        self.error_dic_get = error_dic_get
        self.fqdn_resolve = fqdn_resolve
        self.fqdn_in_san_check = fqdn_in_san_check
        self.generate_random_string = generate_random_string
        self.get_url = get_url
        self.hooks_load = hooks_load
        self.jwk_thumbprint_get = jwk_thumbprint_get
        self.load_config = load_config
        self.logger_setup = logger_setup
        self.logger_info = logger_info
        self.logger_nonce_modify = _logger_nonce_modify
        self.logger_certificate_modify = _logger_certificate_modify
        self.logger_token_modify = _logger_token_modify
        self.logger_challenges_modify = _logger_challenges_modify
        self.patched_create_connection = patched_create_connection
        self.print_debug = print_debug
        self.proxy_check = proxy_check
        self.servercert_get = servercert_get
        self.signature_check = signature_check
        self.txt_get = txt_get
        self.url_get = url_get
        self.url_get_with_own_dns = url_get_with_own_dns
        self.uts_to_date_utc = uts_to_date_utc
        self.validate_email = validate_email
        self.validate_csr = validate_csr
        self.sha256_hash = sha256_hash
        self.sha256_hash_hex = sha256_hash_hex
        self.proxystring_convert = proxystring_convert
        self.handle_exception = handle_exception

    def test_001_helper_b64decode_pad(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-correctly-padded', self.b64decode_pad(self.logger, 'dGhpcy1pcy1mb28tY29ycmVjdGx5LXBhZGRlZA=='))

    def test_002_helper_b64decode_pad(self):
        """ test b64decode_pad() method with a regular base64 encoded string """
        self.assertEqual('this-is-foo-with-incorrect-padding', self.b64decode_pad(self.logger, 'dGhpcy1pcy1mb28td2l0aC1pbmNvcnJlY3QtcGFkZGluZw'))

    def test_003_helper_b64decode_pad(self):
        """ test b64 decoding failure """
        self.assertEqual('ERR: b64 decoding error', self.b64decode_pad(self.logger, 'b'))

    def test_004_helper_decode_deserialize(self):
        """ test successful deserialization of a b64 encoded string """
        self.assertEqual({u'a': u'b', u'c': u'd'}, self.decode_deserialize(self.logger, 'eyJhIiA6ICJiIiwgImMiIDogImQifQ=='))

    def test_005_helper_decode_deserialize(self):
        """ test failed deserialization of a b64 encoded string """
        self.assertEqual('ERR: Json decoding error', self.decode_deserialize(self.logger, 'Zm9vLXdoaWNoLWNhbm5vdC1iZS1qc29uaXplZA=='))

    def test_006_helper_validate_email(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(self.logger, 'foo@example.com'))

    def test_007_helper_validate_email(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(self.logger, 'mailto:foo@example.com'))

    def test_008_helper_validate_email(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(self.logger, 'mailto: foo@example.com'))

    def test_009_helper_validate_email(self):
        """ validate normal email """
        self.assertTrue(self.validate_email(self.logger, ['mailto: foo@example.com', 'mailto: bar@example.com']))

    def test_010_helper_validate_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(self.logger, 'example.com'))

    def test_011_helper_validate_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(self.logger, 'me@exam,ple.com'))

    def test_012_helper_validate_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(self.logger, ['mailto: foo@exa,mple.com', 'mailto: bar@example.com']))

    def test_013_helper_validate_email(self):
        """ validate normal email """
        self.assertFalse(self.validate_email(self.logger, ['mailto: foo@example.com', 'mailto: bar@exa,mple.com']))

    def test_014_helper_signature_check(self):
        """ successful validation of singature """
        mkey = {
            'alg' : 'RS256',
            'e' : 'AQAB',
            'kty' : 'RSA',
            'n' : '2CFMV4MK6Uo_2GQWa0KVWlzffgSDiLwur4ujSZkCRzbA3w5p1ABJgr7l_P84HpRv8R8rGL67hqmDJuT52mGD6fMVAhHPX5pSdtyZlQQuzpXonzNmHbG1DbMSiXrxg5jWVXchCxHx82wAt9Kf13O5ATxD0WOBB5FffpqQHh8zTf29jTL4vBd8N57ce17ZgNWl_EcoByjigqNFJcO0rrvrf6xyNaO9nbun4PAMJTLbfVa6CiEqjnjYMX80VYLH4fCqsAZgxIoli_D2j9P5Kq6KZZUL_bZ2QQV4UuwWZvh6tcA393YQLeMARnhWI6dqlZVdcU74NXi9NhSxcMkM8nZZ8Q',
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((True, None), self.signature_check(self.logger, message, mkey))

    def test_015_helper_signature_check(self):
        """ failed validatio of singature  wrong key"""
        mkey = {
            'alg' : 'rs256',
            'e' : 'AQAB',
            'kty' : 'RSA',
            'n' : 'zncgRHCp22-29g9FO4Hn02iyS1Fo4Y1tB-6cucH1yKSxM6bowjAaVa4HkAnIxgF6Zj9qLROgQR84YjMPeNkq8woBRz1aziDiTIOc0D2aXvLgZbuFGesvxoSGd6uyxjyyV7ONwZEpB8QtDW0I3shlhosKB3Ni1NFu55bPUP9RvxUdPzRRuhxUMHc1CXre1KR0eQmQdNZT6tgQVxpv2lb-iburBADjivBRyrI3k3NmXkYknBggAu8JInaFY4T8pVK0jTwP-f3-0eAV1bg99Rm7uXNXl7SKpQ3oGihwy2OK-XAc59v6C3n4Wq9QpzGkFWsOOlp4zEf13L3_UKugeExEqw',
        }
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'

        if int('%i%i' % (sys.version_info[0], sys.version_info[1])) <= 36:
            result = (False, 'Verification failed for all signatures["Failed: [InvalidJWSSignature(\'Verification failed\',)]"]')
        else:
            result = (False, 'Verification failed for all signatures["Failed: [InvalidJWSSignature(\'Verification failed\')]"]')

        self.assertEqual(result, self.signature_check(self.logger, message, mkey))

    def test_016_helper_signature_check(self):
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

    def test_017_helper_signature_check(self):
        """ failed validatio of singature  no key"""
        mkey = {}
        message = '{"protected": "eyJub25jZSI6ICI3N2M3MmViMDE5NDc0YzBjOWIzODk5MmU4ZjRkMDIzYSIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIiwgImFsZyI6ICJSUzI1NiIsICJraWQiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYWNjdC8xIn0","payload": "eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9","signature": "QYbMYZ1Dk8dHKqOwWBQHvWdnGD7donGZObb2Ry_Y5PsHpcTrj8Y2CM57SNVAR9V0ePg4vhK3-IbwYAKbhZV8jF7E-ylZaYm4PSQcumKLI55qvDiEvDiZ0gmjf_GAcsC40TwBa11lzR1u0dQYxOlQ_y9ak6705c5bM_V4_ttQeslJXCfVIQoV-sZS0Z6tJfy5dPVDR7JYG77bZbD3K-HCCaVbT7ilqcf00rA16lvw13zZnIgbcZsbW-eJ2BM_QxE24PGqc_vMfAxIiUG0VY7DqrKumLs91lHHTEie8I-CapH6AetsBhGtRcB6EL_Rn6qGQZK9YBpvoXANv_qF2-zQkQ"}'
        self.assertEqual((False, 'No key specified.'), self.signature_check(self.logger, message, mkey))

    def test_018_helper_uts_to_date_utc(self):
        """ test uts_to_date_utc for a given format """
        self.assertEqual('2018-12-01', self.uts_to_date_utc(1543640400, '%Y-%m-%d'))

    def test_019_helper_uts_to_date_utc(self):
        """ test uts_to_date_utc without format """
        self.assertEqual('2018-12-01T05:00:00Z', self.uts_to_date_utc(1543640400))

    def test_020_helper_date_to_uts_utc(self):
        """ test date_to_uts_utc for a given format """
        self.assertEqual(1543622400, self.date_to_uts_utc('2018-12-01', '%Y-%m-%d'))

    def test_021_helper_date_to_uts_utc(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(1543640400, self.date_to_uts_utc('2018-12-01T05:00:00'))

    def test_022_helper_date_to_uts_utc(self):
        """ test date_to_uts_utc with a datestring """
        timestamp = datetime.datetime(2018, 12, 1, 5, 0, 1)
        self.assertEqual(1543640401, self.date_to_uts_utc(timestamp))

    def test_023_helper_generate_random_string(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(5, len(self.generate_random_string(self.logger, 5)))

    def test_024_helper_generate_random_string(self):
        """ test date_to_uts_utc without format """
        self.assertEqual(15, len(self.generate_random_string(self.logger, 15)))

    def test_025_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 1 char"""
        self.assertEqual('fafafaf=', self.b64_url_recode(self.logger, 'fafafaf'))

    def test_026_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(self.logger, 'fafafa'))

    def test_027_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(self.logger, 'fafaf'))

    def test_028_helper_b64_url_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(self.logger, 'fafafafa'))

    def test_029_helper_b64_url_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(self.logger, 'fafa-f'))

    def test_030_helper_b64_url_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, 'fafa_f'))

    def test_031_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 1 char"""
        self.assertEqual('fafafaf=', self.b64_url_recode(self.logger, b'fafafaf'))

    def test_032_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 2 char"""
        self.assertEqual('fafafa==', self.b64_url_recode(self.logger, b'fafafa'))

    def test_033_helper_b64_url_recode(self):
        """ test base64url recode to base64 - add padding for 3 char"""
        self.assertEqual('fafaf===', self.b64_url_recode(self.logger, b'fafaf'))

    def test_034_helper_b64_url_recode(self):
        """ test base64url recode to base64 - no padding"""
        self.assertEqual('fafafafa', self.b64_url_recode(self.logger, b'fafafafa'))

    def test_035_helper_b64_url_recode(self):
        """ test base64url replace - with + and pad"""
        self.assertEqual('fafa+f==', self.b64_url_recode(self.logger, b'fafa-f'))

    def test_036_helper_b64_url_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, b'fafa_f'))

    def test_037_helper_b64_url_recode(self):
        """ test base64url replace _ with / and pad"""
        self.assertEqual('fafa/f==', self.b64_url_recode(self.logger, b'fafa_f'))

    def test_038_helper_decode_message(self):
        """ decode message with empty payload - certbot issue"""
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        e_result = (True, None, {u'nonce': u'26e6a46efadd477d908d7c2014e49b34', u'url': u'http://laptop.nclm-samba.local/acme/authz/PG189FFzfao1', u'alg': u'RS256', u'kid': u'http://laptop.nclm-samba.local/acme/acct/yuZ1GUJb76Zk'}, {}, b'encoded_signature')
        self.assertEqual(e_result, self.decode_message(self.logger, data_dic))

    def test_039_helper_decode_message(self):
        """ decode message with empty payload - certbot issue"""
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "eyJmb28iOiAiYmFyMSJ9", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        e_result = (True, None, {u'nonce': u'26e6a46efadd477d908d7c2014e49b34', u'url': u'http://laptop.nclm-samba.local/acme/authz/PG189FFzfao1', u'alg': u'RS256', u'kid': u'http://laptop.nclm-samba.local/acme/acct/yuZ1GUJb76Zk'}, {'foo': 'bar1'}, b'encoded_signature')
        self.assertEqual(e_result, self.decode_message(self.logger, data_dic))

    @patch('json.loads')
    def test_040_helper_decode_message(self, mock_json):
        """ decode message with with exception during decoding """
        mock_json.side_effect = Exception('exc_mock_json')
        data_dic = '{"protected": "eyJub25jZSI6ICIyNmU2YTQ2ZWZhZGQ0NzdkOTA4ZDdjMjAxNGU0OWIzNCIsICJ1cmwiOiAiaHR0cDovL2xhcHRvcC5uY2xtLXNhbWJhLmxvY2FsL2FjbWUvYXV0aHovUEcxODlGRnpmYW8xIiwgImtpZCI6ICJodHRwOi8vbGFwdG9wLm5jbG0tc2FtYmEubG9jYWwvYWNtZS9hY2N0L3l1WjFHVUpiNzZaayIsICJhbGciOiAiUlMyNTYifQ", "payload": "", "signature": "ZW5jb2RlZF9zaWduYXR1cmU="}'
        if int('%i%i' % (sys.version_info[0], sys.version_info[1])) < 37:
            result = 'ERROR:test_a2c:decode_message() err: Invalid JWS Object [Invalid format]'
            e_result = (False, "Invalid JWS Object [Invalid format]", {}, {}, None)
        else:
            result = 'ERROR:test_a2c:decode_message() err: Invalid JWS Object [Invalid format]'
            e_result = (False, "Invalid JWS Object [Invalid format]", {}, {}, None)
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(e_result, self.decode_message(self.logger, data_dic))
        self.assertIn(result, lcm.output)

    def test_041_helper_cert_serial_get(self):
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

    def test_042_helper_cert_san_get(self):
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

    def test_043_helper_cert_san_get(self):
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

    def test_044_helper_cert_serial_get(self):
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

    def test_045_helper_cert_san_get(self):
        """ test cert_san_get for a single SAN and recode = True"""
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
        self.assertEqual(['DNS:foo.example.com'], self.cert_san_get(self.logger, cert, recode=True))

    def test_046_helper_cert_san_get(self):
        """ test cert_san_get for a single SAN and recode = False"""
        cert = """-----BEGIN CERTIFICATE-----\nMIIDDTCCAfWgAwIBAgIBCjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9mb28u
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
                t+eRUDECE+0UnjyeCjTn3EU=\n-----END CERTIFICATE-----"""

        self.assertEqual(['DNS:foo.example.com'], self.cert_san_get(self.logger, cert, recode=False))

    def test_047_helper_build_pem_file(self):
        """ test build_pem_file without exsting content """
        existing = None
        cert = 'cert'
        self.assertEqual('-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_048_helper_build_pem_file(self):
        """ test build_pem_file with exsting content """
        existing = 'existing'
        cert = 'cert'
        self.assertEqual('existing-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_049_helper_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\naaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, True))

    def test_050_helper_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = None
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, False))

    def test_051_helper_build_pem_file(self):
        """ test build_pem_file with long cert (to test wrap) """
        existing = 'existing'
        cert = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        self.assertEqual('existing-----BEGIN CERTIFICATE-----\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n-----END CERTIFICATE-----\n', self.build_pem_file(self.logger, existing, cert, False))


    def test_052_helper_build_pem_file(self):
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

    def test_053_helper_b64_decode(self):
        """ test bas64 decoder for string value"""
        self.assertEqual('test', self.b64_decode(self.logger, 'dGVzdA=='))

    def test_054_helper_b64_decode(self):
        """ test bas64 decoder for byte value """
        self.assertEqual('test', self.b64_decode(self.logger, b'dGVzdA=='))

    def test_055_helper_date_to_datestr(self):
        """ convert dateobj to date-string with default format"""
        self.assertEqual('2019-10-27T00:00:00Z', self.date_to_datestr(datetime.date(2019, 10, 27)))

    def test_056_helper_date_to_datestr(self):
        """ convert dateobj to date-string with a predefined format"""
        self.assertEqual('2019.10.27', self.date_to_datestr(datetime.date(2019, 10, 27), '%Y.%m.%d'))

    def test_057_helper_date_to_datestr(self):
        """ convert dateobj to date-string for an knvalid date"""
        self.assertEqual(None, self.date_to_datestr('foo', '%Y.%m.%d'))

    def test_058_helper_datestr_to_date(self):
        """ convert datestr to date with default format"""
        self.assertEqual(datetime.datetime(2019, 11, 27, 0, 1, 2), self.datestr_to_date('2019-11-27T00:01:02'))

    def test_059_helper_datestr_to_date(self):
        """ convert datestr to date with predefined format"""
        self.assertEqual(datetime.datetime(2019, 11, 27, 0, 0, 0), self.datestr_to_date('2019.11.27', '%Y.%m.%d'))

    def test_060_helper_datestr_to_date(self):
        """ convert datestr to date with invalid format"""
        self.assertEqual(None, self.datestr_to_date('foo', '%Y.%m.%d'))

    def test_061_helper_dkeys_lower(self):
        """ dkeys_lower with a simple string """
        tree = 'fOo'
        self.assertEqual('fOo', self.dkeys_lower(tree))

    def test_062_helper_dkeys_lower(self):
        """ dkeys_lower with a simple list """
        tree = ['fOo', 'bAr']
        self.assertEqual(['fOo', 'bAr'], self.dkeys_lower(tree))

    def test_063_helper_dkeys_lower(self):
        """ dkeys_lower with a simple dictionary """
        tree = {'kEy': 'vAlUe'}
        self.assertEqual({'key': 'vAlUe'}, self.dkeys_lower(tree))

    def test_064_helper_dkeys_lower(self):
        """ dkeys_lower with a nested dictionary containg strings, list and dictionaries"""
        tree = {'kEy1': 'vAlUe2', 'keys2': ['lIsT2', {'kEyS3': 'vAlUe3', 'kEyS4': 'vAlUe3'}], 'keys4': {'kEyS4': 'vAluE5', 'kEyS5': 'vAlUE6'}}
        self.assertEqual({'key1': 'vAlUe2', 'keys2': ['lIsT2', {'keys3': 'vAlUe3', 'keys4': 'vAlUe3'}], 'keys4': {'keys5': 'vAlUE6', 'keys4': 'vAluE5'}}, self.dkeys_lower(tree))

    def test_065_helper_cert_pubkey_get(self):
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

    def test_066_helper_csr_pubkey_get(self):
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

    def test_067_helper_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertEqual('foo', self.convert_byte_to_string('foo'))

    def test_068_helper_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertEqual('foo', self.convert_byte_to_string('foo'))

    def test_069_helper_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertNotEqual('foo', self.convert_byte_to_string('foobar'))

    def test_070_helper_convert_byte_to_string(self):
        """ convert byte2string for a string value """
        self.assertNotEqual('foo', self.convert_byte_to_string(b'foobar'))

    def test_071_helper_b64_url_encode(self):
        """ test b64_url_encode of string """
        self.assertEqual(b'c3RyaW5n', self.b64_url_encode(self.logger, 'string'))

    def test_072_helper_b64_url_encode(self):
        """ test b64_url_encode of byte """
        self.assertEqual(b'Ynl0ZQ', self.b64_url_encode(self.logger, b'byte'))

    def test_073_helper_csr_cn_get(self):
        """ get cn of csr """
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0lk4lyEIa0VL/u5ic01Zo/o+gyYqFpU7xe+nbFgiKA+R1rqrzP/sR6xjHqS0Rkv/BcBXf81sp/+iDmwIQLVlBTkKdimqVHCJMAbTL8ZNpcLDaRUce4liyX1cmczPTSqI/kcyEr8tKpYN+KzvKZZsNx2Pbgu7y7/70P2uSywiW+sqYZ+X28KGFxq6wwENzJtweDVsbWql9LLtw6daF41UQg10auNlRL1nhW0SlWZh1zPPW/0sa6C3xX28jjVh843b4ekkRNLXSEYQMTi0qYR2LomQ5aTlQ/hellf17UknfN2aA2RH5D7Ek+mndj/rH21bxQg26KRmHlaJld9K1IfvJAgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAl3egrkO3I94IpxxfSJmVetd7s9uW3lSBqh9OiypFevQO7ZgUxau+k05NKTUNpSq3W9H/lRr5AG5x3/VX8XZVbcLKXQ0d6e38uXBAUFQQJmjBVYqd8KcMfqLeFFUBsLcG04yek2tNIbhXZfBtw9UYO27Y5ktMgWjAz2VskIXl3E2L0b8tGnSKDoMB07IVpYB9bHfHX4o+ccIgq1HxyYT1d+eVIQuSHHxR7j7Wkgb8RG9bCWpVWaYWKWU0Inh3gMnP06kPBJ9nOB4adgC3Hz37ab/0KpmBuQBEgmMfINwV/OpJVv2Su1FYK+uX7E1qUGae6QDsfg0Yor9uP0Vkv4b1NA=='
        self.assertEqual('foo1.bar.local', self.csr_cn_get(self.logger, csr))

    def test_074_helper_csr_cn_get(self):
        """ get cn of csr """
        csr = b'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0lk4lyEIa0VL/u5ic01Zo/o+gyYqFpU7xe+nbFgiKA+R1rqrzP/sR6xjHqS0Rkv/BcBXf81sp/+iDmwIQLVlBTkKdimqVHCJMAbTL8ZNpcLDaRUce4liyX1cmczPTSqI/kcyEr8tKpYN+KzvKZZsNx2Pbgu7y7/70P2uSywiW+sqYZ+X28KGFxq6wwENzJtweDVsbWql9LLtw6daF41UQg10auNlRL1nhW0SlWZh1zPPW/0sa6C3xX28jjVh843b4ekkRNLXSEYQMTi0qYR2LomQ5aTlQ/hellf17UknfN2aA2RH5D7Ek+mndj/rH21bxQg26KRmHlaJld9K1IfvJAgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAl3egrkO3I94IpxxfSJmVetd7s9uW3lSBqh9OiypFevQO7ZgUxau+k05NKTUNpSq3W9H/lRr5AG5x3/VX8XZVbcLKXQ0d6e38uXBAUFQQJmjBVYqd8KcMfqLeFFUBsLcG04yek2tNIbhXZfBtw9UYO27Y5ktMgWjAz2VskIXl3E2L0b8tGnSKDoMB07IVpYB9bHfHX4o+ccIgq1HxyYT1d+eVIQuSHHxR7j7Wkgb8RG9bCWpVWaYWKWU0Inh3gMnP06kPBJ9nOB4adgC3Hz37ab/0KpmBuQBEgmMfINwV/OpJVv2Su1FYK+uX7E1qUGae6QDsfg0Yor9uP0Vkv4b1NA=='
        self.assertEqual('foo1.bar.local', self.csr_cn_get(self.logger, csr))

    @patch('OpenSSL.crypto.load_certificate_request')
    def test_075_helper_csr_cn_get(self, mock_csrload):
        """ get cn of csr """
        csr = 'csr'
        obj1 = Mock()
        obj1.get_components = Mock(return_value={'CN': 'foo'})
        obj2 = Mock()
        obj2.get_subject = Mock(return_value=obj1)
        mock_csrload.return_value = obj2
        self.assertEqual('foo', self.csr_cn_get(self.logger, csr))

    @patch('OpenSSL.crypto.load_certificate_request')
    def test_076_helper_csr_cn_get(self, mock_csrload):
        """ get cn of csr """
        csr = 'csr'
        obj1 = Mock()
        obj1.get_components = Mock(return_value={b'CN': 'foo'})
        obj2 = Mock()
        obj2.get_subject = Mock(return_value=obj1)
        mock_csrload.return_value = obj2
        self.assertEqual('foo', self.csr_cn_get(self.logger, csr))

    def test_077_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = 'foo.bar'
        self.assertEqual(b'foo.bar', self.convert_string_to_byte(value))

    def test_078_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = b'foo.bar'
        self.assertEqual(b'foo.bar', self.convert_string_to_byte(value))

    def test_079_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = b''
        self.assertEqual(b'', self.convert_string_to_byte(value))

    def test_080_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = ''
        self.assertEqual(b'', self.convert_string_to_byte(value))

    def test_081_helper_convert_string_to_byte(self):
        """ convert string value to byte """
        value = None
        self.assertFalse(self.convert_string_to_byte(value))

    def test_082_helper_get_url(self):
        """ get_url https """
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 443, 'PATH_INFO': 'path_info'}
        self.assertEqual('https://http_host', self.get_url(data_dic, False))

    def test_083_helper_get_url(self):
        """ get_url http """
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 80, 'PATH_INFO': 'path_info'}
        self.assertEqual('http://http_host', self.get_url(data_dic, False))

    def test_084_helper_get_url(self):
        """ get_url http wsgi.scheme """
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 80, 'PATH_INFO': 'path_info', 'wsgi.url_scheme': 'wsgi.url_scheme'}
        self.assertEqual('wsgi.url_scheme://http_host', self.get_url(data_dic, False))

    def test_085_helper_get_url(self):
        """ get_url https include_path true bot no pathinfo"""
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 443}
        self.assertEqual('https://http_host', self.get_url(data_dic, True))

    def test_086_helper_get_url(self):
        """ get_url https and path info"""
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 443, 'PATH_INFO': 'path_info'}
        self.assertEqual('https://http_hostpath_info', self.get_url(data_dic, True))

    def test_087_helper_get_url(self):
        """ get_url wsgi.url and pathinfo """
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 80, 'PATH_INFO': 'path_info', 'wsgi.url_scheme': 'wsgi.url_scheme'}
        self.assertEqual('wsgi.url_scheme://http_hostpath_info', self.get_url(data_dic, True))

    def test_088_helper_get_url(self):
        """ get_url http and pathinfo"""
        data_dic = {'HTTP_HOST': 'http_host', 'SERVER_PORT': 80, 'PATH_INFO': 'path_info'}
        self.assertEqual('http://http_hostpath_info', self.get_url(data_dic, True))

    def test_089_helper_get_url(self):
        """ get_url without hostinfo """
        data_dic = {'SERVER_PORT': 80, 'PATH_INFO': 'path_info'}
        self.assertEqual('http://localhost', self.get_url(data_dic, False))

    def test_090_helper_get_url(self):
        """ get_url without SERVER_PORT """
        data_dic = {'HTTP_HOST': 'http_host'}
        self.assertEqual('http://http_host', self.get_url(data_dic, True))

    @patch('acme_srv.helper.requests.get')
    def test_091_helper_url_get(self, mock_request):
        """ successful url get without dns servers """
        mock_request.return_value.text = 'foo'
        self.assertEqual('foo', self.url_get(self.logger, 'url'))

    @patch('acme_srv.helper.requests.get')
    def test_092_helper_url_get(self, mock_request):
        """ successful url get without dns servers """
        mock_request.return_value.text = 'foo'
        self.assertEqual('foo', self.url_get(self.logger, 'url', 'dns', 'proxy'))

    @patch('acme_srv.helper.requests.get')
    def test_093_helper_url_get(self, mock_request):
        """ unsuccessful url get without dns servers """
        # this is stupid but triggrs an expeption
        mock_request.return_value = {'foo': 'foo'}
        self.assertEqual(None, self.url_get(self.logger, 'url'))

    @patch('acme_srv.helper.url_get_with_own_dns')
    def test_094_helper_url_get(self, mock_request):
        """ successful url get with dns servers """
        mock_request.return_value = 'foo'
        self.assertEqual('foo', self.url_get(self.logger, 'url', 'dns'))

    @patch('acme_srv.helper.requests.get', side_effect=Mock(side_effect=Exception('foo')))
    def test_095_helper_url_get(self, mock_request):
        """ unsuccessful url_get """
        # mock_request.return_value.text = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.url_get(self.logger, 'url'))
        self.assertIn('ERROR:test_a2c:url_get error: foo', lcm.output)

    @patch('acme_srv.helper.requests.get')
    def test_096_helper_url_get(self, mock_request):
        """ unsuccessful url_get fallback to v4"""
        object = Mock()
        object.text = 'foo'
        mock_request.side_effect=[Exception('foo'), object]
        self.assertEqual('foo', self.url_get(self.logger, 'url'))

    @patch('acme_srv.helper.requests.get')
    def test_097_helper_url_get_with_own_dns(self, mock_request):
        """ successful url_get_with_own_dns get with dns servers """
        mock_request.return_value.text = 'foo'
        self.assertEqual('foo', self.url_get_with_own_dns(self.logger, 'url'))

    @patch('acme_srv.helper.requests.get')
    def test_098_helper_url_get_with_own_dns(self, mock_request):
        """ successful url_get_with_own_dns get with dns servers """
        mock_request.return_value = {'foo': 'foo'}
        self.assertEqual(None, self.url_get_with_own_dns(self.logger, 'url'))

    @patch('acme_srv.helper.load_config')
    def test_099_helper_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with empty config file """
        mock_load_config.return_value = {}
        self.assertEqual(['9.9.9.9', '8.8.8.8'], self.dns_server_list_load())

    @patch('acme_srv.helper.load_config')
    def test_100_helper_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with empty Challenge section """
        mock_load_config.return_value = {'Challenge': {}}
        self.assertEqual(['9.9.9.9', '8.8.8.8'], self.dns_server_list_load())

    @patch('acme_srv.helper.load_config')
    def test_101_helper_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with wrong Challenge section """
        mock_load_config.return_value = {'Challenge': {'foo': 'bar'}}
        self.assertEqual(['9.9.9.9', '8.8.8.8'], self.dns_server_list_load())

    @patch('acme_srv.helper.load_config')
    def test_102_helper_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with wrong json format """
        mock_load_config.return_value = {'Challenge': {'dns_server_list': 'bar'}}
        self.assertEqual(['9.9.9.9', '8.8.8.8'], self.dns_server_list_load())

    @patch('acme_srv.helper.load_config')
    def test_103_helper_dns_server_list_load(self, mock_load_config):
        """ successful dns_server_list_load with wrong json format """
        mock_load_config.return_value = {'Challenge': {'dns_server_list': '["foo", "bar"]'}}
        self.assertEqual(['foo', 'bar'], self.dns_server_list_load())

    def test_104_helper_csr_san_get(self):
        """ get sans but no csr """
        csr = None
        self.assertEqual([], self.csr_san_get(self.logger, csr))

    def test_105_helper_csr_san_get(self):
        """ get sans but one san with == """
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ=='
        self.assertEqual(['DNS:foo1.bar.local'], self.csr_san_get(self.logger, csr))

    def test_106_helper_csr_san_get(self):
        """ get sans but one san without == """
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ'
        self.assertEqual(['DNS:foo1.bar.local'], self.csr_san_get(self.logger, csr))

    def test_107_helper_csr_san_get(self):
        """ get sans but two sans """
        csr = 'MIICpzCCAY8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgSTBHBgkqhkiG9w0BCQ4xOjA4MAsGA1UdDwQEAwIF4DApBgNVHREEIjAggg5mb28xLmJhci5sb2NhbIIOZm9vMi5iYXIubG9jYWwwDQYJKoZIhvcNAQELBQADggEBADeuf4J8Xziw2OuvLNnLOSgHQl2HdMFtRdgJoun7zPobsP3L3qyXLvvhJcQsIJggu5ZepnHGrCxroSbtRSO65GtLQA0Rq3DCGcPIC1fe9AYrqoynx8bWt2Hd+PyDrBppHVoQzj6yNCt6XNSDs04BMtjs9Pu4DD6DDHmxFMVNdHXea2Rms7C5nLQvXgw7yOF3Zk1vEu7Kue7d3zZMhN+HwwrNEA7RGAEzHHlCv5LL4Mw+kf6OJ8nf/WDiLDKEQIh6bnOuB42Y2wUMpzui8Uur0VJO+twY46MvjiVMMBZE3aPJU33eNPAQVC7GinStn+zQIJA5AADdcO8Lk1qdtaDiGp8'
        self.assertEqual(['DNS:foo1.bar.local', 'DNS:foo2.bar.local'], self.csr_san_get(self.logger, csr))

    def test_108_helper_csr_san_get(self):
        """ get sans but three sans """
        csr = 'MIICtzCCAZ8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgWTBXBgkqhkiG9w0BCQ4xSjBIMAsGA1UdDwQEAwIF4DA5BgNVHREEMjAwgg5mb28xLmJhci5sb2NhbIIOZm9vMi5iYXIubG9jYWyCDmZvbzMuYmFyLmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQAQRkub6G4uijaXOYpCkoz40I+SVRsbRDgnMNjsooZz1+7DVglFjrr6Pb0PPTOvOxtmbHP2KK0WokDn4LqOD2t0heuI+KPQy7m/ROpOB/YZOzTWEB8yS4vjkf/RFiJ7fnCAc8vA+3K/mBVb+89F8w/KlyPmpg1GK7UNgjEa5bnznTox8q12CocCJVykPEiC8AT/VPWUOPfg6gs+V6LO8R73VRPMVy0ttYKGX80ob+KczDTMUhoxXg8OG+G+bXXU+4Tu4l+nQWf2lFejECi/vNKzUT90IbcGJwyk7rc4Q7BJ/t/5nMo+vuV9f+2HI7qakHcw6u9RGylL4OYDf1CrqF1R'
        self.assertEqual(['DNS:foo1.bar.local', 'DNS:foo2.bar.local', 'DNS:foo3.bar.local'], self.csr_san_get(self.logger, csr))

    def test_109_helper_csr_extensions_get(self):
        """ get sns in hex """
        csr = 'MIIClzCCAX8CAQAwGTEXMBUGA1UEAwwOZm9vMS5iYXIubG9jYWwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMwfxxbCCTsZY8mTFZkoQ5cAJyQZLUiz34sDDRvEpI9ZzdNNm2AEZR7AgKNuBkLwzUzY5iQ182huNzYJYZZEvYX++ocF2ngapTMQgfB+bWS5bpWIdjnAcz1/86jmJgTciwL25dSnEWL17Yn3pAWweoewr730rq/PMyIbviQrasksnSo7abe2mctxkHjHb5sZ+Z1yRTN6ir/bObXmxr+vHeeD2vLRv4Hd5XaA1d+k31J2FVMnrn5OpWbxGHo49zd0xdy2mgTdZ9UraLaQnyGlkjYzV0rqHIAIm8HOUjGN5U75/rlOPF0x62FCICZU/z1AgRvugaA5eO8zTSQJiMiBe3AgMBAAGgOTA3BgkqhkiG9w0BCQ4xKjAoMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEANAXOIkv0CovmdzyoAv1dsiK0TK2XHBdBTEPFDsrT7MnrIXOFS4FnDrg8zpn7QBzBRTl3HaKN8fnpIHkA/6ZRDqaEJq0AeskjxIg9LKDBBx5TEdgPh1CwruRWLlXtrqU7XXQmk0wLIo/kfaDRcTjyJ3yHTEK06mCAaws0sTKlTw2D4pIiDRp8zbLHeSEUX5UKOSGbLSSUY/F2XwgPB8nC2BCD/gkvHRR+dMQSdOCiS9GLwZdYAAyESw6WhmGPjmVbeTRgSt/9//yx3JKQgkFYmpSMLKR2G525M+l1qfku/4b0iMOa4vQjFRj5AXZH0SBpAKtvnFxUpP6P9mTE7+akOQ'
        self.assertEqual(['AwIF4A==', 'MBCCDmZvbzEuYmFyLmxvY2Fs'], self.csr_extensions_get(self.logger, csr))

    def test_110_helper_csr_extensions_get(self):
        """ get tnauth identifier """
        csr = 'MIICuzCCAaMCAQAwHjEcMBoGA1UEAwwTY2VydC5zdGlyLmJhci5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALsLm4zgkl2lEx2EHy1ENfh3cYB79Xb5sD3ehkY+1pXphIWoM9KYVqHKOurModjsh75YjRBSilRfTFSk6kCUahTJyeCbM6Vzl75CcZy7poUxiK+u80JMU/xymUsrqY4GZlh2/XtFMxXHUSf3bhKZAIjBNugsvR/sHtEvJ6RJiuYqHMWUzZ/Vby5L0ywNl+LPSY7AVTUAZ0lKrnUCP4dHnbjwjf+nPi7vT6G0yrEg0qPOYXtJOXdf7vvjLi8J+ap758NtG2qapLdbToIPr0uOEvMO6zs8z1bIyjOHU3kzlpKHzDsPYy8txxKC/3Rae7sKB9gWm8WUxFBmuA7gaFDGQAECAwEAAaBYMFYGCSqGSIb3DQEJDjFJMEcwCwYDVR0PBAQDAgXgMB4GA1UdEQQXMBWCE2NlcnQuc3Rpci5iYXIubG9jYWwwGAYIKwYBBQUHARoEDDAKoAgWBjEyMzQ1NjANBgkqhkiG9w0BAQsFAAOCAQEAjyhJfgb/zJBMYp6ylRtEXgtBpsX9ePUL/iLgIDMcGtwaFm3pkQOSBr4xiTxftnqN77SlC8UEu7PDR73JX6iqLNJWucPlhAXVrr367ygO8GGLrtGddClZmo0lhRBRErgpagWB/jFkbL8afPGJwgQQXF0KWFMcajAPiIl1l6M0w11KqJ23Pwrmi7VJHzIgh4ys0D2UrX7KuV4PIOOmG0s7jTfBSB+yUH2zwVzOAzbr3wrD1WubD7hRaHDUi4bn4DRbquQOzbqfTI6QhetUcNpq4DwhBRcnZwUMJUIcxLAsFnDgGSW+dmJe6JH8MsS+8ZmOLllyQxWzYEVquQQvxFVTZA'
        self.assertEqual(['AwIF4A==', 'MBWCE2NlcnQuc3Rpci5iYXIubG9jYWw=', 'MAqgCBYGMTIzNDU2'], self.csr_extensions_get(self.logger, csr))

    def test_111_helper_validate_email(self):
        """ validate email containing "-" in domain """
        self.assertTrue(self.validate_email(self.logger, 'foo@example-example.com'))

    def test_112_helper_validate_email(self):
        """ validate email containing "-" in user"""
        self.assertTrue(self.validate_email(self.logger, 'foo-foo@example.com'))

    def test_113_helper_get_url(self):
        """ get_url with xforwarded https """
        data_dic = {'HTTP_X_FORWARDED_PROTO': 'https', 'HTTP_HOST': 'http_host', 'SERVER_PORT': 443, 'PATH_INFO': 'path_info'}
        self.assertEqual('https://http_host', self.get_url(data_dic, False))

    def test_114_helper_get_url(self):
        """ get_url with xforwarded http """
        data_dic = {'HTTP_X_FORWARDED_PROTO': 'http', 'HTTP_HOST': 'http_host', 'SERVER_PORT': 443, 'PATH_INFO': 'path_info'}
        self.assertEqual('http://http_host', self.get_url(data_dic, False))

    def test_115_helper_validate_email(self):
        """ validate email containing first letter of domain cannot be a number"""
        self.assertFalse(self.validate_email(self.logger, 'foo@1example.com'))

    def test_116_helper_validate_email(self):
        """ validate email containing last letter of domain cannot - """
        self.assertFalse(self.validate_email(self.logger, 'foo@example-.com'))

    def test_117_helper_cert_dates_get(self):
        """ get issuing and expiration date from rsa certificate """
        cert = 'MIIElTCCAn2gAwIBAgIRAKD_ulfqPUn-ggOUHOxjp40wDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEXMBUGA1UECgwOQWNtZTJDZXJ0aWZpZXIxDzANBgNVBAMMBnN1Yi1jYTAeFw0yMDA1MjcxMjMwMjNaFw0yMDA2MjYxMjMwMjNaMBkxFzAVBgNVBAMMDmZvbzEuYmFyLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbx-z-9wsEewBf1hnk3yAy5TFg-lWVdwk2QRdAMDTExVP823QF_K-t6cxJV_-QuWVbHN-lx6nQCXIqCZSN97hN0YTkrw8jnA4FpZzyvYI9rKEO3p4sxqndbu4X-gtyMBbXOLhjTlN2f7Z081XWIgkikvuZU2XzMZ-BbRFDfsPdDRwbwvgJU6NxpdIKm2DmYIP1MFo-tLu0toAc0nm9v8Otme28_kpJxmW3iOMkqN9BE-qAkggFDeNoxPtXRyP2PrRgbaj94e1uznsyni7CYw_a9O1NPrjKFQmPaCk8k9ICvPoLHXtLabekCmvdxyRlDwD_Xoaygpd9-UHCREhcOu_wIDAQABo4GoMIGlMAsGA1UdDwQEAwIF4DAZBgNVHREEEjAQgg5mb28xLmJhci5sb2NhbDAdBgNVHQ4EFgQUqy5KOBlkyX29l4EHTCSzhZuDg-EwDgYDVR0PAQH_BAQDAgWgMB8GA1UdIwQYMBaAFBs0P896R0FUZHfnxMJL52ftKQOkMAwGA1UdEwEB_wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMA0GCSqGSIb3DQEBCwUAA4ICAQB7pQpILzxqcU2RKlr17rcne6NSJTUJnNXALeUFy5PrnjjJY1_B1cKaWluk3p7AMFvUjBpcucGCfEDudW290AQxYjrvl8_ePkzRzEkAo76L7ZqED5upYBZVn_3lA5Alr8L67UC0bDMhKTsy8WJzhWHQlMb37_YFUvtNPoI_MI09Q842VXeNQz5UDZmW9qhyeDIkf6fwOAO66VnGTLuUm2LGQZ-St2GauxR0ZUcRtMJoc-c7WOdHs8DlUCoFtglrzVH98501Sx749CG4nkJr4QNDpkw2hAhlo4Cxzp6PlljPNSgM9MsqqVdrgqDteDM_n-yrVFGezCik4QexDkWARPutRLQtpbhudExVnoFM68ihZ0y3oeDjgUBLybBQpcBAsBqiJ66Q8HTZRSqO9zlKW5Vm1KwAVDh_qgELxvqd0wIVkyxBKPta2l1fvb5YBiVqo4JyNcCTnoBS1emO4vk8XjroKijwLnU0cEXwHrY4JF1uU_kOtoZMGPul5EuBMcODLs7JJ3_IqJd8quI7Vf5zSsaB6nSzQ8XmiQiVogKflBeLl7AWmYCiL-FLP_q4dSJmvdr6fPMNy4-cfDO4Awc8RNfv-VjF5Mq57X1IXJrWKkat4lCEoPMq5WRJV8uVm6XNdwvUJxgCYR9mfol7T6imODDd7BNV4dKYvyteoS0auC0iww'
        self.assertEqual((1590582623, 1593174623), self.cert_dates_get(self.logger, cert))

    def test_118_helper_cert_dates_get(self):
        """ get issuing and expiration date no certificate """
        cert = None
        self.assertEqual((0, 0), self.cert_dates_get(self.logger, cert))

    def test_119_helper_cert_dates_get(self):
        """ get issuing and expiration date damaged certificate """
        cert = 'foo'
        self.assertEqual((0, 0), self.cert_dates_get(self.logger, cert))

    def test_120_helper_cert_dates_get(self):
        """ get issuing and expiration date ecc certificate """
        cert = 'MIIDozCCAYugAwIBAgIIMMxkE7mRR+YwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMDA3MTEwNDUzMTFaFw0yMTA3MTEwNDUzMTFaMBkxFzAVBgNVBAMMDmZvbzEuYmFyLmxvY2FsMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER/KMoV5+zQgegqYue2ztPK2nZVpK2vxb02UzwyHw4ebhJ2gBobI23lSBRa1so1ug0kej7U+ohm5aGFdNxLM0G6OBqDCBpTALBgNVHQ8EBAMCBeAwGQYDVR0RBBIwEIIOZm9vMS5iYXIubG9jYWwwHQYDVR0OBBYEFCSaU743wU8jMETIO381r13tVLdMMA4GA1UdDwEB/wQEAwIFoDAfBgNVHSMEGDAWgBS/3o6OBiIiq61DyN3UT6irSEE+1TAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAgEAmmhHuBhXNM2Azv53rCKY72yTQIoDVHjYrAvTmS6NsJzYflEOMkI7FCes64dWp54BerSD736Yax67b4XmLXc/+T41d7QAcnhY5xvLJiMpSsW37icHcLZpjlOrYDoRmny2U7n6t1aQ03nwgV+BgdaUQYLkUZuczs4kdqH1c9Ot9CCRTHpqSWlmWzGeRgt2uT4gKhFESP9lzx37YwKBHulBGthv1kcAaz8w8iPXBg01OEDiraXCBZFoYDEpDi2w2Y6ChCr7sNsY7aJ3a+2iHGYlktXEntk78S+g00HW61G9oLoRgeqEH3L6qVIpnswPAU/joub0YhNBIUFenCj8c3HMBgMcczzdZL+qStdymhpVkZetzXtMTKtgmxhkRzAOQUBBcHFc+wM97FqC0S4HJAuoHQ4EJ46MxwZH0jBVqcqCPMSaJ88uV902+VGGXrnxMR8RbGWLoCmsYb1ISmBUt+31PjMCYbXKwLmzvbRpO7XAQimvtOqoufl5yeRUJRLcUS6Let0QzU196/nZ789d7Etep7RjDYQm7/QhiWH197yKZ5/mUxqfyHDQ3hk5iX7S/gbo1jQXElEv5tB8Ozs+zVQmB2bXpN8c+8XUaZnwvYC2y+0LAQN4z7xilReCaasxQSsEOLCrlsannkGV704HYnnaKBS2tI948QotHnADHdfHl3o'
        self.assertEqual((1594443191, 1625979191), self.cert_dates_get(self.logger, cert))

    @patch('dns.resolver.Resolver')
    def test_121_helper_fqdn_resolve(self, mock_resolve):
        """ successful dns-query returning covering github """
        mock_resolve.return_value.query.return_value = ['foo']
        self.assertEqual((None, False), self.fqdn_resolve('foo', dnssrv='10.0.0.1'))

    @patch('dns.resolver.Resolver')
    def test_122_helper_fqdn_resolve(self, mock_resolve):
        """ successful dns-query returning covering github """
        mock_resolve.return_value.query.return_value = ['foo']
        self.assertEqual(('foo', False), self.fqdn_resolve('foo.bar.local', dnssrv='10.0.0.1'))


    @patch('dns.resolver.Resolver')
    def test_123_helper_fqdn_resolve(self, mock_resolve):
        """ successful dns-query returning covering github """
        mock_resolve.return_value.query.return_value = ['foo']
        self.assertEqual((None, False), self.fqdn_resolve('foo'))

    @patch('dns.resolver.Resolver')
    def test_124_helper_fqdn_resolve(self, mock_resolve):
        """ successful dns-query returning one value """
        mock_resolve.return_value.query.return_value = ['foo']
        self.assertEqual(('foo', False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver')
    def test_125_helper_fqdn_resolve(self, mock_resolve):
        """ successful dns-query returning two values """
        mock_resolve.return_value.query.return_value = ['bar', 'foo']
        self.assertEqual(('bar', False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=Mock(side_effect=dns.resolver.NXDOMAIN))
    def test_126_helper_fqdn_resolve(self, mock_resolve):
        """ catch NXDOMAIN """
        self.assertEqual((None, True), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=Mock(side_effect=dns.resolver.NoAnswer))
    def test_127_helper_fqdn_resolve(self, mock_resolve):
        """ catch NoAnswer """
        self.assertEqual((None, True), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=Mock(side_effect=dns.resolver.NoNameservers))
    def test_128_helper_fqdn_resolve(self, mock_resolve):
        """ catch other dns related execption """
        self.assertEqual((None, False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=Mock(side_effect=Exception('foo')))
    def test_129_helper_fqdn_resolve(self, mock_resolve):
        """ catch other execption """
        self.assertEqual((None, False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=[Mock(side_effect=dns.resolver.NXDOMAIN), ['foo']])
    def test_130_helper_fqdn_resolve(self, mock_resolve):
        """ catch NXDOMAIN on v4 and fine in v6 """
        self.assertEqual(('foo', False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=[Mock(side_effect=dns.resolver.NoAnswer), ['foo']])
    def test_131_helper_fqdn_resolve(self, mock_resolve):
        """ catch NoAnswer on v4 and fine in v6 """
        self.assertEqual(('foo', False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=[Mock(side_effect=dns.resolver.NoNameservers), ['foo']])
    def test_132_helper_fqdn_resolve(self, mock_resolve):
        """ catch other dns related execption on v4 and fine in v6 """
        self.assertEqual(('foo', False), self.fqdn_resolve('foo.bar.local'))

    @patch('dns.resolver.Resolver.query', side_effect=[Mock(side_effect=Exception('foo')), ['foo']])
    def test_133_helper_fqdn_resolve(self, mock_resolve):
        """ catch other execption when resolving v4 but fine in v6"""
        self.assertEqual(('foo', False), self.fqdn_resolve('foo.bar.local'))

    def test_134_helper_signature_check(self):
        """ sucessful validation symmetric key"""
        mkey = '{"k": "ZndUSkZvVldvMEFiRzQ5VWNCdERtNkNBNnBTcTl4czNKVEVxdUZiaEdpZXZNUVJBVmRuSFREcDJYX2s3X0NxTA", "kty": "oct"}'
        message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
        self.assertEqual((True, None), self.signature_check(self.logger, message, mkey, json_=True))

    def test_135_helper_signature_check(self):
        """ sucessful validation wrong symmetric key"""
        mkey = '{"k": "ZndUSkZvVldvMEFiRzQ5VWNCdERtNkNBNnBTcTl4czNKVEVxdUZiaEdpZXZNUVJBVmRuSFREcDJYX2s3X0NxvA", "kty": "oct"}'
        message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'

        if int('%i%i' % (sys.version_info[0], sys.version_info[1])) <= 36:
            error = 'Verification failed for all signatures["Failed: [InvalidJWSSignature(\'Verification failed\',)]"]'
        else:
            error = 'Verification failed for all signatures["Failed: [InvalidJWSSignature(\'Verification failed\')]"]'
        self.assertEqual((False, error), self.signature_check(self.logger, message, mkey, json_=True))

    def test_136_helper_signature_check(self):
        """ sucessful validation wrong symmetric key without json_ flag set """
        mkey = '{"k": "ZndUSkZvVldvMEFiRzQ5VWNCdERtNkNBNnBTcTl4czNKVEVxdUZiaEdpZXZNUVJBVmRuSFREcDJYX2s3X0NxvA", "kty": "oct"}'
        message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
        if int('%i%i' % (sys.version_info[0], sys.version_info[1])) < 39:
            error = 'type object argument after ** must be a mapping, not str'
        else:
            error = 'jwcrypto.jwk.JWK() argument after ** must be a mapping, not str'
        self.assertEqual((False, error), self.signature_check(self.logger, message, mkey))

    def test_137_helper_signature_check(self):
        """ sucessful validation invalid key """
        mkey = 'invalid key'
        message = '{"payload": "eyJlIjogIkFRQUIiLCAia3R5IjogIlJTQSIsICJuIjogIm5kN3ZWUTNraW4zS3BKdTd6RUZNTlVPb0ZIQmVDUWRFRTUyOF9iOHo2djNDNnYtQS0zeUdBcTFWTjZmRTluUXdYSmNlZ2ZNdm1MczlCVVllVjZ2M1FzdGhkVFRCdW5FS1l0TVVZUVRmNkpwaHNEb1pHTkt1dnpCY2ZxSlN2TXpCNHdwa3hORm1Pa2M1QVhwRzhnQWJiTTRuS3JDQkdCQ21lZ2RJUEc3U0g3Mk9tejN6YjIwemZfZlo4dHVoUzk1eUJKdndKRjhZRGtCdDViWUV5ZnQ4aVoyWVFGVmRZZW5FMDhKOGRBUGNVQy1HYld6NmJXUm9Xc0xOT21VNkVjSndsSV9tRXRqazA5aTNlVEhOa2Vna3NrZUJOeXhlSkdtaVRtMHRtS1MwOEVvY0VQTDA1UktxSm9XNnhVcHNITDcwSzdzUVRaUDBHSUY1VXBwSkZXMnlVdyJ9", "protected": "eyJ1cmwiOiAiaHR0cDovL2FjbWUtc3J2LmJhci5sb2NhbC9hY21lL25ld2FjY291bnQiLCAiYWxnIjogIkhTMjU2IiwgImtpZCI6ICJiYXIifQ", "signature": "VXYLfPuoClsn_rhPPV8qjspZV1Q7HyX8rXv6odWYnLI"}'
        self.assertEqual((False, ''), self.signature_check(self.logger, message, mkey, json_=True))

    def test_138_fqdn_in_san_check(self):
        """ successful check one entry one match """
        fqdn = 'foo.bar.local'
        san_list = ['DNS:foo.bar.local']
        self.assertTrue(self.fqdn_in_san_check(self.logger, san_list, fqdn))

    def test_139_fqdn_in_san_check(self):
        """ successful check two entries one match """
        fqdn = 'foo.bar.local'
        san_list = ['DNS:foo1.bar.local', 'DNS:foo.bar.local']
        self.assertTrue(self.fqdn_in_san_check(self.logger, san_list, fqdn))

    def test_140_fqdn_in_san_check(self):
        """ successful check two entries no DNS one match """
        fqdn = 'foo.bar.local'
        san_list = ['IP: 10.0.0.l', 'DNS:foo.bar.local']
        self.assertTrue(self.fqdn_in_san_check(self.logger, san_list, fqdn))

    def test_141_fqdn_in_san_check(self):
        """ successful check no fqdn """
        fqdn = None
        san_list = ['IP: 10.0.0.l', 'DNS:foo.bar.local']
        self.assertFalse(self.fqdn_in_san_check(self.logger, san_list, fqdn))

    def test_142_fqdn_in_san_check(self):
        """ successful check no fqdn """
        fqdn = ''
        san_list = ['IP: 10.0.0.l', 'DNS:foo.bar.local']
        self.assertFalse(self.fqdn_in_san_check(self.logger, san_list, fqdn))

    def test_143_fqdn_in_san_check(self):
        """ successful check blank fqdn """
        fqdn = ' '
        san_list = ['IP: 10.0.0.l', 'DNS:foo.bar.local']
        self.assertFalse(self.fqdn_in_san_check(self.logger, san_list, fqdn))

    def test_144_fqdn_in_san_check(self):
        """ successful check empty san_list """
        fqdn = 'foo.bar.local'
        san_list = []
        self.assertFalse(self.fqdn_in_san_check(self.logger, san_list, fqdn))

    def test_145_fqdn_in_san_check(self):
        """ successful check two entries one match """
        fqdn = 'foo.bar.local'
        san_list = ['foo1.bar.local', 'DNS:foo.bar.local']
        self.assertTrue(self.fqdn_in_san_check(self.logger, san_list, fqdn))

    def test_146_fqdn_in_san_check(self):
        """ successful check two entries one match """
        fqdn = 'foo.bar.local'
        san_list = ['foo1.bar.local']
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.fqdn_in_san_check(self.logger, san_list, fqdn))
        self.assertIn('ERROR:test_a2c:ERROR: fqdn_in_san_check() SAN split failed: foo1.bar.local', lcm.output)

    def test_147_sha256_hash_hex(self):
        """ sha256 digest as hex file """
        self.assertEqual('2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', self.sha256_hash_hex(self.logger, 'foo'))

    def test_148_sha256_hash_hex(self):
        """ sha256 digest as hex file """
        self.assertEqual('fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9', self.sha256_hash_hex(self.logger, 'bar'))

    def test_149_sha256_hash(self):
        """ sha256 digest """
        self.assertEqual(b'LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564', self.b64_url_encode(self.logger, self.sha256_hash(self.logger, 'foo')))

    def test_150_sha256_hash(self):
        """ sha256 digest """
        self.assertEqual(b'_N4rLtula_QIYB-3If6bXDONEO5CnqBPrlURto-_j7k', self.b64_url_encode(self.logger, self.sha256_hash(self.logger, 'bar')))

    def test_151_b64_encode(self):
        """ base64 encode string """
        self.assertEqual('Zm9v', self.b64_encode(self.logger, b'foo'))

    def test_152_b64_encode(self):
        """ base64 encode string """
        self.assertEqual('YmFyMQ==', self.b64_encode(self.logger, b'bar1'))

    def test_153_b64_encode(self):
        """ base64 encode string """
        self.assertEqual('YmFyMTI=', self.b64_encode(self.logger, b'bar12'))

    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    def test_154_cert_der2pem(self, mock_load, mock_dump):
       """ test cert_der2pem """
       mock_load.return_value = 'load'
       mock_dump.return_value = 'dump'
       self.assertEqual('load', self.cert_der2pem('foo'))

    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    def test_155_cert_pem2der(self, mock_load, mock_dump):
       """ test cert_der2pem """
       mock_load.return_value = 'load'
       mock_dump.return_value = 'dump'
       self.assertEqual('load', self.cert_pem2der('foo'))

    def test_156_helper_cert_extensions_get(self):
        """ test cert_san_get for a single SAN and recode = False"""
        cert = """-----BEGIN CERTIFICATE-----
MIIEZDCCAkygAwIBAgIIe941mx0FQtAwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UE
CxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMTA0MDkxNTUy
MDBaFw0yNjA0MDkxNTUyMDBaMBgxFjAUBgNVBAMTDWVzdGNsaWVudC5lc3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAn6IqwTE1RvZUm3gelpu4tmrd
Fj8Ub98J1YeQz7qrew5iA81NeH9tR484edjcY0ieOt3e1MfxJoziWtaeqxpsfytm
VB/i+850kVZmvRCR1jhW/4AzidkVBMQiCR5erPmmheeCxbKkto0rHb7ziRA+F8/f
ZLKfLNsahEQPxDuMItyQFCOQFHh8Hfuend2NgsQKeZ1r5Czf3n5Q6NFff7HG+MDe
NDNdPB3ShgcvvNCFUS1z615/GIItfSqcWTAVaJ7436cA7yy5y4+0SvjfXYtHYfyt
hBj/5UqlUmjni8Irj5K8uEtb1YUujmvlTTbzPkhYqIkSoyr7t21Dz+gcYn49AgMB
AAGjgZ8wgZwwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUN3Z0iLv1FE17DCDBfpxW
2P+5+kIwCwYDVR0PBAQDAgO4MBMGA1UdJQQMMAoGCCsGAQUFBwMCMBgGA1UdEQQR
MA+CDWVzdGNsaWVudC5lc3QwEQYJYIZIAYb4QgEBBAQDAgWgMB4GCWCGSAGG+EIB
DQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACMAHHH4/0eA
XbS/uKsIjLN1QPnnzgjxC0xoUon8UVM0PUMH+FMg6rs21Xyl5tn5iItmvKI9c3ak
AZ00RUQKVdmJVFRUKywmfF7n5epBpXtWJrSH817NT9GOp+PO5VUTDV5VkvpVLoy7
WzThrheLKz1nC1dWowRz86tcBLAsC1zT17fsNZXQDuv4LiQQXs7QKhUU75r1Ixrd
BPeBQSP5skGpWxm8sapQSfOALoXu1pSoGIr6tqvNGuEoZGvUuWeQHG/G8c2ufL+6
lEzZBBCd6e2tErkqD/vqfCRzbLcGgSPX0HVWdkjH09nHWXI5UhNr2YgGF7YvSTKW
JfbDVlTql1BuSn2yTQtDk4E8k9BLr8WfqFSZvYrivT9Ax1n3BD9jvQL5+QRdioH1
kqNGMme0Pb43pHciX4hu9L5rGenZRmxeGXZ78uSOR+n2bGxAMw1OY7Rx/lsNSKWD
SN+7xIrwjjXO5Uthev1ecrLAK2+EpjITa6Y85ms39V4ypCEdujkKEBeVxuN8DdMJ
2GaFGluSRZeYZ0LAPfYr5sp6G6904WF+PcT0WjGenH4PJLXrAttbhhvQxXU0Q8s2
CUwUHy5OT/DW3POq7WETc+zmFGwZqiP3W9gmN0hHXsKqkNmz2RYgoH57lPS1PJb0
klGUNHG98CtsmlhrivhSTJWqSIOfyKGF
-----END CERTIFICATE-----"""
        self.assertEqual(['MAA=', 'BBQ3dnSIu/UUTXsMIMF+nFbY/7n6Qg==', 'AwIDuA==', 'MAoGCCsGAQUFBwMC', 'MA+CDWVzdGNsaWVudC5lc3Q=', 'AwIFoA==', 'Fg94Y2EgY2VydGlmaWNhdGU='], self.cert_extensions_get(self.logger, cert, recode=False))

    def test_157_helper_cert_extensions_get(self):
        """ test cert_san_get for a single SAN and recode = True"""
        cert = "MIIEZDCCAkygAwIBAgIIe941mx0FQtAwDQYJKoZIhvcNAQELBQAwKjEXMBUGA1UECxMOYWNtZTJjZXJ0aWZpZXIxDzANBgNVBAMTBnN1Yi1jYTAeFw0yMTA0MDkxNTUyMDBaFw0yNjA0MDkxNTUyMDBaMBgxFjAUBgNVBAMTDWVzdGNsaWVudC5lc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAn6IqwTE1RvZUm3gelpu4tmrdFj8Ub98J1YeQz7qrew5iA81NeH9tR484edjcY0ieOt3e1MfxJoziWtaeqxpsfytmVB/i+850kVZmvRCR1jhW/4AzidkVBMQiCR5erPmmheeCxbKkto0rHb7ziRA+F8/fZLKfLNsahEQPxDuMItyQFCOQFHh8Hfuend2NgsQKeZ1r5Czf3n5Q6NFff7HG+MDeNDNdPB3ShgcvvNCFUS1z615/GIItfSqcWTAVaJ7436cA7yy5y4+0SvjfXYtHYfythBj/5UqlUmjni8Irj5K8uEtb1YUujmvlTTbzPkhYqIkSoyr7t21Dz+gcYn49AgMBAAGjgZ8wgZwwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUN3Z0iLv1FE17DCDBfpxW2P+5+kIwCwYDVR0PBAQDAgO4MBMGA1UdJQQMMAoGCCsGAQUFBwMCMBgGA1UdEQQRMA+CDWVzdGNsaWVudC5lc3QwEQYJYIZIAYb4QgEBBAQDAgWgMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACMAHHH4/0eAXbS/uKsIjLN1QPnnzgjxC0xoUon8UVM0PUMH+FMg6rs21Xyl5tn5iItmvKI9c3akAZ00RUQKVdmJVFRUKywmfF7n5epBpXtWJrSH817NT9GOp+PO5VUTDV5VkvpVLoy7WzThrheLKz1nC1dWowRz86tcBLAsC1zT17fsNZXQDuv4LiQQXs7QKhUU75r1IxrdBPeBQSP5skGpWxm8sapQSfOALoXu1pSoGIr6tqvNGuEoZGvUuWeQHG/G8c2ufL+6lEzZBBCd6e2tErkqD/vqfCRzbLcGgSPX0HVWdkjH09nHWXI5UhNr2YgGF7YvSTKWJfbDVlTql1BuSn2yTQtDk4E8k9BLr8WfqFSZvYrivT9Ax1n3BD9jvQL5+QRdioH1kqNGMme0Pb43pHciX4hu9L5rGenZRmxeGXZ78uSOR+n2bGxAMw1OY7Rx/lsNSKWDSN+7xIrwjjXO5Uthev1ecrLAK2+EpjITa6Y85ms39V4ypCEdujkKEBeVxuN8DdMJ2GaFGluSRZeYZ0LAPfYr5sp6G6904WF+PcT0WjGenH4PJLXrAttbhhvQxXU0Q8s2CUwUHy5OT/DW3POq7WETc+zmFGwZqiP3W9gmN0hHXsKqkNmz2RYgoH57lPS1PJb0klGUNHG98CtsmlhrivhSTJWqSIOfyKGF"
        self.assertEqual(['MAA=', 'BBQ3dnSIu/UUTXsMIMF+nFbY/7n6Qg==', 'AwIDuA==', 'MAoGCCsGAQUFBwMC', 'MA+CDWVzdGNsaWVudC5lc3Q=', 'AwIFoA==', 'Fg94Y2EgY2VydGlmaWNhdGU='], self.cert_extensions_get(self.logger, cert, recode=True))

    def test_158_csr_dn_get(self):
        """" test csr_dn_get """
        csr = 'MIICjDCCAXQCAQAwFzEVMBMGA1UEAwwMdGVzdF9yZXF1ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy6VRYaXuLS/DPa+pf5IEwycpjPfZ2vTFlvjvhwu9A3yaQQn4kD33Fu4p+zorIVmsjgpkUel2104lxFeSV081YKGzOtsajzaIRZhF7mHG5aVA8cahVPHlnxT06kO8F545ZsxE6T22tCbrLJpZk4hcaQUmGcZDWZqI7CXhbi1LSuIVIAAF0lTGMsanIM97ZEtA9mhtxFd7TsLlJpmls1l8MTavFcBtAZXqAsi4LnzEbozSjaLnuXsTe7tPmOS0uOLX+EcTAH/SxkbIg3whehTzC/sVmz5STbpklq3QuudtUl/509fpSa/UQ+WFOUUC3GhiiMM813ZsbAnt1BJepKtrfQIDAQABoDAwLgYJKoZIhvcNAQkOMSEwHzAdBgNVHREEFjAUghJ0ZXN0X3JlcXVlc3QubG9jYWwwDQYJKoZIhvcNAQELBQADggEBAFcKxjJXHBVjzqF3e6fCkDbF1JnVtNyDxZB+h4b5lI7SIuA9O/+0hcl/njeFB1gJbRODws10kKkiAYLXvS/fsLJg1gdyFPmDiCd2nJhDUCBcGmVYraGhV45x67jcUmoeqSSj5KyUY9zI+v3nANvZMf+g31ORtW8PuspkiiLJiyuGzFS67DGovbcBRrM67IApO7p04VwLA0hssFUa+wF9PUWIyu9TLx+w0rNYcp3d1wkJ905TB8gwOKXeB0RwkporlOF3KEcT+ueKZE04867bjZ/ZpiuIDFnO23MsUKLKU9ebWgwYN/xzxA8sroM69y+Acpt9Zwn3vRjVlT92Ztl218Q='
        self.assertEqual('/CN=test_request', self.csr_dn_get(self.logger, csr))

    def test_159_logger_setup(self):
        """ logger setup """
        self.assertTrue(self.logger_setup(False))

    def test_160_logger_setup(self):
        """ logger setup """
        self.assertTrue(self.logger_setup(True))

    @patch('acme_srv.helper.load_config')
    def test_161_logger_setup(self, mock_load_cfg):
        """ logger setup """
        mock_load_cfg.return_value = {'Helper': {'log_format': 'foo'}}
        self.assertTrue(self.logger_setup(True))

    @patch('configparser.RawConfigParser')
    def test_162_load_config(self, mock_parser):
        """ load config """
        self.assertTrue(self.load_config(None, None, None))

    @patch.dict('os.environ', {'ACME_SRV_CONFIGFILE': 'ACME_SRV_CONFIGFILE'})
    @patch('configparser.RawConfigParser')
    def test_163_load_config(self, mock_parser):
        """ load config """
        self.assertTrue(self.load_config(None, None, None))

    def test_164_logger_info(self):
        """ logger info """
        addr = 'addr'
        url = 'url'
        data_dic = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.logger_info(self.logger, addr, url, data_dic)
        self.assertIn("INFO:test_a2c:addr url {'foo': 'bar'}", lcm.output)

    def test_165_logger_info(self):
        """ logger info replace remove Nonce in header """
        addr = 'addr'
        url = 'url'
        data_dic = {'foo': 'bar', 'header': {'Replay-Nonce': 'Replay-Nonce'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.logger_info(self.logger, addr, url, data_dic)
        self.assertIn("INFO:test_a2c:addr url {'foo': 'bar', 'header': {'Replay-Nonce': '- modified -'}}", lcm.output)

    def test_166_logger_info(self):
        """ logger info replace remnove cert """
        addr = 'addr'
        url = '/acme/cert/secret'
        data_dic = {'foo': 'bar', 'data': {'Replay-Nonce': 'Replay-Nonce'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.logger_info(self.logger, addr, url, data_dic)
        self.assertIn("INFO:test_a2c:addr /acme/cert/secret {'foo': 'bar', 'data': ' - certificate - '}", lcm.output)

    def test_167_logger_info(self):
        """ logger info replace remove token """
        addr = 'addr'
        url = 'url'
        data_dic = {'foo': 'bar', 'data': {'token': 'token'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.logger_info(self.logger, addr, url, data_dic)
        self.assertIn("INFO:test_a2c:addr url {'foo': 'bar', 'data': {'token': '- modified -'}}", lcm.output)

    def test_168_logger_info(self):
        """ logger info replace remove single token in challenges """
        addr = 'addr'
        url = 'url'
        data_dic = {'foo': 'bar', 'data': {'challenges': [{'foo1': 'bar1', 'token': 'token1'}]}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.logger_info(self.logger, addr, url, data_dic)
        self.assertIn("INFO:test_a2c:addr url {'foo': 'bar', 'data': {'challenges': [{'foo1': 'bar1', 'token': '- modified - '}]}}", lcm.output)

    def test_169_logger_info(self):
        """ logger info replace remove two token in challenges """
        addr = 'addr'
        url = 'url'
        data_dic = {'foo': 'bar', 'data': {'challenges': [{'foo1': 'bar1', 'token': 'token1'}, {'foo2': 'bar2', 'token': 'token1'}]}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.logger_info(self.logger, addr, url, data_dic)
        self.assertIn("INFO:test_a2c:addr url {'foo': 'bar', 'data': {'challenges': [{'foo1': 'bar1', 'token': '- modified - '}, {'foo2': 'bar2', 'token': '- modified - '}]}}", lcm.output)

    @patch('builtins.print')
    def test_170_print_debug(self, mock_print):
        """ test print_debug """
        self.print_debug(False, 'test')
        self.assertFalse(mock_print.called)

    @patch('builtins.print')
    def test_171_print_debug(self, mock_print):
        """ test print_debug """
        self.print_debug(True, 'test')
        self.assertTrue(mock_print.called)

    def test_172_jwk_thumbprint_get(self):
        """ test jwk_thumbprint_get with empty pubkey """
        pub_key = None
        self.assertFalse(self.jwk_thumbprint_get(self.logger, pub_key))

    @patch('jwcrypto.jwk.JWK')
    def test_173_jwk_thumbprint_get(self, mock_jwk):
        """ test jwk_thumbprint_get with  pubkey """
        pub_key = {'pub_key': 'pub_key'}
        mock_jwk = Mock()
        self.assertTrue(self.jwk_thumbprint_get(self.logger, pub_key))

    @patch('jwcrypto.jwk.JWK')
    def test_174_jwk_thumbprint_get(self, mock_jwk):
        """ test jwk_thumbprint_get with  pubkey """
        pub_key = {'pub_key': 'pub_key'}
        mock_jwk.side_effect = Exception('exc_jwk_jwk')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.jwk_thumbprint_get(self.logger, pub_key))
        self.assertIn('ERROR:test_a2c:jwk_thumbprint_get(): error: exc_jwk_jwk', lcm.output)

    @patch('socket.AF_INET')
    def test_175_allowed_gai_family(self, mock_sock):
        """ test allowed_gai_family """
        self.assertTrue(self.allowed_gai_family())

    def test_176_validate_csr(self):
        """ patched_create_connection """
        self.assertTrue(self.validate_csr(self.logger, 'oder_dic', 'csr'))

    @patch('acme_srv.helper.proxystring_convert')
    @patch('ssl.DER_cert_to_PEM_cert')
    @patch('ssl.SSLContext.wrap_socket')
    @patch('socks.socksocket')
    def test_177_servercert_get(self, mock_sock, mock_context, mock_cert, mock_convert):
        """ test servercert get """
        mock_convert.return_value = ('proxy_proto', 'proxy_addr', 'proxy_port')
        mock_sock = Mock()
        mock_context = Mock()
        mock_cert.return_value = 'foo'
        self.assertEqual('foo', self.servercert_get(self.logger, 'hostname'))

    @patch('acme_srv.helper.proxystring_convert')
    @patch('ssl.DER_cert_to_PEM_cert')
    @patch('ssl.SSLContext.wrap_socket')
    @patch('socks.socksocket')
    def test_178_servercert_get(self, mock_sock, mock_context, mock_cert, mock_convert):
        """ test servercert get with proxy """
        mock_convert.return_value = ('proxy_proto', 'proxy_addr', 'proxy_port')
        mock_sock = Mock()
        mock_context = Mock()
        mock_cert.return_value = 'foo'
        self.assertEqual('foo', self.servercert_get(self.logger, 'hostname', 443, 'proxy'))
        self.assertTrue(mock_convert.called)

    @patch('ssl.DER_cert_to_PEM_cert')
    @patch('ssl.SSLContext.wrap_socket')
    @patch('socks.socksocket')
    def test_179_servercert_get(self, mock_sock, mock_context, mock_cert):
        """ test servercert exception """
        mock_sock = Mock()
        mock_context.side_effect = Exception('exc_warp_sock')
        mock_cert.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(None, self.servercert_get(self.logger, 'hostname', 443))
        self.assertFalse(mock_cert.called)
        self.assertIn('ERROR:test_a2c:servercert_get() failed with: exc_warp_sock', lcm.output)

    @patch('dns.resolver.Resolver')
    @patch('dns.resolver.query')
    def test_180_txt_get(self, mock_resolve, mock_res):
        """ successful dns-query returning one txt record """
        resp_obj = Mock()
        resp_obj.strings = ['foo', 'bar']
        mock_resolve.return_value = [resp_obj]
        self.assertEqual(['foo'], self.txt_get(self.logger, 'foo', '10.0.0.1'))
        self.assertTrue(mock_res.called)

    @patch('dns.resolver.query')
    def test_181_txt_get(self, mock_resolve):
        """ successful dns-query returning one txt record """
        resp_obj = Mock()
        resp_obj.strings = ['foo', 'bar']
        mock_resolve.return_value = [resp_obj]
        self.assertEqual(['foo'], self.txt_get(self.logger, 'foo'))

    @patch('dns.resolver.query')
    def test_182_txt_get(self, mock_resolve):
        """ successful dns-query returning one txt record """
        resp_obj1 = Mock()
        resp_obj1.strings = ['foo1', 'bar1']
        resp_obj2 = Mock()
        resp_obj2.strings = ['foo2', 'bar2']
        mock_resolve.return_value = [resp_obj1, resp_obj2]
        self.assertEqual(['foo1', 'foo2'], self.txt_get(self.logger, 'foo'))

    @patch('dns.resolver.query')
    def test_183_txt_get(self, mock_resolve):
        """ successful dns-query returning one txt record """
        mock_resolve.side_effect = Exception('mock_resolve')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.txt_get(self.logger, 'foo'))
        self.assertIn('ERROR:test_a2c:txt_get() error: mock_resolve', lcm.output)

    def test_184_proxystring_convert(self):
        """ convert proxy_string http """
        self.assertEqual((3, 'proxy', 8080), self.proxystring_convert(self.logger, 'http://proxy:8080'))

    def test_185_proxystring_convert(self):
        """ convert proxy_string socks4 """
        self.assertEqual((1, 'proxy', 8080), self.proxystring_convert(self.logger, 'socks4://proxy:8080'))

    def test_186_proxystring_convert(self):
        """ convert proxy_string socks5 """
        self.assertEqual((2, 'proxy', 8080), self.proxystring_convert(self.logger, 'socks5://proxy:8080'))

    def test_187_proxystring_convert(self):
        """ convert proxy_string unknown protocol """
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, 'proxy', 8080), self.proxystring_convert(self.logger, 'unk://proxy:8080'))
        self.assertIn('ERROR:test_a2c:proxystring_convert(): unknown proxy protocol: unk', lcm.output)

    def test_188_proxystring_convert(self):
        """ convert proxy_string unknown protocol """
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((3, 'proxy', None), self.proxystring_convert(self.logger, 'http://proxy:ftp'))
        self.assertIn('ERROR:test_a2c:proxystring_convert(): unknown proxy port: ftp', lcm.output)

    def test_189_proxystring_convert(self):
        """ convert proxy_string porxy sting without protocol """
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None), self.proxystring_convert(self.logger, 'proxy'))
        self.assertIn('ERROR:test_a2c:proxystring_convert(): error splitting proxy_server string: proxy',  lcm.output)
        self.assertIn('ERROR:test_a2c:proxystring_convert(): proxy_proto (None), proxy_addr (None) or proxy_port (None) missing', lcm.output)

    def test_190_proxystring_convert(self):
        """ convert proxy_string porxy sting without port """
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None), self.proxystring_convert(self.logger, 'http://proxy'))
        self.assertIn('ERROR:test_a2c:proxystring_convert(): error splitting proxy into host/port: proxy', lcm.output)
        self.assertIn('ERROR:test_a2c:proxystring_convert(): proxy_proto (http), proxy_addr (None) or proxy_port (None) missing', lcm.output)

    def test_191_proxy_check(self):
        """ check proxy for empty list  """
        fqdn = 'foo.bar.local'
        proxy_list = {}
        self.assertFalse(self.proxy_check(self.logger, fqdn, proxy_list))

    def test_192_proxy_check(self):
        """ check proxy - no match """
        fqdn = 'foo.bar.local'
        proxy_list = {'foo1.bar.local': 'proxy_match'}
        self.assertFalse(self.proxy_check(self.logger, fqdn, proxy_list))

    def test_193_proxy_check(self):
        """ check proxy - single entry """
        fqdn = 'foo.bar.local'
        proxy_list = {'foo.bar.local': 'proxy_match'}
        self.assertEqual('proxy_match', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_194_proxy_check(self):
        """ check proxy  - multiple entry """
        fqdn = 'foo.bar.local'
        proxy_list = {'bar.bar.local': 'proxy_nomatch', 'foo.bar.local': 'proxy_match'}
        self.assertEqual('proxy_match', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_195_proxy_check(self):
        """ check proxy  -  multiple entrie domain match"""
        fqdn = 'foo.bar.local'
        proxy_list = {'bar.bar.local': 'proxy_nomatch', 'bar.local$': 'proxy_match'}
        self.assertEqual('proxy_match', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_196_proxy_check(self):
        """ check proxy for empty list  multiple entrie domain match"""
        fqdn = 'foo.bar.local'
        proxy_list = {'bar.local$': 'proxy_nomatch', 'foo.bar.local$': 'proxy_match'}
        self.assertEqual('proxy_match', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_197_proxy_check(self):
        """ check proxy - multiple entrie domain match"""
        fqdn = 'foo.bar.local'
        proxy_list = {'bar.local$': 'proxy_match', 'foo1.bar.local$': 'proxy_nomatch'}
        self.assertEqual('proxy_match', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_198_proxy_check(self):
        """ check proxy - wildcard """
        fqdn = 'foo.bar.local'
        proxy_list = {'foo1.bar.local$': 'proxy_nomatch', '*.bar.local$': 'proxy_match'}
        self.assertEqual('proxy_match', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_199_proxy_check(self):
        """ check proxy - wildcard """
        fqdn = 'foo.bar.local'
        proxy_list = {'.local$': 'proxy_nomatch', '*.bar.local$': 'proxy_match'}
        self.assertEqual('proxy_match', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_200_proxy_check(self):
        """ check proxy - wildcard """
        fqdn = 'local'
        proxy_list = {'local$': 'proxy_match', '*.bar.local$': 'proxy_no_match'}
        self.assertEqual('proxy_match', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_201_proxy_check(self):
        """ check proxy - wildcard """
        fqdn = 'foo.bar.local'
        proxy_list = {'*': 'wildcard', 'notlocal$': 'proxy_no_match', '*.notbar.local$': 'proxy_no_match'}
        self.assertEqual('wildcard', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_202_handle_exception(self):
        """ test exception handler """
        exc_type = FakeDBStore
        exc_value = Mock()
        exc_traceback = Mock()
        self.handle_exception(exc_type, exc_value, exc_traceback)

    def test_203_proxy_check(self):
        """ check proxy - wildcard """
        fqdn = 'foo.bar.local'
        proxy_list = {'*.bar.local$': 'proxy_match'}
        self.assertEqual('proxy_match', self.proxy_check(self.logger, fqdn, proxy_list))

    def test_204_ca_handler_load(self):
        """ test ca_handler_load """
        config_dic = {'foo': 'bar'}
        self.assertFalse(self.ca_handler_load(self.logger, config_dic))

    def test_205_ca_handler_load(self):
        """ test ca_handler_load """
        config_dic = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.ca_handler_load(self.logger, config_dic))
        self.assertIn('ERROR:test_a2c:Helper.ca_handler_load(): CAhandler configuration missing in config file', lcm.output)

    @patch('importlib.import_module')
    def test_206_ca_handler_load(self, mock_imp):
        """ test ca_handler_load """
        config_dic = {'CAhandler': {'foo': 'bar'}}
        mock_imp.side_effect = Exception('exc_mock_imp')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.ca_handler_load(self.logger, config_dic))
        self.assertIn('CRITICAL:test_a2c:Helper.ca_handler_load(): loading default CAhandler failed with err: exc_mock_imp', lcm.output)

    @patch('importlib.import_module')
    def test_207_ca_handler_load(self, mock_imp):
        """ test ca_handler_load """
        config_dic = {'CAhandler': {'foo': 'bar'}}
        mock_imp.return_value = 'foo'
        self.assertEqual('foo', self.ca_handler_load(self.logger, config_dic))

    @patch('importlib.util')
    def test_208_ca_handler_load(self, mock_util):
        """ test ca_handler_load """
        config_dic = {'CAhandler': {'handler_file': 'foo'}}
        mock_util.module_from_spec = Mock(return_value='foo')
        self.assertEqual('foo', self.ca_handler_load(self.logger, config_dic))

    @patch('importlib.import_module')
    @patch('importlib.util')
    def test_209_ca_handler_load(self, mock_util, mock_imp):
        """ test ca_handler_load """
        config_dic = {'CAhandler': {'handler_file': 'foo'}}
        mock_util.module_from_spec.side_effect = Exception('exc_mock_util')
        mock_imp.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('foo', self.ca_handler_load(self.logger, config_dic))
        self.assertIn('CRITICAL:test_a2c:Helper.ca_handler_load(): loading CAhandler configured in cfg failed with err: exc_mock_util', lcm.output)

    @patch('importlib.import_module')
    @patch('importlib.util')
    def test_210_ca_handler_load(self, mock_util, mock_imp):
        """ test ca_handler_load """
        config_dic = {'CAhandler': {'handler_file': 'foo'}}
        mock_util.module_from_spec.side_effect = Exception('exc_mock_util')
        mock_imp.side_effect = Exception('exc_mock_imp')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.ca_handler_load(self.logger, config_dic))
        self.assertIn('CRITICAL:test_a2c:Helper.ca_handler_load(): loading default CAhandler failed with err: exc_mock_imp', lcm.output)

    def test_211_eab_handler_load(self):
        """ test eab_handler_load """
        config_dic = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.eab_handler_load(self.logger, config_dic))
        self.assertIn('ERROR:test_a2c:Helper.eab_handler_load(): EABhandler configuration missing in config file', lcm.output)

    @patch('importlib.import_module')
    def test_212_eab_handler_load(self, mock_imp):
        """ test eab_handler_load """
        config_dic = {'EABhandler': {'foo': 'bar'}}
        mock_imp.side_effect = Exception('exc_mock_imp')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.eab_handler_load(self.logger, config_dic))
        self.assertIn('CRITICAL:test_a2c:Helper.eab_handler_load(): loading default EABhandler failed with err: exc_mock_imp', lcm.output)

    @patch('importlib.import_module')
    def test_213_eab_handler_load(self, mock_imp):
        """ test eab_handler_load """
        config_dic = {'EABhandler': {'foo': 'bar'}}
        mock_imp.return_value = 'foo'
        self.assertEqual('foo', self.eab_handler_load(self.logger, config_dic))

    @patch('importlib.util')
    def test_214_eab_handler_load(self, mock_util):
        """ test eab_handler_load """
        config_dic = {'EABhandler': {'eab_handler_file': 'foo'}}
        mock_util.module_from_spec = Mock(return_value='foo')
        self.assertEqual('foo', self.eab_handler_load(self.logger, config_dic))

    @patch('importlib.import_module')
    @patch('importlib.util')
    def test_215_eab_handler_load(self, mock_util, mock_imp):
        """ test eab_handler_load """
        config_dic = {'EABhandler': {'eab_handler_file': 'foo'}}
        mock_util.module_from_spec.side_effect = Exception('exc_mock_util')
        mock_imp.return_value = 'foo'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('foo', self.eab_handler_load(self.logger, config_dic))
        self.assertIn('CRITICAL:test_a2c:Helper.eab_handler_load(): loading EABhandler configured in cfg failed with err: exc_mock_util', lcm.output)

    @patch('importlib.import_module')
    @patch('importlib.util')
    def test_216_eab_handler_load(self, mock_util, mock_imp):
        """ test eab_handler_load """
        config_dic = {'EABhandler': {'eab_handler_file': 'foo'}}
        mock_util.module_from_spec.side_effect = Exception('exc_mock_util')
        mock_imp.side_effect = Exception('exc_mock_imp')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.eab_handler_load(self.logger, config_dic))
        self.assertIn('CRITICAL:test_a2c:Helper.eab_handler_load(): loading default EABhandler failed with err: exc_mock_imp', lcm.output)

    def test_217_hooks_load(self):
        """ test hooks load with empty config_dic """
        config_dic = {}
        self.assertFalse(self.hooks_load(self.logger, config_dic))

    def test_218_hooks_load(self):
        """ test hooks load with hooks but no hooks_file in config_dic """
        config_dic = {'Hooks': {'foo': 'bar'}}
        self.assertFalse(self.hooks_load(self.logger, config_dic))

    @patch('importlib.util')
    def test_219_hooks_load(self, mock_util):
        """ test hooks load with hooks but no hooks_file in  config_dic """
        config_dic = {'Hooks': {'hooks_file': 'bar'}}
        mock_util.module_from_spec = Mock(return_value='foo')
        self.assertEqual('foo', self.hooks_load(self.logger, config_dic))
        self.assertTrue(mock_util.spec_from_file_location.called)
        self.assertTrue(mock_util.module_from_spec.called)

    @patch('importlib.util')
    def test_220_hooks_load(self, mock_util):
        """ test hooks load with hooks but no hooks_file in  config_dic """
        config_dic = {'Hooks': {'hooks_file': 'bar'}}
        mock_util.module_from_spec = Exception('exc_mock_util')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.hooks_load(self.logger, config_dic))
        self.assertIn("CRITICAL:test_a2c:Helper.hooks_load(): loading Hooks configured in cfg failed with err: 'Exception' object is not callable", lcm.output)

    def test_221_error_dic_get(self):
        """ test error_dic_get """
        result = {
            'badcsr': 'urn:ietf:params:acme:error:badCSR',
            'malformed': 'urn:ietf:params:acme:error:malformed',
            'invalidcontact': 'urn:ietf:params:acme:error:invalidContact',
            'accountdoesnotexist': 'urn:ietf:params:acme:error:accountDoesNotExist',
            'unauthorized': 'urn:ietf:params:acme:error:unauthorized',
            'externalaccountrequired': 'urn:ietf:params:acme:error:externalAccountRequired',
            'badpubkey': 'urn:ietf:params:acme:error:badPublicKey',
            'useractionrequired': 'urn:ietf:params:acme:error:userActionRequired',
            'alreadyrevoked': 'urn:ietf:params:acme:error:alreadyRevoked',
            'serverinternal': 'urn:ietf:params:acme:error:serverInternal',
            'unsupportedidentifier': 'urn:ietf:params:acme:error:unsupportedIdentifier',
            'ordernotready': 'urn:ietf:params:acme:error:orderNotReady',
            'ratelimited': 'urn:ietf:params:acme:error:rateLimited',
            'badrevocationreason': 'urn:ietf:params:acme:error:badRevocationReason'}
        self.assertEqual(result, self.error_dic_get(self.logger))

    def test_222_logger_nonce_modify(self):
        """ test _logger_nonce_modify() """
        data_dic = {'foo': 'bar'}
        self.assertEqual({'foo': 'bar'}, self.logger_nonce_modify(data_dic))

    def test_223_logger_nonce_modify(self):
        """ test _logger_nonce_modify() """
        data_dic = {'foo': 'bar', 'header': {'foo': 'bar'}}
        self.assertEqual({'foo': 'bar', 'header': {'foo': 'bar'}}, self.logger_nonce_modify(data_dic))

    def test_224_logger_nonce_modify(self):
        """ test _logger_nonce_modify() """
        data_dic = {'foo': 'bar', 'header': {'Replay-Nonce': 'bar'}}
        self.assertEqual({'foo': 'bar', 'header': {'Replay-Nonce': '- modified -'}}, self.logger_nonce_modify(data_dic))

    def test_225_logger_certificate_modify(self):
        """ test _logger_certificate_modify() """
        data_dic = {'data': 'bar'}
        self.assertEqual({'data': 'bar'}, self.logger_certificate_modify(data_dic, 'locator'))

    def test_226_logger_certificate_modify(self):
        """ test _logger_certificate_modify() """
        data_dic = {'data': 'bar'}
        self.assertEqual({'data': ' - certificate - '}, self.logger_certificate_modify(data_dic, 'foo/acme/cert'))

    def test_227_logger_token_modify(self):
        """ test _logger_token_modify() """
        data_dic = {'data': 'bar'}
        self.assertEqual({'data': 'bar'}, self.logger_token_modify(data_dic))

    def test_228_logger_token_modify(self):
        """ test _logger_token_modify() """
        data_dic = {'data': {'token': 'token'}}
        self.assertEqual({'data': {'token': '- modified -'}}, self.logger_token_modify(data_dic))

    def test_229_logger_challenges_modify(self):
        """ test _logger_challenges_modify() """
        data_dic = {'data': 'bar'}
        self.assertEqual({'data': 'bar'}, self.logger_challenges_modify(data_dic))

    def test_230_logger_challenges_modify(self):
        """ test _logger_challenges_modify() """
        data_dic = {'data': {'challenges': [{'token': 'token1'}]}}
        self.assertEqual({'data': {'challenges': [{'token': '- modified - '}]}}, self.logger_challenges_modify(data_dic))

    def test_231_logger_challenges_modify(self):
        """ test _logger_challenges_modify() """
        data_dic = {'data': {'challenges': [{'token': 'token1'}, {'token': 'token2'}]}}
        self.assertEqual({'data': {'challenges': [{'token': '- modified - '}, {'token': '- modified - '}]}}, self.logger_challenges_modify(data_dic))

if __name__ == '__main__':
    unittest.main()
