#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, R0913, W0212
import sys
import os
import unittest
from unittest.mock import patch, mock_open, Mock, MagicMock
# from OpenSSL import crypto
import shutil

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class FakeDBStore(object):
    """ face DBStore class needed for mocking """
    # pylint: disable=W0107, R0903
    pass

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """
    def setUp(self):
        """ setup unittest """
        models_mock = MagicMock()
        models_mock.acme_srv.db_handler.DBstore.return_value = FakeDBStore
        modules = {'acme_srv.db_handler': models_mock}
        patch.dict('sys.modules', modules).start()
        import logging
        from examples.ca_handler.acme_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)

    def tearDown(self):
        """ teardown """
        pass

    def test_001___init__(self):
        """ init """
        self.assertTrue(self.cahandler.__enter__())

    def test_002___exit__(self):
        """ exit """
        self.assertFalse(self.cahandler.__exit__())

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_003__config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "CAhandler" section is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_004__config_load(self, mock_load_cfg):
        """ test _config_load empty cahandler section """
        mock_load_cfg.return_value = {'CAhandler': {}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_005__config_load(self, mock_load_cfg):
        """ test _config_load unknown values """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_006__config_load(self, mock_load_cfg):
        """ test _config_load key_file value """
        mock_load_cfg.return_value = {'CAhandler': {'acme_keyfile': 'key_file'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('key_file', self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_007__config_load(self, mock_load_cfg):
        """ test _config_load url value """
        mock_load_cfg.return_value = {'CAhandler': {'acme_url': 'url'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertEqual('url', self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_008__config_load(self, mock_load_cfg):
        """ test _config_load account values """
        mock_load_cfg.return_value = {'CAhandler': {'acme_account': 'acme_account'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertEqual('acme_account', self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_009__config_load(self, mock_load_cfg):
        """ test _config_load key_size """
        mock_load_cfg.return_value = {'CAhandler': {'acme_account_keysize': 'acme_account_keysize'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual('acme_account_keysize', self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_010__config_load(self, mock_load_cfg):
        """ test _config_load email """
        mock_load_cfg.return_value = {'CAhandler': {'acme_account_email': 'acme_account_email'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'directory_path': '/directory', 'acct_path' : '/acme/acct/'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertEqual('acme_account_email', self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_011__config_load(self, mock_load_cfg):
        """ test _config_load email """
        mock_load_cfg.return_value = {'CAhandler': {'directory_path': 'directory_path'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'acct_path': '/acme/acct/', 'directory_path': 'directory_path'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_012__config_load(self, mock_load_cfg):
        """ test _config_load email """
        mock_load_cfg.return_value = {'CAhandler': {'account_path': 'account_path'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'acct_path': 'account_path', 'directory_path': '/directory'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_013__config_load(self, mock_load_cfg):
        """ test _config_load allowlist """
        mock_load_cfg.return_value = {'CAhandler': {'allowed_domainlist': '["foo", "bar"]'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'acct_path': '/acme/acct/', 'directory_path': '/directory'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertEqual(['foo', 'bar'], self.cahandler.allowed_domainlist)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_014__config_load(self, mock_load_cfg):
        """ test _config_load allowlist - failed json parse """
        mock_load_cfg.return_value = {'CAhandler': {'allowed_domainlist': 'foo'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'acct_path': '/acme/acct/', 'directory_path': '/directory'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): failed to parse allowed_domainlist: Expecting value: line 1 column 1 (char 0)', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_015__config_load(self, mock_load_cfg):
        """ test _config_load allowlist - failed json parse """
        mock_load_cfg.return_value = {'CAhandler': {'eab_kid': 'eab_kid'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'acct_path': '/acme/acct/', 'directory_path': '/directory'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertEqual('eab_kid', self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.load_config')
    def test_016__config_load(self, mock_load_cfg):
        """ test _config_load allowlist - failed json parse """
        mock_load_cfg.return_value = {'CAhandler': {'eab_hmac_key': 'eab_hmac_key'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.keyfile)
        self.assertFalse(self.cahandler.url)
        self.assertFalse(self.cahandler.account)
        self.assertEqual({'acct_path': '/acme/acct/', 'directory_path': '/directory'}, self.cahandler.path_dic)
        self.assertEqual(2048, self.cahandler.key_size)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.allowed_domainlist)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertEqual('eab_hmac_key', self.cahandler.eab_hmac_key)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_keyfile" parameter is missing in config file', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load() configuration incomplete: "acme_url" parameter is missing in config file', lcm.output)

    def test_017__challenge_filter(self):
        """ test _challenge_filter single http """
        challenge1 = Mock(return_value='foo')
        challenge1.chall.typ = 'http-01'
        challenge1.chall.value = 'value-01'
        authz = Mock()
        authz.body.challenges = [challenge1]
        self.assertEqual('http-01', self.cahandler._challenge_filter(authz).chall.typ)
        self.assertEqual('value-01', self.cahandler._challenge_filter(authz).chall.value)

    def test_018__challenge_filter(self):
        """ test _challenge_filter dns and http """
        challenge1 = Mock(return_value='foo')
        challenge1.chall.typ = 'dns-01'
        challenge1.chall.value = 'value-01'
        challenge2 = Mock(return_value='foo')
        challenge2.chall.typ = 'http-01'
        challenge2.chall.value = 'value-02'
        authz = Mock()
        authz.body.challenges = [challenge1, challenge2]
        self.assertEqual('http-01', self.cahandler._challenge_filter(authz).chall.typ)
        self.assertEqual('value-02', self.cahandler._challenge_filter(authz).chall.value)

    def test_019__challenge_filter(self):
        """ test _challenge_filter double http to test break """
        challenge1 = Mock(return_value='foo')
        challenge1.chall.typ = 'http-01'
        challenge1.chall.value = 'value-01'
        challenge2 = Mock(return_value='foo')
        challenge2.chall.typ = 'http-01'
        challenge2.chall.value = 'value-02'
        authz = Mock()
        authz.body.challenges = [challenge1, challenge2]
        self.assertEqual('http-01', self.cahandler._challenge_filter(authz).chall.typ)
        self.assertEqual('value-01', self.cahandler._challenge_filter(authz).chall.value)

    def test_020__challenge_filter(self):
        """ test _challenge_filter no http challenge """
        challenge1 = Mock(return_value='foo')
        challenge1.chall.typ = 'type-01'
        challenge1.chall.value = 'value-01'
        challenge2 = Mock(return_value='foo')
        challenge2.chall.typ = 'type-02'
        challenge2.chall.value = 'value-02'
        authz = Mock()
        authz.body.challenges = [challenge1, challenge2]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._challenge_filter(authz))
        self.assertIn('ERROR:test_a2c:CAhandler._challenge_filter() ended. Could not find challenge of type http-01', lcm.output)

    def test_021__challenge_store(self):
        """ test _challenge_store() no challenge_content """
        # mock_add.return_value = 'ff'
        self.cahandler._challenge_store('challenge_name', None)
        self.assertFalse(self.cahandler.dbstore.cahandler_add.called)

    def test_022__challenge_store(self):
        """ test _challenge_store() no challenge_content """
        # mock_add.return_value = 'ff'
        self.cahandler._challenge_store(None, 'challenge_content')
        self.assertFalse(self.cahandler.dbstore.cahandler_add.called)

    def test_023__challenge_store(self):
        """ test _challenge_store() """
        self.cahandler._challenge_store('challenge_name', 'challenge_content')
        self.assertTrue(self.cahandler.dbstore.cahandler_add.called)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter')
    def test_024__http_challenge_info(self, mock_filter):
        """ test _http_challenge_info - all ok """
        response = Mock()
        response.chall.validation = Mock(return_value='foo.bar')
        mock_filter.return_value = response
        self.assertIn('foo', self.cahandler._http_challenge_info('authzr', 'user_key')[0])
        self.assertIn('foo.bar', self.cahandler._http_challenge_info('authzr', 'user_key')[1])

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter')
    def test_025__http_challenge_info(self, mock_filter):
        """ test _http_challenge_info - wrong split """
        response = Mock()
        response.chall.validation = Mock(return_value='foobar')
        mock_filter.return_value = response
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            response = self.cahandler._http_challenge_info('authzr', 'user_key')
        self.assertFalse(response[0])
        self.assertIn('foobar', response[1])
        self.assertIn('ERROR:test_a2c:CAhandler._http_challenge_info() challenge split failed: foobar', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter')
    def test_026__http_challenge_info(self, mock_filter):
        """ test _http_challenge_info - wrong split """
        response = Mock()
        response.chall.validation = Mock(return_value='foobar')
        mock_filter.return_value = response
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None), self.cahandler._http_challenge_info(None, 'user_key'))
        self.assertIn('ERROR:test_a2c:CAhandler._http_challenge_info() authzr is missing', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_filter')
    def test_027__http_challenge_info(self, mock_filter):
        """ test _http_challenge_info - wrong split """
        response = Mock()
        response.chall.validation = Mock(return_value='foobar')
        mock_filter.return_value = response
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None), self.cahandler._http_challenge_info('authzr', None))
        self.assertIn('ERROR:test_a2c:CAhandler._http_challenge_info() userkey is missing', lcm.output)

    @patch('josepy.JWKRSA')
    def test_028__key_generate(self, mock_key):
        """ test _key_generate()  """
        mock_key.return_value = 'key'
        self.assertEqual('key', self.cahandler._key_generate())

    @patch('josepy.JWKRSA.json_loads')
    @patch("builtins.open", mock_open(read_data='csv_dump'), create=True)
    @patch('os.path.exists')
    def test_029__user_key_load(self, mock_file, mock_key):
        """ test user_key_load for an existing file """
        mock_file.return_value = True
        mock_key.return_value = 'loaded_key'
        self.assertEqual('loaded_key', self.cahandler._user_key_load())
        self.assertTrue(mock_key.called)

    @patch('json.dumps')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._key_generate')
    @patch("builtins.open", mock_open(read_data='csv_dump'), create=True)
    @patch('os.path.exists')
    def test_030__user_key_load(self, mock_file, mock_key, mock_json):
        """ test user_key_load for an existing file """
        mock_file.return_value = False
        mock_key.to_json.return_value = {'foo': 'generate_key'}
        mock_json.return_value = 'foo'
        self.assertTrue(self.cahandler._user_key_load())
        self.assertTrue(mock_key.called)
        self.assertTrue(mock_json.called)

    @patch('acme.messages')
    def test_031__account_register(self, mock_messages):
        """ test account register existing account - no replacement """
        response = Mock()
        response.uri = 'uri'
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value = response)
        mock_messages = Mock()
        directory = {'newAccount': 'newAccount'}
        self.cahandler.url = 'url'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('uri', self.cahandler._account_register(acmeclient, 'user_key', directory).uri)
        self.assertIn('INFO:test_a2c:acme-account id is uri. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups', lcm.output)
        self.assertEqual('uri', self.cahandler.account)

    @patch('acme.messages')
    def test_032__account_register(self, mock_messages):
        """ test account register existing account - url replacement """
        response = Mock()
        response.uri = 'urluri'
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value = response)
        mock_messages = Mock()
        directory = {'newAccount': 'newAccount'}
        self.cahandler.url = 'url'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('urluri', self.cahandler._account_register(acmeclient, 'user_key', directory).uri)
        self.assertIn('INFO:test_a2c:acme-account id is uri. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups', lcm.output)
        self.assertEqual('uri', self.cahandler.account)

    @patch('acme.messages')
    def test_033__account_register(self, mock_messages):
        """ test account register existing account - acct_path replacement """
        response = Mock()
        response.uri = 'acct_pathuri'
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value = response)
        mock_messages = Mock()
        directory = {'newAccount': 'newAccount'}
        self.cahandler.url = 'url'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('acct_pathuri', self.cahandler._account_register(acmeclient, 'user_key', directory).uri)
        self.assertIn('INFO:test_a2c:acme-account id is uri. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups', lcm.output)
        self.assertEqual('uri', self.cahandler.account)

    @patch('acme.messages')
    def test_034__account_register(self, mock_messages):
        """ test account register existing account - with email """
        response = Mock()
        response.uri = 'newuri'
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value = response)
        mock_messages = Mock()
        self.cahandler.email = 'email'
        self.cahandler.url = 'url'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual('newuri', self.cahandler._account_register(acmeclient, 'user_key', 'directory').uri)
        self.assertIn('INFO:test_a2c:acme-account id is newuri. Please add an corresponding acme_account parameter to your acme_srv.cfg to avoid unnecessary lookups', lcm.output)
        self.assertEqual('newuri', self.cahandler.account)

    @patch('acme.messages')
    def test_035__account_register(self, mock_messages):
        """ test account register existing account - no email """
        response = Mock()
        response.uri = 'newuri'
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value = response)
        mock_messages = Mock()
        self.cahandler.url = 'url'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._account_register(acmeclient, 'user_key', 'directory'))
        self.assertFalse(self.cahandler.account)

    @patch('acme.messages')
    def test_036__account_register(self, mock_messages):
        """ test account register existing account - no url """
        response = Mock()
        response.uri = 'newuri'
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value = response)
        mock_messages = Mock()
        self.cahandler.email = 'email'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        self.assertEqual('newuri', self.cahandler._account_register(acmeclient, 'user_key', 'directory').uri)
        self.assertFalse(self.cahandler.account)

    @patch('acme.messages')
    def test_037__account_register(self, mock_messages):
        """ test account register existing account - wrong pathdic """
        response = Mock()
        response.uri = 'newuri'
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value = response)
        mock_messages = Mock()
        self.cahandler.email = 'email'
        self.cahandler.path_dic = {'acct_path1': 'acct_path'}
        self.cahandler.url = 'url'
        self.assertEqual('newuri', self.cahandler._account_register(acmeclient, 'user_key', 'directory').uri)
        self.assertFalse(self.cahandler.account)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._zerossl_eab_get')
    @patch('acme.messages')
    def test_038__account_register(self, mock_messages, mock_eab):
        """ test account register existing account - normal url """
        response = Mock()
        response.uri = 'urluri'
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value = response)
        mock_messages = Mock()
        self.cahandler.email = 'email'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        self.cahandler.url = 'url'
        self.assertEqual('urluri', self.cahandler._account_register(acmeclient, 'user_key', 'directory').uri)
        self.assertEqual('uri', self.cahandler.account)
        self.assertFalse(mock_eab.called)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._zerossl_eab_get')
    @patch('acme.messages')
    def test_039__account_register(self, mock_messages, mock_eab):
        """ test account register existing account - zerossl.com url """
        response = Mock()
        response.uri = 'zerossl.comuri'
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value = response)
        mock_messages = Mock()
        self.cahandler.email = 'email'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        self.cahandler.url = 'zerossl.com'
        self.cahandler.url_dic = {'host': 'acme.zerossl.com'}
        self.assertEqual('zerossl.comuri', self.cahandler._account_register(acmeclient, 'user_key', 'directory').uri)
        self.assertEqual('uri', self.cahandler.account)
        self.assertTrue(mock_eab.called)

    @patch('examples.ca_handler.acme_ca_handler.messages.ExternalAccountBinding.from_data')
    @patch('acme.messages')
    def test_040__account_register(self, mock_messages, mock_eab):
        """ test account register existing account - zerossl.com url """
        response = Mock()
        response.uri = 'urluri'
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value = response)
        mock_messages = Mock()
        self.cahandler.email = 'email'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        self.cahandler.url = 'url'
        self.assertEqual('urluri', self.cahandler._account_register(acmeclient, 'user_key', 'directory').uri)
        self.assertEqual('uri', self.cahandler.account)
        self.assertFalse(mock_eab.called)

    @patch('examples.ca_handler.acme_ca_handler.messages.ExternalAccountBinding.from_data')
    @patch('acme.messages')
    def test_041__account_register(self, mock_messages, mock_eab):
        """ test account register existing account - zerossl.com url """
        response = Mock()
        response.uri = 'urluri'
        acmeclient = Mock()
        acmeclient.new_account = Mock(return_value = response)
        mock_eab.return_value = Mock()
        self.cahandler.email = 'email'
        self.cahandler.path_dic = {'acct_path': 'acct_path'}
        self.cahandler.url = 'url'
        self.cahandler.eab_kid = 'kid'
        self.cahandler.eab_hmac_key = 'hmac_key'
        self.assertEqual('urluri', self.cahandler._account_register(acmeclient, 'user_key', 'directory').uri)
        self.assertEqual('uri', self.cahandler.account)
        self.assertTrue(mock_eab.called)

    def test_042_trigger(self):
        """ test trigger """
        self.assertEqual(('Not implemented', None, None), self.cahandler.trigger('payload'))

    def test_043_poll(self):
        """ test poll """
        self.assertEqual(('Not implemented', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier','csr'))

    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_store')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_info')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._account_register')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._user_key_load')
    @patch('acme.client.ClientV2.poll_and_finalize')
    @patch('acme.client.ClientV2.answer_challenge')
    @patch('acme.client.ClientV2.new_order')
    @patch('acme.client.ClientNetwork')
    @patch('acme.messages')
    def test_044_enroll(self, mock_messages, mock_clientnw, mock_c2o, mock_ach, mock_pof, mock_key, mock_reg, mock_cinfo, mock_store, mock_dumpcert, mock_loadcert):
        """ test enroll with no account configured """
        mock_key.return_value = 'key'
        mock_messages = Mock()
        response = Mock()
        response.body.status = 'valid'
        mock_reg.return_value = response
        mock_norder = Mock()
        mock_norder.authorizations = ['1', '2']
        mock_c2o.return_value = mock_norder
        chall = Mock()
        mock_ach.return_value = 'auth_response'
        mock_cinfo.return_value = ('challenge_name', 'challenge_content', chall)
        resp_pof = Mock()
        resp_pof.fullchain_pem = 'fullchain'
        mock_pof.return_value = resp_pof
        mock_dumpcert.return_value = b'mock_dumpcert'
        mock_loadcert.return_value = 'mock_loadcert'
        self.assertEqual((None, 'fullchain', 'bW9ja19kdW1wY2VydA==', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_ach.called)
        self.assertTrue(mock_reg.called)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._csr_check')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_store')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_info')
    @patch('acme.client.ClientV2.query_registration')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._user_key_load')
    @patch('acme.client.ClientV2.poll_and_finalize')
    @patch('acme.client.ClientV2.answer_challenge')
    @patch('acme.client.ClientV2.new_order')
    @patch('acme.client.ClientNetwork')
    @patch('acme.messages')
    def test_045_enroll(self, mock_messages, mock_clientnw, mock_c2o, mock_ach, mock_pof, mock_key, mock_reg, mock_cinfo, mock_store, mock_dumpcert, mock_loadcert, mock_csrchk):
        """ test enroll with existing account """
        self.cahandler.account = 'account'
        mock_key.return_value = 'key'
        mock_messages = Mock()
        response = Mock()
        response.body.status = 'valid'
        mock_reg.return_value = response
        mock_norder = Mock()
        mock_norder.authorizations = ['1', '2']
        mock_c2o.return_value = mock_norder
        chall = Mock()
        mock_ach.return_value = 'auth_response'
        mock_cinfo.return_value = ('challenge_name', 'challenge_content', chall)
        resp_pof = Mock()
        resp_pof.fullchain_pem = 'fullchain'
        mock_pof.return_value = resp_pof
        mock_dumpcert.return_value = b'mock_dumpcert'
        mock_loadcert.return_value = 'mock_loadcert'
        mock_csrchk.return_value = True
        self.assertEqual((None, 'fullchain', 'bW9ja19kdW1wY2VydA==', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_ach.called)
        self.assertTrue(mock_reg.called)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._csr_check')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_store')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_info')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._account_register')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._user_key_load')
    @patch('acme.client.ClientV2.poll_and_finalize')
    @patch('acme.client.ClientV2.answer_challenge')
    @patch('acme.client.ClientV2.new_order')
    @patch('acme.client.ClientNetwork')
    @patch('acme.messages')
    def test_046_enroll(self, mock_messages, mock_clientnw, mock_c2o, mock_ach, mock_pof, mock_key, mock_reg, mock_cinfo, mock_store, mock_dumpcert, mock_loadcert, mock_csrchk):
        """ test enroll with bodystatus invalid """
        mock_key.return_value = 'key'
        mock_messages = Mock()
        response = Mock()
        response.body.status = 'invalid'
        response.body.error = 'error'
        mock_reg.return_value = response
        mock_norder = Mock()
        mock_norder.authorizations = ['1', '2']
        mock_c2o.return_value = mock_norder
        chall = Mock()
        mock_ach.return_value = 'auth_response'
        mock_cinfo.return_value = ('challenge_name', 'challenge_content', chall)
        resp_pof = Mock()
        resp_pof.fullchain_pem = 'fullchain'
        mock_pof.return_value = resp_pof
        mock_dumpcert.return_value = b'mock_dumpcert'
        mock_loadcert.return_value = 'mock_loadcert'
        mock_csrchk.return_value = True
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Bad ACME account: error', None, None, None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_ach.called)
        self.assertTrue(mock_reg.called)
        self.assertIn('ERROR:test_a2c:CAhandler.enroll: Bad ACME account: error', lcm.output)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._csr_check')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_store')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._http_challenge_info')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._account_register')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._user_key_load')
    @patch('acme.client.ClientV2.poll_and_finalize')
    @patch('acme.client.ClientV2.answer_challenge')
    @patch('acme.client.ClientV2.new_order')
    @patch('acme.client.ClientNetwork')
    @patch('acme.messages')
    def test_047_enroll(self, mock_messages, mock_clientnw, mock_c2o, mock_ach, mock_pof, mock_key, mock_reg, mock_cinfo, mock_store, mock_dumpcert, mock_loadcert, mock_csrchk):
        """ test enroll with no fullchain """
        mock_key.return_value = 'key'
        mock_messages = Mock()
        response = Mock()
        response.body.status = 'valid'
        mock_reg.return_value = response
        mock_norder = Mock()
        mock_norder.authorizations = ['1', '2']
        mock_c2o.return_value = mock_norder
        chall = Mock()
        mock_ach.return_value = 'auth_response'
        mock_cinfo.return_value = ('challenge_name', 'challenge_content', chall)
        resp_pof = Mock()
        resp_pof.fullchain_pem = None
        resp_pof.error = 'order_error'
        mock_pof.return_value = resp_pof
        mock_dumpcert.return_value = b'mock_dumpcert'
        mock_loadcert.return_value = 'mock_loadcert'
        mock_csrchk.return_value = True
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Error getting certificate: order_error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll: Error getting certificate: order_error', lcm.output)
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_ach.called)
        self.assertTrue(mock_reg.called)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._csr_check')
    @patch('acme.client.ClientV2.query_registration')
    @patch('acme.client.ClientNetwork')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._account_register')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_store')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._user_key_load')
    def test_048_enroll(self, mock_key, mock_store, mock_reg, mock_nw, mock_newreg, mock_csrchk):
        """ test enroll exception during enrollment  """
        mock_csrchk.return_value = True
        mock_key.side_effect = Exception('ex_user_key_load')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('ex_user_key_load', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll: error: ex_user_key_load', lcm.output)
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_nw.called)
        self.assertFalse(mock_reg.called)
        self.assertFalse(mock_newreg.called)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._csr_check')
    @patch('acme.client.ClientV2.query_registration')
    @patch('acme.client.ClientNetwork')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._account_register')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._challenge_store')
    @patch('examples.ca_handler.acme_ca_handler.CAhandler._user_key_load')
    def test_049_enroll(self, mock_key, mock_store, mock_reg, mock_nw, mock_newreg, mock_csrchk):
        """ test enroll exception during enrollment  """
        mock_csrchk.return_value = False
        mock_key.side_effect = Exception('ex_user_key_load')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('CSR rejected. Either CN or SANs are not allowed by policy', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll: CSR rejected. Either CN or SANs are not allowed by policy.', lcm.output)
        self.assertFalse(mock_store.called)
        self.assertFalse(mock_nw.called)
        self.assertFalse(mock_reg.called)
        self.assertFalse(mock_newreg.called)



    @patch('acme.messages')
    def test_050__account_lookup(self, mock_messages):
        """ test account register existing account - no replacement """
        response = Mock()
        response.uri = 'urluriacc_info'
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value = response)
        mock_messages = Mock()
        directory = {'newAccount': 'newAccount'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._account_lookup(acmeclient, 'reg', directory)
        self.assertIn('INFO:test_a2c:CAhandler._account_lookup: found existing account: urluriacc_info', lcm.output)
        self.assertEqual('urluriacc_info', self.cahandler.account)

    @patch('acme.messages')
    def test_051__account_lookup(self, mock_messages):
        """ test account register existing account - url replacement """
        response = Mock()
        response.uri = 'urluriacc_info'
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value = response)
        mock_messages = Mock()
        directory = {'newAccount': 'newAccount'}
        self.cahandler.url = 'url'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._account_lookup(acmeclient, 'reg', directory)
        self.assertIn('INFO:test_a2c:CAhandler._account_lookup: found existing account: urluriacc_info', lcm.output)
        self.assertEqual('uriacc_info', self.cahandler.account)

    @patch('acme.messages')
    def test_052__account_lookup(self, mock_messages):
        """ test account register existing account - acct_path replacement """
        response = Mock()
        response.uri = 'urluriacc_info'
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value = response)
        mock_messages = Mock()
        directory = {'newAccount': 'newAccount'}
        self.cahandler.path_dic = {'acct_path': 'acc_info'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._account_lookup(acmeclient, 'reg', directory)
        self.assertIn('INFO:test_a2c:CAhandler._account_lookup: found existing account: urluriacc_info', lcm.output)
        self.assertEqual('urluri', self.cahandler.account)

    @patch('acme.messages')
    def test_053__account_lookup(self, mock_messages):
        """ test account register existing account - acct_path replacement """
        response = Mock()
        response.uri = 'urluriacc_info'
        acmeclient = Mock()
        acmeclient.query_registration = Mock(return_value = response)
        mock_messages = Mock()
        directory = {'newAccount': 'newAccount'}
        self.cahandler.url = 'url'
        self.cahandler.path_dic = {'acct_path': 'acc_info'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._account_lookup(acmeclient, 'reg', directory)
        self.assertIn('INFO:test_a2c:CAhandler._account_lookup: found existing account: urluriacc_info', lcm.output)
        self.assertEqual('uri', self.cahandler.account)

    @patch('acme.client.ClientV2.revoke')
    @patch('acme.client.ClientV2.query_registration')
    @patch('acme.messages')
    @patch('acme.client.ClientNetwork')
    @patch('josepy.JWKRSA')
    @patch("builtins.open", mock_open(read_data='mock_open'), create=True)
    @patch('josepy.ComparableX509')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('os.path.exists')
    def test_054_revoke(self, mock_exists, mock_load, mock_comp, mock_kload, mock_nw, mock_mess, mock_reg, mock_revoke):
        """ test revoke successful """
        self.cahandler.keyfile = 'keyfile'
        self.cahandler.account = 'account'
        mock_exists.return_value = True
        response = Mock()
        response.body.status = 'valid'
        mock_reg.return_value = response
        self.assertEqual((200, None, None), self.cahandler.revoke('cert', 'reason', 'date'))

    @patch('acme.client.ClientV2.revoke')
    @patch('acme.client.ClientV2.query_registration')
    @patch('acme.messages')
    @patch('acme.client.ClientNetwork')
    @patch('josepy.JWKRSA')
    @patch("builtins.open", mock_open(read_data='mock_open'), create=True)
    @patch('josepy.ComparableX509')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('os.path.exists')
    def test_055_revoke(self, mock_exists, mock_load, mock_comp, mock_kload, mock_nw, mock_mess, mock_reg, mock_revoke):
        """ test revoke invalid status after reglookup """
        self.cahandler.keyfile = 'keyfile'
        self.cahandler.account = 'account'
        mock_exists.return_value = True
        response = Mock()
        response.body.status = 'invalid'
        response.body.error = 'error'
        mock_reg.return_value = response
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Bad ACME account: error'), self.cahandler.revoke('cert', 'reason', 'date'))

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._account_lookup')
    @patch('acme.messages')
    @patch('acme.client.ClientNetwork')
    @patch('josepy.JWKRSA')
    @patch("builtins.open", mock_open(read_data='mock_open'), create=True)
    @patch('josepy.ComparableX509')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('os.path.exists')
    def test_056_revoke(self, mock_exists, mock_load, mock_comp, mock_kload, mock_nw, mock_mess, mock_lookup):
        """ test revoke account lookup failed """
        self.cahandler.keyfile = 'keyfile'
        mock_exists.return_value = True
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'account lookup failed'), self.cahandler.revoke('cert', 'reason', 'date'))
        self.assertTrue(mock_lookup.called)

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._account_lookup')
    @patch('acme.messages')
    @patch('acme.client.ClientNetwork')
    @patch('josepy.JWKRSA')
    @patch("builtins.open", mock_open(read_data='mock_open'), create=True)
    @patch('josepy.ComparableX509')
    @patch('OpenSSL.crypto.load_certificate')
    @patch('os.path.exists')
    def test_057_revoke(self, mock_exists, mock_load, mock_comp, mock_kload, mock_nw, mock_mess, mock_lookup):
        """ test revoke user key load failed """
        self.cahandler.keyfile = 'keyfile'
        mock_exists.return_value = False
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Internal Error'), self.cahandler.revoke('cert', 'reason', 'date'))
        self.assertFalse(mock_lookup.called)
        self.assertIn('ERROR:test_a2c:CAhandler.revoke(): could not load user_key keyfile', lcm.output)

    @patch("builtins.open", mock_open(read_data='mock_open'), create=True)
    @patch('josepy.ComparableX509')
    @patch('OpenSSL.crypto.load_certificate')
    def test_058_revoke(self, mock_load, mock_comp):
        """ test revoke exception during processing """
        self.cahandler.keyfile = 'keyfile'
        mock_load.side_effect = Exception('ex_user_key_load')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'ex_user_key_load'), self.cahandler.revoke('cert', 'reason', 'date'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll: error: ex_user_key_load', lcm.output)

    def test_059_list_check(self):
        """ CAhandler._list_check failed check as empty entry"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = None
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_060_list_check(self):
        """ CAhandler._list_check check against empty list"""
        list_ = []
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_061_list_check(self):
        """ CAhandler._list_check successful check against 1st element of a list"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_062_list_check(self):
        """ CAhandler._list_check unsuccessful as endcheck failed"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo.bar_'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_063_list_check(self):
        """ CAhandler._list_check successful without $"""
        list_ = ['bar.foo', 'foo.bar$']
        entry = 'host.bar.foo.bar_'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_064_list_check(self):
        """ CAhandler._list_check wildcard check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = '*.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_065_list_check(self):
        """ CAhandler._list_check failed wildcard check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = '*.bar.foo_'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_066_list_check(self):
        """ CAhandler._list_check not end check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'bar.foo gna'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_067_list_check(self):
        """ CAhandler._list_check $ at the end"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'bar.foo$'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_068_list_check(self):
        """ CAhandler._list_check check against empty list flip"""
        list_ = []
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_, True))

    def test_069_list_check(self):
        """ CAhandler._list_check flip successful check """
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_, True))

    def test_070_list_check(self):
        """ CAhandler._list_check flip unsuccessful check"""
        list_ = ['bar.foo$', 'foo.bar$']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_, True))

    def test_071_list_check(self):
        """ CAhandler._list_check unsuccessful whildcard check"""
        list_ = ['foo.bar$', r'\*.bar.foo']
        entry = 'host.bar.foo'
        self.assertFalse(self.cahandler._list_check(entry, list_))

    def test_072_list_check(self):
        """ CAhandler._list_check successful whildcard check"""
        list_ = ['foo.bar$', r'\*.bar.foo']
        entry = '*.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    def test_073_list_check(self):
        """ CAhandler._list_check successful whildcard in list but not in string """
        list_ = ['foo.bar$', '*.bar.foo']
        entry = 'foo.bar.foo'
        self.assertTrue(self.cahandler._list_check(entry, list_))

    @patch('examples.ca_handler.acme_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.acme_ca_handler.csr_san_get')
    def test_074_csr_check(self,  mock_san, mock_cn):
        """ CAhandler._check_csr with empty allowed_domainlist """
        self.cahandler.allowed_domainlist = []
        self.cahandler.blacklist = []
        mock_san.return_value = ['DNS:host.foo.bar']
        mock_cn.return_value = 'host2.foo.bar'
        csr = 'csr'
        self.assertTrue(self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._list_check')
    @patch('examples.ca_handler.acme_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.acme_ca_handler.csr_san_get')
    def test_075_csr_check(self, mock_san, mock_cn, mock_lcheck):
        """ CAhandler._check_csr with list and failed check """
        self.cahandler.allowed_domainlist = ['foo.bar']
        mock_san.return_value = ['DNS:host.foo.bar']
        mock_cn.return_value = 'host2.foo.bar'
        mock_lcheck.side_effect = [True, False]
        csr = 'csr'
        self.assertFalse(self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._list_check')
    @patch('examples.ca_handler.acme_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.acme_ca_handler.csr_san_get')
    def test_076_csr_check(self, mock_san, mock_cn, mock_lcheck):
        """ CAhandler._check_csr with list and successful check """
        self.cahandler.allowed_domainlist = ['foo.bar']
        mock_san.return_value = ['DNS:host.foo.bar']
        mock_cn.return_value = 'host2.foo.bar'
        mock_lcheck.side_effect = [True, True]
        csr = 'csr'
        self.assertTrue(self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.acme_ca_handler.CAhandler._list_check')
    @patch('examples.ca_handler.acme_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.acme_ca_handler.csr_san_get')
    def test_077_csr_check(self, mock_san, mock_cn, mock_lcheck):
        """ CAhandler._check_csr san parsing failed """
        self.cahandler.allowed_domainlist = ['foo.bar']
        mock_san.return_value = ['host.google.com']
        mock_cn.return_value = 'host2.foo.bar'
        mock_lcheck.side_effect = [True, True]
        csr = 'csr'
        self.assertFalse(self.cahandler._csr_check(csr))

    @patch('examples.ca_handler.acme_ca_handler.csr_cn_get')
    @patch('examples.ca_handler.acme_ca_handler.csr_san_get')
    def test_078_csr_check(self, mock_san, mock_cn):
        """ CAhandler._check_csr san parsing failed """
        self.cahandler.allowed_domainlist = ['foo.bar']
        mock_san.return_value = []
        mock_cn.return_value = None
        csr = 'csr'
        self.assertFalse(False, self.cahandler._csr_check(csr))

    @patch('requests.post')
    def test_079__zerossl_eab_get(self, mock_post):
        """ CAhandler._zerossl_eab_get() - all ok """
        mock_post.return_value.json.return_value = {'success': True, 'eab_kid': 'eab_kid', 'eab_hmac_key': 'eab_hmac_key'}
        self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertEqual('eab_kid', self.cahandler.eab_kid)
        self.assertEqual('eab_hmac_key', self.cahandler.eab_hmac_key)

    @patch('requests.post')
    def test_080__zerossl_eab_get(self, mock_post):
        """ CAhandler._zerossl_eab_get() - success false """
        mock_post.return_value.json.return_value = {'success': False, 'eab_kid': 'eab_kid', 'eab_hmac_key': 'eab_hmac_key'}
        mock_post.return_value.text = 'text'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn('ERROR:test_a2c:CAhandler._zerossl_eab_get() failed: text', lcm.output)

    @patch('requests.post')
    def test_081__zerossl_eab_get(self, mock_post):
        """ CAhandler._zerossl_eab_get() - no success key """
        mock_post.return_value.json.return_value = {'eab_kid': 'eab_kid', 'eab_hmac_key': 'eab_hmac_key'}
        mock_post.return_value.text = 'text'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn('ERROR:test_a2c:CAhandler._zerossl_eab_get() failed: text', lcm.output)

    @patch('requests.post')
    def test_082__zerossl_eab_get(self, mock_post):
        """ CAhandler._zerossl_eab_get() - no eab_kid key """
        mock_post.return_value.json.return_value = {'success': True, 'eab_hmac_key': 'eab_hmac_key'}
        mock_post.return_value.text = 'text'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn('ERROR:test_a2c:CAhandler._zerossl_eab_get() failed: text', lcm.output)

    @patch('requests.post')
    def test_083__zerossl_eab_get(self, mock_post):
        """ CAhandler._zerossl_eab_get() - no eab_mac key """
        mock_post.return_value.json.return_value = {'success': True, 'eab_kid': 'eab_kid'}
        mock_post.return_value.text = 'text'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._zerossl_eab_get()
        self.assertTrue(mock_post.called)
        self.assertFalse(self.cahandler.eab_kid)
        self.assertFalse(self.cahandler.eab_hmac_key)
        self.assertIn('ERROR:test_a2c:CAhandler._zerossl_eab_get() failed: text', lcm.output)

if __name__ == '__main__':

    unittest.main()
