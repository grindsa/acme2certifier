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
        from acme_srv.authorization import Authorization
        self.authorization = Authorization(False, 'http://tester.local', self.logger)

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.authorization.uts_now')
    @patch('acme_srv.authorization.generate_random_string')
    def test_001_authorization__authz_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = [{'type' : 'identifier_type', 'value' : 'identifier_value', 'status__name' : 'foo'}]
        self.assertEqual({'status': 'foo', 'expires': '2018-12-02T05:00:00Z', 'identifier': {'type': 'identifier_type', 'value': 'identifier_value'}, 'challenges': [{'key2': 'value2', 'key1': 'value1'}]}, self.authorization._authz_info('http://tester.local/acme/authz/foo'))

    @patch('acme_srv.message.Message.check')
    def test_002_authorization_new_post(self, mock_mcheck):
        """ Authorization.new_post() failed bcs. of failed message check """
        mock_mcheck.return_value = (400, 'message', 'detail', None, None, 'account_name')
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'detail', 'type': 'message', 'status': 400}}, self.authorization.new_post(message))

    @patch('acme_srv.authorization.Authorization._authz_info')
    @patch('acme_srv.message.Message.check')
    def test_003_authorization_new_post(self, mock_mcheck, mock_authzinfo):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, 'protected', 'payload', 'account_name')
        mock_authzinfo.return_value = {'authz_foo': 'authz_bar'}
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 400, 'data': {'detail': 'url is missing in protected', 'type': 'urn:ietf:params:acme:error:malformed', 'status': 400}}, self.authorization.new_post(message))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.authorization.Authorization._authz_info')
    @patch('acme_srv.message.Message.check')
    def test_004_authorization_new_post(self, mock_mcheck, mock_authzinfo, mock_nnonce):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, {'url' : 'foo_url'}, 'payload', 'account_name')
        mock_authzinfo.return_value = {'authz_foo': 'authz_bar'}
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {'Replay-Nonce': 'new_nonce'}, 'code': 200, 'data': {'authz_foo': 'authz_bar'}}, self.authorization.new_post(message))

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.authorization.uts_now')
    @patch('acme_srv.authorization.generate_random_string')
    def test_005_authorization__authz_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() in case auth_lookup failed """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = []
        self.assertEqual({}, self.authorization._authz_info('http://tester.local/acme/authz/foo'))

    @patch('acme_srv.nonce.Nonce.generate_and_add')
    @patch('acme_srv.authorization.Authorization._authz_info')
    @patch('acme_srv.message.Message.check')
    def test_006_authorization_new_post(self, mock_mcheck, mock_authzinfo, mock_nnonce):
        """ Authorization.new_post() failed bcs url is missing in protected """
        mock_mcheck.return_value = (200, None, None, {'url' : 'foo_url'}, 'payload', 'account_name')
        mock_authzinfo.return_value = {}
        mock_nnonce.return_value = 'new_nonce'
        message = '{"foo" : "bar"}'
        self.assertEqual({'header': {}, 'code': 403, 'data': {'detail': 'authorizations lookup failed', 'type': 'urn:ietf:params:acme:error:unauthorized', 'status': 403}}, self.authorization.new_post(message))

    def test_007_authorization_invalidate(self):
        """ test Authorization.invalidate() empty authz list """
        timestamp = 1596240000
        self.authorization.dbstore.authorizations_expired_search.return_value = []
        self.assertEqual((['id', 'name', 'expires', 'value', 'created_at', 'token', 'status__id', 'status__name', 'order__id', 'order__name'], []), self.authorization.invalidate(timestamp))

    def test_008_authorization_invalidate(self):
        """ test Authorization.invalidate() authz with just a name """
        timestamp = 1596240000
        self.authorization.dbstore.authorizations_expired_search.return_value = [{'name': 'name'}]
        self.assertEqual((['id', 'name', 'expires', 'value', 'created_at', 'token', 'status__id', 'status__name', 'order__id', 'order__name'], []), self.authorization.invalidate(timestamp))

    def test_009_authorization_invalidate(self):
        """ test Authorization.invalidate() authz with a name and non-expirewd status """
        timestamp = 1596240000
        self.authorization.dbstore.authorizations_expired_search.return_value = [{'name': 'name', 'status__name': 'foo'}]
        self.assertEqual((['id', 'name', 'expires', 'value', 'created_at', 'token', 'status__id', 'status__name', 'order__id', 'order__name'], [{'name': 'name', 'status__name': 'foo'}]), self.authorization.invalidate(timestamp))

    def test_010_authorization_invalidate(self):
        """ test Authorization.invalidate() authz with a name and non-expirewd status """
        timestamp = 1596240000
        self.authorization.dbstore.authorizations_expired_search.return_value = [{'name': 'name', 'status__name': 'expired'}]
        self.assertEqual((['id', 'name', 'expires', 'value', 'created_at', 'token', 'status__id', 'status__name', 'order__id', 'order__name'], []), self.authorization.invalidate(timestamp))

    def test_011_authorization_invalidate(self):
        """ test Authorization.invalidate() authz - dbstore.authorization_update() raises an exception """
        timestamp = 1596240000
        self.authorization.dbstore.authorizations_expired_search.return_value = [{'name': 'name', 'status__name': 'foo'}]
        self.authorization.dbstore.authorization_update.side_effect = Exception('exc_authz_update')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.authorization.invalidate(timestamp)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Authorization.invalidate(): exc_authz_update', lcm.output)

    def test_012_authorization_invalidate(self):
        """ test Authorization.invalidate() cornercase - do not invalidte authorizations with expires 0 """
        timestamp = 1596240000
        self.authorization.dbstore.authorizations_expired_search.return_value = [{'name': 'name', 'status__name': 'foo', 'expires': 0}]
        self.assertEqual((['id', 'name', 'expires', 'value', 'created_at', 'token', 'status__id', 'status__name', 'order__id', 'order__name'], []), self.authorization.invalidate(timestamp))

    def test_013_authorization_invalidate(self):
        """ test Authorization.invalidate() authz - dbstore.authorization_update() raises an exception """
        timestamp = 1596240000
        self.authorization.dbstore.authorizations_expired_search.side_effect = Exception('exc_authz_exp_search')
        # self.authorization.dbstore.authorization_update.side_effect = Exception('exc_authz_update')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.authorization.invalidate(timestamp)
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Authorization.invalidate(): exc_authz_exp_search', lcm.output)

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.authorization.uts_now')
    @patch('acme_srv.authorization.generate_random_string')
    def test_014_authorization__authz_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() - dbstore.authorization update raises an exception """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.side_effect = Exception('exc_authz_update')
        self.authorization.dbstore.authorization_lookup.return_value = [{'name': 'foo'}]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.authorization._authz_info('http://tester.local/acme/authz/foo')
        self.assertIn('ERROR:test_a2c:acme2certifier database error in Authorization._authz_info(foo) update: exc_authz_update', lcm.output)

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.authorization.uts_now')
    @patch('acme_srv.authorization.generate_random_string')
    def test_015_authorization__authz_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() - dbstore.authorization lookup raises an exception """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = [{'type' : 'identifier_type', 'value1' : 'identifier_value', 'status__name' : 'foo'}]
        result = {'expires': '2018-12-02T05:00:00Z', 'status': 'foo', 'challenges': [{'key1': 'value1', 'key2': 'value2'}]}
        self.assertEqual(result, self.authorization._authz_info('http://tester.local/acme/authz/foo'))

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.authorization.uts_now')
    @patch('acme_srv.authorization.generate_random_string')
    def test_016_authorization__authz_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() - dbstore.authorization lookup raises an exception """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = [{'type' : 'TNAuthList', 'value' : 'identifier_value', 'status__name' : 'foo'}]
        result = {'expires': '2018-12-02T05:00:00Z', 'status': 'foo', 'challenges': [{'key1': 'value1', 'key2': 'value2'}], 'identifier': {'type': 'TNAuthList', 'value': 'identifier_value'}}
        self.assertEqual(result, self.authorization._authz_info('http://tester.local/acme/authz/foo'))

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.authorization.uts_now')
    @patch('acme_srv.authorization.generate_random_string')
    def test_017_authorization__authz_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() - dbstore.authorization lookup raises an exception """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.return_value = [{'type' : 'type', 'value' : '*.bar.local', 'status__name' : 'foo'}]
        result = {'expires': '2018-12-02T05:00:00Z', 'status': 'foo', 'challenges': [{'key1': 'value1', 'key2': 'value2'}], 'identifier': {'type': 'type', 'value': 'bar.local'}, 'wildcard': True}
        self.assertEqual(result, self.authorization._authz_info('http://tester.local/acme/authz/foo'))

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.authorization.uts_now')
    @patch('acme_srv.authorization.generate_random_string')
    def test_018_authorization__authz_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() in case auth_lookup failed """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.side_effect = Exception('exc_acc_lookup')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual({}, self.authorization._authz_info('http://tester.local/acme/authz/foo'))
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Authorization._authz_lookup(foo) lookup: exc_acc_lookup', lcm.output)

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.authorization.uts_now')
    @patch('acme_srv.authorization.generate_random_string')
    def test_019_authorization__authz_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() - dbstore.authorization lookup raises an exception """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.side_effect = Exception('exc_authz_update')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.authorization._authz_info('http://tester.local/acme/authz/foo')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Authorization._authz_lookup(foo) lookup: exc_authz_update', lcm.output)

    @patch('acme_srv.challenge.Challenge.new_set')
    @patch('acme_srv.authorization.uts_now')
    @patch('acme_srv.authorization.generate_random_string')
    def test_020_authorization__authz_info(self, mock_name, mock_uts, mock_challengeset):
        """ test Authorization.auth_info() - dbstore.authorization lookup raises an exception """
        mock_name.return_value = 'randowm_string'
        mock_uts.return_value = 1543640400
        mock_challengeset.return_value = [{'key1' : 'value1', 'key2' : 'value2'}]
        self.authorization.dbstore.authorization_update.return_value = 'foo'
        self.authorization.dbstore.authorization_lookup.side_effect = [[{'type' : 'identifier_type', 'value1' : 'identifier_value', 'status__name' : 'foo'}], Exception('exc_authz_lookup')]
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.authorization._authz_info('http://tester.local/acme/authz/foo')
        self.assertIn('CRITICAL:test_a2c:acme2certifier database error in Authorization._authz_lookup(foo) lookup: exc_authz_lookup', lcm.output)

    @patch('acme_srv.authorization.Authorization._config_load')
    def test_021__enter__(self, mock_cfg):
        """ test enter """
        mock_cfg.return_value = True
        self.authorization.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch('acme_srv.authorization.load_config')
    def test_022_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        self.authorization._config_load()
        self.assertFalse(self.authorization.expiry_check_disable)
        self.assertEqual(86400, self.authorization.validity )

    @patch('acme_srv.authorization.load_config')
    def test_023_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Authorization'] = {'foo': 'bar'}
        mock_load_cfg.return_value = parser
        self.authorization._config_load()
        self.assertFalse(self.authorization.expiry_check_disable)
        self.assertEqual(86400, self.authorization.validity )

    @patch('acme_srv.authorization.load_config')
    def test_024_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Authorization'] = {'expiry_check_disable': False}
        mock_load_cfg.return_value = parser
        self.authorization._config_load()
        self.assertFalse(self.authorization.expiry_check_disable)
        self.assertEqual(86400, self.authorization.validity )

    @patch('acme_srv.authorization.load_config')
    def test_025_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Authorization'] = {'expiry_check_disable': True}
        mock_load_cfg.return_value = parser
        self.authorization._config_load()
        self.assertTrue(self.authorization.expiry_check_disable)
        self.assertEqual(86400, self.authorization.validity )

    @patch('acme_srv.authorization.load_config')
    def test_026_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Authorization'] = {'validity': 60}
        mock_load_cfg.return_value = parser
        self.authorization._config_load()
        self.assertFalse(self.authorization.expiry_check_disable)
        self.assertEqual(60, self.authorization.validity )

    @patch('acme_srv.authorization.load_config')
    def test_027_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Authorization'] = {'validity': 'foo'}
        mock_load_cfg.return_value = parser
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.authorization._config_load()
        self.assertFalse(self.authorization.expiry_check_disable)
        self.assertEqual(86400, self.authorization.validity )
        self.assertIn('WARNING:test_a2c:Authorization._config_load(): failed to parse validity: foo', lcm.output)

    @patch('acme_srv.authorization.load_config')
    def test_028_config_load(self, mock_load_cfg):
        """ test _config_load """
        parser = configparser.ConfigParser()
        parser['Directory'] = {'url_prefix': 'url_prefix'}
        mock_load_cfg.return_value = parser
        self.authorization._config_load()
        self.assertFalse(self.authorization.expiry_check_disable)
        self.assertEqual(86400, self.authorization.validity )
        self.assertEqual({'authz_path': 'url_prefix/acme/authz/'}, self.authorization.path_dic)

    @patch('acme_srv.authorization.Authorization._authz_info')
    def test_029_new_get(self, mock_info):
        """ new get """
        mock_info.return_value = 'foo'
        result = {'code': 200, 'data': 'foo', 'header': {}}
        self.assertEqual(result, self.authorization.new_get('url'))



if __name__ == '__main__':
    unittest.main()
