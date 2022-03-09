#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for openssl_ca_handler """
# pylint: disable=C0415, R0904, R0913, W0212
import sys
import unittest
from unittest.mock import patch, mock_open, Mock

sys.path.insert(0, '.')
sys.path.insert(1, '..')


class TestACMEHandler(unittest.TestCase):
    """ test class for mswcce_ca_handler """
    def setUp(self):
        """ setup unittest """
        import logging
        from examples.ca_handler.mswcce_ca_handler import CAhandler
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        self.cahandler = CAhandler(False, self.logger)

    def tearDown(self):
        """ teardown """
        pass

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_002_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_003_config_load(self, mock_load_cfg):
        """ test _config_load wrongly configured cahandler section """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch.dict('os.environ', {'host_var': 'host_var'})
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_004_config_load(self, mock_load_cfg):
        """ test _config_load - load host from variable """
        mock_load_cfg.return_value = {'CAhandler': {'host_variable': 'host_var'}}
        self.cahandler._config_load()
        self.assertEqual('host_var', self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch.dict('os.environ', {'host_var': 'host_var'})
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_005_config_load(self, mock_load_cfg):
        """ test _config_load - load host from not_existing variable """
        mock_load_cfg.return_value = {'CAhandler': {'host_variable': 'unk'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load host_variable:'unk'", lcm.output)

    @patch.dict('os.environ', {'host_var': 'host_var'})
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load - overwrite host variable """
        mock_load_cfg.return_value = {'CAhandler': {'host_variable': 'host_var', 'host': 'host_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('host_local', self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite host', lcm.output)

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load - load host from config file """
        mock_load_cfg.return_value = {'CAhandler': {'host': 'host_local'}}
        self.cahandler._config_load()
        self.assertEqual('host_local', self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch.dict('os.environ', {'user_var': 'user_var'})
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_008_config_load(self, mock_load_cfg):
        """ test _config_load - load user from variable """
        mock_load_cfg.return_value = {'CAhandler': {'user_variable': 'user_var'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertEqual('user_var', self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch.dict('os.environ', {'user_var': 'user_var'})
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_009_config_load(self, mock_load_cfg):
        """ test _config_load - load user from not existing variable """
        mock_load_cfg.return_value = {'CAhandler': {'user_variable': 'unk'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load user_variable:'unk'", lcm.output)

    @patch.dict('os.environ', {'user_var': 'user_var'})
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_010_config_load(self, mock_load_cfg):
        """ test _config_load - overwrite user variable """
        mock_load_cfg.return_value = {'CAhandler': {'user_variable': 'user_var', 'user': 'user_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertEqual('user_local', self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite user', lcm.output)

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg):
        """ test _config_load - load user from config file """
        mock_load_cfg.return_value = {'CAhandler': {'user': 'user_local'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertEqual('user_local', self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch.dict('os.environ', {'password_var': 'password_var'})
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg):
        """ test _config_load - load password from variable """
        mock_load_cfg.return_value = {'CAhandler': {'password_variable': 'password_var'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertEqual('password_var', self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch.dict('os.environ', {'password_var': 'password_var'})
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg):
        """ test _config_load - load password from not existing variable """
        mock_load_cfg.return_value = {'CAhandler': {'password_variable': 'unk'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn("ERROR:test_a2c:CAhandler._config_load() could not load password_variable:'unk'", lcm.output)

    @patch.dict('os.environ', {'password_var': 'password_var'})
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_014_config_load(self, mock_load_cfg):
        """ test _config_load - overwrite password variable """
        mock_load_cfg.return_value = {'CAhandler': {'password_variable': 'password_var', 'password': 'password_local'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertEqual('password_local', self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertIn('INFO:test_a2c:CAhandler._config_load() overwrite password', lcm.output)

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_015_config_load(self, mock_load_cfg):
        """ test _config_load - load password from config file """
        mock_load_cfg.return_value = {'CAhandler': {'password': 'password_local'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertEqual('password_local', self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_016_config_load(self, mock_load_cfg):
        """ test _config_load - load target domain from config file """
        mock_load_cfg.return_value = {'CAhandler': {'target_domain': 'target_domain'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('target_domain', self.cahandler.target_domain)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_017_config_load(self, mock_load_cfg):
        """ test _config_load - load domain_controller from config file """
        mock_load_cfg.return_value = {'CAhandler': {'domain_controller': 'domain_controller'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('domain_controller', self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.ca_name)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_018_config_load(self, mock_load_cfg):
        """ test _config_load - load ca_name from config file """
        mock_load_cfg.return_value = {'CAhandler': {'ca_name': 'ca_name'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('ca_name', self.cahandler.ca_name)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_bundle)

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg):
        """ test _config_load - load ca_name from config file """
        mock_load_cfg.return_value = {'CAhandler': {'ca_bundle': 'ca_bundle'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('ca_bundle', self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)

    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_020_config_load(self, mock_load_cfg):
        """ test _config_load - load template from config file """
        mock_load_cfg.return_value = {'CAhandler': {'template': 'template'}}
        self.cahandler._config_load()
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertEqual('template', self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)

    @patch('examples.ca_handler.mswcce_ca_handler.proxy_check')
    @patch('json.loads')
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_021_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """ test _config_load ca_handler configured load proxies """
        mock_load_cfg.return_value = {'DEFAULT': {'proxy_server_list': 'foo'}}
        mock_json.return_value = 'foo.bar.local'
        mock_chk.return_value = 'proxy.bar.local'
        self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertTrue(mock_chk.called)
        self.assertEqual({'http': 'proxy.bar.local', 'https': 'proxy.bar.local'}, self.cahandler.proxy)
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)

    @patch('examples.ca_handler.mswcce_ca_handler.proxy_check')
    @patch('json.loads')
    @patch('examples.ca_handler.mswcce_ca_handler.load_config')
    def test_022_config_load(self, mock_load_cfg, mock_json, mock_chk):
        """ test _config_load ca_handler configured load proxies failed with exception in json.load """
        mock_load_cfg.return_value = {'DEFAULT': {'proxy_server_list': 'foo'}}
        mock_json.side_effect = Exception('exc_load_config')
        mock_chk.side = 'proxy.bar.local'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertTrue(mock_json.called)
        self.assertFalse(mock_chk.called)
        self.assertFalse(self.cahandler.proxy)
        self.assertFalse(self.cahandler.host)
        self.assertFalse(self.cahandler.user)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.template)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.target_domain)
        self.assertFalse(self.cahandler.domain_controller)
        self.assertFalse(self.cahandler.ca_name)
        self.assertIn('WARNING:test_a2c:CAhandler._config_load() proxy_server_list failed with error: exc_load_config', lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_023__file_load(self):
        """ test _load file() """
        self.assertEqual('foo', self.cahandler._file_load('filename'))

    @patch("builtins.open")
    def test_024__file_load(self, mock_op):
        """ test _load file() """
        mock_op.side_effect = Exception('ex_mock_open')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertFalse(self.cahandler._file_load('filename'))
        self.assertIn('ERROR:test_a2c:CAhandler._file_load(): could not load filename. Error: ex_mock_open', lcm.output)

    def test_025_revoke(self):
        """ test revocation """
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert', 'rev_reason', 'rev_date'))

    def test_026_poll(self):
        """ test polling """
        self.assertEqual(('Method not implemented.', None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_027_trigger(self):
        """ test trigger """
        self.assertEqual(('Method not implemented.', None, None), self.cahandler.trigger('payload'))

    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler.request_create')
    def test_028_enroll(self, mock_rcr):
        """ test enrollment - unconfigured """
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_rcr.called)

    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler.request_create')
    def test_029_enroll(self, mock_rcr):
        """ test enrollment - host unconfigured """
        self.cahandler.host = None
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_rcr.called)

    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler.request_create')
    def test_30_enroll(self, mock_rcr):
        """ test enrollment - user unconfigured """
        self.cahandler.host = 'host'
        self.cahandler.user = None
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_rcr.called)

    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler.request_create')
    def test_031_enroll(self, mock_rcr):
        """ test enrollment - password unconfigured """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = None
        self.cahandler.template = 'template'
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_rcr.called)

    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler.request_create')
    def test_032_enroll(self, mock_rcr):
        """ test enrollment - template unconfigured """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = None
        self.assertEqual(('Config incomplete', None, None, None), self.cahandler.enroll('csr'))
        self.assertFalse(mock_rcr.called)

    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler.request_create')
    @patch('examples.ca_handler.mswcce_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.mswcce_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler._file_load')
    @patch('examples.ca_handler.mswcce_ca_handler.build_pem_file')
    def test_033_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """ test enrollment - ca_server.get_cert() triggers exception """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        mock_rcr.return_value = Mock(return_value='raw_data')
        mock_file.return_value = 'file_load'
        mock_s2b.return_value = 's2b'
        mock_b2s.side_effect = Exception('ex_b2s')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('cert bundling failed', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:ca_server.get_cert() failed with error: ex_b2s', lcm.output)
        self.assertIn('ERROR:test_a2c:cert bundling failed', lcm.output)
        self.assertTrue(mock_rcr.called)

    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler.request_create')
    @patch('examples.ca_handler.mswcce_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.mswcce_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler._file_load')
    @patch('examples.ca_handler.mswcce_ca_handler.build_pem_file')
    def test_034_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """ test enrollment - no certificate returned by ca_server.get_cert() """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        mock_rcr.return_value = Mock(return_value='raw_data')
        mock_file.return_value = 'file_load'
        mock_s2b.return_value = 's2b'
        mock_b2s.return_value = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('cert bundling failed', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:cert bundling failed', lcm.output)
        self.assertTrue(mock_rcr.called)

    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler.request_create')
    @patch('examples.ca_handler.mswcce_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.mswcce_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler._file_load')
    @patch('examples.ca_handler.mswcce_ca_handler.build_pem_file')
    def test_035_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """ test enrollment - certificate and bundling successful """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        mock_rcr.return_value = Mock(return_value='raw_data')
        mock_file.return_value = 'file_load'
        mock_s2b.return_value = 's2b'
        mock_b2s.return_value = 'b2s'
        self.assertEqual((None, 'b2sfile_load', 'b2s', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_rcr.called)

    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler.request_create')
    @patch('examples.ca_handler.mswcce_ca_handler.convert_string_to_byte')
    @patch('examples.ca_handler.mswcce_ca_handler.convert_byte_to_string')
    @patch('examples.ca_handler.mswcce_ca_handler.CAhandler._file_load')
    @patch('examples.ca_handler.mswcce_ca_handler.build_pem_file')
    def test_036_enroll(self, mock_pem, mock_file, mock_b2s, mock_s2b, mock_rcr):
        """ test enrollment - certificate and bundling successful replacement test """
        self.cahandler.host = 'host'
        self.cahandler.user = 'user'
        self.cahandler.password = 'password'
        self.cahandler.template = 'template'
        mock_rcr.return_value = Mock(return_value='raw_data')
        mock_file.return_value = 'file_load'
        mock_s2b.return_value = 's2b'
        mock_b2s.return_value = '-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\n'
        self.assertEqual((None, '-----BEGIN CERTIFICATE-----\nb2s_replacement\n-----END CERTIFICATE-----\nfile_load', 'b2s_replacement', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_rcr.called)

    @patch('examples.ca_handler.mswcce_ca_handler.Request')
    @patch('examples.ca_handler.mswcce_ca_handler.Target')
    def test_037_request_create(self, mock_target, mock_request):
        """ test request create """
        mock_target.return_value = True
        mock_request.return_value ='foo'
        self.assertEqual('foo', self.cahandler.request_create())

if __name__ == '__main__':

    unittest.main()
