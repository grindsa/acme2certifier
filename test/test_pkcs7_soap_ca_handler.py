#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, Mock, mock_open
import requests

sys.path.insert(0, '.')
sys.path.insert(1, '..')

class TestACMEHandler(unittest.TestCase):
    """ test class for cgi_handler """

    def setUp(self):
        """ setup unittest """
        import logging
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger('test_a2c')
        from examples.ca_handler.pkcs7_soap_ca_handler import CAhandler, binary_read, binary_write
        self.cahandler = CAhandler(False, self.logger)
        self.binary_read = binary_read
        self.binary_write = binary_write
        # self.cahandler.api_host = 'api_host'
        # self.cahandler.auth = 'auth'

    def test_001_default(self):
        """ default test which always passes """
        self.assertEqual('foo', 'foo')

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_002_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        self.assertIn('ERROR:test_a2c:CAhandler._config_load(): CAhandler section is missing', lcm.output)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_003_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {'CAhandler': {'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_004_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {'CAhandler': {'email': 'email', 'foo': 'bar'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertEqual('email', self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)


    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_005_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {'CAhandler': {'soap_srv': 'soap_srv'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertEqual('soap_srv', self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_006_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {'CAhandler': {'profilename': 'profilename'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertEqual('profilename', self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_007_config_load(self, mock_load_cfg):
        """ test _config_load no cahandler section """
        mock_load_cfg.return_value = {'CAhandler': {'ca_bundle': 'ca_bundle'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertEqual('ca_bundle', self.cahandler.ca_bundle)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)

    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_008_config_load(self, mock_load_cfg, mock_file):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = False
        mock_load_cfg.return_value = {'CAhandler': {'signing_cert': 'signing_cert'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert signing_cert not found.',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.x509.load_pem_x509_certificate')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_009_config_load(self, mock_load_cfg, mock_file, mock_load):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = True
        mock_load.return_value = 'signing_cert'
        mock_load_cfg.return_value = {'CAhandler': {'signing_cert': 'signing_cert'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertEqual('signing_cert', self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)

    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg, mock_file):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = False
        mock_load_cfg.return_value = {'CAhandler': {'signing_key': 'signing_key'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key signing_key not found.',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg, mock_file, mock_load):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = True
        mock_load.return_value = 'signing_key'
        mock_load_cfg.return_value = {'CAhandler': {'signing_key': 'signing_key'}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertEqual('signing_key', self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertFalse(self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg, mock_file, mock_load):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = True
        mock_load.return_value = 'signing_key'
        mock_load_cfg.return_value = {'CAhandler': {'signing_script': 'signing_script'}}
        self.maxDiff = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertEqual({'signing_script': 'signing_script'}, self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file'
        ]
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_014_config_load(self, mock_load_cfg, mock_file, mock_load):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = True
        mock_load.return_value = 'signing_key'
        mock_load_cfg.return_value = {'CAhandler': {'signing_script': 'signing_script', 'signing_alias': 'signing_alias'}}
        self.maxDiff = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertEqual({'signing_alias': 'signing_alias', 'signing_script': 'signing_script'}, self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file'
        ]
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_015_config_load(self, mock_load_cfg, mock_file, mock_load):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = True
        mock_load.return_value = 'signing_key'
        mock_load_cfg.return_value = {'CAhandler': {'signing_script': 'signing_script', 'signing_csr_path': 'signing_csr_path'}}
        self.maxDiff = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertEqual({'signing_csr_path': 'signing_csr_path', 'signing_script': 'signing_script'}, self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file'
        ]
        self.assertEqual(error_buffer, lcm.output)


    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_016_config_load(self, mock_load_cfg, mock_file, mock_load):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = True
        mock_load.return_value = 'signing_key'
        mock_load_cfg.return_value = {'CAhandler': {'signing_script': 'signing_script', 'signing_config_variant': 'signing_config_variant'}}
        self.maxDiff = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertEqual({'signing_script': 'signing_script', 'signing_config_variant': 'signing_config_variant'}, self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file'
        ]
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_017_config_load(self, mock_load_cfg, mock_file, mock_load):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = True
        mock_load.return_value = 'signing_key'
        mock_load_cfg.return_value = {'CAhandler': {'signing_script': 'signing_script', 'signing_user': 'signing_user'}}
        self.maxDiff = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertEqual({'signing_script': 'signing_script', 'signing_user': 'signing_user'}, self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file'
        ]
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_018_config_load(self, mock_load_cfg, mock_file, mock_load):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = True
        mock_load.return_value = 'signing_key'
        mock_load_cfg.return_value = {'CAhandler': {'signing_script': 'signing_script', 'signing_sleep_timer': 'signing_sleep_timer'}}
        self.maxDiff = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertEqual({'signing_script': 'signing_script', 'signing_sleep_timer': 'signing_sleep_timer'}, self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file'
        ]
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_019_config_load(self, mock_load_cfg, mock_file, mock_load):
        """ test _config_load signing cert configured but does not exist """
        mock_file.return_value = True
        mock_load.return_value = 'signing_key'
        mock_load_cfg.return_value = {'CAhandler': {'signing_script': 'signing_script', 'signing_interpreter': 'signing_interpreter'}}
        self.maxDiff = None
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.soap_srv)
        self.assertFalse(self.cahandler.profilename)
        self.assertFalse(self.cahandler.email)
        self.assertFalse(self.cahandler.signing_cert)
        self.assertFalse(self.cahandler.signing_key)
        self.assertFalse(self.cahandler.password)
        self.assertEqual({'signing_script': 'signing_script', 'signing_interpreter': 'signing_interpreter'}, self.cahandler.signing_script_dic)
        error_buffer = [
            'ERROR:test_a2c:CAhandler._config_load(): soap_srv option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file',
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file'
        ]
        self.assertEqual(error_buffer, lcm.output)


    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._config_load')
    def test_013_enter(self, mock_cfgload):
        """ enter - no soap server configured """
        self.cahandler.__enter__()
        self.assertTrue(mock_cfgload.called)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._config_load')
    def test_014_enter(self, mock_cfgload):
        """ enter soap server configured """
        self.cahandler.soap_srv = 'mock_srv'
        self.cahandler.__enter__()
        self.assertFalse(mock_cfgload.called)

    def test_015_exit(self):
        """ enter - no soap server configured """
        self.cahandler.__exit__()

    @patch('pyasn1.codec.der.decoder.decode')
    def test_016_cert_decode(self, mock_der):
        """ test _cert_decode()"""
        mock_der.return_value = 'decode'
        cert = Mock()
        cert.public_bytes = Mock()
        self.assertEqual('decode', self.cahandler._cert_decode(cert))

    def test_017_poll(self):
        """ test poll """
        self.assertEqual((None, None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_018_revoke(self):
        """ test revoke """
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert_name', 'reason', 'date'))

    def test_019_trigger(self):
        """ test revoke """
        self.assertEqual((None, None, None), self.cahandler.trigger('identifier'))

    def test_020_soaprequest_build(self):
        """ test soap request build """
        self.cahandler.profilename = 'profilename'
        self.cahandler.email = 'email'
        pkcs7 = 'pkcs7'
        result = """
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:aur="http://monetplus.cz/services/kb/aurora">
<soapenv:Header/>
<soapenv:Body>
    <aur:RequestCertificate>
        <aur:request>
            <aur:ProfileName>profilename</aur:ProfileName>
            <aur:CertificateRequestRaw>pkcs7</aur:CertificateRequestRaw>
            <aur:Email>email</aur:Email>
            <aur:ReturnCertificateCaChain>true</aur:ReturnCertificateCaChain>
        </aur:request>
    </aur:RequestCertificate>
</soapenv:Body>
</soapenv:Envelope>\n"""
        self.assertEqual(result, self.cahandler._soaprequest_build(pkcs7))

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_021_binary_read(self):
        """ test read binary file """
        self.assertEqual('foo', self.binary_read(self.logger, 'filename'))

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_022_binary_write(self):
        """ test wrote binary file """
        self.assertFalse(self.binary_write(self.logger, 'filename', 'content'))


if __name__ == '__main__':

    unittest.main()