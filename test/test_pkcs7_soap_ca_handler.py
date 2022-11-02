#!/usr/bin/python
# -*- coding: utf-8 -*-
""" unittests for acme2certifier """
# pylint: disable= C0415, W0212
import unittest
import sys
import os
from unittest.mock import patch, Mock, mock_open
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import base64

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
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        self.binary_read = binary_read
        self.binary_write = binary_write


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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file'
            ]
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file'
            ]
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file'
            ]
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file'
            ]
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
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file'
            ]
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert signing_cert not found.',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file'
            ]
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key option is missing in config file']
        self.assertEqual(error_buffer, lcm.output)

    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_010_config_load(self, mock_load_cfg, mock_file):
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_key signing_key not found.',
            ]
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_011_config_load(self, mock_load_cfg, mock_file, mock_load):
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_cert option is missing in config file'
            ]
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_012_config_load(self, mock_load_cfg, mock_file, mock_load):
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file',
        ]
        self.assertEqual(error_buffer, lcm.output)

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    @patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
    @patch('os.path.exists')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.load_config')
    def test_013_config_load(self, mock_load_cfg, mock_file, mock_load):
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file',
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file'
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file'
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file'
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file'
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
            'WARNING:test_a2c:CAhandler._config_load(): SOAP server certificate validation disabled',
            'ERROR:test_a2c:CAhandler._config_load(): profilename option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): email option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_alias option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_csr_path option is missing in config file',
            'ERROR:test_a2c:CAhandler._config_load(): signing_config_variant option is missing in config file',
        ]
        self.assertEqual(error_buffer, lcm.output)


    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._config_load')
    def test_019_enter(self, mock_cfgload):
        """ enter - no soap server configured """
        self.cahandler.__enter__()
        self.assertTrue(mock_cfgload.called)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._config_load')
    def test_020_enter(self, mock_cfgload):
        """ enter soap server configured """
        self.cahandler.soap_srv = 'mock_srv'
        self.cahandler.__enter__()
        self.assertFalse(mock_cfgload.called)

    def test_021_exit(self):
        """ enter - no soap server configured """
        self.cahandler.__exit__()

    @patch('pyasn1.codec.der.decoder.decode')
    def test_022_cert_decode(self, mock_der):
        """ test _cert_decode()"""
        mock_der.return_value = 'decode'
        cert = Mock()
        cert.public_bytes = Mock()
        self.assertEqual('decode', self.cahandler._cert_decode(cert))

    def test_023_poll(self):
        """ test poll """
        self.assertEqual((None, None, None, 'poll_identifier', False), self.cahandler.poll('cert_name', 'poll_identifier', 'csr'))

    def test_024_revoke(self):
        """ test revoke """
        self.assertEqual((500, 'urn:ietf:params:acme:error:serverInternal', 'Revocation is not supported.'), self.cahandler.revoke('cert_name', 'reason', 'date'))

    def test_025_trigger(self):
        """ test revoke """
        self.assertEqual((None, None, None), self.cahandler.trigger('identifier'))

    def test_026_soaprequest_build(self):
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
    def test_027_binary_read(self):
        """ test read binary file """
        self.assertEqual('foo', self.binary_read(self.logger, 'filename'))

    @patch("builtins.open", mock_open(read_data='foo'), create=True)
    def test_028_binary_write(self):
        """ test wrote binary file """
        self.assertFalse(self.binary_write(self.logger, 'filename', 'content'))

    def test_029_sign(self):
        """ test _sign unkown key format """
        key = 'key'
        payload = 'foo'
        self.assertEqual((None, None), self.cahandler._sign(key, payload))

    @patch('cryptography.hazmat.primitives.asymmetric.rsa')
    def test_030_sign(self, mock_rsa):
        """ test _sign rsa key """
        with open(self.dir_path + '/ca/sub-ca-key.pem', 'rb') as open_file:
            key = serialization.load_pem_private_key(open_file.read(), password=None, backend=default_backend())
        payload = b'foo'
        result = self.cahandler._sign(key, payload)
        signature = b'4oTEIybGnmkfnG+Fvf0t8Sx8YHSf55tm3WtcdPagvtNM3vLjsidWKc2yliGYVmDqT9E+/wx3tvsMeDrgRiAzMhbjPYOeKwyx30BZT++4Fw9OkRQyriwyLB3ncFReVF8DyBRj/3S1Ftoy6Msa2CCk59LhYm/ubBQAm88gYiBzCFtVhneNOg5vS2s79UuyLjE2J90Yjs3z7OCckWrZ1UxI3UBoaJAWQg83M6fnF4aMkpnO3Jd6oQ4nq7r4EeVKYYEwrOINKKfh/1ykaCLg2K9OAD2LY1b9LilHTG8lcoUhS+bBMJkESHi508EzFQ4IUdsA42porTkEkdc5g9ZmCm7PPjroSRZGtM00R6aV/4z8Tlp4JBaov9x3fUd5wKjGIP0mdLQamAfxhK/pUqzM/lXtndprV7yh07tzypHa1XNvmTn/di2jNu90cq3eGgi3nBY98u+GcHTFnFH2aW2hk7kxqmxT4ymsZhlviIX8GIT4blE2nJgcl91Ktxm9QataRMjny/uJd//olQAXGMcbDwhNpYBfdJe99XoeuY+xNtJtlQt7IciTmJ3DEcK2kTtsNZ2i/lvn+iYR4iD9fJ/S4FedHqPZi48Q+LSnGC61zD21ZgbT8FrzUTnmmgw9BeDTWezGDGgBdOIuG313waZlvdDahk+6AYz9tOxS+bm9Epcj3NY='
        alg = """AlgorithmIdentifier:\n algorithm=1.2.840.113549.1.1.11\n parameters=0x0500\n"""
        self.assertEqual(signature, base64.b64encode(result[0]))
        self.assertEqual(alg, str(result[1]))

    @patch('cryptography.hazmat.primitives.asymmetric.rsa')
    def test_031_sign(self, mock_rsa):
        """ test _sign ecc key """
        ecc_key = b'-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIGCu1fYGkqMdPtsNH7xVc8QBjCWCkcUTVKX6f8vLhtkvoAoGCCqGSM49\nAwEHoUQDQgAEan72++swi7J5B1HVYp1CjXPqckkQquiMIQhz5xYesv9f4KK/ouKS\n1uJ3ZYwPbWUsDd8/03vf9VdlfZzL3W3ZQw==\n-----END EC PRIVATE KEY-----'
        key = serialization.load_pem_private_key(ecc_key, password=None, backend=default_backend())
        payload = b'foo'
        result = self.cahandler._sign(key, payload)
        # signature = b'MEQCIHuL0+ZfJAKIDeHHj4zhIA//SKhzcuMZQfPXjGEjFWQPAiA2gFoIklkXIqEDG4rWKqJKhfWsk/TDEupuHDvyEATx5Q=='
        # self.assertEqual(signature, base64.b64encode(result[0]))
        alg = """AlgorithmIdentifier:\n algorithm=1.2.840.10045.4.3.2\n"""
        self.assertEqual(alg, str(result[1]))

    def test_032_certraw_get(self):
        """ test _certraw_get """""
        with open(self.dir_path + '/ca/sub-ca-client.pem', 'r') as fso:
            pem_data = fso.read()
        result = 'MIIEGDCCAgCgAwIBAgIJALL8aztMPfV2MA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xFzAVBgNVBAoMDkFjbWUyQ2VydGlmaWVyMQ8wDQYDVQQDDAZzdWItY2EwHhcNMTkwNjI1MDEyNTAwWhcNMjAwNjI1MDEyNTAwWjBPMQswCQYDVQQGEwJERTEPMA0GA1UEBxMGQmVybGluMRcwFQYDVQQKEw5BY21lMkNlcnRpZmllcjEWMBQGA1UEAwwNY2xpZW50X3N1Yi1jYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALvoKKg3ciBVWZtquiWyMogWU6ydEfmLbXktK6T+owxzxHVaoePVGH9DZvTZD2pHS8xJ6fpFr3pZYiuqiUHuxdMpj9gVxik5ivBrSJIkZXLxwvNJWpMa1o1Hxz1By3Hrlm3ebKIzfQPqRRcdjWtJgCFbcTpalwhE1RQFMp4Icb08aAE9uEaZQ4uZ8Ls30J6IHC4PG63lGI1tkAtLIoUWupRAmnWDx0ysXzXeN7m+Lff9ols9MZNgzRMgY/zGUq0LzZfi+L+Iev3sztCdoIOBA/K63jv0hOPyYg331L05XIwbLeUoUG41J4pZzafx6MAFp4Zam1w+aafCzEw7ZPHQvn0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEABPgWo4KAXJNXNfEBbixDuCxtwO1JuphSOTcpIlEp+uNOSDzgNEbrhUXTNM8SPshzFjBpudc29okiyC62CfLD/X+EvIeKo/oa477kN6MuNfqLGZ42a935ES3S00Wy8rbwyIoPCsKWT/6VsHRHUn8XhFNFUBKZ8FGxwXcAVpPanyikURqVH1MgAk62hJQdYjSxdga/GKS1dS39fyxQz7uBPt5WIQZPzL6dr2Yn/4lQUvTUVus2e1cTh3z02yB5EDlEAcMMvMNpfYvNdU5H6QEPwysbkW9E/Ep84aq21zwuPxICh0KdjHWKkHtCqDoEYIADDl1AD5UdJTMQ9LIzUjsBvtB5I6yT7jgsx/iqTDrkJVK/zRf4NeKRa3AW57jsPUIcUstUFnVJbg+MM4fYmapx8Hqm/Aq+II9ip80AM6hXvierTQn4MNQivL0ZJfj0Ro9KEIDAHN3IAfIlFovbkBPLMi9PtfyhuVmXpthE9OaDlgUguWb45LAKwgfu1TFGPPpf5jTw2qVx0F+iCiUwK8ZgnakkXOKE5+KIb8ejL+3pPd5Wt+45w/7gEFOjT6XAzZGnUtcMH/lpxmgbl3/SKkyrW4h7PnF2FEEVC4XnZuQm+ZwD/PpXfmAA52ygKHBzUr9V33CkW0FhvjqkAUya5x9CqWlHoal0RVvFavnw+4ImqbE='
        self.assertEqual(result, self.cahandler._certraw_get(pem_data))

    def test_033_pkcs7_create(self):
        """ test pkcs7_create """
        with open(self.dir_path + '/ca/csr.der', 'rb') as open_file:
           csr_der = open_file.read()
        with open(self.dir_path + '/ca/sub-ca-key.pem', 'rb') as open_file:
            signing_key = serialization.load_pem_private_key(open_file.read(), password=None, backend=default_backend())
        with open(self.dir_path + '/ca/sub-ca-cert.pem', 'rb') as open_file:
            signing_cert = x509.load_pem_x509_certificate(open_file.read(), default_backend())

        decoded_cert = self.cahandler._cert_decode(signing_cert)
        expected_result = b'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'
        (_error, result) = self.cahandler._pkcs7_create(decoded_cert, csr_der, signing_key)
        self.assertEqual(expected_result, base64.b64encode(result))

    @patch('requests.post')
    def test_034_soaprequest_send(self, mock_post):
        """ soaprequest_send() - request exception """
        mock_post.side_effect = Exception('exc_api_post')
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Connection error', None), self.cahandler._soaprequest_send('payload'))
        self.assertIn('ERROR:test_a2c:CAhandler._soaprequest_send(): exc_api_post', lcm.output)

    @patch('xmltodict.parse')
    @patch('requests.post')
    def test_035_soaprequest_send(self, mock_post, mock_xml_parse):
        """ soaprequest_send() - 200 xml-parsing error """
        mock_post.return_value = Mock(status_code=200)
        mock_xml_parse.return_value = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Parsing error', None), self.cahandler._soaprequest_send('payload'))
        self.assertIn('ERROR:test_a2c:CAhandler._soaprequest_send() - XML Parsing error', lcm.output)

    @patch('xmltodict.parse')
    @patch('requests.post')
    def test_036_soaprequest_send(self, mock_post, mock_xml_parse):
        """ soaprequest_send() - 200 xml-parsing successful """
        mock_post.return_value = Mock(status_code=200)
        mock_xml_parse.return_value = {'s:Envelope': {'s:Body': {'RequestCertificateResponse': {'RequestCertificateResult': {'IssuedCertificate': 'foo'}}}}}
        self.assertEqual((None, 'foo'), self.cahandler._soaprequest_send('payload'))

    @patch('xmltodict.parse')
    @patch('requests.post')
    def test_037_soaprequest_send(self, mock_post, mock_xml_parse):
        """ soaprequest_send() - 400 xml-parsing error """
        mock_post.return_value = Mock(status_code=400)
        mock_xml_parse.return_value = {'foo': 'bar'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Server error', None), self.cahandler._soaprequest_send('payload'))
        self.assertIn('ERROR:test_a2c:CAhandler._soaprequest_send(): http status_code 400', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._soaprequest_send() - unkown error', lcm.output)

    @patch('xmltodict.parse')
    @patch('requests.post')
    def test_038_soaprequest_send(self, mock_post, mock_xml_parse):
        """ soaprequest_send() - 400 xml-parsing successful """
        mock_post.return_value = Mock(status_code=400)
        mock_xml_parse.return_value = {'s:Envelope': {'s:Body': {'s:Fault': {'faultcode': 'faultcode', 'faultstring': 'faultstring'}}}}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Server error', None), self.cahandler._soaprequest_send('payload'))
        self.assertIn('ERROR:test_a2c:CAhandler._soaprequest_send(): http status_code 400', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._soaprequest_send() - faultcode: faultcode', lcm.output)
        self.assertIn('ERROR:test_a2c:CAhandler._soaprequest_send() - faultstring: faultstring', lcm.output)

    def test_039_get_certificates(self):
        """ test pkcs7_create """
        with open(self.dir_path + '/ca/certs_der.p7b', 'rb') as open_file:
           pkcs7_bundle = open_file.read()
        result = ['-----BEGIN CERTIFICATE-----\nMIIFTzCCAzegAwIBAgIIAzHyhSyrXfMwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MTM1\nNDAwWhcNMzAwNTI2MjM1OTAwWjAqMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEP\nMA0GA1UEAxMGc3ViLWNhMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\nxXHaGZsolXe+PBdUryngHP9VbBC1mehqeTtYI+hqsqGNH7q9a7bSrxMwFuF1kYL8\njqqxkJdtl0L94xcxJg/ZdMx7Nt0vGI+BaAuTpEpUEHeN4tqS6NhB/m/0LGkAELc/\nqkzmoO4B1FDwEEj/3IXtZcupqG80oDt7jWSGXdtF7NTjzcumznMeRXidCdhxRxT/\n/WrsChaytXo0xWZ56oeNwd6x6Dr8/39PBOWtj4fldyDcg+Q+alci2tx9pxmu2bCV\nXcB9ftCLKhDk2WEHE88bgKSp7fV2RCmq9po+Tx8JJ7qecLunUsK/F0XN4kpoQLm9\nhcymqchnMSncSiyin1dQHGHWgXDtBDdq6A2Z6rx26Qk5H9HTYvcNSe1YwFEDoGLB\nZQjbCPWiaqoaH4agBQTclPvrrSCRaVmhUSO+pBtSXDkmN4t3MDZxfgRkp8ixwkB1\n5Y5f0LTpCyAJsdQDw8+Ea0aDqO30eskh4CErnm9+Fejd9Ew2cwpdwfBXzVSbYilM\nGueQihZHvJmVRxAwU69aO2Qs8B0tQ60CfWKVlmWPiakrvYYlPp0FBsM61G6LZEN8\nhH2CKnS8hHv5IWEXZvp0Pk8V3P5h6bWN0Tl+x/V1Prt7Wp8NoiPETE8XyDDxe6dm\nKxztWBH/mTsJyMGb6ZiUoXdPU9TFUKqHxTRLHaxfsPsCAwEAAaN4MHYwEgYDVR0T\nAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUv96OjgYiIqutQ8jd1E+oq0hBPtUwDgYD\nVR0PAQH/BAQDAgGGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYP\neGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBbHLEVyg4f9uEujroc\n31UVyDRLMdPgEPLjOenSBCBmH0N81whDmxNI/7JAAB6J14WMX8OLF0HkZnb7G77W\nvDhy1aFvQFbXHBz3/zUO9Mw9J4L2XEW6ond3Nsh1m2oXeBde3R3ANxuIzHqZDlP9\n6YrRcHjnf4+1/5AKDJAvJD+gFb5YnYUKH2iSvHUvG17xcZx98Rf2eo8LealG4JqH\nJh4sKRy0VjDQD7jXSCbweTHEb8wz+6OfNGrIo+BhTFP5vPcwE4nlJwYBoaOJ5cVa\n7gdQJ7WkLSxvwHxuxzvSVK73u3jl3I9SqTrbMLG/jeJyV0P8EvdljOaGnCtQVRwC\nzM4ptXUvKhKOHy7/nyTF/Bc35ZwwL/2xWvNK1+NibgE/6CFxupwWpdmxQbVVuoQ3\n2tUil9ty0yC6m5GKE8+t1lrZuxyA+b/TBnYNO5xo8UEMbkpxaNYSwmw+f/loxXP/\nM7sIBcLvy2ugHEBxwd9o/kLXeXT2DaRvxPjp4yk8MpJRpNmz3aB5HJwaUnaRLVo5\nZ3XWWXmjMGZ6/m0AAoDbDz/pXtOoJZT8BJdD1DuDdszVsQnLVn4B/LtIXL6FbXsF\nzfv6ERP9a5gpKUZ+4NjgrnlGtdccNZpwyWF0IXcvaq3b8hXIRO4hMjzHeHfzJN4t\njX1vlY35Ofonc4+6dRVamBiF9A==\n-----END CERTIFICATE-----\n', '-----BEGIN CERTIFICATE-----\nMIIFcDCCA1igAwIBAgIIevLTTxOMoZgwDQYJKoZIhvcNAQELBQAwKzEXMBUGA1UE\nCxMOYWNtZTJjZXJ0aWZpZXIxEDAOBgNVBAMTB3Jvb3QtY2EwHhcNMjAwNTI3MDAw\nMDAwWhcNMzAwNTI2MjM1OTU5WjArMRcwFQYDVQQLEw5hY21lMmNlcnRpZmllcjEQ\nMA4GA1UEAxMHcm9vdC1jYTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\nAJy4UZHdZgYt64k/rFamoC676tYvtabeuiqVw1c6oVZI897cFLG6BYwyr2Eaj7tF\nrqTJDeMN4vZSudLsmLDq6m8KwX/riPzUTIlcjM5aIMANZr9rLEs3NWtcivolB5aQ\n1slhdVitUPLuxsFnYeQTyxFyP7lng9M/Z403KLG8phdmKjM0vJkaj4OuKOXf3UsW\nqWQYyRl/ms07xVj02uq08LkoeO+jtQisvyVXURdaCceZtyK/ZBQ7NFCsbK112cVR\n1e2aJol7NJAA6Wm6iBzAdkAA2l3kh40SLoEbaiaVMixLN2vilIZOOAoDXX4+T6ir\n+KnDVSJ2yu5c/OJMwuXwHrh7Lgg1vsFR5TNehknhjUuWOUO+0TkKPg2A7KTg72OZ\n2mOcLZIbxzr1P5RRvdmLQLPrTF2EJvpQPNmbXqN3ZVWEvfHTjkkTFY/dsOTvFTgS\nri15zYKch8votcU7z+BQhgmMtwO2JhPMmZ6ABd9skI7ijWpwOltAhxtdoBO6T6CB\nCrE2yXc6V/PyyAKcFglNmIght5oXsnE+ub/dtx8f9Iea/xNPdo5aGy8fdaitolDK\n16kd3Kb7OE4HMHIwOxxF1BEAqerxxhbLMRBr8hRSZI5cvLzWLvpAQ5zuhjD6V3b9\nBYFd4ujAu3zl3mbzdbYjFoGOX6aBZaGDxlc4O2W7HxntAgMBAAGjgZcwgZQwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDGVvuTFYZtEAkz3af9wRKDDvAswwHwYD\nVR0jBBgwFoAUDGVvuTFYZtEAkz3af9wRKDDvAswwDgYDVR0PAQH/BAQDAgGGMBEG\nCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRl\nMA0GCSqGSIb3DQEBCwUAA4ICAQAjko7dX+iCgT+m3Iy1Vg6j7MRevPAzq1lqHRRN\nNdt2ct530pIut7Fv5V2xYk35ka+i/G+XyOvTXa9vAUKiBtiRnUPsXu4UcS7CcrCX\nEzHx4eOtHnp5wDhO0Fx5/OUZTaP+L7Pd1GD/j953ibx5bMa/M9Rj+S486nst57tu\nDRmEAavFDiMd6L3jH4YSckjmIH2uSeDIaRa9k6ag077XmWhvVYQ9tuR7RGbSuuV3\nFc6pqcFbbWpoLhNRcFc+hbUKOsKl2cP+QEKP/H2s3WMllqgAKKZeO+1KOsGo1CDs\n475bIXyCBpFbH2HOPatmu3yZRQ9fj9ta9EW46n33DFRNLinFWa4WJs4yLVP1juge\n2TCOyA1t61iy++RRXSG3e7NFYrEZuCht1EdDAdzIUY89m9NCPwoDYS4CahgnfkkO\n7YQe6f6yqK6isyf8ZFcp1uF58eERDiF/FDqS8nLmCdURuI56DDoNvDpig5J/9RNW\nG8vEvt2p7QrjeZ3EAatx5JuYty/NKTHZwJWk51CgzEgzDwzE2JIiqeldtL5d0Sl6\neVuv0G04BEyuXxEWpgVVzBS4qEFIBSnTJzgu1PXmId3yLvg2Nr8NKvwyZmN5xKFp\n0A9BWo15zW1PXDaD+l39oTYD7agjXkzTAjYIcfNJ7ATIYFD0xAvNAOf70s7aNupF\nfvkG2Q==\n-----END CERTIFICATE-----\n']
        self.assertEqual(result, self.cahandler._get_certificate(pkcs7_bundle))

    def test_040_pkcs7_signing_config_verify(self):
        """ test _pkcs7_signing_config_verify() """
        self.cahandler.signing_script_dic = {}
        self.assertEqual('signing config incomplete: option signing_script is missing', self.cahandler._pkcs7_signing_config_verify())

    def test_041_pkcs7_signing_config_verify(self):
        """ test _pkcs7_signing_config_verify() """
        self.cahandler.signing_script_dic = {'signing_script': 'signing_script'}
        self.assertEqual('signing config incomplete: option signing_alias is missing', self.cahandler._pkcs7_signing_config_verify())

    def test_042_pkcs7_signing_config_verify(self):
        """ test _pkcs7_signing_config_verify() """
        self.cahandler.signing_script_dic = {'signing_script': 'signing_script', 'signing_alias': 'signing_alias'}
        self.assertEqual('signing config incomplete: option signing_csr_path is missing', self.cahandler._pkcs7_signing_config_verify())

    @patch('os.path.isdir')
    def test_043_pkcs7_signing_config_verify(self, mock_path):
        """ test _pkcs7_signing_config_verify() """
        mock_path.return_value = False
        self.cahandler.signing_script_dic = {'signing_script': 'signing_script', 'signing_alias': 'signing_alias', 'signing_csr_path': 'signing_csr_path'}
        self.assertEqual('signing_csr_path signing_csr_path does not exist or is not a directory', self.cahandler._pkcs7_signing_config_verify())

    @patch('os.path.isdir')
    def test_044_pkcs7_signing_config_verify(self, mock_path):
        """ test _pkcs7_signing_config_verify() """
        mock_path.return_value = True
        self.cahandler.signing_script_dic = {'signing_script': 'signing_script', 'signing_alias': 'signing_alias', 'signing_csr_path': 'signing_csr_path'}
        self.assertEqual('signing config incomplete: option signing_config_variant is missing', self.cahandler._pkcs7_signing_config_verify())

    @patch('os.path.isdir')
    def test_045_pkcs7_signing_config_verify(self, mock_path):
        """ test _pkcs7_signing_config_verify() """
        mock_path.return_value = True
        self.cahandler.signing_script_dic = {'signing_script': 'signing_script', 'signing_alias': 'signing_alias', 'signing_csr_path': 'signing_csr_path', 'signing_config_variant': 'signing_config_variant'}
        self.assertEqual(None, self.cahandler._pkcs7_signing_config_verify())

    def test_046_signing_command_build(self):
        """ test _signing_command_build() """
        self.cahandler.signing_script_dic = {}
        self.assertEqual([], self.cahandler._signing_command_build('csr_unsigned', 'csr_signed'))

    def test_047_signing_command_build(self):
        """ test _signing_command_build() """
        self.cahandler.signing_script_dic = {}
        self.assertEqual([], self.cahandler._signing_command_build('csr_unsigned', 'csr_signed'))

    def test_048_signing_command_build(self):
        """ test _signing_command_build() """
        self.cahandler.signing_script_dic = {'signing_user': 'signing_user'}
        self.assertEqual([], self.cahandler._signing_command_build('csr_unsigned', 'csr_signed'))

    def test_049_signing_command_build(self):
        """ test _signing_command_build() """
        self.cahandler.signing_script_dic = {'signing_user': 'signing_user', 'signing_script': 'signing_script'}
        self.assertEqual(['sudo', 'signing_user', 'signing_script', 'csr_unsigned', 'csr_signed'], self.cahandler._signing_command_build('csr_unsigned', 'csr_signed'))

    def test_050_signing_command_build(self):
        """ test _signing_command_build() """
        self.cahandler.signing_script_dic = {'signing_user': 'signing_user', 'signing_script': 'signing_script', 'signing_interpreter': 'signing_interpreter'}
        self.assertEqual(['sudo', 'signing_user', 'signing_interpreter', 'signing_script', 'csr_unsigned', 'csr_signed'], self.cahandler._signing_command_build('csr_unsigned', 'csr_signed'))

    def test_051_signing_command_build(self):
        """ test _signing_command_build() """
        self.cahandler.signing_script_dic = {'signing_script': 'signing_script', 'signing_interpreter': 'signing_interpreter'}
        self.assertEqual(['signing_interpreter', 'signing_script', 'csr_unsigned', 'csr_signed'], self.cahandler._signing_command_build('csr_unsigned', 'csr_signed'))

    def test_052_signing_command_build(self):
        """ test _signing_command_build() """
        self.cahandler.signing_script_dic = {'signing_script': 'signing_script', 'signing_interpreter': 'signing_interpreter', 'signing_alias': 'signing_alias'}
        self.assertEqual(['signing_interpreter', 'signing_script', 'csr_unsigned', 'csr_signed'], self.cahandler._signing_command_build('csr_unsigned', 'csr_signed'))

    def test_053_signing_command_build(self):
        """ test _signing_command_build() """
        self.cahandler.signing_script_dic = {'signing_script': 'signing_script', 'signing_interpreter': 'signing_interpreter', 'signing_alias': 'signing_alias', 'signing_config_variant': 'signing_config_variant'}
        self.assertEqual(['signing_interpreter', 'signing_script', 'csr_unsigned', 'csr_signed', 'signing_alias', 'signing_config_variant'], self.cahandler._signing_command_build('csr_unsigned', 'csr_signed'))

    @patch('os.remove')
    @patch('os.path.isfile')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.binary_read')
    @patch('subprocess.call')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.binary_write')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._signing_command_build')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.generate_random_string')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_signing_config_verify')
    def test_054_pkcs7_sign_external(self, mock_vrf, mock_rand, mock_build, mock_write, mock_call, mock_read, mock_file, mock_rm):
        """ test _pkcs7_sign_external() """
        mock_vrf.return_value = True
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('Config incomplete', None), self.cahandler._pkcs7_sign_external('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler._pkcs7_sign_external(): config incomplete: True', lcm.output)
        self.assertFalse(mock_rand.called)
        self.assertFalse(mock_build.called)
        self.assertFalse(mock_write.called)
        self.assertFalse(mock_call.called)
        self.assertFalse(mock_read.called)
        self.assertFalse(mock_file.called)
        self.assertFalse(mock_rm.called)

    @patch('os.remove')
    @patch('os.path.isfile')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.binary_read')
    @patch('subprocess.call')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.binary_write')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._signing_command_build')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.generate_random_string')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_signing_config_verify')
    def test_055_pkcs7_sign_external(self, mock_vrf, mock_rand, mock_build, mock_write, mock_call, mock_read, mock_file, mock_rm):
        """ test _pkcs7_sign_external() all good """
        mock_vrf.return_value = False
        mock_read.return_value = 'foo'
        mock_call.return_value = None
        mock_file.return_value = True
        self.cahandler.signing_script_dic = {'signing_csr_path': 'signing_csr_path'}
        # with self.assertLogs('test_a2c', level='INFO') as lcm:
        self.assertEqual((None, 'foo'), self.cahandler._pkcs7_sign_external('csr'))
        # self.assertIn('ERROR:test_a2c:CAhandler._pkcs7_sign_external(): config incomplete: True', lcm.output)
        self.assertTrue(mock_rand.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_write.called)
        self.assertTrue(mock_call.called)
        self.assertTrue(mock_read.called)
        self.assertTrue(mock_file.called)
        self.assertTrue(mock_rm.called)

    @patch('os.remove')
    @patch('os.path.isfile')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.binary_read')
    @patch('subprocess.call')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.binary_write')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._signing_command_build')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.generate_random_string')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_signing_config_verify')
    def test_056_pkcs7_sign_external(self, mock_vrf, mock_rand, mock_build, mock_write, mock_call, mock_read, mock_file, mock_rm):
        """ test _pkcs7_sign_external() no delete """
        mock_vrf.return_value = False
        mock_read.return_value = 'foo'
        mock_call.return_value = None
        mock_file.return_value = False
        self.cahandler.signing_script_dic = {'signing_csr_path': 'signing_csr_path'}
        self.assertEqual((None, 'foo'), self.cahandler._pkcs7_sign_external('csr'))
        self.assertTrue(mock_rand.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_write.called)
        self.assertTrue(mock_call.called)
        self.assertTrue(mock_read.called)
        self.assertTrue(mock_file.called)
        self.assertFalse(mock_rm.called)

    @patch('os.remove')
    @patch('os.path.isfile')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.binary_read')
    @patch('subprocess.call')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.binary_write')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._signing_command_build')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.generate_random_string')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_signing_config_verify')
    def test_057_pkcs7_sign_external(self, mock_vrf, mock_rand, mock_build, mock_write, mock_call, mock_read, mock_file, mock_rm):
        """ test _pkcs7_sign_external() subprocess call returns something """
        mock_vrf.return_value = False
        mock_read.return_value = 'foo'
        mock_call.return_value = 1
        mock_file.return_value = True
        self.cahandler.signing_script_dic = {'signing_csr_path': 'signing_csr_path'}
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((1, None), self.cahandler._pkcs7_sign_external('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler._pkcs7_sign_external() aborted with error: 1', lcm.output)
        self.assertTrue(mock_rand.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_write.called)
        self.assertTrue(mock_call.called)
        self.assertFalse(mock_read.called)
        self.assertTrue(mock_file.called)
        self.assertTrue(mock_rm.called)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._certraw_get')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._get_certificate')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_send')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_build')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_encode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_create')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._cert_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_sign_external')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_url_recode')
    def test_058_enroll(self, mock_recode, mock_decode, mock_sigext, mock_cert_decode, mock_pkcs7_cr, mock_encode, mock_sbuild, mock_ssend, mock_cert_get, mock_cert_raw):
        """ test enroll() external signature script returning an error """
        self.cahandler.signing_script_dic = {'foo': 'bar'}
        mock_sigext.return_value = ('error', None)
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll() aborted with error: error', lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_decode.called)
        self.assertTrue(mock_sigext.called)
        self.assertFalse(mock_cert_decode.called)
        self.assertFalse(mock_pkcs7_cr.called)
        self.assertFalse(mock_encode.called)
        self.assertFalse(mock_sbuild.called)
        self.assertFalse(mock_ssend.called)
        self.assertFalse(mock_cert_get.called)
        self.assertFalse(mock_cert_raw.called)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._certraw_get')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._get_certificate')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_send')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_build')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_encode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_create')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._cert_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_sign_external')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_url_recode')
    def test_059_enroll(self, mock_recode, mock_decode, mock_sigext, mock_cert_decode, mock_pkcs7_cr, mock_encode, mock_sbuild, mock_ssend, mock_cert_get, mock_cert_raw):
        """ test enroll() internal signer returns error """
        self.cahandler.signing_script_dic = {}
        mock_pkcs7_cr.return_value = ('error', None)
        mock_cert_decode.return_value = 'decoded_cert'
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll() aborted with error: error', lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_decode.called)
        self.assertFalse(mock_sigext.called)
        self.assertTrue(mock_cert_decode.called)
        self.assertTrue(mock_pkcs7_cr.called)
        self.assertFalse(mock_encode.called)
        self.assertFalse(mock_sbuild.called)
        self.assertFalse(mock_ssend.called)
        self.assertFalse(mock_cert_get.called)
        self.assertFalse(mock_cert_raw.called)


    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._certraw_get')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._get_certificate')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_send')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_build')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_encode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_create')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._cert_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_sign_external')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_url_recode')
    def test_060_enroll(self, mock_recode, mock_decode, mock_sigext, mock_cert_decode, mock_pkcs7_cr, mock_encode, mock_sbuild, mock_ssend, mock_cert_get, mock_cert_raw):
        """ test enroll() - soap_request_send returns error """
        self.cahandler.signing_script_dic = {}
        mock_cert_decode.return_value = 'decoded_cert'
        mock_pkcs7_cr.return_value = (None, 'pkcs_7')
        mock_ssend.return_value = ('error', None)
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual(('error', None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll() _soaprequest_send() aborted with error: error', lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_decode.called)
        self.assertFalse(mock_sigext.called)
        self.assertTrue(mock_cert_decode.called)
        self.assertTrue(mock_pkcs7_cr.called)
        self.assertTrue(mock_encode.called)
        self.assertTrue(mock_sbuild.called)
        self.assertTrue(mock_ssend.called)
        self.assertFalse(mock_cert_get.called)
        self.assertFalse(mock_cert_raw.called)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._certraw_get')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._get_certificate')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_send')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_build')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_encode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_create')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._cert_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_sign_external')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_url_recode')
    def test_061_enroll(self, mock_recode, mock_decode, mock_sigext, mock_cert_decode, mock_pkcs7_cr, mock_encode, mock_sbuild, mock_ssend, mock_cert_get, mock_cert_raw):
        """ test enroll() - soap_request_send returns no error but no bundle """
        self.cahandler.signing_script_dic = {}
        mock_cert_decode.return_value = 'decoded_cert'
        mock_pkcs7_cr.return_value = (None, 'pkcs_7')
        mock_ssend.return_value = (None, None)
        with self.assertLogs('test_a2c', level='INFO') as lcm:
            self.assertEqual((None, None, None, None), self.cahandler.enroll('csr'))
        self.assertIn('ERROR:test_a2c:CAhandler.enroll() _soaprequest_send() did not return a bundle', lcm.output)
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_decode.called)
        self.assertFalse(mock_sigext.called)
        self.assertTrue(mock_cert_decode.called)
        self.assertTrue(mock_pkcs7_cr.called)
        self.assertTrue(mock_encode.called)
        self.assertTrue(mock_sbuild.called)
        self.assertTrue(mock_ssend.called)
        self.assertFalse(mock_cert_get.called)
        self.assertFalse(mock_cert_raw.called)

    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._certraw_get')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._get_certificate')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_send')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._soaprequest_build')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_encode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_create')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._cert_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.CAhandler._pkcs7_sign_external')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_decode')
    @patch('examples.ca_handler.pkcs7_soap_ca_handler.b64_url_recode')
    def test_062_enroll(self, mock_recode, mock_decode, mock_sigext, mock_cert_decode, mock_pkcs7_cr, mock_encode, mock_sbuild, mock_ssend, mock_cert_get, mock_cert_raw):
        """ test enroll() - soap_request_send returns no error but no bundle """
        self.cahandler.signing_script_dic = {}
        mock_cert_decode.return_value = 'decoded_cert'
        mock_pkcs7_cr.return_value = (None, 'pkcs_7')
        mock_ssend.return_value = (None, 'pkcs7_bundle')
        mock_cert_get.return_value = ['cert_1', 'cert_2']
        mock_cert_raw.return_value = 'cert_raw'
        self.assertEqual((None, 'cert_1cert_2', 'cert_raw', None), self.cahandler.enroll('csr'))
        self.assertTrue(mock_recode.called)
        self.assertTrue(mock_decode.called)
        self.assertFalse(mock_sigext.called)
        self.assertTrue(mock_cert_decode.called)
        self.assertTrue(mock_pkcs7_cr.called)
        self.assertTrue(mock_encode.called)
        self.assertTrue(mock_sbuild.called)
        self.assertTrue(mock_ssend.called)
        self.assertTrue(mock_cert_get.called)
        self.assertTrue(mock_cert_raw.called)


if __name__ == '__main__':

    unittest.main()