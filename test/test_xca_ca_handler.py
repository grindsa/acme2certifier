#!/usr/bin/python
# -*- coding: utf-8 -*-
"""unittests for openssl_ca_handler"""

# pylint: disable=C0302, C0415, R0904, R0913, W0212
import sys
import os
import re
import unittest
from unittest.mock import patch, Mock, MagicMock

# from OpenSSL import crypto
import shutil
from cryptography import x509
from cryptography.x509 import (
    BasicConstraints,
    ExtendedKeyUsage,
    SubjectKeyIdentifier,
    AuthorityKeyIdentifier,
    KeyUsage,
    SubjectAlternativeName,
)
import configparser

sys.path.insert(0, ".")
sys.path.insert(1, "..")


def _prepare(dir_path):
    """prepare testing"""
    # copy clean database
    if os.path.exists(dir_path + "/ca/acme2certifier-clean.xdb"):
        shutil.copy(
            dir_path + "/ca/acme2certifier-clean.xdb",
            dir_path + "/ca/acme2certifier.xdb",
        )


def _cleanup(dir_path):
    """cleanup function"""
    # remove old db
    if os.path.exists(dir_path + "/ca/acme2certifier.xdb"):
        os.remove(dir_path + "/ca/acme2certifier.xdb")


def return_input(*args, **kwargs):
    """this function just returns input to output"""
    _foo = kwargs
    return args


class TestACMEHandler(unittest.TestCase):
    """test class for cgi_handler"""

    def setUp(self):
        """setup unittest"""
        import logging
        from acme2certifier.cahandlers.xca_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        _prepare(self.dir_path)

    def tearDown(self):
        """teardown"""
        _cleanup(self.dir_path)

    def test_001_default(self):
        """default test which always passes"""
        self.assertEqual("foo", "foo")

    def test_002_check_config(self):
        """CAhandler._config_check with an empty config_dict"""
        self.assertEqual(
            "xdb_file must be specified in config file", self.cahandler._config_check()
        )

    def test_003_check_config(self):
        """CAhandler._config_check non existing xdb"""
        self.cahandler.xdb_file = "foo"
        self.assertEqual("xdb_file foo does not exist", self.cahandler._config_check())

    @patch("os.path.exists")
    def test_004_check_config(self, mock_file):
        """CAhandler._config_check xdb exists but no issuing ca_name"""
        self.cahandler.xdb_file = "foo"
        mock_file.return_value = True
        self.assertEqual(
            "issuing_ca_name must be set in config file", self.cahandler._config_check()
        )

    @patch("os.path.exists")
    def test_005_check_config(self, mock_file):
        """CAhandler._config_check xdb exists but no issuing ca_name"""
        self.cahandler.xdb_file = "foo"
        self.cahandler.issuing_ca_name = "foo"
        mock_file.return_value = True
        self.assertFalse(self.cahandler._config_check())

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    def test_006_csr_search(self, mock_check):
        """CAhandler._config_check non existing request"""
        mock_check.return_value = True
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.assertFalse(self.cahandler._csr_search("name", "foo"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    def test_007_csr_search(self, mock_check):
        """CAhandler._config_check existing request"""
        mock_check.return_value = True
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.assertTrue(self.cahandler._csr_search("name", "test_request"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    def test_008_csr_search(self, mock_check):
        """CAhandler._config_check existing request"""
        mock_check.return_value = False
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._csr_search("name", "test_request"))
        self.assertIn(
            "WARNING:test_a2c:column: name not in view_requests table", lcm.output
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_cert_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    def test_009_ca_load(self, mock_key, mock_cert):
        """CAhandler._ca_load for both cert and key"""
        mock_key.return_value = "key"
        mock_cert.return_value = ("cert", 1)
        self.assertEqual(("key", "cert", 1), self.cahandler._ca_load())

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_cert_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    def test_010_ca_load(self, mock_key, mock_cert):
        """CAhandler._ca_load for cert only"""
        mock_key.return_value = None
        mock_cert.return_value = ("cert", 1)
        self.assertEqual((None, "cert", 1), self.cahandler._ca_load())

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_cert_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    def test_011_ca_load(self, mock_key, mock_cert):
        """CAhandler._ca_load for cert only"""
        mock_key.return_value = "key"
        mock_cert.return_value = (None, None)
        self.assertEqual(("key", None, None), self.cahandler._ca_load())

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_cert_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    def test_012_ca_load(self, mock_key, mock_cert):
        """CAhandler._ca_load without key and cert"""
        mock_key.return_value = None
        mock_cert.return_value = (None, None)
        self.assertEqual((None, None, None), self.cahandler._ca_load())

    def test_013_ca_cert_load(self):
        """CAhandler._ca_cert_load"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        self.assertTrue(self.cahandler._ca_cert_load())

    def test_014_ca_cert_load(self):
        """CAhandler._ca_cert_load for non existing cert"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "bar"
        self.assertEqual((None, None), self.cahandler._ca_cert_load())

    def test_015_ca_key_load(self):
        """CAhandler._ca_key_load"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_key = "sub-ca"
        self.cahandler.passphrase = "test1234"
        self.assertTrue(self.cahandler._ca_key_load())

    def test_016_ca_key_load(self):
        """CAhandler._ca_key_load with wrong passphrase"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        self.cahandler.passphrase = "wrongpw"
        self.assertFalse(self.cahandler._ca_key_load())

    def test_017_ca_key_load(self):
        """CAhandler._ca_key_load without passphrase (should fail)"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        # self.cahandler.passphrase = 'wrongpw'
        self.assertFalse(self.cahandler._ca_key_load())

    @patch("cryptography.hazmat.primitives.serialization.load_pem_private_key")
    def test_018_ca_key_load(self, mock_key):
        """CAhandler._ca_key_load"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_key = "sub-ca"
        self.cahandler.passphrase = "test1234"
        mock_key.side_effect = Exception("exc_key_load")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._ca_key_load()
        self.assertIn(
            "ERROR:test_a2c:Failed to load CA private key from database: exc_key_load",
            lcm.output,
        )

    @patch("cryptography.x509.load_der_x509_certificate")
    def test_019_ca_cert_load(self, mock_certload):
        """CAhandler._ca_cert_load"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        mock_certload.side_effect = Exception("exc_cert_load")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual((None, None, None), self.cahandler._ca_load())
        self.assertIn(
            "ERROR:test_a2c:Failed to load CA certificate from database: exc_cert_load",
            lcm.output,
        )

    def test_020_csr_insert(self):
        """CAhandler._csr_insert empty item dic"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        csr_dic = {}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_021_csr_insert(self):
        """CAhandler._csr_insert full item dic"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        csr_dic = {"item": 2, "signed": 0, "request": "request"}
        self.assertEqual(2, self.cahandler._csr_insert(csr_dic))

    def test_022_csr_insert(self):
        """CAhandler._csr_insert full item dic item has wrong datatype"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        csr_dic = {"item": "2", "signed": 0, "request": "request"}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_023_csr_insert(self):
        """CAhandler._csr_insert full item dic item has wrong datatype"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        csr_dic = {"item": 2, "signed": "0", "request": "request"}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_024_csr_insert(self):
        """CAhandler._csr_insert item dic without item"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        csr_dic = {"signed": 0, "request": "request"}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_025_csr_insert(self):
        """CAhandler._csr_insert item dic without signed"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        csr_dic = {"item": 2, "request": "request"}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_026_csr_insert(self):
        """CAhandler._csr_insert item dic without request"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        csr_dic = {"item": 2, "signed": 0}
        self.assertFalse(self.cahandler._csr_insert(csr_dic))

    def test_027_item_insert(self):
        """CAhandler._item_insert empty item dic"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        item_dic = {}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_028_item_insert(self):
        """CAhandler._item_insert full item dic"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        item_dic = {
            "name": "name",
            "type": 2,
            "source": 0,
            "date": "date",
            "comment": "comment",
        }
        self.assertEqual(15, self.cahandler._item_insert(item_dic))

    def test_029_item_insert(self):
        """CAhandler._item_insert no name"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        item_dic = {"type": 2, "source": 0, "date": "date", "comment": "comment"}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_030_item_insert(self):
        """CAhandler._item_insert no type"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        item_dic = {"name": "name", "source": 0, "date": "date", "comment": "comment"}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_031_item_insert(self):
        """CAhandler._item_insert no siurce"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        item_dic = {"name": "name", "item": 2, "date": "date", "comment": "comment"}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_032_item_insert(self):
        """CAhandler._item_insert no date"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        item_dic = {"name": "name", "type": 2, "source": 0, "comment": "comment"}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_033_item_insert(self):
        """CAhandler._item_insert no date"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        item_dic = {"name": "name", "type": 2, "source": 0, "date": "date"}
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_034_item_insert(self):
        """CAhandler._item_insert full item dic type has wrong datatype"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        item_dic = {
            "name": "name",
            "type": "2",
            "source": 0,
            "date": "date",
            "comment": "comment",
        }
        self.assertFalse(self.cahandler._item_insert(item_dic))

    def test_035_item_insert(self):
        """CAhandler._item_insert full item dic source has wrong datatype"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        item_dic = {
            "name": "name",
            "type": 2,
            "source": "0",
            "date": "date",
            "comment": "comment",
        }
        self.assertFalse(self.cahandler._item_insert(item_dic))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_search")
    def test_036_csr_import(self, mock_search):
        """CAhandler._csr_import with existing cert_dic"""
        mock_search.return_value = {"foo", "bar"}
        self.assertEqual(
            {"foo", "bar"}, self.cahandler._csr_import("csr", "request_name")
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._item_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_search")
    def test_037_csr_import(self, mock_search, mock_csr_insert, mock_item_insert):
        """CAhandler._csr_import with existing cert_dic"""
        mock_search.return_value = {}
        mock_csr_insert.return_value = 5
        mock_item_insert.return_value = 10
        self.assertEqual(
            {"item": 10, "signed": 1, "request": "csr"},
            self.cahandler._csr_import("csr", "request_name"),
        )

    def test_038_cert_insert(self):
        """CAhandler._csr_import with empty cert_dic"""
        cert_dic = {}
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_039_cert_insert(self):
        """CAhandler._csr_import item missing"""
        cert_dic = {
            "serial": "serial",
            "issuer": "issuer",
            "ca": "ca",
            "cert": "cert",
            "iss_hash": "iss_hash",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_040_cert_insert(self):
        """CAhandler._csr_import serial missing"""
        cert_dic = {
            "item": "item",
            "issuer": "issuer",
            "ca": "ca",
            "cert": "cert",
            "iss_hash": "iss_hash",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_041_cert_insert(self):
        """CAhandler._csr_import issuer missing"""
        cert_dic = {
            "item": "item",
            "serial": "serial",
            "ca": "ca",
            "cert": "cert",
            "iss_hash": "iss_hash",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_042_cert_insert(self):
        """CAhandler._csr_import ca missing"""
        cert_dic = {
            "item": "item",
            "serial": "serial",
            "issuer": "issuer",
            "cert": "cert",
            "iss_hash": "iss_hash",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_043_cert_insert(self):
        """CAhandler._csr_import cert missing"""
        cert_dic = {
            "item": "item",
            "serial": "serial",
            "issuer": "issuer",
            "ca": "ca",
            "iss_hash": "iss_hash",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_044_cert_insert(self):
        """CAhandler._csr_import iss_hash missing"""
        cert_dic = {
            "item": "item",
            "serial": "serial",
            "issuer": "issuer",
            "ca": "ca",
            "cert": "cert",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_045_cert_insert(self):
        """CAhandler._csr_import hash missing"""
        cert_dic = {
            "item": "item",
            "serial": "serial",
            "issuer": "issuer",
            "ca": "ca",
            "cert": "cert",
            "iss_hash": "iss_hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_046_cert_insert(self):
        """CAhandler._csr_import with item not int"""
        cert_dic = {
            "item": "item",
            "serial": "serial",
            "issuer": "issuer",
            "ca": "ca",
            "cert": "cert",
            "iss_hash": "iss_hash",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_047_cert_insert(self):
        """CAhandler._csr_import with issuer not int"""
        cert_dic = {
            "item": 1,
            "serial": "serial",
            "issuer": "issuer",
            "ca": "ca",
            "cert": "cert",
            "iss_hash": "iss_hash",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_048_cert_insert(self):
        """CAhandler._csr_import with ca not int"""
        cert_dic = {
            "item": 1,
            "serial": "serial",
            "issuer": 1,
            "ca": "ca",
            "cert": "cert",
            "iss_hash": "iss_hash",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_049_cert_insert(self):
        """CAhandler._csr_import with iss_hash not int"""
        cert_dic = {
            "item": 1,
            "serial": "serial",
            "issuer": 2,
            "ca": 3,
            "cert": "cert",
            "iss_hash": "iss_hash",
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    def test_050_cert_insert(self):
        """CAhandler._csr_import with hash not int"""
        cert_dic = {
            "item": 1,
            "serial": "serial",
            "issuer": 2,
            "ca": 3,
            "cert": "cert",
            "iss_hash": 4,
            "hash": "hash",
        }
        self.assertFalse(self.cahandler._cert_insert(cert_dic))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_051_cert_insert(self, mock_open, mock_close):
        """CAhandler._csr_import with hash not int"""
        cert_dic = {
            "item": 1,
            "serial": "serial",
            "issuer": 2,
            "ca": 3,
            "cert": "cert",
            "iss_hash": 4,
            "hash": 5,
        }
        mock_open.return_value = True
        mock_close.return_value = True
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.lastrowid = 5
        self.assertEqual(5, self.cahandler._cert_insert(cert_dic))
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    def test_052_pemcertchain_generate(self):
        """CAhandler._pemcertchain_generate no certificates"""
        ee_cert = None
        issuer_cert = None
        self.cahandler.ca_cert_chain_list = []
        self.assertFalse(self.cahandler._pemcertchain_generate(ee_cert, issuer_cert))

    def test_053_pemcertchain_generate(self):
        """CAhandler._pemcertchain_generate no issuer"""
        ee_cert = "ee_cert"
        issuer_cert = None
        self.cahandler.ca_cert_chain_list = []
        self.assertEqual(
            "ee_cert", self.cahandler._pemcertchain_generate(ee_cert, issuer_cert)
        )

    def test_054_pemcertchain_generate(self):
        """CAhandler._pemcertchain_generate no ca chain"""
        ee_cert = "ee_cert"
        issuer_cert = "issuer_cert"
        self.cahandler.ca_cert_chain_list = []
        self.assertEqual(
            "ee_certissuer_cert",
            self.cahandler._pemcertchain_generate(ee_cert, issuer_cert),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_search")
    @patch("OpenSSL.crypto.load_certificate")
    def test_055_pemcertchain_generate(self, mock_cert, mock_search):
        """CAhandler._pemcertchain_generate empty cert dic in ca_chain"""
        ee_cert = "ee_cert"
        issuer_cert = "issuer_cert"
        self.cahandler.ca_cert_chain_list = ["foo_bar"]
        mock_search.return_value = None
        mock_cert.side_effect = ["foo", "bar"]
        self.assertEqual(
            "ee_certissuer_cert",
            self.cahandler._pemcertchain_generate(ee_cert, issuer_cert),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_search")
    @patch("OpenSSL.crypto.load_certificate")
    def test_056_pemcertchain_generate(self, mock_cert, mock_search):
        """CAhandler._pemcertchain_generate empty no cert in chain"""
        ee_cert = "ee_cert"
        issuer_cert = "issuer_cert"
        self.cahandler.ca_cert_chain_list = ["foo_bar"]
        mock_search.return_value = {"foo", "bar"}
        mock_cert.side_effect = ["foo", "bar"]
        self.assertEqual(
            "ee_certissuer_cert",
            self.cahandler._pemcertchain_generate(ee_cert, issuer_cert),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_decode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_search")
    @patch("cryptography.x509.load_der_x509_certificate")
    def test_057_pemcertchain_generate(self, mock_load, mock_search, mock_b64dec):
        """CAhandler._pemcertchain_generate one cert in chain"""
        ee_cert = "ee_cert"
        issuer_cert = "issuer_cert"
        self.cahandler.ca_cert_chain_list = ["foo_bar"]
        mock_search.return_value = {"cert": "foo"}
        mock_load.return_value = Mock()
        mock_load.return_value.public_bytes.side_effect = ["foo1", "foo2"]
        mock_b64dec.return_value = "b64dec"
        self.assertEqual(
            "ee_certissuer_certfoo1",
            self.cahandler._pemcertchain_generate(ee_cert, issuer_cert),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_decode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_search")
    @patch("cryptography.x509.load_der_x509_certificate")
    def test_058_pemcertchain_generate(self, mock_load, mock_search, mock_b64dec):
        """CAhandler._pemcertchain_generate two certs in chain"""
        ee_cert = "ee_cert"
        issuer_cert = "issuer_cert"
        self.cahandler.ca_cert_chain_list = ["foo_bar", "foo_bar"]
        mock_search.return_value = {"cert": "foo"}
        mock_load.return_value = Mock()
        mock_load.return_value.public_bytes.side_effect = ["foo1", "foo2"]
        mock_b64dec.return_value = "b64dec"
        self.assertEqual(
            "ee_certissuer_certfoo1foo2",
            self.cahandler._pemcertchain_generate(ee_cert, issuer_cert),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_cn_get")
    def test_059_requestname_get(self, mock_cn):
        """CAhandler._requestname_get from cn"""
        mock_cn.return_value = "foo"
        self.assertEqual("foo", self.cahandler._requestname_get("csr"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_san_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_cn_get")
    def test_060_requestname_get(self, mock_cn, mock_san):
        """CAhandler._requestname_get empty cn empty san"""
        mock_cn.return_value = None
        mock_san.return_value = []
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._requestname_get("csr"))
        self.assertIn(
            "ERROR:test_a2c:Failed to split SAN from CSR subjectAltName: []",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_san_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_cn_get")
    def test_061_requestname_get(self, mock_cn, mock_san):
        """CAhandler._requestname_get empty cn empty dsmaged san"""
        mock_cn.return_value = None
        mock_san.return_value = ["foo"]
        self.assertFalse(self.cahandler._requestname_get("csr"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_san_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_cn_get")
    def test_062_requestname_get(self, mock_cn, mock_san):
        """CAhandler._requestname_get empty cn empty dsmaged san"""
        mock_cn.return_value = None
        mock_san.return_value = ["dns:foo"]
        self.assertEqual("foo", self.cahandler._requestname_get("csr"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_san_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_cn_get")
    def test_063_requestname_get(self, mock_cn, mock_san):
        """CAhandler._requestname_get empty cn empty damaged san"""
        mock_cn.return_value = None
        mock_san.return_value = ["dns:foo", "bar"]
        self.assertEqual("foo", self.cahandler._requestname_get("csr"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_san_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.csr_cn_get")
    def test_064_requestname_get(self, mock_cn, mock_san):
        """CAhandler._requestname_get empty cn empty damaged san"""
        mock_cn.return_value = None
        mock_san.return_value = ["foo", "bar"]
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(None, self.cahandler._requestname_get("csr"))
        self.assertIn(
            "ERROR:test_a2c:Failed to split SAN from CSR subjectAltName: ['foo', 'bar']",
            lcm.output,
        )

    def test_065_cert_insert(self):
        """CAhandler._revocation_insert with empty rev_dic"""
        rev_dic = {}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_066_cert_insert(self):
        """CAhandler._revocation_insert no caID"""
        rev_dic = {
            "serial": "serial",
            "date": "date",
            "invaldate": "invaldate",
            "reasonBit": 0,
        }
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_067_cert_insert(self):
        """CAhandler._revocation_insert no serial"""
        rev_dic = {"caID": 4, "date": "date", "invaldate": "invaldate", "reasonBit": 0}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_068_cert_insert(self):
        """CAhandler._revocation_insert no date"""
        rev_dic = {
            "caID": 4,
            "serial": "serial",
            "invaldate": "invaldate",
            "reasonBit": 0,
        }
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_069_cert_insert(self):
        """CAhandler._revocation_insert no invaldate"""
        rev_dic = {"caID": 4, "serial": "serial", "date": "date", "reasonBit": 0}
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_070_cert_insert(self):
        """CAhandler._revocation_insert no resonBit"""
        rev_dic = {
            "caID": 4,
            "serial": "serial",
            "date": "date",
            "invaldate": "invaldate",
        }
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_071_cert_insert(self):
        """CAhandler._revocation_insert with caID is not int"""
        rev_dic = {
            "caID": "caID",
            "serial": "serial",
            "date": "date",
            "invaldate": "invaldate",
            "reasonBit": 0,
        }
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    def test_072_cert_insert(self):
        """CAhandler._revocation_insert with caID is not int"""
        rev_dic = {
            "caID": 0,
            "serial": "serial",
            "date": "date",
            "invaldate": "invaldate",
            "reasonBit": "0",
        }
        self.assertFalse(self.cahandler._revocation_insert(rev_dic))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_073_rev_insert(self, mock_open, mock_close):
        """CAhandler._revocation_insert with caID is not inall okt"""
        mock_close.return_value = True
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.lastrowid = 5
        rev_dic = {
            "caID": 0,
            "serial": "serial",
            "date": "date",
            "invaldate": "invaldate",
            "reasonBit": 0,
        }
        self.assertEqual(5, self.cahandler._revocation_insert(rev_dic))
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.uts_to_date_utc")
    def test_074_revoke(self, mock_date):
        """CAhandler.revocation without xdb file"""
        mock_date.return_value = "foo"
        self.assertEqual(
            (500, "urn:ietf:params:acme:error:serverInternal", "Configuration error"),
            self.cahandler.revoke("cert", "reason", None),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.cert_serial_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.uts_to_date_utc")
    def test_075_revoke(self, mock_date, mock_ca, mock_serial):
        """CAhandler.revocation no CA ID"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        mock_date.return_value = "foo"
        mock_ca.return_value = ("key", "cert", None)
        mock_serial.return_value = 1000
        self.assertEqual(
            (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "certificate lookup failed",
            ),
            self.cahandler.revoke("cert", "reason", None),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.cert_serial_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.uts_to_date_utc")
    def test_076_revoke(self, mock_date, mock_ca, mock_serial):
        """CAhandler.revocation no serial"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        mock_date.return_value = "foo"
        mock_ca.return_value = ("key", "cert", 2)
        mock_serial.return_value = None
        self.assertEqual(
            (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "certificate lookup failed",
            ),
            self.cahandler.revoke("cert", "reason", None),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._revocation_search")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._revocation_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.cert_serial_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.uts_to_date_utc")
    def test_077_revoke(
        self, mock_date, mock_ca, mock_serial, mock_rev_insert, mock_search
    ):
        """CAhandler.revocation no serial"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        mock_date.return_value = "foo"
        mock_ca.return_value = ("key", "cert", 2)
        mock_search.return_value = None
        mock_rev_insert.return_value = None
        mock_serial.return_value = 1000
        self.assertEqual(
            (
                500,
                "urn:ietf:params:acme:error:serverInternal",
                "database update failed",
            ),
            self.cahandler.revoke("cert", "reason", None),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._revocation_search")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._revocation_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.cert_serial_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.uts_to_date_utc")
    def test_078_revoke(
        self, mock_date, mock_ca, mock_serial, mock_rev_insert, mock_search
    ):
        """CAhandler.revocation no serial"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        mock_date.return_value = "foo"
        mock_ca.return_value = ("key", "cert", 2)
        mock_search.return_value = "foo"
        mock_rev_insert.return_value = 20
        mock_serial.return_value = 1000
        self.assertEqual(
            (
                400,
                "urn:ietf:params:acme:error:alreadyRevoked",
                "Certificate has already been revoked",
            ),
            self.cahandler.revoke("cert", "reason", None),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_revocation_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._revocation_search")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._revocation_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.cert_serial_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.uts_to_date_utc")
    def test_079_revoke(
        self, mock_date, mock_ca, mock_serial, mock_rev_insert, mock_search, mock_eab
    ):
        """CAhandler.revocation no serial"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        mock_date.return_value = "foo"
        mock_ca.return_value = ("key", "cert", 2)
        mock_search.return_value = None
        mock_rev_insert.return_value = 20
        mock_serial.return_value = 1000
        self.assertEqual(
            (200, None, None), self.cahandler.revoke("cert", "reason", None)
        )
        self.assertFalse(mock_eab.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_revocation_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._revocation_search")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._revocation_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.cert_serial_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.uts_to_date_utc")
    def test_080_revoke(
        self, mock_date, mock_ca, mock_serial, mock_rev_insert, mock_search, mock_eab
    ):
        """CAhandler.revocation no serial"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.eab_profiling = True
        mock_date.return_value = "foo"
        mock_ca.return_value = ("key", "cert", 2)
        mock_search.return_value = None
        mock_rev_insert.return_value = 20
        mock_serial.return_value = 1000
        self.assertEqual(
            (200, None, None), self.cahandler.revoke("cert", "reason", None)
        )
        self.assertTrue(mock_eab.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    def test_081_cert_search(self, mock_check):
        """CAhandler._cert_sarch cert can be found"""
        mock_check.return_value = True
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        search_result = {
            "item": 6,
            "hash": 1675584264,
            "iss_hash": 1339028853,
            "serial": "0BCC30C544EF26A4",
            "issuer": 4,
            "ca": 0,
            "cert": "MIIEQTCCAimgAwIBAgIIC8wwxUTvJqQwDQYJKoZIhvcNAQELBQAwETEPMA0GA1UEAxMGc3ViLWNhMB4XDTIwMDYwOTE3MTkwMFoXDTIxMDYwOTE3MTkwMFowGzEZMBcGA1UEAxMQY2xpZW50LmJhci5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJps2tk/d5pqv1gSeLnDBFQSzznY/iSBtzRNLlRWm6J7yOAERgGsbMBW7s5AhYRbuHuberlBtsyFyKenWvijo6r7DTOGiv2oBf7iCoCXYbNAqlvnP5inzp6ZmmgmxigLFbdlTfPQBkaytDzLAav1KLCmCof4DpQunsxdDjW0kBm8jRC7HY5bauxeFKQb2NcGmjlB3kQjZNHF52xG/GgkMIH7E0NJUhmsVfItSezkmFUQFhP2VqYYsiPRtvXlZqpzPISxn2InGcUaaBzJFO7RWif0IIsgzcyzqXvt8KEqeoI15gmd1G4lXPeyadXG8kzE8L+8f4J+gGgQSA1eR4VMkOMCAwEAAaOBkjCBjzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRjovc4aaN6LCIE5E/ZgsLBH+3/WDAOBgNVHQ8BAf8EBAMCA+gwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBsGA1UdEQQUMBKCEGNsaWVudC5iYXIubG9jYWwwEQYJYIZIAYb4QgEBBAQDAgZAMA0GCSqGSIb3DQEBCwUAA4ICAQCZm5d3jc9oopD193bGwJFo8NNo1wzYvvqbK/lONy/JsisX1pERxN+EZyTB2CLxQ4yKZU9Xnx0fmcJExqoPLEva6hAMdOiSEsEs52yyL6gjMLHxJJfdXBiqMZetp+BCPf23rc96ONzyjURDCfsN4VMg7090e9yKpuyHKIOHStqMT+ZLvPcd+YiU4jMazoagauEW2mdpqyA8mN92qiphwo8QMCv3XZJWJ1PEwaCTGhBxlzMoaknWKzCD2YQ/yyGE4Ha8vBaymk1eh7txo5B53C0OpO0UT4WGUOZDP1GPySymqQfDO6R9BhBjyggsG5G9FA84tUqZJAKlGhPesQyIQBM4SZlQTJt/hP/cCoZ6BiibBdaZnLzOyH+NTJ9ou0hpmMp2LZiB8G2Igam7wdXySvQe9sxXXDDTKhxwqk7V+by2gS6asfcQjstQQeMN/iMrg3AtZt/Kl5WcHcwSjZAypHugPiwjr48WHvDS2lUKnbbDuiCxvc1TsPGG6Z+b/0aTwrps6yMeTRuDk3A8DYceHftrWZSOgg+5A2ISd58vPOHiamATVLXGJ1vnCP0Sm/Z4QCnIGfOvxltdAnrcA75MnefaOmQv9CrhwyBembugd9fPC/uFi/ESKGPuo6zLYwjFwLqwNe99UgU98iYz9rfdKNqJ6fWRolzz4AXqUHQ4Dc8eZA==",
        }
        self.assertEqual(search_result, self.cahandler._cert_search("name", "client"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    def test_082_cert_search(self, mock_check):
        """CAhandler._cert_sarch cert failed"""
        mock_check.return_value = True
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.assertFalse(self.cahandler._cert_search("name", "client_failed"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    def test_083_cert_search(self, mock_check):
        """CAhandler._cert_sarch item search succ / cert_search failed"""
        mock_check.return_value = True
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.assertFalse(self.cahandler._cert_search("name", "item_no_cert"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    def test_084_cert_search(self, mock_check):
        """CAhandler._cert_sarch cert can be found"""
        mock_check.return_value = False
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        search_result = {
            "item": 6,
            "hash": 1675584264,
            "iss_hash": 1339028853,
            "serial": "0BCC30C544EF26A4",
            "issuer": 4,
            "ca": 0,
            "cert": "MIIEQTCCAimgAwIBAgIIC8wwxUTvJqQwDQYJKoZIhvcNAQELBQAwETEPMA0GA1UEAxMGc3ViLWNhMB4XDTIwMDYwOTE3MTkwMFoXDTIxMDYwOTE3MTkwMFowGzEZMBcGA1UEAxMQY2xpZW50LmJhci5sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJps2tk/d5pqv1gSeLnDBFQSzznY/iSBtzRNLlRWm6J7yOAERgGsbMBW7s5AhYRbuHuberlBtsyFyKenWvijo6r7DTOGiv2oBf7iCoCXYbNAqlvnP5inzp6ZmmgmxigLFbdlTfPQBkaytDzLAav1KLCmCof4DpQunsxdDjW0kBm8jRC7HY5bauxeFKQb2NcGmjlB3kQjZNHF52xG/GgkMIH7E0NJUhmsVfItSezkmFUQFhP2VqYYsiPRtvXlZqpzPISxn2InGcUaaBzJFO7RWif0IIsgzcyzqXvt8KEqeoI15gmd1G4lXPeyadXG8kzE8L+8f4J+gGgQSA1eR4VMkOMCAwEAAaOBkjCBjzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRjovc4aaN6LCIE5E/ZgsLBH+3/WDAOBgNVHQ8BAf8EBAMCA+gwIAYDVR0lAQH/BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBsGA1UdEQQUMBKCEGNsaWVudC5iYXIubG9jYWwwEQYJYIZIAYb4QgEBBAQDAgZAMA0GCSqGSIb3DQEBCwUAA4ICAQCZm5d3jc9oopD193bGwJFo8NNo1wzYvvqbK/lONy/JsisX1pERxN+EZyTB2CLxQ4yKZU9Xnx0fmcJExqoPLEva6hAMdOiSEsEs52yyL6gjMLHxJJfdXBiqMZetp+BCPf23rc96ONzyjURDCfsN4VMg7090e9yKpuyHKIOHStqMT+ZLvPcd+YiU4jMazoagauEW2mdpqyA8mN92qiphwo8QMCv3XZJWJ1PEwaCTGhBxlzMoaknWKzCD2YQ/yyGE4Ha8vBaymk1eh7txo5B53C0OpO0UT4WGUOZDP1GPySymqQfDO6R9BhBjyggsG5G9FA84tUqZJAKlGhPesQyIQBM4SZlQTJt/hP/cCoZ6BiibBdaZnLzOyH+NTJ9ou0hpmMp2LZiB8G2Igam7wdXySvQe9sxXXDDTKhxwqk7V+by2gS6asfcQjstQQeMN/iMrg3AtZt/Kl5WcHcwSjZAypHugPiwjr48WHvDS2lUKnbbDuiCxvc1TsPGG6Z+b/0aTwrps6yMeTRuDk3A8DYceHftrWZSOgg+5A2ISd58vPOHiamATVLXGJ1vnCP0Sm/Z4QCnIGfOvxltdAnrcA75MnefaOmQv9CrhwyBembugd9fPC/uFi/ESKGPuo6zLYwjFwLqwNe99UgU98iYz9rfdKNqJ6fWRolzz4AXqUHQ4Dc8eZA==",
        }
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._cert_search("name", "client"))
        self.assertIn(
            "WARNING:test_a2c:column: name not in items table",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_085_config_load(self, mock_load_cfg):
        """test _config_load - ca_chain is not json format"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_cert_chain_list": "[foo]"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.ca_cert_chain_list)
        self.assertIn(
            'ERROR:test_a2c:Parameter "ca_cert_chain_list" cannot be loaded',
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_086_config_load(self, mock_load_cfg):
        """test _config_load - load template"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"template_name": "foo"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("foo", self.cahandler.template_name)

    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_087_config_load(self, mock_load_cfg):
        """test _config_load - load template"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"xdb_file": "foo"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("foo", self.cahandler.xdb_file)

    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_088_config_load(self, mock_load_cfg):
        """test _config_load - load template"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"passphrase": "foo"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("foo", self.cahandler.passphrase)

    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_089_config_load(self, mock_load_cfg):
        """test _config_load - load template"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"issuing_ca_name": "foo"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("foo", self.cahandler.issuing_ca_name)

    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_090_config_load(self, mock_load_cfg):
        """test _config_load - load template"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"issuing_ca_key": "foo"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("foo", self.cahandler.issuing_ca_key)

    @patch.dict("os.environ", {"foo": "foo_var"})
    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_091_config_load(self, mock_load_cfg):
        """test _config_load - load template with passphrase variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"passphrase_variable": "foo"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("foo_var", self.cahandler.passphrase)

    @patch.dict("os.environ", {"foo": "foo_var"})
    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_092_config_load(self, mock_load_cfg):
        """test _config_load - load template passpharese variable configured but does not exist"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"passphrase_variable": "does_not_exist"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertFalse(self.cahandler.passphrase)
        self.assertIn(
            "ERROR:test_a2c:Could not load passphrase_variable:'does_not_exist'",
            lcm.output,
        )

    @patch.dict("os.environ", {"foo": "foo_var"})
    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_093_config_load(self, mock_load_cfg):
        """test _config_load - load template with passphrase variable  - overwritten bei cfg file"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"passphrase_variable": "foo", "passphrase": "foo_file"}
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertEqual("foo_file", self.cahandler.passphrase)
        self.assertIn(
            "INFO:test_a2c:Overwrite passphrase",
            lcm.output,
        )

    def test_094_stream_split(self):
        """test stream_split - all ok"""
        byte_stream = b"before\x00\x00\x00\x0cafter"
        self.assertEqual(
            (b"before\x00\x00\x00\x0c", b"after"),
            self.cahandler._stream_split(byte_stream),
        )

    def test_095_stream_split(self):
        """test stream_split - no bytestream"""
        byte_stream = None
        self.assertEqual((None, None), self.cahandler._stream_split(byte_stream))

    def test_096_stream_split(self):
        """test stream_split - no match"""
        byte_stream = b"foofoobar"
        self.assertEqual((None, None), self.cahandler._stream_split(byte_stream))

    def test_097_stream_split(self):
        """test stream_split - start with match match"""
        byte_stream = b"\x00\x00\x00\x0cafter"
        self.assertEqual(
            (b"\x00\x00\x00\x0c", b"after"), self.cahandler._stream_split(byte_stream)
        )

    def test_098__utf_stream_parse(self):
        """test _utf_stream_parse()  - all ok"""
        utf_stream = b"foo\x00\x00\x00bar"
        self.assertEqual(({"foo": "ar"}), self.cahandler._utf_stream_parse(utf_stream))

    def test_099__utf_stream_parse(self):
        """test _utf_stream_parse()  - two parameter"""
        utf_stream = b"foo1\x00\x00\x00_bar1\x00\x00\x00_foo2\x00\x00\x00_bar2"
        self.assertEqual(
            ({"foo1": "bar1", "foo2": "bar2"}),
            self.cahandler._utf_stream_parse(utf_stream),
        )

    def test_100__utf_stream_parse(self):
        """test _utf_stream_parse()  - non even parameter"""
        utf_stream = b"foo1\x00\x00\x00_bar1\x00\x00\x00_foo2"
        self.assertEqual(
            ({"foo1": "bar1"}), self.cahandler._utf_stream_parse(utf_stream)
        )

    def test_101__utf_stream_parse(self):
        """test _utf_stream_parse()  - replace single \x00 in list key"""
        utf_stream = b"f\x00oo1\x00\x00\x00_bar1\x00\x00\x00_foo2"
        self.assertEqual(
            ({"foo1": "bar1"}), self.cahandler._utf_stream_parse(utf_stream)
        )

    def test_102__utf_stream_parse(self):
        """test _utf_stream_parse()  - replace multiple \x00 in list key"""
        utf_stream = b"f\x00o\x00o\x001\x00\x00\x00_bar1\x00\x00\x00_foo2"
        self.assertEqual(
            ({"foo1": "bar1"}), self.cahandler._utf_stream_parse(utf_stream)
        )

    def test_103__utf_stream_parse(self):
        """test _utf_stream_parse()  - replace single \x00 in list value"""
        utf_stream = b"foo1\x00\x00\x00_b\x00ar1\x00\x00\x00_foo2"
        self.assertEqual(
            ({"foo1": "bar1"}), self.cahandler._utf_stream_parse(utf_stream)
        )

    def test_104__utf_stream_parse(self):
        """test _utf_stream_parse()  - replace multiple \x00 in list value"""
        utf_stream = b"foo\x001\x00\x00\x00_b\x00a\x00r1\x00\x00\x00_foo2"
        self.assertEqual(
            ({"foo1": "bar1"}), self.cahandler._utf_stream_parse(utf_stream)
        )

    def test_105__utf_stream_parse(self):
        """test _utf_stream_parse()  - no utf_stream"""
        utf_stream = None
        self.assertFalse(self.cahandler._utf_stream_parse(utf_stream))

    def test_106__utf_stream_parse(self):
        """test _utf_stream_parse()  - skip template with empty eku"""
        utf_stream = b"foo1\x00\x00\x00_bar1\x00\x00\x00_foo2\x00\x00\x00_eKeyUse\xff\xff\xff\xff"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                ({"foo1": "bar1"}), self.cahandler._utf_stream_parse(utf_stream)
            )
        self.assertIn(
            "INFO:test_a2c:Hack to skip template with empty eku - maybe a bug in xca...",
            lcm.output,
        )

    def test_107__ans1_stream_parse(self):
        """test _ans1_stream_parse  - with country"""
        asn1_stream = b"12345678foo\x06\x03\x55\x04\x06\02fco"
        self.assertEqual(
            ({"countryName": "co"}), self.cahandler._asn1_stream_parse(asn1_stream)
        )

    def test_108__ans1_stream_parse(self):
        """test _ans1_stream_parse  - country, loc"""
        asn1_stream = (
            b"12345678foo\x06\x03\x55\x04\x06\02fco\x06\x03\x55\x04\x07\03floc"
        )
        self.assertEqual(
            ({"countryName": "co", "localityName": "loc"}),
            self.cahandler._asn1_stream_parse(asn1_stream),
        )

    def test_109__ans1_stream_parse(self):
        """test _ans1_stream_parse  - country, lo, state"""
        asn1_stream = b"12345678foo\x06\x03\x55\x04\x06\02fco\x06\x03\x55\x04\x07\03floc\x06\x03\x55\x04\x08\05fstate"
        self.assertEqual(
            (
                {
                    "countryName": "co",
                    "localityName": "loc",
                    "stateOrProvinceName": "state",
                }
            ),
            self.cahandler._asn1_stream_parse(asn1_stream),
        )

    def test_110__ans1_stream_parse(self):
        """test _ans1_stream_parse  - country, loc, state, org"""
        asn1_stream = b"12345678foo\x06\x03\x55\x04\x06\02fco\x06\x03\x55\x04\x07\03floc\x06\x03\x55\x04\x08\05fstate\x06\x03\x55\x04\x0a\03forg"
        self.assertEqual(
            (
                {
                    "countryName": "co",
                    "localityName": "loc",
                    "stateOrProvinceName": "state",
                    "organizationName": "org",
                }
            ),
            self.cahandler._asn1_stream_parse(asn1_stream),
        )

    def test_111__ans1_stream_parse(self):
        """test _ans1_stream_parse  - country, loc, state, org, ou"""
        asn1_stream = b"12345678foo\x06\x03\x55\x04\x06\02fco\x06\x03\x55\x04\x07\03floc\x06\x03\x55\x04\x08\05fstate\x06\x03\x55\x04\x0a\03forg\x06\x03\x55\x04\x0b\02fou"
        self.assertEqual(
            (
                {
                    "countryName": "co",
                    "localityName": "loc",
                    "stateOrProvinceName": "state",
                    "organizationName": "org",
                    "organizationalUnitName": "ou",
                }
            ),
            self.cahandler._asn1_stream_parse(asn1_stream),
        )

    def test_112__ans1_stream_parse(self):
        """test _ans1_stream_parse  - extralong value"""
        asn1_stream = b"12345678foo\x06\x03\x55\x04\x07\x11flllllllllllllllll"
        self.assertEqual(
            ({"localityName": "lllllllllllllllll"}),
            self.cahandler._asn1_stream_parse(asn1_stream),
        )

    def test_113__ans1_stream_parse(self):
        """test _ans1_stream_parse - empty stream"""
        asn1_stream = None
        self.assertFalse(self.cahandler._asn1_stream_parse(asn1_stream))

    def test_114__ans1_stream_parse(self):
        """test _ans1_stream_parse - too short"""
        asn1_stream = b"123456"
        self.assertFalse(self.cahandler._asn1_stream_parse(asn1_stream))

    def test_115__ans1_stream_parse(self):
        """test _ans1_stream_parse  - country, non existing value in beteeen"""
        asn1_stream = (
            b"12345678foo\x06\x03\x55\x04\x06\02fco\x06\x03\x55\x05\x07\03floc"
        )
        self.assertEqual(
            ({"countryName": "co"}), self.cahandler._asn1_stream_parse(asn1_stream)
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._validity_calculate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._utf_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._asn1_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._stream_split")
    def test_116__template_parse(self, mock_split, mock_asn, mock_utf, mock_valid):
        """__template_parse() - all good"""
        byte_string = "foo"
        mock_split.return_value = (b"foo", b"bar")
        mock_asn.return_value = {"foo1": "bar1"}
        mock_utf.return_value = {"foo2": "bar2"}
        mock_valid.return_value = "valid"
        self.assertEqual(
            ({"foo1": "bar1"}, {"foo2": "bar2", "validity": "valid"}),
            self.cahandler._template_parse(byte_string),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._validity_calculate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._utf_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._asn1_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._stream_split")
    def test_117__template_parse(self, mock_split, mock_asn, mock_utf, mock_valid):
        """__template_parse() - multiple values"""
        byte_string = "foo"
        mock_split.return_value = (b"foo", b"bar")
        mock_asn.return_value = {"foo1": "bar1", "foo11": "bar11"}
        mock_utf.return_value = {"foo2": "bar2", "foo21": "bar21"}
        mock_valid.return_value = "valid"
        self.assertEqual(
            (
                {"foo1": "bar1", "foo11": "bar11"},
                {"foo2": "bar2", "foo21": "bar21", "validity": "valid"},
            ),
            self.cahandler._template_parse(byte_string),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._validity_calculate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._utf_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._stream_split")
    def test_118__template_parse(self, mock_split, mock_utf, mock_valid):
        """__template_parse() - no asn1_stream returned"""
        byte_string = "foo"
        mock_split.return_value = (None, b"bar")
        mock_utf.return_value = {"foo2": "bar2"}
        mock_valid.return_value = "valid"
        self.assertEqual(
            ({}, {"foo2": "bar2", "validity": "valid"}),
            self.cahandler._template_parse(byte_string),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._asn1_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._stream_split")
    def test_119__template_parse(self, mock_split, mock_asn):
        """__template_parse() - no asn1_stream returned"""
        byte_string = "foo"
        mock_split.return_value = (b"foo", None)
        mock_asn.return_value = {"foo1": "bar1"}
        self.assertEqual(
            ({"foo1": "bar1"}, {}), self.cahandler._template_parse(byte_string)
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._stream_split")
    def test_120__template_parse(self, mock_split):
        """__template_parse() - no asn1_stream returned"""
        byte_string = "foo"
        mock_split.return_value = (None, None)
        self.assertEqual(({}, {}), self.cahandler._template_parse(byte_string))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._validity_calculate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._utf_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._asn1_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._stream_split")
    def test_121__template_parse(self, mock_split, mock_asn, mock_utf, mock_valid):
        """__template_parse() - multiple values replace blank with None"""
        byte_string = "foo"
        mock_split.return_value = (b"foo", b"bar")
        mock_asn.return_value = {"foo1": "bar1", "foo11": "bar11"}
        mock_utf.return_value = {"foo2": "bar2", "foo21": ""}
        mock_valid.return_value = "valid"
        self.assertEqual(
            (
                {"foo1": "bar1", "foo11": "bar11"},
                {"foo2": "bar2", "foo21": None, "validity": "valid"},
            ),
            self.cahandler._template_parse(byte_string),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._validity_calculate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._utf_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._asn1_stream_parse")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._stream_split")
    def test_122__template_parse(self, mock_split, mock_asn, mock_utf, mock_valid):
        """__template_parse() - multiple values replace blanks with None"""
        byte_string = "foo"
        mock_split.return_value = (b"foo", b"bar")
        mock_asn.return_value = {"foo1": "bar1", "foo11": "bar11"}
        mock_utf.return_value = {"foo2": "bar2", "foo21": "", "foo22": ""}
        mock_valid.return_value = "valid"
        self.assertEqual(
            (
                {"foo1": "bar1", "foo11": "bar11"},
                {"foo2": "bar2", "foo21": None, "foo22": None, "validity": "valid"},
            ),
            self.cahandler._template_parse(byte_string),
        )

    def test_123__template_load(self):
        """CAhandler._templatelod - existing template"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.template_name = "template"
        dn_dic = {
            "countryName": "co",
            "stateOrProvinceName": "prov",
            "localityName": "loc",
            "organizationName": "org",
            "organizationalUnitName": "ou",
        }
        # template_dic = {'validity': 30, 'validN': '30', 'validMidn': '0', 'validM': '0', 'subKey': '0', 'subAltName': None, 'nsSslServerName': None, 'nsRevocationUrl': None, 'nsRenewalUrl': None, 'nsComment': 'xca certificate', 'nsCertType': '0', 'nsCaPolicyUrl': None, 'nsCARevocationUrl': None, 'nsBaseUrl': None, 'noWellDefinedExpDate': '0', 'kuCritical': '1', 'keyUse': '3', 'issAltName': None, 'ekuCritical': '1', 'eKeyUse': 'serverAuth, clientAuth', 'crlDist': None, 'ca': '0', 'bcCritical': '0', 'basicPath': None, 'authKey': '0', 'authInfAcc': None, 'adv_ext': None}
        template_dic = {
            "validN": "30",
            "validMidn": "0",
            "validM": "0",
            "subKey": "0",
            "subAltName": None,
            "nsSslServerName": None,
            "nsRevocationUrl": None,
            "nsRenewalUrl": None,
            "nsComment": "xca certificate",
            "nsCertType": "0",
            "nsCaPolicyUrl": None,
            "nsCARevocationUrl": None,
            "nsBaseUrl": None,
            "noWellDefinedExpDate": "0",
            "kuCritical": "1",
            "keyUse": "3",
            "issAltName": None,
            "ekuCritical": "1",
            "eKeyUse": "clientAuth, codeSigning",
            "crlDist": None,
            "ca": "0",
            "bcCritical": "0",
            "basicPath": None,
            "authKey": "0",
            "authInfAcc": None,
            "adv_ext": None,
            "OCSPstaple": "0",
            "validity": 30,
        }
        self.assertEqual((dn_dic, template_dic), self.cahandler._template_load())

    def test_124__template_load(self):
        """CAhandler._templatelod - not existing template"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.template_name = "notexist"
        self.assertEqual(({}, {}), self.cahandler._template_load())

    def test_125__validity_calculate(self):
        """CAhandler._validity_calculate() - day value"""
        template_dic = {"validM": "0", "validN": "10"}
        self.assertEqual(10, self.cahandler._validity_calculate(template_dic))

    def test_126__validity_calculate(self):
        """CAhandler._validity_calculate() - month value"""
        template_dic = {"validM": "1", "validN": "10"}
        self.assertEqual(300, self.cahandler._validity_calculate(template_dic))

    def test_127__validity_calculate(self):
        """CAhandler._validity_calculate() - year value"""
        template_dic = {"validM": "2", "validN": "2"}
        self.assertEqual(730, self.cahandler._validity_calculate(template_dic))

    def test_128__validity_calculate(self):
        """CAhandler._validity_calculate() - novalidn"""
        template_dic = {"validM": "2", "novalidN": "2"}
        self.assertEqual(365, self.cahandler._validity_calculate(template_dic))

    def test_129__validity_calculate(self):
        """CAhandler._validity_calculate() - novalidn"""
        template_dic = {"novalidM": "2", "validN": "2"}
        self.assertEqual(365, self.cahandler._validity_calculate(template_dic))

    def test_130__kue_generate(self):
        """CAhandler._kue_generate() - kup 0 defaulting to 23"""
        kup = 0
        result = {
            "digital_signature": True,
            "content_commitment": True,
            "key_encipherment": True,
            "data_encipherment": False,
            "key_agreement": True,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        }
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.assertEqual(result, self.cahandler._kue_generate(kup))
        self.assertIn(
            "DEBUG:test_a2c:Generate KeyUsage Extension with value 23", lcm.output
        )

    def test_131__kue_generate(self):
        """CAhandler._kue_generate() - kup '0' defaulting to 23"""
        kup = "0"
        result = {
            "digital_signature": True,
            "content_commitment": True,
            "key_encipherment": True,
            "data_encipherment": False,
            "key_agreement": True,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        }
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.assertEqual(result, self.cahandler._kue_generate(kup))
        self.assertIn(
            "DEBUG:test_a2c:Generate KeyUsage Extension with value 23", lcm.output
        )

    def test_132__kue_generate(self):
        """CAhandler._kue_generate() - kup cannot get converted to int"""
        kup = "a"
        result = {
            "digital_signature": True,
            "content_commitment": True,
            "key_encipherment": True,
            "data_encipherment": False,
            "key_agreement": True,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        }
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.assertEqual(result, self.cahandler._kue_generate(kup))
        self.assertIn(
            "DEBUG:test_a2c:Generate KeyUsage Extension with value 23", lcm.output
        )

    def test_133__kue_generate(self):
        """CAhandler._kue_generate() - kup none"""
        kup = None
        result = {
            "digital_signature": True,
            "content_commitment": True,
            "key_encipherment": True,
            "data_encipherment": False,
            "key_agreement": True,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        }
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.assertEqual(result, self.cahandler._kue_generate(kup))
        self.assertIn(
            "DEBUG:test_a2c:Generate KeyUsage Extension with value 23", lcm.output
        )

    def test_134__kue_generate(self):
        """CAhandler._kue_generate() - kup none but csr_extensions"""
        kup = None
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.assertEqual("ku_csr", self.cahandler._kue_generate(kup, "ku_csr"))
        self.assertIn(
            "DEBUG:test_a2c:Generate KeyUsage Extension with data from csr", lcm.output
        )

    def test_135__kue_generate(self):
        """CAhandler._kue_generate() - kup csr_extensions"""
        kup = 4
        result = {
            "digital_signature": False,
            "content_commitment": False,
            "key_encipherment": True,
            "data_encipherment": False,
            "key_agreement": False,
            "key_cert_sign": False,
            "crl_sign": False,
            "encipher_only": False,
            "decipher_only": False,
        }
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.assertEqual(result, self.cahandler._kue_generate(kup, "ku_csr"))
        self.assertIn(
            "DEBUG:test_a2c:Generate KeyUsage Extension with data from template",
            lcm.output,
        )

    def test_136__kue_generate(self):
        """CAhandler._kue_generate() - kup 0 csr_extensions"""
        kup = 0
        with self.assertLogs("test_a2c", level="DEBUG") as lcm:
            self.assertEqual("ku_csr", self.cahandler._kue_generate(kup, "ku_csr"))
        self.assertIn(
            "DEBUG:test_a2c:Generate KeyUsage Extension with data from csr", lcm.output
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._kue_generate")
    def test_137___keyusage_generate(self, mock_kuegen):
        """key usage generate - keyUse in template_dic but not kuCritical"""
        template_dic = {"keyUse": {"foo": "bar"}}
        csr_extensions_dic = {}
        mock_kuegen.return_value = "kue_string"
        self.assertEqual(
            (False, "kue_string"),
            self.cahandler._keyusage_generate(template_dic, csr_extensions_dic),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._kue_generate")
    def test_138___keyusage_generate(self, mock_kuegen):
        """key usage generate - keyUse in template_dic kuCritical string"""
        template_dic = {"keyUse": "foo", "kuCritical": "1"}
        csr_extensions_dic = {}
        mock_kuegen.return_value = "kue_string"
        self.assertEqual(
            (True, "kue_string"),
            self.cahandler._keyusage_generate(template_dic, csr_extensions_dic),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._kue_generate")
    def test_139___keyusage_generate(self, mock_kuegen):
        """key usage generate - keyUse in template_dic kuCritical int"""
        template_dic = {"keyUse": "foo", "kuCritical": 1}
        csr_extensions_dic = {}
        mock_kuegen.return_value = "kue_string"
        self.assertEqual(
            (True, "kue_string"),
            self.cahandler._keyusage_generate(template_dic, csr_extensions_dic),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._kue_generate")
    def test_140___keyusage_generate(self, mock_kuegen):
        """key usage generate - keyUse in template_dic kuCritical string 0"""
        template_dic = {"keyUse": "foo", "kuCritical": "0"}
        csr_extensions_dic = {}
        mock_kuegen.return_value = "kue_string"
        self.assertEqual(
            (False, "kue_string"),
            self.cahandler._keyusage_generate(template_dic, csr_extensions_dic),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._kue_generate")
    def test_141___keyusage_generate(self, mock_kuegen):
        """key usage generate - keyUse in template_dic kuCritical string 0"""
        template_dic = {"keyUse": "foo", "kuCritical": 0}
        csr_extensions_dic = {}
        mock_kuegen.return_value = "kue_string"
        self.assertEqual(
            (False, "kue_string"),
            self.cahandler._keyusage_generate(template_dic, csr_extensions_dic),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._kue_generate")
    def test_142___keyusage_generate(self, mock_kuegen):
        """key usage generate - keyUse in template_dic kuCritical triggers exception"""
        template_dic = {"keyUse": "foo", "kuCritical": "to fail"}
        csr_extensions_dic = {}
        mock_kuegen.return_value = "kue_string"
        self.assertEqual(
            (False, "kue_string"),
            self.cahandler._keyusage_generate(template_dic, csr_extensions_dic),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._kue_generate")
    def test_143___keyusage_generate(self, mock_kuegen):
        """key usage generate - keyUse extension dic"""
        template_dic = {}
        csr_keyusage = Mock()
        csr_keyusage.__str__ = Mock(return_value="foo")
        csr_extensions_dic = {"keyUsage": csr_keyusage}
        mock_kuegen.return_value = "kue_string"
        self.assertEqual(
            (False, "kue_string"),
            self.cahandler._keyusage_generate(template_dic, csr_extensions_dic),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._kue_generate")
    def test_144___keyusage_generate(self, mock_kuegen):
        """key usage generate - empty emplate dic and empty CSR dic"""
        template_dic = {}
        csr_extensions_dic = {}
        mock_kuegen.return_value = "kue_string"
        self.assertEqual(
            (False, "kue_string"),
            self.cahandler._keyusage_generate(template_dic, csr_extensions_dic),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_load")
    def test_145__enter__(self, mock_cfg):
        """test enter"""
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertTrue(mock_cfg.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_load")
    def test_146__enter__(self, mock_cfg):
        """test enter"""
        self.cahandler.xdb_file = self.dir_path + "/ca/est_proxy.xdb"
        mock_cfg.return_value = True
        self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)

    def test_147_trigger(self):
        """test trigger"""
        self.assertEqual(
            ("Method not implemented.", None, None), self.cahandler.trigger("payload")
        )

    def test_148_poll(self):
        """test poll"""
        self.assertEqual(
            ("Method not implemented.", None, None, "poll_identifier", False),
            self.cahandler.poll("cert_name", "poll_identifier", "csr"),
        )

    def test_149_stub_func(self):
        """test stubfunc"""
        self.assertEqual("parameter", self.cahandler._stub_func("parameter"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._item_insert")
    def test_150__store_cert(self, mock_i_insert, mock_c_insert):
        """test insert"""
        mock_i_insert.return_value = 1
        mock_c_insert.return_value = 2
        self.cahandler._store_cert(
            "ca_id", "cert_name", "serial", "cert", "name_hash", "issuer_hash"
        )
        self.assertTrue(mock_i_insert.called)
        self.assertTrue(mock_c_insert.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.dict_from_row")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_151_revocation_search(
        self, mock_open, mock_close, mock_dicfrow, mock_id_check
    ):
        """revocation search"""
        mock_id_check.return_value = True
        mock_dicfrow.return_value = {"foo": "bar"}
        mock_open.return_value = True
        mock_close.return_value = True
        self.cahandler.cursor = Mock()
        self.assertEqual(
            {"foo": "bar"}, self.cahandler._revocation_search("column", "value")
        )
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)
        self.assertTrue(mock_dicfrow.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.dict_from_row")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_152_revocation_search(
        self, mock_open, mock_close, mock_dicfrow, mock_id_check
    ):
        """revocation search  dicfromrow throws exception"""
        mock_id_check.return_value = True
        mock_dicfrow.side_effect = Exception("exc_dicfromrow")
        mock_open.return_value = True
        mock_close.return_value = True
        self.cahandler.cursor = Mock()
        self.assertFalse(self.cahandler._revocation_search("column", "value"))
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)
        self.assertTrue(mock_dicfrow.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.dict_from_row")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_153_revocation_search(
        self, mock_open, mock_close, mock_dicfrow, mock_id_check
    ):
        """revocation search"""
        mock_id_check.return_value = True
        mock_dicfrow.return_value = {"foo": "bar"}
        mock_open.return_value = True
        mock_close.return_value = True
        self.cahandler.cursor = Mock()
        self.assertEqual(
            {"foo": "bar"}, self.cahandler._revocation_search("column", "value")
        )
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)
        self.assertTrue(mock_dicfrow.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.dict_from_row")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_154_revocation_search(
        self, mock_open, mock_close, mock_dicfrow, mock_id_check
    ):
        """revocation search  dicfromrow throws exception"""
        mock_id_check.return_value = True
        mock_dicfrow.side_effect = Exception("exc_dicfromrow")
        mock_open.return_value = True
        mock_close.return_value = True
        self.cahandler.cursor = Mock()
        self.assertFalse(self.cahandler._revocation_search("column", "value"))
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)
        self.assertTrue(mock_dicfrow.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.dict_from_row")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_155_revocation_search(
        self, mock_open, mock_close, mock_dicfrow, mock_id_check
    ):
        """revocation search  dicfromrow throws exception"""
        mock_id_check.return_value = False
        mock_dicfrow.side_effect = Exception("exc_dicfromrow")
        mock_open.return_value = True
        mock_close.return_value = True
        self.cahandler.cursor = Mock()
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(self.cahandler._revocation_search("column", "value"))
        self.assertIn(
            "WARNING:test_a2c:column: column not in revocations table", lcm.output
        )
        self.assertFalse(mock_open.called)
        self.assertFalse(mock_close.called)
        self.assertFalse(mock_dicfrow.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._item_insert")
    def test_156__store_cert(self, mock_i_insert, mock_c_insert):
        """test insert"""
        mock_i_insert.return_value = 1
        mock_c_insert.return_value = 2
        self.cahandler._store_cert(
            "ca_id", "cert_name", "serial", "cert", "name_hash", "issuer_hash"
        )
        self.assertTrue(mock_i_insert.called)
        self.assertTrue(mock_c_insert.called)

    def test_157___extended_keyusage_generate(self):
        """_extended_keyusage_generate template dic and csr_extensions_dic are empty"""
        template_dic = {}
        csr_extensions_dic = {}
        self.assertEqual(
            (False, None),
            self.cahandler._extended_keyusage_generate(
                template_dic, csr_extensions_dic
            ),
        )

    def test_158___extended_keyusage_generate(self):
        """_extended_keyusage_generate template dic eKeyUse in template not critical"""
        template_dic = {"eKeyUse": "eKeyUse"}
        csr_extensions_dic = {}
        self.assertEqual(
            (False, ["eKeyUse"]),
            self.cahandler._extended_keyusage_generate(
                template_dic, csr_extensions_dic
            ),
        )

    def test_159___extended_keyusage_generate(self):
        """_extended_keyusage_generate template dic eKeyUse in template critical string"""
        template_dic = {"eKeyUse": "eKeyUse", "ekuCritical": "1"}
        csr_extensions_dic = {}
        self.assertEqual(
            (True, ["eKeyUse"]),
            self.cahandler._extended_keyusage_generate(
                template_dic, csr_extensions_dic
            ),
        )

    def test_160__extended_keyusage_generate(self):
        """_extended_keyusage_generate template dic eKeyUse in template critical in"""
        template_dic = {"eKeyUse": "eKeyUse", "ekuCritical": 1}
        csr_extensions_dic = {}
        self.assertEqual(
            (True, ["eKeyUse"]),
            self.cahandler._extended_keyusage_generate(
                template_dic, csr_extensions_dic
            ),
        )

    def test_161___extended_keyusage_generate(self):
        """_extended_keyusage_generate template dic eKeyUse in template critical zero"""
        template_dic = {"eKeyUse": "eKeyUse", "ekuCritical": "0"}
        csr_extensions_dic = {}
        self.assertEqual(
            (False, ["eKeyUse"]),
            self.cahandler._extended_keyusage_generate(
                template_dic, csr_extensions_dic
            ),
        )

    def test_162___extended_keyusage_generate(self):
        """_extended_keyusage_generate template dic eKeyUse in template critical int zero"""
        template_dic = {"eKeyUse": "eKeyUse", "ekuCritical": 0}
        csr_extensions_dic = {}
        self.assertEqual(
            (False, ["eKeyUse"]),
            self.cahandler._extended_keyusage_generate(
                template_dic, csr_extensions_dic
            ),
        )

    def test_163___extended_keyusage_generate(self):
        """_extended_keyusage_generate template dic eKeyUse in template convert to int fail"""
        template_dic = {"eKeyUse": "eKeyUse", "ekuCritical": "convertfail"}
        csr_extensions_dic = {}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                (False, ["eKeyUse"]),
                self.cahandler._extended_keyusage_generate(
                    template_dic, csr_extensions_dic
                ),
            )
        self.assertIn(
            "ERROR:test_a2c:Failed to convert EKU critical flag to int, defaulting to False",
            lcm.output,
        )

    def test_164___extended_keyusage_generate(self):
        """_extended_keyusage_generate template dic unknown eKeyUse in template"""
        template_dic = {"eKeyUse": "unkeKeyUse", "ekuCritical": "1"}
        csr_extensions_dic = {}
        self.assertEqual(
            (True, []),
            self.cahandler._extended_keyusage_generate(
                template_dic, csr_extensions_dic
            ),
        )

    def test_165__cdp_list_generate(self):
        """test _cdp_list_generate()"""
        cdp_string = None
        self.assertEqual([], self.cahandler._cdp_list_generate(cdp_string))

    @patch("cryptography.x509.DistributionPoint")
    def test_166__cdp_list_generate(self, mock_cdp):
        """test _cdp_list_generate()"""
        cdp_string = "foo"
        mock_cdp.side_effect = ["foo1", "foo2"]
        self.assertEqual(["foo1"], self.cahandler._cdp_list_generate(cdp_string))

    @patch("cryptography.x509.DistributionPoint")
    def test_167__cdp_list_generate(self, mock_cdp):
        """test _cdp_list_generate()"""
        cdp_string = "foo, bar"
        mock_cdp.side_effect = ["foo1", "foo2"]
        self.assertEqual(
            ["foo1", "foo2"], self.cahandler._cdp_list_generate(cdp_string)
        )

    @patch("cryptography.x509.Name")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._subject_modify")
    def test_168__cert_subject_generate(self, mock_submod, mock_name):
        """_cert_subject_generate()"""
        req = Mock()
        req.subject = "subject"
        request_name = "request_name"
        dn_dic = {}
        self.assertEqual(
            "subject", self.cahandler._cert_subject_generate(req, request_name, dn_dic)
        )
        self.assertFalse(mock_submod.called)
        self.assertFalse(mock_name.called)

    @patch("cryptography.x509.Name")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._subject_modify")
    def test_169__cert_subject_generate(self, mock_submod, mock_name):
        """_cert_subject_generate()"""
        req = Mock()
        req.subject = None
        mock_name.return_value = "mock_name"
        request_name = "request_name"
        dn_dic = {}
        self.assertEqual(
            "mock_name",
            self.cahandler._cert_subject_generate(req, request_name, dn_dic),
        )
        self.assertFalse(mock_submod.called)
        self.assertTrue(mock_name.called)

    @patch("cryptography.x509.Name")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._subject_modify")
    def test_170__cert_subject_generate(self, mock_submod, mock_name):
        """_cert_subject_generate()"""
        req = Mock()
        req.subject = None
        mock_name.return_value = "mock_name"
        mock_submod.return_value = "mock_submod"
        request_name = "request_name"
        dn_dic = {"foo": "bar"}
        self.assertEqual(
            "mock_submod",
            self.cahandler._cert_subject_generate(req, request_name, dn_dic),
        )
        self.assertTrue(mock_submod.called)
        self.assertTrue(mock_name.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    def test_171__extension_list_default(
        self, mock_bc, mock_ku, mock_ski, mock_aki, mock_eku
    ):
        """_extension_list_default()"""
        cert = Mock()
        mock_bc.return_value = "mock_bc"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        result = [
            {"name": "mock_bc", "critical": True},
            {"name": "mock_ku", "critical": True},
            {"critical": False, "name": "mock_eku"},
            {"name": "mock_ski", "critical": False},
            {"name": "mock_aki", "critical": False},
        ]
        self.assertEqual(result, self.cahandler._extension_list_default(cert, cert))

    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    def test_172__extension_list_default(
        self, mock_bc, mock_ku, mock_ski, mock_aki, mock_eku
    ):
        """_extension_list_default()"""
        cert = Mock()
        mock_bc.return_value = "mock_bc"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        result = [
            {"name": "mock_bc", "critical": True},
            {"name": "mock_ku", "critical": True},
            {"critical": False, "name": "mock_eku"},
            {"name": "mock_ski", "critical": False},
        ]
        self.assertEqual(result, self.cahandler._extension_list_default(None, cert))

    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    def test_173__extension_list_default(
        self, mock_bc, mock_ku, mock_ski, mock_aki, mock_eku
    ):
        """_extension_list_default()"""
        cert = Mock()
        mock_bc.return_value = "mock_bc"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        result = [
            {"name": "mock_bc", "critical": True},
            {"name": "mock_ku", "critical": True},
            {"critical": False, "name": "mock_eku"},
            {"name": "mock_aki", "critical": False},
        ]
        self.assertEqual(result, self.cahandler._extension_list_default(cert, None))

    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._extension_list_default")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._xca_template_process")
    def test_174__extension_list_generate(
        self, mock_template, mock_extlist, mock_convert
    ):
        """_extension_list_generate()"""
        cert = Mock()
        mock_extlist.return_value = "mock_extlist"
        mock_template.return_value = "mock_template"
        mock_convert.return_value = "mock_convert"
        csr_extensions_list = []
        template_dic = {}
        self.assertEqual(
            "mock_extlist",
            self.cahandler._extension_list_generate(
                template_dic, cert, csr_extensions_list
            ),
        )
        self.assertTrue(mock_extlist.called)
        self.assertFalse(mock_template.called)
        self.assertFalse(mock_convert.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._extension_list_default")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._xca_template_process")
    def test_175__extension_list_generate(
        self, mock_template, mock_extlist, mock_convert
    ):
        """_extension_list_generate()"""
        cert = Mock()
        mock_extlist.return_value = "mock_extlist"
        mock_template.return_value = "mock_template"
        mock_convert.return_value = "mock_convert"
        csr_extensions_list = []
        template_dic = {"foo": "bar"}
        self.assertEqual(
            "mock_template",
            self.cahandler._extension_list_generate(
                template_dic, cert, csr_extensions_list
            ),
        )
        self.assertFalse(mock_extlist.called)
        self.assertTrue(mock_template.called)
        self.assertFalse(mock_convert.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._extension_list_default")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._xca_template_process")
    def test_176__extension_list_generate(
        self, mock_template, mock_extlist, mock_convert
    ):
        """_extension_list_generate()"""
        cert = Mock()
        mock_extlist.return_value = "mock_extlist"
        mock_template.return_value = "mock_template"
        mock_convert.return_value = "mock_convert"
        ext = Mock()
        csr_extensions_list = [ext]
        template_dic = {}
        self.assertEqual(
            "mock_extlist",
            self.cahandler._extension_list_generate(
                template_dic, cert, cert, csr_extensions_list
            ),
        )
        self.assertTrue(mock_extlist.called)
        self.assertFalse(mock_template.called)
        self.assertTrue(mock_convert.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectAlternativeName")
    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._extension_list_default")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._xca_template_process")
    def test_177__extension_list_generate(
        self, mock_template, mock_extlist, mock_convert, mock_san
    ):
        """_extension_list_generate()"""
        cert = Mock()
        mock_extlist.return_value = ["mock_extlist"]
        mock_template.return_value = "mock_template"
        mock_convert.side_effect = ["mock_convert", "subjectAltName"]
        mock_san.return_value = "mock_san"
        ext = Mock()
        csr_extensions_list = [ext, ext]
        template_dic = {}
        self.assertEqual(
            ["mock_extlist", {"name": "mock_san", "critical": False}],
            self.cahandler._extension_list_generate(
                template_dic, cert, cert, csr_extensions_list
            ),
        )
        self.assertTrue(mock_extlist.called)
        self.assertFalse(mock_template.called)
        self.assertTrue(mock_convert.called)

    @patch("OpenSSL.crypto.X509.from_cryptography")
    def test_178__subject_name_hash_get(self, mock_x509):
        """_subject_name_hash_get()"""
        # mock_x509 = Mock()
        obj = Mock()
        obj.subject_name_hash.return_value = 111111111111111111
        mock_x509.return_value = obj
        self.assertEqual(73429447, self.cahandler._subject_name_hash_get("cert"))

    @patch("OpenSSL.crypto.X509.from_cryptography")
    def test_179__subject_name_hash_get(self, mock_x509):
        """_subject_name_hash_get()"""
        # mock_x509 = Mock()
        obj = Mock()
        obj.subject_name_hash.return_value = 11111111111111111
        mock_x509.return_value = obj
        self.assertEqual(651588039, self.cahandler._subject_name_hash_get("cert"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.Name")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.NameAttribute")
    def test_180__subject_modify(self, mock_addr, mock_name):
        """_subject_modify()"""
        mock_name.return_value = "mock_name"
        mock_addr.return_value = "mock_addr"
        dn_dic = {"organizationalUnitName": "organizationalUnitName"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "mock_name", self.cahandler._subject_modify("subject", dn_dic)
            )
        self.assertIn("INFO:test_a2c:Rewrite OU to organizationalUnitName", lcm.output)

    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.Name")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.NameAttribute")
    def test_181__subject_modify(self, mock_addr, mock_name):
        """_subject_modify()"""
        mock_name.return_value = "mock_name"
        mock_addr.return_value = "mock_addr"
        dn_dic = {"organizationName": "organizationName"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "mock_name", self.cahandler._subject_modify("subject", dn_dic)
            )
        self.assertIn("INFO:test_a2c:Rewrite O to organizationName", lcm.output)

    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.Name")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.NameAttribute")
    def test_182__subject_modify(self, mock_addr, mock_name):
        """_subject_modify()"""
        mock_name.return_value = "mock_name"
        mock_addr.return_value = "mock_addr"
        dn_dic = {"localityName": "localityName"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "mock_name", self.cahandler._subject_modify("subject", dn_dic)
            )
        self.assertIn("INFO:test_a2c:Rewrite L to localityName", lcm.output)

    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.Name")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.NameAttribute")
    def test_183__subject_modify(self, mock_addr, mock_name):
        """_subject_modify()"""
        mock_name.return_value = "mock_name"
        mock_addr.return_value = "mock_addr"
        dn_dic = {"stateOrProvinceName": "stateOrProvinceName"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "mock_name", self.cahandler._subject_modify("subject", dn_dic)
            )
        self.assertIn("INFO:test_a2c:Rewrite ST to stateOrProvinceName", lcm.output)

    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.Name")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.NameAttribute")
    def test_184__subject_modify(self, mock_addr, mock_name):
        """_subject_modify()"""
        mock_name.return_value = "mock_name"
        mock_addr.return_value = "mock_addr"
        dn_dic = {"countryName": "countryName"}
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(
                "mock_name", self.cahandler._subject_modify("subject", dn_dic)
            )
        self.assertIn("INFO:test_a2c:Rewrite C to countryName", lcm.output)

    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_185_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
    ):
        """test enroll()"""
        mock_chk.return_value = "error"
        mock_prof.return_value = None
        self.assertEqual(("error", None, None, None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_chk.called)
        self.assertFalse(mock_reqname.called)
        self.assertFalse(mock_csr.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_build.called)
        self.assertFalse(mock_ca.called)
        self.assertFalse(mock_sign.called)
        self.assertFalse(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_186_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
    ):
        """test enroll()"""
        mock_chk.return_value = "error"
        mock_prof.return_value = None
        self.assertEqual(("error", None, None, None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_chk.called)
        self.assertFalse(mock_reqname.called)
        self.assertFalse(mock_csr.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_build.called)
        self.assertFalse(mock_ca.called)
        self.assertFalse(mock_sign.called)
        self.assertFalse(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_187_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
        mock_db,
    ):
        """test enroll()"""
        mock_db.return_value = "mock_db"
        mock_chk.return_value = None
        mock_reqname.return_value = None
        mock_prof.return_value = None
        self.assertEqual(("mock_db", None, None, None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_chk.called)
        self.assertFalse(mock_reqname.called)
        self.assertFalse(mock_csr.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_build.called)
        self.assertFalse(mock_ca.called)
        self.assertFalse(mock_sign.called)
        self.assertFalse(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_188_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
        mock_db,
    ):
        """test enroll()"""
        mock_db.return_value = None
        mock_chk.return_value = None
        mock_reqname.return_value = None
        mock_prof.return_value = None
        self.assertEqual(
            ("request_name lookup failed", None, None, None),
            self.cahandler.enroll("csr"),
        )
        self.assertTrue(mock_chk.called)
        self.assertTrue(mock_reqname.called)
        self.assertFalse(mock_csr.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_build.called)
        self.assertFalse(mock_ca.called)
        self.assertFalse(mock_sign.called)
        self.assertTrue(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_189_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
        mock_db,
    ):
        """test enroll()"""
        mock_db.return_value = None
        mock_chk.return_value = None
        mock_reqname.return_value = None
        mock_prof.return_value = None
        self.assertEqual(
            ("request_name lookup failed", None, None, None),
            self.cahandler.enroll("csr"),
        )
        self.assertTrue(mock_chk.called)
        self.assertTrue(mock_reqname.called)
        self.assertFalse(mock_csr.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_build.called)
        self.assertFalse(mock_ca.called)
        self.assertFalse(mock_sign.called)
        self.assertTrue(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_190_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
        mock_db,
    ):
        """test enroll()"""
        mock_db.return_value = None
        mock_chk.return_value = None
        mock_reqname.return_value = "request_name"
        mock_ca.return_value = [None, "cert", "id"]
        mock_prof.return_value = None
        self.assertEqual(
            ("ca lookup failed", None, None, None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_chk.called)
        self.assertTrue(mock_reqname.called)
        self.assertTrue(mock_csr.called)
        self.assertTrue(mock_b64.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_ca.called)
        self.assertFalse(mock_sign.called)
        self.assertTrue(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_191_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
        mock_db,
    ):
        """test enroll()"""
        mock_db.return_value = None
        mock_chk.return_value = None
        mock_reqname.return_value = "request_name"
        mock_ca.return_value = ["key", None, "id"]
        mock_prof.return_value = None
        self.assertEqual(
            ("ca lookup failed", None, None, None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_chk.called)
        self.assertTrue(mock_reqname.called)
        self.assertTrue(mock_csr.called)
        self.assertTrue(mock_b64.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_ca.called)
        self.assertFalse(mock_sign.called)
        self.assertTrue(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_192_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
        mock_db,
    ):
        """test enroll()"""
        mock_db.return_value = None
        mock_chk.return_value = None
        mock_reqname.return_value = "request_name"
        mock_ca.return_value = ["key", "cert", None]
        mock_prof.return_value = None
        self.assertEqual(
            ("ca lookup failed", None, None, None), self.cahandler.enroll("csr")
        )
        self.assertTrue(mock_chk.called)
        self.assertTrue(mock_reqname.called)
        self.assertTrue(mock_csr.called)
        self.assertTrue(mock_b64.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_ca.called)
        self.assertFalse(mock_sign.called)
        self.assertTrue(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_193_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
        mock_db,
    ):
        """test enroll()"""
        mock_db.return_value = None
        mock_chk.return_value = None
        mock_reqname.return_value = "request_name"
        mock_ca.return_value = ["key", "cert", "caid"]
        mock_sign.return_value = ["bundle", "raw"]
        mock_prof.return_value = None
        self.assertEqual((None, "bundle", "raw", None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_chk.called)
        self.assertTrue(mock_reqname.called)
        self.assertTrue(mock_csr.called)
        self.assertTrue(mock_b64.called)
        self.assertTrue(mock_build.called)
        self.assertTrue(mock_ca.called)
        self.assertTrue(mock_sign.called)
        self.assertTrue(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_194_enroll(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
        mock_db,
    ):
        """test enroll()"""
        mock_db.return_value = None
        mock_chk.return_value = None
        mock_reqname.return_value = "request_name"
        mock_ca.return_value = ["key", "cert", "caid"]
        mock_sign.return_value = ["bundle", "raw"]
        mock_prof.return_value = "prof_error"
        self.assertEqual(("prof_error", None, None, None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_chk.called)
        self.assertFalse(mock_reqname.called)
        self.assertFalse(mock_csr.called)
        self.assertFalse(mock_b64.called)
        self.assertFalse(mock_build.called)
        self.assertFalse(mock_ca.called)
        self.assertFalse(mock_sign.called)
        self.assertTrue(mock_prof.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.enrollment_config_log")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CertificateBuilder")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_encode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._pemcertchain_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._store_cert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._subject_name_hash_get")
    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extension_list_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.load_pem_x509_csr")
    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._template_load")
    def test_195_cert_sign(
        self,
        mock_teml_load,
        mock_str2byte,
        mock_load,
        mock_extlist,
        mock_hash,
        mock_store,
        mock_chain,
        mock_cvt,
        mock_b64,
        mock_builder,
        mock_ecl,
    ):
        """test cert sign"""
        ca_cert = Mock()
        ca_cert.subject = "subject"
        mock_hash.return_value = "mock_hash"
        mock_chain.return_value = "mock_pem"
        mock_cvt.return_value = "mock_cvt"
        # mock_builder.return_value.not_valid_before.return_value.not_valid_after.return_value.issuer_name.return_value.serial_number.return_value.public_key.return_value.subject_name.return_value.sign.return_value.public_bytes.return_value = 'mock_public_bytes'
        mock_builder.return_value.not_valid_before.return_value.not_valid_after.return_value.issuer_name.return_value.serial_number.return_value.public_key.return_value.subject_name.return_value.sign.return_value.serial_number = (
            1234
        )
        self.assertEqual(
            ("mock_pem", "mock_cvt"),
            self.cahandler._cert_sign(
                "csr", "request_name", "ca_key", ca_cert, "ca_id"
            ),
        )
        self.assertFalse(mock_teml_load.called)
        self.assertTrue(mock_str2byte.called)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_extlist.called)
        self.assertTrue(mock_hash.called)
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_chain.called)
        self.assertTrue(mock_cvt.called)
        self.assertTrue(mock_builder.called)
        self.assertFalse(mock_ecl.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.enrollment_config_log")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CertificateBuilder")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_encode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._pemcertchain_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._store_cert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._subject_name_hash_get")
    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extension_list_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.load_pem_x509_csr")
    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._template_load")
    def test_196_cert_sign(
        self,
        mock_teml_load,
        mock_str2byte,
        mock_load,
        mock_extlist,
        mock_hash,
        mock_store,
        mock_chain,
        mock_cvt,
        mock_b64,
        mock_builder,
        mock_ecl,
    ):
        """test cert sign"""
        ca_cert = Mock()
        ca_cert.subject = "subject"
        mock_hash.return_value = "mock_hash"
        mock_chain.return_value = "mock_pem"
        mock_cvt.return_value = "mock_cvt"
        self.cahandler.template_name = "template_name"
        mock_extlist.return_value = [{"name": "name", "critical": True}]
        mock_teml_load.return_value = [{"foo": "bar"}, {"foo": "bar"}]
        self.cahandler.enrollment_config_log = True
        mock_builder.return_value.not_valid_before.return_value.not_valid_after.return_value.issuer_name.return_value.serial_number.return_value.public_key.return_value.add_extension.return_value.subject_name.return_value.sign.return_value.serial_number = (
            1234
        )
        self.assertEqual(
            ("mock_pem", "mock_cvt"),
            self.cahandler._cert_sign(
                "csr", "request_name", "ca_key", ca_cert, "ca_id"
            ),
        )
        self.assertTrue(mock_teml_load.called)
        self.assertTrue(mock_str2byte.called)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_extlist.called)
        self.assertTrue(mock_hash.called)
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_chain.called)
        self.assertTrue(mock_cvt.called)
        self.assertTrue(mock_builder.called)
        self.assertTrue(mock_ecl.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CertificateBuilder")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_encode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_byte_to_string")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._pemcertchain_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._store_cert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._subject_name_hash_get")
    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extension_list_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.load_pem_x509_csr")
    @patch("acme2certifier.cahandlers.xca_ca_handler.convert_string_to_byte")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._template_load")
    def test_197_cert_sign(
        self,
        mock_teml_load,
        mock_str2byte,
        mock_load,
        mock_extlist,
        mock_hash,
        mock_store,
        mock_chain,
        mock_cvt,
        mock_b64,
        mock_builder,
    ):
        """test cert sign"""
        ca_cert = Mock()
        ca_cert.subject = "subject"
        mock_hash.return_value = "mock_hash"
        mock_chain.return_value = "mock_pem"
        mock_cvt.return_value = "mock_cvt"
        self.cahandler.template_name = "template_name"
        mock_extlist.return_value = [{"name": "name", "critical": True}]
        mock_teml_load.return_value = [{"foo": "bar"}, {"validity": 30}]
        mock_builder.return_value.not_valid_before.return_value.not_valid_after.return_value.issuer_name.return_value.serial_number.return_value.public_key.return_value.add_extension.return_value.subject_name.return_value.sign.return_value.serial_number = (
            1234
        )
        self.assertEqual(
            ("mock_pem", "mock_cvt"),
            self.cahandler._cert_sign(
                "csr", "request_name", "ca_key", ca_cert, "ca_id"
            ),
        )
        self.assertTrue(mock_teml_load.called)
        self.assertTrue(mock_str2byte.called)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_extlist.called)
        self.assertTrue(mock_hash.called)
        self.assertTrue(mock_store.called)
        self.assertTrue(mock_chain.called)
        self.assertTrue(mock_cvt.called)
        self.assertTrue(mock_builder.called)

    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extended_keyusage_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cdp_list_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._keyusage_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CRLDistributionPoints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    def test_198_xca_template_process(
        self,
        mock_ski,
        mock_aki,
        mock_ku,
        mock_eku,
        mock_crl,
        mock_bc,
        mock_kug,
        mock_cdp,
        mock_ekug,
    ):
        """test _xca_template_process()"""
        csr_extensions_dic = {}
        template_dic = {"foo": "bar"}
        cert = Mock()
        cert.public_key.return_value = "public_key"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_ekug.return_value = (False, {})
        mock_kug.return_value = (True, {"mock_kug": "mock_kug"})
        mock_cdp.return_value = ["mock_cdp"]
        result = [
            {"name": "mock_ski", "critical": False},
            {"name": "mock_aki", "critical": False},
            {"name": "mock_ku", "critical": True},
        ]
        self.assertEqual(
            result,
            self.cahandler._xca_template_process(
                template_dic, csr_extensions_dic, cert, cert
            ),
        )
        self.assertTrue(mock_ku.called)
        self.assertFalse(mock_eku.called)
        self.assertTrue(mock_ekug.called)
        self.assertTrue(mock_kug.called)
        self.assertFalse(mock_crl.called)
        self.assertFalse(mock_bc.called)
        self.assertFalse(mock_cdp.called)

    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extended_keyusage_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cdp_list_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._keyusage_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CRLDistributionPoints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    def test_199_xca_template_process(
        self,
        mock_ski,
        mock_aki,
        mock_ku,
        mock_eku,
        mock_crl,
        mock_bc,
        mock_kug,
        mock_cdp,
        mock_ekug,
    ):
        """test _xca_template_process()"""
        csr_extensions_dic = {}
        template_dic = {"foo": "bar"}
        cert = Mock()
        cert.public_key.return_value = "public_key"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_ekug.return_value = (False, ["eku_list"])
        mock_kug.return_value = (True, {"mock_kug": "mock_kug"})
        mock_cdp.return_value = ["mock_cdp"]
        result = [
            {"name": "mock_ski", "critical": False},
            {"name": "mock_aki", "critical": False},
            {"name": "mock_ku", "critical": True},
            {"critical": False, "name": "mock_eku"},
        ]
        self.assertEqual(
            result,
            self.cahandler._xca_template_process(
                template_dic, csr_extensions_dic, cert, cert
            ),
        )
        self.assertTrue(mock_ku.called)
        self.assertTrue(mock_eku.called)
        self.assertTrue(mock_ekug.called)
        self.assertTrue(mock_kug.called)
        self.assertFalse(mock_crl.called)
        self.assertFalse(mock_bc.called)
        self.assertFalse(mock_cdp.called)

    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extended_keyusage_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cdp_list_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._keyusage_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CRLDistributionPoints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    def test_200_xca_template_process(
        self,
        mock_ski,
        mock_aki,
        mock_ku,
        mock_eku,
        mock_crl,
        mock_bc,
        mock_kug,
        mock_cdp,
        mock_ekug,
    ):
        """test _xca_template_process()"""
        csr_extensions_dic = {}
        template_dic = {"crlDist": "crlDist"}
        cert = Mock()
        cert.public_key.return_value = "public_key"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_crl.return_value = "mock_crl"
        mock_ekug.return_value = (False, {})
        mock_kug.return_value = (True, {"mock_kug": "mock_kug"})
        mock_cdp.return_value = ["mock_cdp"]
        result = [
            {"name": "mock_ski", "critical": False},
            {"name": "mock_aki", "critical": False},
            {"name": "mock_ku", "critical": True},
            {"critical": False, "name": "mock_crl"},
        ]
        self.assertEqual(
            result,
            self.cahandler._xca_template_process(
                template_dic, csr_extensions_dic, cert, cert
            ),
        )
        self.assertTrue(mock_ku.called)
        self.assertFalse(mock_eku.called)
        self.assertTrue(mock_ekug.called)
        self.assertTrue(mock_kug.called)
        self.assertTrue(mock_crl.called)
        self.assertFalse(mock_bc.called)
        self.assertTrue(mock_cdp.called)

    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extended_keyusage_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cdp_list_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._keyusage_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CRLDistributionPoints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    def test_201_xca_template_process(
        self,
        mock_ski,
        mock_aki,
        mock_ku,
        mock_eku,
        mock_crl,
        mock_bc,
        mock_kug,
        mock_cdp,
        mock_ekug,
    ):
        """test _xca_template_process()"""
        csr_extensions_dic = {}
        template_dic = {"ca": "1", "bcCritical": True}
        cert = Mock()
        cert.public_key.return_value = "public_key"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_bc.return_value = "mock_bc"
        mock_ekug.return_value = (False, {})
        mock_kug.return_value = (True, {"mock_kug": "mock_kug"})
        mock_cdp.return_value = ["mock_cdp"]
        result = [
            {"name": "mock_ski", "critical": False},
            {"name": "mock_aki", "critical": False},
            {"name": "mock_ku", "critical": True},
            {"critical": True, "name": "mock_bc"},
        ]
        self.assertEqual(
            result,
            self.cahandler._xca_template_process(
                template_dic, csr_extensions_dic, cert, cert
            ),
        )
        self.assertTrue(mock_ku.called)
        self.assertFalse(mock_eku.called)
        self.assertTrue(mock_ekug.called)
        self.assertTrue(mock_kug.called)
        self.assertFalse(mock_crl.called)
        self.assertTrue(mock_bc.called)
        self.assertFalse(mock_cdp.called)

    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extended_keyusage_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cdp_list_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._keyusage_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CRLDistributionPoints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    def test_202_xca_template_process(
        self,
        mock_ski,
        mock_aki,
        mock_ku,
        mock_eku,
        mock_crl,
        mock_bc,
        mock_kug,
        mock_cdp,
        mock_ekug,
    ):
        """test _xca_template_process()"""
        csr_extensions_dic = {}
        template_dic = {"ca": "1", "bcCritical": False}
        cert = Mock()
        cert.public_key.return_value = "public_key"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_bc.return_value = "mock_bc"
        mock_ekug.return_value = (False, {})
        mock_kug.return_value = (True, {"mock_kug": "mock_kug"})
        mock_cdp.return_value = ["mock_cdp"]
        result = [
            {"name": "mock_ski", "critical": False},
            {"name": "mock_aki", "critical": False},
            {"name": "mock_ku", "critical": True},
            {"critical": False, "name": "mock_bc"},
        ]
        self.assertEqual(
            result,
            self.cahandler._xca_template_process(
                template_dic, csr_extensions_dic, cert, cert
            ),
        )
        self.assertTrue(mock_ku.called)
        self.assertFalse(mock_eku.called)
        self.assertTrue(mock_ekug.called)
        self.assertTrue(mock_kug.called)
        self.assertFalse(mock_crl.called)
        self.assertTrue(mock_bc.called)
        self.assertFalse(mock_cdp.called)

    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extended_keyusage_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cdp_list_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._keyusage_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CRLDistributionPoints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    def test_203_xca_template_process(
        self,
        mock_ski,
        mock_aki,
        mock_ku,
        mock_eku,
        mock_crl,
        mock_bc,
        mock_kug,
        mock_cdp,
        mock_ekug,
    ):
        """test _xca_template_process()"""
        csr_extensions_dic = {}
        template_dic = {"ca": "1", "bcCritical": "aa"}
        cert = Mock()
        cert.public_key.return_value = "public_key"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_bc.return_value = "mock_bc"
        mock_ekug.return_value = (False, {})
        mock_kug.return_value = (True, {"mock_kug": "mock_kug"})
        mock_cdp.return_value = ["mock_cdp"]
        result = [
            {"name": "mock_ski", "critical": False},
            {"name": "mock_aki", "critical": False},
            {"name": "mock_ku", "critical": True},
            {"critical": False, "name": "mock_bc"},
        ]
        self.assertEqual(
            result,
            self.cahandler._xca_template_process(
                template_dic, csr_extensions_dic, cert, cert
            ),
        )
        self.assertTrue(mock_ku.called)
        self.assertFalse(mock_eku.called)
        self.assertTrue(mock_ekug.called)
        self.assertTrue(mock_kug.called)
        self.assertFalse(mock_crl.called)
        self.assertTrue(mock_bc.called)
        self.assertFalse(mock_cdp.called)

    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extended_keyusage_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cdp_list_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._keyusage_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CRLDistributionPoints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    def test_204_xca_template_process(
        self,
        mock_ski,
        mock_aki,
        mock_ku,
        mock_eku,
        mock_crl,
        mock_bc,
        mock_kug,
        mock_cdp,
        mock_ekug,
    ):
        """test _xca_template_process()"""
        csr_extensions_dic = {}
        template_dic = {"ca": "2", "bcCritical": "aa"}
        cert = Mock()
        cert.public_key.return_value = "public_key"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_bc.return_value = "mock_bc"
        mock_ekug.return_value = (False, {})
        mock_kug.return_value = (True, {"mock_kug": "mock_kug"})
        mock_cdp.return_value = ["mock_cdp"]
        result = [
            {"name": "mock_ski", "critical": False},
            {"name": "mock_aki", "critical": False},
            {"name": "mock_ku", "critical": True},
            {"critical": False, "name": "mock_bc"},
        ]
        self.assertEqual(
            result,
            self.cahandler._xca_template_process(
                template_dic, csr_extensions_dic, cert, cert
            ),
        )
        self.assertTrue(mock_ku.called)
        self.assertFalse(mock_eku.called)
        self.assertTrue(mock_ekug.called)
        self.assertTrue(mock_kug.called)
        self.assertFalse(mock_crl.called)
        self.assertTrue(mock_bc.called)
        self.assertFalse(mock_cdp.called)

    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.CAhandler._extended_keyusage_generate"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cdp_list_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._keyusage_generate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.BasicConstraints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.CRLDistributionPoints")
    @patch("acme2certifier.cahandlers.xca_ca_handler.ExtendedKeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.KeyUsage")
    @patch("acme2certifier.cahandlers.xca_ca_handler.AuthorityKeyIdentifier")
    @patch("acme2certifier.cahandlers.xca_ca_handler.SubjectKeyIdentifier")
    def test_205_xca_template_process(
        self,
        mock_ski,
        mock_aki,
        mock_ku,
        mock_eku,
        mock_crl,
        mock_bc,
        mock_kug,
        mock_cdp,
        mock_ekug,
    ):
        """test _xca_template_process()"""
        csr_extensions_dic = {}
        template_dic = {"ca": "1"}
        cert = Mock()
        cert.public_key.return_value = "public_key"
        mock_ski.from_public_key.return_value = "mock_ski"
        mock_aki.from_issuer_public_key.return_value = "mock_aki"
        mock_ku.return_value = "mock_ku"
        mock_eku.return_value = "mock_eku"
        mock_bc.return_value = "mock_bc"
        mock_ekug.return_value = (False, {})
        mock_kug.return_value = (True, {"mock_kug": "mock_kug"})
        mock_cdp.return_value = ["mock_cdp"]
        result = [
            {"name": "mock_ski", "critical": False},
            {"name": "mock_aki", "critical": False},
            {"name": "mock_ku", "critical": True},
            {"critical": False, "name": "mock_bc"},
        ]
        self.assertEqual(
            result,
            self.cahandler._xca_template_process(
                template_dic, csr_extensions_dic, cert, cert
            ),
        )
        self.assertTrue(mock_ku.called)
        self.assertFalse(mock_eku.called)
        self.assertTrue(mock_ekug.called)
        self.assertTrue(mock_kug.called)
        self.assertFalse(mock_crl.called)
        self.assertTrue(mock_bc.called)
        self.assertFalse(mock_cdp.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.oct")
    @patch("os.access")
    @patch("os.stat")
    def test_206_db_check(self, mock_stat, mock_access, mock_oct, mock_load):
        """test _db_check()"""
        self.cahandler.xdb_file = "xdb_file"
        mock_stat.return_value.st_mode = 2222
        mock_oct.return_value = "660"
        mock_access.side_effect = [True, True]
        mock_load.return_value = "ca_key"
        self.assertEqual(None, self.cahandler._db_check())

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.oct")
    @patch("os.access")
    @patch("os.stat")
    def test_207_db_check(self, mock_stat, mock_access, mock_oct, mock_load):
        """test _db_check()"""
        self.cahandler.xdb_file = "xdb_file"
        mock_stat.return_value.st_mode = 2222
        mock_oct.return_value = "660"
        mock_access.side_effect = [False, True]
        mock_load.return_value = "ca_key"
        self.assertEqual(
            "xdb_file xdb_file is not readable", self.cahandler._db_check()
        )
        self.assertFalse(mock_load.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.oct")
    @patch("os.access")
    @patch("os.stat")
    def test_208_db_check(self, mock_stat, mock_access, mock_oct, mock_load):
        """test _db_check()"""
        self.cahandler.xdb_file = "xdb_file"
        mock_stat.return_value.st_mode = 2222
        mock_oct.return_value = "660"
        mock_access.side_effect = [True, False]
        mock_load.return_value = "ca_key"
        self.assertEqual(
            "xdb_file xdb_file is not writeable", self.cahandler._db_check()
        )
        self.assertFalse(mock_load.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.oct")
    @patch("os.access")
    @patch("os.stat")
    def test_209_db_check(self, mock_stat, mock_access, mock_oct, mock_load):
        """test _db_check()"""
        self.cahandler.xdb_file = "xdb_file"
        mock_stat.return_value.st_mode = 2222
        mock_oct.return_value = "660"
        mock_access.side_effect = [True, True]
        mock_load.return_value = None
        self.assertEqual(
            "ca_key_load failed. Please check passphrase", self.cahandler._db_check()
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.oct")
    @patch("os.access")
    @patch("os.stat")
    def test_210_db_check(self, mock_stat, mock_access, mock_oct, mock_load):
        """test _db_check()"""
        self.cahandler.xdb_file = "xdb_file"
        mock_stat.return_value.st_mode = 2222
        self.cahandler.xdb_permission = "220"
        mock_oct.return_value = "660"
        mock_access.side_effect = [True, True]
        mock_load.return_value = "ca_key"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(None, self.cahandler._db_check())
        self.assertIn(
            "WARNING:test_a2c:File permissions 660 for 'xdb_file' are too permissive. Should be 220.",
            lcm.output,
        )
        self.assertTrue(mock_access.called)
        self.assertTrue(mock_load.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.oct")
    @patch("os.access")
    @patch("os.stat")
    def test_211_db_check(self, mock_stat, mock_access, mock_oct, mock_load):
        """test _db_check()"""
        self.cahandler.xdb_file = "xdb_file"
        mock_stat.return_value.st_mode = 2222
        self.cahandler.xdb_permission = "220"
        mock_oct.return_value = "260"
        mock_access.side_effect = [True, True]
        mock_load.return_value = "ca_key"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(None, self.cahandler._db_check())
        self.assertIn(
            "WARNING:test_a2c:File permissions 260 for 'xdb_file' are too permissive. Should be 220.",
            lcm.output,
        )
        self.assertTrue(mock_access.called)
        self.assertTrue(mock_load.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.oct")
    @patch("os.access")
    @patch("os.stat")
    def test_212_db_check(self, mock_stat, mock_access, mock_oct, mock_load):
        """test _db_check()"""
        self.cahandler.xdb_file = "xdb_file"
        mock_stat.return_value.st_mode = 2222
        self.cahandler.xdb_permission = "220"
        mock_oct.return_value = "222"
        mock_access.side_effect = [True, True]
        mock_load.return_value = "ca_key"
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(None, self.cahandler._db_check())
        self.assertIn(
            "WARNING:test_a2c:File permissions 222 for 'xdb_file' are too permissive. Should be 220.",
            lcm.output,
        )
        self.assertTrue(mock_access.called)
        self.assertTrue(mock_load.called)

    def test_213_table_check(self):
        """test _table_check() method"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.assertTrue(self.cahandler._table_check("requests"))
        self.assertTrue(self.cahandler._table_check("view_certs"))
        self.assertFalse(self.cahandler._table_check("unknown_table"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._columnnames_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._table_check")
    def test_214_identifier_check(self, mock_chk, mock_col):
        """test _identifier_check() method"""
        mock_chk.return_value = True
        mock_col.return_value = ["item", "foo"]
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.assertTrue(self.cahandler._identifier_check("certs", "item"))
        self.assertFalse(self.cahandler._identifier_check("certs", "unkown"))
        self.assertTrue(self.cahandler._identifier_check("certs", "certs.foo"))
        self.assertFalse(self.cahandler._identifier_check("certs", "certs.unkown"))
        self.assertTrue(self.cahandler._identifier_check("certs", "certs__foo"))
        self.assertFalse(self.cahandler._identifier_check("certs", "certs__unkown"))

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._table_check")
    def test_215_identifier_check(self, mock_tg):
        """test _identifier_check() method"""
        mock_tg.return_value = False
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertFalse(
                self.cahandler._identifier_check("unknown_table", "unkown")
            )
        self.assertIn(
            "WARNING:test_a2c:Table 'unknown_table' does not exist in the database.",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_216_columnnames_get(self, mock_open, mock_close):
        """test _columnnames_get() method"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        mock_open.return_value = True
        mock_close.return_value = True
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.description = [["foo", "foobar"], ["foo1", "bar1"]]
        self.assertEqual(
            ["foo", "foo1"],
            self.cahandler._columnnames_get("requests"),
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_217_handler_check(self, mock_cfg, mock_db):
        """test handler_check() method"""
        mock_cfg.return_value = False
        mock_db.return_value = False
        self.assertFalse(self.cahandler.handler_check())
        self.assertTrue(mock_cfg.called)
        self.assertTrue(mock_db.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_218_handler_check(self, mock_cfg, mock_db):
        """test handler_check() method"""
        mock_cfg.return_value = False
        mock_db.return_value = "db_error"
        self.assertEqual("db_error", self.cahandler.handler_check())
        self.assertTrue(mock_cfg.called)
        self.assertTrue(mock_db.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_219_handler_check(self, mock_cfg, mock_db):
        """test handler_check() method"""
        mock_cfg.return_value = "cfg_error"
        mock_db.return_value = "db_error"
        self.assertEqual("cfg_error", self.cahandler.handler_check())
        self.assertTrue(mock_cfg.called)
        self.assertFalse(mock_db.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_220_config_load_no_cahandler_section(self, mock_load_cfg):
        """_config_load without CAhandler section must not raise"""
        parser = configparser.ConfigParser()
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertIsNone(self.cahandler.passphrase)
        self.assertIsNone(self.cahandler.xdb_file)

    def test_221_x509super_insert(self):
        """_x509super_insert writes a row linked to a new item"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        item_id = self.cahandler._item_insert(
            {
                "name": "x509super-test",
                "type": 3,
                "source": 2,
                "date": "20200101000000Z",
                "comment": "from acme2certifier",
            }
        )
        row_id = self.cahandler._x509super_insert(
            {
                "item": item_id,
                "subj_hash": 1,
                "pkey": None,
                "key_hash": 2,
            }
        )
        self.assertTrue(row_id)

    def test_222_public_key_hash_get(self):
        """_public_key_hash_get matches XCA fixture key_hash for sub-ca cert"""
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler.issuing_ca_name = "sub-ca"
        ca_cert, _ca_id = self.cahandler._ca_cert_load()
        self.assertEqual(
            2066264345, self.cahandler._public_key_hash_get(ca_cert.public_key())
        )

    def test_223_dict_from_row(self):
        """dict_from_row normalizes None, dict, and sqlite rows"""
        from acme2certifier.cahandlers.xca_ca_handler import dict_from_row

        self.assertEqual({}, dict_from_row(None))
        self.assertEqual(
            {"id": 1, "name": "ca"}, dict_from_row({"ID": 1, "Name": "ca"})
        )
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.cahandler._db_open()
        try:
            self.cahandler.cursor.execute(
                "SELECT id, name FROM items WHERE id = ?", [1]
            )
            row = dict_from_row(self.cahandler.cursor.fetchone())
        finally:
            self.cahandler._db_close()
        self.assertIn("id", row)
        self.assertIn("name", row)

    def test_224_sql_match(self):
        """numeric lookups use =; text keeps LIKE (PostgreSQL rejects integer LIKE)"""
        from acme2certifier.cahandlers.xca_ca_handler import sql_match

        self.assertEqual("name LIKE ?", sql_match("name", "ca"))
        self.assertEqual("item = ?", sql_match("item", 2))
        self.assertEqual("flag LIKE ?", sql_match("flag", True))

    def test_225_xcadb_rewrite_prefix(self):
        """XcaDb.rewrite_prefix matches XCA concatenation on tables and views"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        db = XcaDb()
        db.configure(table_prefix="pki_")
        sql = db.rewrite_prefix(
            "SELECT * FROM view_certs JOIN items ON items.id = view_certs.item"
        )
        self.assertIn("pki_view_certs", sql)
        self.assertIn("pki_items", sql)
        self.assertIsNone(re.search(r"\bview_certs\b", sql))
        self.assertIsNone(re.search(r"\bitems\b", sql))
        db.configure(table_prefix="")
        sql = db.rewrite_prefix("SELECT * FROM items")
        self.assertEqual("SELECT * FROM items", sql)

    def test_226_xcadb_convert_sql_sqlite(self):
        """sqlite keeps ? placeholders and does not rewrite tables"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        db = XcaDb()
        sql, params = db.convert_sql("SELECT * FROM items WHERE name LIKE ?", ["a"])
        self.assertEqual("SELECT * FROM items WHERE name LIKE ?", sql)
        self.assertEqual(["a"], params)

    def test_227_xcadb_convert_sql_mysql(self):
        """mysql converts ? to %s and applies the table prefix"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        db = XcaDb()
        db.configure(engine="mysql", table_prefix="xca")
        sql, params = db.convert_sql(
            "SELECT * FROM view_certs WHERE name LIKE ?", ["a"]
        )
        self.assertEqual("SELECT * FROM xcaview_certs WHERE name LIKE %s", sql)
        self.assertEqual(["a"], params)

    def test_228_xcadb_convert_sql_named(self):
        """postgres converts :name placeholders to pyformat"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        db = XcaDb()
        db.configure(engine="postgresql")
        sql, params = db.convert_sql(
            "INSERT INTO items(id, name) VALUES(:id, :name)",
            {"id": 1, "name": "ca"},
        )
        self.assertEqual("INSERT INTO items(id, name) VALUES(%(id)s, %(name)s)", sql)
        self.assertEqual({"id": 1, "name": "ca"}, params)

    def test_229_xcadb_catalog_and_physical_name(self):
        """catalog SQL and prefixed physical names per engine"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        db = XcaDb(logger=self.logger)
        self.assertIn("sqlite_master", db.catalog_sql())
        self.assertEqual("items", db.physical_name("items"))
        db.configure(engine="mysql", table_prefix="pki_")
        self.assertIn("information_schema.tables", db.catalog_sql())
        self.assertIn("DATABASE()", db.catalog_sql())
        self.assertEqual("pki_items", db.physical_name("items"))
        db.configure(engine="postgresql", table_prefix="pki_")
        self.assertIn("current_schema()", db.catalog_sql())
        db.configure(engine="unknown")
        self.assertIn("sqlite_master", db.catalog_sql())

    def test_230_config_check_unsupported_engine(self):
        """_config_check rejects unknown xdb_engine values"""
        self.cahandler.xdb_engine = "mssql"
        self.assertEqual("unsupported xdb_engine mssql", self.cahandler._config_check())

    def test_231_config_check_remote_missing_host(self):
        """remote engine requires host, name and user"""
        self.cahandler.xdb_engine = "mysql"
        self.cahandler.xdb_password = "secret"
        self.assertEqual(
            "xdb_host, xdb_name and xdb_user must be specified in config file",
            self.cahandler._config_check(),
        )

    def test_232_config_check_remote_missing_password(self):
        """remote engine requires xdb_password"""
        self.cahandler.xdb_engine = "postgresql"
        self.cahandler.xdb_host = "db.example"
        self.cahandler.xdb_name = "xca"
        self.cahandler.xdb_user = "xca"
        self.assertEqual(
            "xdb_password must be specified in config file",
            self.cahandler._config_check(),
        )

    def test_233_config_check_remote_ok(self):
        """remote mysql config is valid without xdb_file"""
        self.cahandler.xdb_engine = "mysql"
        self.cahandler.xdb_host = "db.example"
        self.cahandler.xdb_name = "xca"
        self.cahandler.xdb_user = "xca"
        self.cahandler.xdb_password = "secret"
        self.cahandler.issuing_ca_name = "sub-ca"
        self.assertFalse(self.cahandler._config_check())

    def test_234_config_check_mariadb_alias(self):
        """mariadb is accepted as mysql"""
        self.cahandler.xdb_engine = "mariadb"
        self.cahandler.xdb_host = "db.example"
        self.cahandler.xdb_name = "xca"
        self.cahandler.xdb_user = "xca"
        self.cahandler.xdb_password = "secret"
        self.cahandler.issuing_ca_name = "sub-ca"
        self.assertFalse(self.cahandler._config_check())
        self.assertEqual("mysql", self.cahandler._xdb_engine_normalized())

    def test_235_config_check_mutual_exclusive(self):
        """xdb_file cannot be combined with a remote engine"""
        self.cahandler.xdb_engine = "postgresql"
        self.cahandler.xdb_file = "/tmp/foo.xdb"
        self.cahandler.xdb_host = "db.example"
        self.cahandler.xdb_name = "xca"
        self.cahandler.xdb_user = "xca"
        self.cahandler.xdb_password = "secret"
        self.assertEqual(
            "xdb_file and remote xdb_engine are mutually exclusive",
            self.cahandler._config_check(),
        )

    @patch.dict("os.environ", {"XCA_DB_PASSWORD": "dbpass"})
    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_236_config_load_remote(self, mock_load_cfg):
        """_config_load maps remote keys and xdb_password_variable"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "xdb_engine": "MariaDB",
            "xdb_host": "10.1.0.1",
            "xdb_port": "3306",
            "xdb_name": "xca",
            "xdb_user": "xca",
            "xdb_password_variable": "XCA_DB_PASSWORD",
            "xdb_table_prefix": "pki1",
            "xdb_ssl_ca": "/etc/ssl/ca.pem",
            "xdb_ssl_mode": "verify-ca",
            "issuing_ca_name": "sub-ca",
        }
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("mysql", self.cahandler.xdb_engine)
        self.assertEqual("10.1.0.1", self.cahandler.xdb_host)
        self.assertEqual(3306, self.cahandler.xdb_port)
        self.assertEqual("xca", self.cahandler.xdb_name)
        self.assertEqual("xca", self.cahandler.xdb_user)
        self.assertEqual("dbpass", self.cahandler.xdb_password)
        self.assertEqual("pki1", self.cahandler.xdb_table_prefix)
        self.assertEqual("/etc/ssl/ca.pem", self.cahandler.xdb_ssl_ca)
        self.assertEqual("verify-ca", self.cahandler.xdb_ssl_mode)
        self.assertEqual("mysql", self.cahandler.xca_db.engine)
        self.assertEqual("pki1", self.cahandler.xca_db.table_prefix)
        self.assertEqual("dbpass", self.cahandler.xca_db.password)

    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_237_config_load_postgres_alias(self, mock_load_cfg):
        """postgres and pgsql aliases map to postgresql"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"xdb_engine": "postgres"}
        mock_load_cfg.return_value = parser
        self.cahandler._config_load()
        self.assertEqual("postgresql", self.cahandler.xdb_engine)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_load")
    def test_238_enter_remote_skips_config_load(self, mock_cfg):
        """__enter__ treats remote host/name/user as configured"""
        self.cahandler.xdb_engine = "mysql"
        self.cahandler.xdb_host = "db.example"
        self.cahandler.xdb_name = "xca"
        self.cahandler.xdb_user = "xca"
        self.cahandler.__enter__()
        self.assertFalse(mock_cfg.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_239_db_check_remote(self, mock_open, mock_close, mock_load):
        """remote _db_check connects with SELECT 1 and skips file perms"""
        self.cahandler.xdb_engine = "mysql"
        self.cahandler.cursor = Mock()
        mock_load.return_value = "ca_key"
        self.assertEqual(None, self.cahandler._db_check())
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)
        self.cahandler.cursor.execute.assert_called_with("SELECT 1")
        self.assertTrue(mock_load.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_key_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_240_db_check_remote_connect_failed(self, mock_open, mock_close, mock_load):
        """remote _db_check surfaces connection errors"""
        self.cahandler.xdb_engine = "postgresql"
        mock_open.side_effect = Exception("refused")
        self.assertEqual(
            "database connection failed: refused", self.cahandler._db_check()
        )
        self.assertFalse(mock_load.called)
        self.assertFalse(mock_close.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    def test_241_table_check_prefix(self, mock_open, mock_close):
        """_table_check matches catalog names including the XCA prefix"""
        self.cahandler.xca_db.configure(engine="mysql", table_prefix="pki_")
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.fetchall.return_value = [{"name": "pki_requests"}]
        self.assertTrue(self.cahandler._table_check("requests"))
        self.assertFalse(self.cahandler._table_check("certs"))
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    def test_242_inserted_row_id(self):
        """_inserted_row_id falls back to rowcount when lastrowid is 0"""
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.lastrowid = 0
        self.cahandler.cursor.rowcount = 1
        self.assertEqual(1, self.cahandler._inserted_row_id())
        self.cahandler.cursor.lastrowid = 15
        self.assertEqual(15, self.cahandler._inserted_row_id())
        self.cahandler.cursor.lastrowid = 0
        self.cahandler.cursor.rowcount = 0
        self.assertIsNone(self.cahandler._inserted_row_id())

    def test_243_db_configured(self):
        """_db_configured is true for sqlite file or complete remote settings"""
        self.assertFalse(self.cahandler._db_configured())
        self.cahandler.xdb_file = "/tmp/foo.xdb"
        self.assertTrue(self.cahandler._db_configured())
        self.cahandler.xdb_file = None
        self.cahandler.xdb_engine = "mysql"
        self.assertFalse(self.cahandler._db_configured())
        self.cahandler.xdb_host = "db.example"
        self.cahandler.xdb_name = "xca"
        self.cahandler.xdb_user = "xca"
        self.assertTrue(self.cahandler._db_configured())

    def test_244_connect_mysql_ssl_verify_ca(self):
        """verify-ca must not set check_hostname (PyMySQL defaults True)"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        mock_pymysql = MagicMock()
        mock_cursors = MagicMock()
        with patch.dict(
            sys.modules, {"pymysql": mock_pymysql, "pymysql.cursors": mock_cursors}
        ):
            db = XcaDb(logger=Mock())
            db.configure(
                engine="mysql",
                host="db.example",
                name="xca",
                user="xca",
                password="secret",
                ssl_ca="/etc/ssl/ca.pem",
                ssl_mode="verify-ca",
            )
            db._connect_mysql()
        kwargs = mock_pymysql.connect.call_args.kwargs
        self.assertEqual("/etc/ssl/ca.pem", kwargs["ssl"]["ca"])
        self.assertFalse(kwargs["ssl"]["check_hostname"])

    def test_245_connect_mysql_ssl_verify_full(self):
        """verify-full enables hostname checks"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        mock_pymysql = MagicMock()
        mock_cursors = MagicMock()
        with patch.dict(
            sys.modules, {"pymysql": mock_pymysql, "pymysql.cursors": mock_cursors}
        ):
            db = XcaDb(logger=Mock())
            db.configure(
                engine="mysql",
                host="db.example",
                name="xca",
                user="xca",
                password="secret",
                ssl_ca="/etc/ssl/ca.pem",
                ssl_mode="verify-full",
            )
            db._connect_mysql()
        kwargs = mock_pymysql.connect.call_args.kwargs
        self.assertTrue(kwargs["ssl"]["check_hostname"])

    def test_246_xca_cursor_lastrowid_rowcount_description(self):
        """_XcaCursor exposes lastrowid, rowcount and description"""
        from acme2certifier.cahandlers.xca_ca_handler import _XcaCursor

        inner = Mock()
        inner.lastrowid = 9
        inner.rowcount = 3
        inner.description = (("id",),)
        cursor = _XcaCursor(inner, lambda sql, params: (sql, params))
        self.assertEqual(9, cursor.lastrowid)
        self.assertEqual(3, cursor.rowcount)
        self.assertEqual((("id",),), cursor.description)

    def test_247_xcadb_is_remote(self):
        """XcaDb.is_remote is true for mysql and postgresql"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        db = XcaDb(logger=self.logger)
        self.assertFalse(db.is_remote())
        db.engine = "mysql"
        self.assertTrue(db.is_remote())
        db.engine = "postgresql"
        self.assertTrue(db.is_remote())

    def test_248_connect_mysql_postgresql_unsupported(self):
        """XcaDb.connect dispatches mysql/postgresql and rejects unknown engines"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        db = XcaDb(logger=self.logger)
        conn, cur = Mock(), Mock()
        db.engine = "mysql"
        with patch.object(db, "_connect_mysql", return_value=(conn, cur)) as mock_my:
            got_conn, got_cur = db.connect()
        self.assertTrue(mock_my.called)
        self.assertIs(conn, got_conn)
        self.assertEqual(conn, db.connection)
        db.engine = "postgresql"
        with patch.object(
            db, "_connect_postgresql", return_value=(conn, cur)
        ) as mock_pg:
            db.connect()
        self.assertTrue(mock_pg.called)
        db.engine = "mssql"
        with self.assertRaises(ValueError):
            db.connect()

    def test_249_connect_mysql_import_error_and_port(self):
        """_connect_mysql raises without PyMySQL and passes port when set"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        db = XcaDb(logger=self.logger)
        db.configure(
            engine="mysql",
            host="db.example",
            name="xca",
            user="xca",
            password="secret",
            port=3306,
        )
        with patch.dict(sys.modules, {"pymysql": None, "pymysql.cursors": None}):
            with self.assertRaises(ImportError):
                db._connect_mysql()
        mock_pymysql = MagicMock()
        mock_cursors = MagicMock()
        with patch.dict(
            sys.modules, {"pymysql": mock_pymysql, "pymysql.cursors": mock_cursors}
        ):
            db._connect_mysql()
        self.assertEqual(3306, mock_pymysql.connect.call_args.kwargs["port"])

    def test_250_connect_postgresql_options_and_import_error(self):
        """_connect_postgresql raises without psycopg2 and maps ssl/port"""
        from acme2certifier.cahandlers.xca_ca_handler import XcaDb

        db = XcaDb(logger=self.logger)
        db.configure(
            engine="postgresql",
            host="db.example",
            name="xca",
            user="xca",
            password="secret",
            port=5432,
            ssl_mode="verify-full",
            ssl_ca="/etc/ssl/ca.pem",
        )
        with patch.dict(sys.modules, {"psycopg2": None, "psycopg2.extras": None}):
            with self.assertRaises(ImportError):
                db._connect_postgresql()
        mock_psycopg2 = MagicMock()
        mock_extras = MagicMock()
        mock_conn = Mock()
        mock_psycopg2.connect.return_value = mock_conn
        with patch.dict(
            sys.modules, {"psycopg2": mock_psycopg2, "psycopg2.extras": mock_extras}
        ):
            conn, cursor = db._connect_postgresql()
        kwargs = mock_psycopg2.connect.call_args.kwargs
        self.assertEqual(5432, kwargs["port"])
        self.assertEqual("verify-full", kwargs["sslmode"])
        self.assertEqual("/etc/ssl/ca.pem", kwargs["sslrootcert"])
        self.assertIs(mock_conn, conn)
        self.assertTrue(mock_conn.cursor.called)
        self.assertIs(cursor, mock_conn.cursor.return_value)

    def test_251_exit_closes_nested_refs_and_logs_disconnect_errors(self):
        """__exit__ drains nested db refs; close errors are logged"""
        self.cahandler._db_refcount = 2
        self.cahandler.dbs = Mock()
        self.cahandler.dbs.close.side_effect = RuntimeError("close fail")
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler.__exit__(None, None, None)
        self.assertEqual(0, self.cahandler._db_refcount)
        self.assertIsNone(self.cahandler.dbs)
        self.assertIn(
            "ERROR:test_a2c:Failed to close XCA database connection: close fail",
            lcm.output,
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.dict_from_row",
        side_effect=RuntimeError("bad row"),
    )
    def test_252_ca_cert_load_row_error(self, _mock_dfr, mock_open, mock_close):
        """_ca_cert_load logs when the cert row cannot be converted"""
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.fetchone.return_value = object()
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            ca_cert, ca_id = self.cahandler._ca_cert_load()
        self.assertIsNone(ca_cert)
        self.assertIsNone(ca_id)
        self.assertIn(
            "ERROR:test_a2c:Certificate lookup in database failed: bad row",
            lcm.output,
        )
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.dict_from_row",
        side_effect=RuntimeError("bad key"),
    )
    def test_253_ca_key_load_row_error(self, _mock_dfr, mock_open, mock_close):
        """_ca_key_load logs when the private-key row cannot be converted"""
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.fetchone.return_value = object()
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(self.cahandler._ca_key_load())
        self.assertIn(
            "ERROR:test_a2c:Failed to load CA private key from database: bad key",
            lcm.output,
        )
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.dict_from_row",
        side_effect=RuntimeError("bad item"),
    )
    def test_254_cert_search_item_row_error(
        self, _mock_dfr, mock_open, mock_close, mock_check
    ):
        """_cert_search logs when the items row cannot be converted"""
        mock_check.return_value = True
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.fetchone.return_value = object()
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual({}, self.cahandler._cert_search("name", "client"))
        self.assertIn(
            "ERROR:test_a2c:Certificate item search in database failed: bad item",
            lcm.output,
        )
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    @patch("acme2certifier.cahandlers.xca_ca_handler.dict_from_row")
    def test_255_cert_search_cert_row_error(
        self, mock_dfr, mock_open, mock_close, mock_check
    ):
        """_cert_search logs when the certs row cannot be converted"""
        mock_check.return_value = True
        mock_dfr.side_effect = [{"id": 6}, RuntimeError("bad cert")]
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.fetchone.return_value = object()
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual({}, self.cahandler._cert_search("name", "client"))
        self.assertIn(
            "ERROR:test_a2c:Certificate search in database failed for item 6: bad cert",
            lcm.output,
        )
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.load_config")
    def test_256_config_load_invalid_xdb_port(self, mock_load_cfg):
        """_config_load logs when xdb_port is not an integer"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "xdb_engine": "mysql",
            "xdb_host": "db.example",
            "xdb_port": "not-a-port",
            "issuing_ca_name": "sub-ca",
        }
        mock_load_cfg.return_value = parser
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.cahandler._config_load()
        self.assertIn(
            'ERROR:test_a2c:Parameter "xdb_port" cannot be loaded',
            lcm.output,
        )
        self.assertIsNone(self.cahandler.xdb_port)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._identifier_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.dict_from_row",
        side_effect=RuntimeError("bad csr"),
    )
    def test_257_csr_search_row_error(
        self, _mock_dfr, mock_open, mock_close, mock_check
    ):
        """_csr_search logs when the request row cannot be converted"""
        mock_check.return_value = True
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.fetchone.return_value = object()
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual({}, self.cahandler._csr_search("name", "req"))
        self.assertIn(
            "ERROR:test_a2c:CSR search in database failed: bad csr",
            lcm.output,
        )
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    def test_258_row_first_value_none_and_dict(self):
        """_row_first_value handles None, dict and sequence rows"""
        self.assertIsNone(self.cahandler._row_first_value(None))
        self.assertEqual(4, self.cahandler._row_first_value({"id": 4}))
        self.assertEqual(7, self.cahandler._row_first_value((7, "name")))

    def test_259_x509super_insert_validation_errors(self):
        """_x509super_insert rejects incomplete and mistyped payloads"""
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(self.cahandler._x509super_insert({"item": 1}))
        self.assertIn(
            "ERROR:test_a2c:x509super insert aborted due to incomplete dataset: {'item': 1}",
            lcm.output,
        )
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertIsNone(
                self.cahandler._x509super_insert(
                    {"item": "1", "subj_hash": 2, "key_hash": 3}
                )
            )
        self.assertIn(
            "ERROR:test_a2c:x509super insert aborted due to wrong datatypes:",
            lcm.output[0],
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._x509super_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._public_key_hash_get")
    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.pyossslcrypto.load_certificate_request"
    )
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.load_pem_x509_csr")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    def test_260_x509super_store_from_csr(
        self, mock_b64, mock_pem, mock_load_csr, mock_load_req, mock_hash, mock_ins
    ):
        """_x509super_store_from_csr inserts a row from a parsed CSR"""
        mock_b64.return_value = "recode"
        mock_pem.return_value = "-----BEGIN CERTIFICATE REQUEST-----\nMII\n-----END CERTIFICATE REQUEST-----"
        mock_load_csr.return_value.public_key.return_value = Mock()
        mock_load_req.return_value.get_subject.return_value.hash.return_value = 99
        mock_hash.return_value = 12
        self.cahandler._x509super_store_from_csr("csr", 8)
        mock_ins.assert_called_once_with(
            {"item": 8, "subj_hash": 99, "pkey": None, "key_hash": 12}
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._x509super_insert")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._public_key_hash_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.x509.load_der_x509_certificate")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_decode")
    def test_261_x509super_store_from_cert(
        self, mock_b64, mock_load, mock_hash, mock_ins
    ):
        """_x509super_store_from_cert inserts a row from a stored certificate"""
        mock_b64.return_value = b"der"
        mock_load.return_value.public_key.return_value = Mock()
        mock_hash.return_value = 21
        self.cahandler._x509super_store_from_cert("YQ==", 5, "17")
        mock_ins.assert_called_once_with(
            {"item": 5, "subj_hash": 17, "pkey": None, "key_hash": 21}
        )

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    @patch(
        "acme2certifier.cahandlers.xca_ca_handler.dict_from_row",
        side_effect=RuntimeError("bad template"),
    )
    def test_262_template_load_row_error(self, _mock_dfr, mock_open, mock_close):
        """_template_load logs when the template row cannot be converted"""
        self.cahandler.cursor = Mock()
        self.cahandler.cursor.fetchone.return_value = object()
        with self.assertLogs("test_a2c", level="INFO") as lcm:
            self.assertEqual(({}, {}), self.cahandler._template_load())
        self.assertIn(
            "ERROR:test_a2c:template lookup failed: bad template",
            lcm.output,
        )
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_close")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_open")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._db_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.eab_profile_header_info_check")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._cert_sign")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._ca_load")
    @patch("acme2certifier.cahandlers.xca_ca_handler.build_pem_file")
    @patch("acme2certifier.cahandlers.xca_ca_handler.b64_url_recode")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._csr_import")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._requestname_get")
    @patch("acme2certifier.cahandlers.xca_ca_handler.CAhandler._config_check")
    def test_263_enroll_opens_db_session(
        self,
        mock_chk,
        mock_reqname,
        mock_csr,
        mock_b64,
        mock_build,
        mock_ca,
        mock_sign,
        mock_prof,
        mock_db,
        mock_open,
        mock_close,
    ):
        """enroll opens and closes the database when it is already configured"""
        mock_chk.return_value = None
        mock_db.return_value = None
        mock_prof.return_value = None
        mock_reqname.return_value = "client.example"
        mock_ca.return_value = ("key", "cert", 1)
        mock_sign.return_value = ("bundle", "raw")
        self.cahandler.xdb_file = self.dir_path + "/ca/acme2certifier.xdb"
        self.assertEqual((None, "bundle", "raw", None), self.cahandler.enroll("csr"))
        self.assertTrue(mock_open.called)
        self.assertTrue(mock_close.called)

    @patch("os.path.exists")
    def test_264_config_check_keeps_issuing_ca_key(self, mock_file):
        """_config_check does not overwrite an explicit issuing_ca_key."""
        self.cahandler.xdb_file = "foo"
        self.cahandler.issuing_ca_name = "ca-name"
        self.cahandler.issuing_ca_key = "ca-key"
        mock_file.return_value = True
        self.assertFalse(self.cahandler._config_check())
        self.assertEqual("ca-key", self.cahandler.issuing_ca_key)


if __name__ == "__main__":

    unittest.main()
