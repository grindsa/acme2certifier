# -*- coding: utf-8 -*-
"""unittests for cert_chain_skip_list (handler-independent chain rewrite phase 1)"""

# pylint: disable=C0415
import configparser
import datetime
import json
import logging
import sys
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, ".")
sys.path.insert(1, "..")


def _issue_cert(
    common_name: str,
    subject_key,
    issuer_name: x509.Name,
    issuer_key,
    is_ca: bool,
) -> x509.Certificate:
    """issue a certificate (self-signed when issuer_key is the subject key)"""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def _pem(*certs: x509.Certificate) -> str:
    return "".join(
        cert.public_bytes(serialization.Encoding.PEM).decode("utf-8") for cert in certs
    )


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


_ROOT_KEY = ec.generate_private_key(ec.SECP256R1())
_ICA_KEY = ec.generate_private_key(ec.SECP256R1())
_LEAF_KEY = ec.generate_private_key(ec.SECP256R1())
_ROOT_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "old-root")])
CERT_ROOT = _issue_cert("old-root", _ROOT_KEY, _ROOT_NAME, _ROOT_KEY, True)
CERT_ICA = _issue_cert("intermediate", _ICA_KEY, CERT_ROOT.subject, _ROOT_KEY, True)
CERT_LEAF = _issue_cert("leaf", _LEAF_KEY, CERT_ICA.subject, _ICA_KEY, False)
BUNDLE = _pem(CERT_LEAF, CERT_ICA, CERT_ROOT)


class TestCertChainSkipListLoad(unittest.TestCase):
    """config_cert_chain_skip_list_load()"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.config import (
            _cert_chain_fingerprint_normalize,
            config_cert_chain_skip_list_load,
        )

        self.normalize = _cert_chain_fingerprint_normalize
        self.load = config_cert_chain_skip_list_load

    def test_001_unset(self):
        """missing key returns an empty list"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_name": "ca"}
        self.assertEqual((None, []), self.load(self.logger, parser))

    def test_002_no_section(self):
        """no CAhandler section returns an empty list"""
        parser = configparser.ConfigParser()
        self.assertEqual((None, []), self.load(self.logger, parser))

    def test_003_valid_list(self):
        """JSON list of fingerprints is loaded and normalized"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {
            "cert_chain_skip_list": json.dumps(
                [_fingerprint(CERT_ROOT).upper(), "AA:BB:CC"]
            )
        }
        error, skip_list = self.load(self.logger, parser)
        self.assertIsNone(error)
        self.assertEqual([_fingerprint(CERT_ROOT), "aabbcc"], skip_list)

    def test_004_invalid_json(self):
        """invalid JSON is a configuration error"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_skip_list": "not-json"}
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, skip_list = self.load(self.logger, parser)
        self.assertTrue(error.startswith("Configuration error:"))
        self.assertIsNone(skip_list)
        self.assertTrue(
            any("Failed to parse cert_chain_skip_list" in line for line in lcm.output)
        )

    def test_005_not_a_list(self):
        """JSON object is rejected"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_skip_list": '{"foo": "bar"}'}
        error, skip_list = self.load(self.logger, parser)
        self.assertEqual(
            "Configuration error: cert_chain_skip_list must be a JSON list",
            error,
        )
        self.assertIsNone(skip_list)

    def test_006_non_string_entry(self):
        """non-string entries are rejected"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_skip_list": "[1, 2]"}
        error, skip_list = self.load(self.logger, parser)
        self.assertEqual(
            "Configuration error: cert_chain_skip_list entries must be strings",
            error,
        )
        self.assertIsNone(skip_list)

    def test_007_normalize(self):
        """colons, spaces and case are stripped"""
        self.assertEqual("aabbcc", self.normalize("AA:BB CC"))


class TestCertChainSkip(unittest.TestCase):
    """cert_chain_skip()"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.certificates import cert_chain_skip

        self.skip = cert_chain_skip

    def test_001_empty_skip_passthrough(self):
        """empty skip list does not parse the bundle"""
        with patch(
            "acme2certifier.acme_srv.helpers.certificates.load_pem_x509_certificate"
        ) as mock_load:
            error, bundle = self.skip(self.logger, "not-pem", [])
        self.assertIsNone(error)
        self.assertEqual("not-pem", bundle)
        self.assertFalse(mock_load.called)

    def test_002_none_skip_passthrough(self):
        """None skip list does not parse"""
        error, bundle = self.skip(self.logger, BUNDLE, None)
        self.assertIsNone(error)
        self.assertEqual(BUNDLE, bundle)

    def test_003_empty_bundle(self):
        """empty bundle is returned unchanged"""
        self.assertEqual((None, None), self.skip(self.logger, None, ["aa"]))
        self.assertEqual((None, ""), self.skip(self.logger, "", ["aa"]))

    def test_004_drop_root(self):
        """listed root is dropped, leaf and intermediate stay"""
        error, bundle = self.skip(self.logger, BUNDLE, [_fingerprint(CERT_ROOT)])
        self.assertIsNone(error)
        self.assertEqual(_pem(CERT_LEAF, CERT_ICA), bundle)

    def test_005_unlisted_fingerprint(self):
        """unknown fingerprint leaves the chain unchanged"""
        error, bundle = self.skip(self.logger, BUNDLE, ["ff" * 32])
        self.assertIsNone(error)
        self.assertEqual(BUNDLE, bundle)

    def test_006_drop_intermediate(self):
        """intermediate can be skipped; leaf is kept"""
        error, bundle = self.skip(self.logger, BUNDLE, [_fingerprint(CERT_ICA)])
        self.assertIsNone(error)
        self.assertEqual(_pem(CERT_LEAF, CERT_ROOT), bundle)

    def test_007_leaf_in_skip_list_fails(self):
        """end-entity fingerprint is a configuration error"""
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, bundle = self.skip(self.logger, BUNDLE, [_fingerprint(CERT_LEAF)])
        self.assertEqual(
            "Configuration error: cert_chain_skip_list includes the end-entity certificate",
            error,
        )
        self.assertIsNone(bundle)
        self.assertTrue(any("end-entity certificate" in line for line in lcm.output))

    def test_008_unparseable_bundle_fails(self):
        """skip list set against a non-PEM bundle fails closed"""
        error, bundle = self.skip(self.logger, "foo", ["aa" * 32])
        self.assertEqual(
            "Configuration error: Failed to parse certificate chain", error
        )
        self.assertIsNone(bundle)

    def test_009_colon_fingerprint_matches(self):
        """openssl-style colon fingerprint still matches after load+skip"""
        from acme2certifier.acme_srv.helpers.config import (
            config_cert_chain_skip_list_load,
        )

        colon = ":".join(
            _fingerprint(CERT_ROOT)[i : i + 2]
            for i in range(0, len(_fingerprint(CERT_ROOT)), 2)
        ).upper()
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_skip_list": json.dumps([colon])}
        load_error, skip_list = config_cert_chain_skip_list_load(self.logger, parser)
        self.assertIsNone(load_error)
        error, bundle = self.skip(self.logger, BUNDLE, skip_list)
        self.assertIsNone(error)
        self.assertEqual(_pem(CERT_LEAF, CERT_ICA), bundle)


class TestBoundCAHandlerSkipList(unittest.TestCase):
    """BoundCAHandler.from_config() loads cert_chain_skip_list from its section"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.cahandler_registry import BoundCAHandler

        self.BoundCAHandler = BoundCAHandler

    def test_001_classical_section(self):
        """[CAhandler] skip-list is loaded onto the bound factory"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_skip_list": json.dumps(["AA"])}
        bound = self.BoundCAHandler.from_config(
            self.logger, object, "CAhandler", "default", parser
        )
        self.assertIsNone(bound.cert_chain_skip_list_error)
        self.assertEqual(["aa"], bound.cert_chain_skip_list)

    def test_002_named_section(self):
        """named handler section is loaded without merging onto [CAhandler]"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_skip_list": json.dumps(["bb"])}
        parser["CAhandler:ejbca"] = {
            "cert_chain_skip_list": json.dumps([_fingerprint(CERT_ROOT)])
        }
        bound = self.BoundCAHandler.from_config(
            self.logger, object, "CAhandler:ejbca", "ejbca", parser
        )
        self.assertIsNone(bound.cert_chain_skip_list_error)
        self.assertEqual([_fingerprint(CERT_ROOT)], bound.cert_chain_skip_list)

    def test_003_named_section_without_skip_list(self):
        """named section with no skip-list does not inherit [CAhandler]"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_skip_list": json.dumps(["bb"])}
        parser["CAhandler:ejbca"] = {}
        bound = self.BoundCAHandler.from_config(
            self.logger, object, "CAhandler:ejbca", "ejbca", parser
        )
        self.assertIsNone(bound.cert_chain_skip_list_error)
        self.assertEqual([], bound.cert_chain_skip_list)


if __name__ == "__main__":
    unittest.main()
