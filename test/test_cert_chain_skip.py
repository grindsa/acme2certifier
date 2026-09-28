# -*- coding: utf-8 -*-
"""unittests for handler-independent certificate chain rewrite"""

# pylint: disable=C0415
import configparser
import datetime
import json
import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
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
_OTHER_KEY = ec.generate_private_key(ec.SECP256R1())
_NEW_ROOT_KEY = ec.generate_private_key(ec.SECP256R1())
_ROOT_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "old-root")])
_OTHER_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other-root")])
_NEW_ROOT_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "new-root")])
CERT_ROOT = _issue_cert("old-root", _ROOT_KEY, _ROOT_NAME, _ROOT_KEY, True)
CERT_ICA = _issue_cert("intermediate", _ICA_KEY, CERT_ROOT.subject, _ROOT_KEY, True)
CERT_LEAF = _issue_cert("leaf", _LEAF_KEY, CERT_ICA.subject, _ICA_KEY, False)
CERT_OTHER = _issue_cert("other-root", _OTHER_KEY, _OTHER_NAME, _OTHER_KEY, True)
CERT_NEW_ROOT = _issue_cert(
    "new-root", _NEW_ROOT_KEY, _NEW_ROOT_NAME, _NEW_ROOT_KEY, True
)
CERT_ICA2 = _issue_cert(
    "intermediate", _ICA_KEY, CERT_NEW_ROOT.subject, _NEW_ROOT_KEY, True
)
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
            "acme2certifier.acme_srv.helpers.certificates.cert_load"
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
        """skipping a non-suffix cert leaves an unlinked chain and fails closed"""
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, bundle = self.skip(self.logger, BUNDLE, [_fingerprint(CERT_ICA)])
        self.assertTrue(
            error.startswith(
                "Configuration error: "
                "certificate does not certify the previous one"
            )
        )
        self.assertIn("previous issuer", error)
        self.assertIsNone(bundle)
        self.assertTrue(
            any("does not certify the previous one" in line for line in lcm.output)
        )

    def test_006b_drop_intermediate_allowed_when_link_check_false(self):
        """cert_chain_link_check False keeps an unlinked remaining chain and warns"""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            error, bundle = self.skip(
                self.logger,
                BUNDLE,
                [_fingerprint(CERT_ICA)],
                link_check=False,
            )
        self.assertIsNone(error)
        self.assertEqual(_pem(CERT_LEAF, CERT_ROOT), bundle)
        self.assertTrue(
            any("cert_chain_link_check is False" in line for line in lcm.output)
        )

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

    def test_010_unparseable_leaf_fails(self):
        """PEM-shaped but invalid leaf fails closed during fingerprinting"""
        bad = (
            "-----BEGIN CERTIFICATE-----\n"
            "not-a-certificate\n"
            "-----END CERTIFICATE-----\n"
        )
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, bundle = self.skip(self.logger, bad, ["aa" * 32])
        self.assertEqual(
            "Configuration error: Failed to parse certificate chain", error
        )
        self.assertIsNone(bundle)
        self.assertTrue(
            any("Failed to parse certificate in chain" in line for line in lcm.output)
        )

    def test_011_unparseable_issuer_fails(self):
        """invalid issuer PEM after a valid leaf fails closed"""
        bad_ica = (
            "-----BEGIN CERTIFICATE-----\n"
            "not-a-certificate\n"
            "-----END CERTIFICATE-----\n"
        )
        error, bundle = self.skip(
            self.logger, _pem(CERT_LEAF) + bad_ica, ["aa" * 32]
        )
        self.assertEqual(
            "Configuration error: Failed to parse certificate chain", error
        )
        self.assertIsNone(bundle)

    def test_012_kept_chain_reparse_error(self):
        """parse error while checking remaining links after skip fails closed"""
        from acme2certifier.acme_srv.helpers import certificates as cert_mod

        real_load = cert_mod.cert_load
        calls = {"n": 0}

        def _load(logger, pem_cert, recode=False):
            calls["n"] += 1
            if calls["n"] > 3:
                raise ValueError("reparse failed")
            return real_load(logger, pem_cert, recode=recode)

        with patch(
            "acme2certifier.acme_srv.helpers.certificates.cert_load",
            side_effect=_load,
        ):
            error, bundle = self.skip(
                self.logger, BUNDLE, [_fingerprint(CERT_ROOT)]
            )
        self.assertEqual(
            "Configuration error: Failed to parse certificate chain", error
        )
        self.assertIsNone(bundle)


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


def _write_pem(directory: str, name: str, *certs: x509.Certificate) -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(_pem(*certs))
    return path


class TestCertChainAppendLoad(unittest.TestCase):
    """config_cert_chain_append_load()"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.config import (
            config_cert_chain_append_load,
        )

        self.load = config_cert_chain_append_load
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_001_unset(self):
        """missing key returns an empty list"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"ca_name": "ca"}
        self.assertEqual((None, []), self.load(self.logger, parser))

    def test_002_valid_file(self):
        """PEM file is loaded into a list of certificates"""
        path = _write_pem(self.tmpdir.name, "root.pem", CERT_ROOT)
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": json.dumps([path])}
        error, pem_list = self.load(self.logger, parser)
        self.assertIsNone(error)
        self.assertEqual([_pem(CERT_ROOT)], pem_list)

    def test_003_bundle_file(self):
        """a file with several certificates is split in order"""
        path = _write_pem(self.tmpdir.name, "chain.pem", CERT_ICA2, CERT_NEW_ROOT)
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": json.dumps([path])}
        error, pem_list = self.load(self.logger, parser)
        self.assertIsNone(error)
        self.assertEqual([_pem(CERT_ICA2), _pem(CERT_NEW_ROOT)], pem_list)

    def test_004_missing_file(self):
        """missing file is a configuration error"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": json.dumps(["/no/such/cert.pem"])}
        error, pem_list = self.load(self.logger, parser)
        self.assertTrue(error.startswith("Configuration error:"))
        self.assertIsNone(pem_list)

    def test_005_empty_file(self):
        """file without certificates is a configuration error"""
        path = os.path.join(self.tmpdir.name, "empty.pem")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("not a certificate\n")
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": json.dumps([path])}
        error, pem_list = self.load(self.logger, parser)
        self.assertTrue(error.startswith("Configuration error:"))
        self.assertIsNone(pem_list)

    def test_006_invalid_json(self):
        """invalid JSON is a configuration error"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": "not-json"}
        error, pem_list = self.load(self.logger, parser)
        self.assertTrue(error.startswith("Configuration error:"))
        self.assertIsNone(pem_list)

    def test_007_relative_path_with_base_dir(self):
        """relative paths are resolved against ACME2CERTIFIER_BASE_DIR"""
        _write_pem(self.tmpdir.name, "root.pem", CERT_ROOT)
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": json.dumps(["root.pem"])}
        with patch.dict(os.environ, {"ACME2CERTIFIER_BASE_DIR": self.tmpdir.name}):
            error, pem_list = self.load(self.logger, parser)
        self.assertIsNone(error)
        self.assertEqual([_pem(CERT_ROOT)], pem_list)

    def test_008_unparseable_pem_in_file(self):
        """file with a PEM header that does not parse fails closed"""
        path = os.path.join(self.tmpdir.name, "bad.pem")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----\n"
            )
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": json.dumps([path])}
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, pem_list = self.load(self.logger, parser)
        self.assertTrue(
            error.startswith("Configuration error: Failed to parse cert_chain_append file")
        )
        self.assertIsNone(pem_list)
        self.assertTrue(
            any("Failed to parse certificate in cert_chain_append file" in line for line in lcm.output)
        )

    def test_009_empty_path_entry(self):
        """blank cert_chain_append path is a configuration error"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": json.dumps(["  "])}
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, pem_list = self.load(self.logger, parser)
        self.assertEqual(
            "Configuration error: cert_chain_append entries must be non-empty paths",
            error,
        )
        self.assertIsNone(pem_list)
        self.assertTrue(
            any("must be non-empty paths" in line for line in lcm.output)
        )


class TestCertChainAppend(unittest.TestCase):
    """cert_chain_append()"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.certificates import cert_chain_append

        self.append = cert_chain_append

    def test_001_empty_append_passthrough(self):
        """empty append list does not parse the bundle"""
        with patch(
            "acme2certifier.acme_srv.helpers.certificates.cert_load"
        ) as mock_load:
            error, bundle = self.append(self.logger, "bundle", [])
        self.assertIsNone(error)
        self.assertEqual("bundle", bundle)
        mock_load.assert_not_called()

    def test_002_append_root_after_ica(self):
        """root that certifies the last chain cert is appended"""
        error, bundle = self.append(
            self.logger, _pem(CERT_LEAF, CERT_ICA), [_pem(CERT_ROOT)]
        )
        self.assertIsNone(error)
        self.assertEqual(_pem(CERT_LEAF, CERT_ICA, CERT_ROOT), bundle)

    def test_003_append_unrelated_fails(self):
        """appended cert that does not certify the previous one fails closed"""
        error, bundle = self.append(
            self.logger, _pem(CERT_LEAF, CERT_ICA), [_pem(CERT_OTHER)]
        )
        self.assertTrue(
            error.startswith(
                "Configuration error: "
                "certificate does not certify the previous one"
            )
        )
        self.assertIn("previous issuer", error)
        self.assertIsNone(bundle)

    def test_003b_append_unrelated_allowed_when_link_check_false(self):
        """cert_chain_link_check False appends an unlinked CA and warns"""
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            error, bundle = self.append(
                self.logger,
                _pem(CERT_LEAF, CERT_ICA),
                [_pem(CERT_OTHER)],
                link_check=False,
            )
        self.assertIsNone(error)
        self.assertEqual(_pem(CERT_LEAF, CERT_ICA, CERT_OTHER), bundle)
        self.assertTrue(
            any("cert_chain_link_check is False" in line for line in lcm.output)
        )

    def test_004_append_leaf_fails(self):
        """appending the end-entity certificate is a configuration error"""
        error, bundle = self.append(self.logger, BUNDLE, [_pem(CERT_LEAF)])
        self.assertEqual(
            "Configuration error: cert_chain_append includes the end-entity certificate",
            error,
        )
        self.assertIsNone(bundle)

    def test_005_append_duplicate_fails(self):
        """appending a cert already in the remaining chain fails closed"""
        error, bundle = self.append(
            self.logger, _pem(CERT_LEAF, CERT_ICA, CERT_ROOT), [_pem(CERT_ROOT)]
        )
        self.assertEqual(
            "Configuration error: "
            "cert_chain_append includes a certificate already in the chain",
            error,
        )
        self.assertIsNone(bundle)

    def test_006_skip_then_append_replacement(self):
        """skip old ICA/root then append a re-issued ICA and new root"""
        from acme2certifier.acme_srv.helpers.cahandler_registry import BoundCAHandler

        bound = BoundCAHandler(
            object,
            "CAhandler",
            "default",
            cert_chain_skip_list=[_fingerprint(CERT_ICA), _fingerprint(CERT_ROOT)],
            cert_chain_append=[_pem(CERT_ICA2), _pem(CERT_NEW_ROOT)],
        )
        error, bundle = bound.cert_chain_rewrite(self.logger, BUNDLE)
        self.assertIsNone(error)
        self.assertEqual(_pem(CERT_LEAF, CERT_ICA2, CERT_NEW_ROOT), bundle)

    def test_007_empty_bundle_passthrough(self):
        """empty bundle is returned unchanged"""
        self.assertEqual((None, None), self.append(self.logger, None, [_pem(CERT_ROOT)]))
        self.assertEqual((None, ""), self.append(self.logger, "", [_pem(CERT_ROOT)]))

    def test_008_unparseable_bundle_fails(self):
        """append against a non-PEM bundle fails closed"""
        error, bundle = self.append(self.logger, "not-pem", [_pem(CERT_ROOT)])
        self.assertEqual(
            "Configuration error: Failed to parse certificate chain", error
        )
        self.assertIsNone(bundle)

    def test_008b_unparseable_pem_bundle_fails(self):
        """PEM-shaped but invalid existing bundle fails closed"""
        bad = (
            "-----BEGIN CERTIFICATE-----\n"
            "not-a-certificate\n"
            "-----END CERTIFICATE-----\n"
        )
        error, bundle = self.append(self.logger, bad, [_pem(CERT_ROOT)])
        self.assertEqual(
            "Configuration error: Failed to parse certificate chain", error
        )
        self.assertIsNone(bundle)

    def test_009_unparseable_append_pem_fails(self):
        """invalid PEM in the append list fails closed"""
        bad = (
            "-----BEGIN CERTIFICATE-----\n"
            "not-a-certificate\n"
            "-----END CERTIFICATE-----\n"
        )
        error, bundle = self.append(
            self.logger, _pem(CERT_LEAF, CERT_ICA), [bad]
        )
        self.assertEqual(
            "Configuration error: Failed to parse certificate chain", error
        )
        self.assertIsNone(bundle)

    def test_010_issuer_name_match_signature_fail(self):
        """same issuer name but wrong key is a broken link"""
        fake_ica = _issue_cert(
            "intermediate", _OTHER_KEY, CERT_ICA.subject, _OTHER_KEY, True
        )
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, bundle = self.append(
                self.logger, _pem(CERT_LEAF), [_pem(fake_ica)]
            )
        self.assertTrue(
            "issuer name matches but signature verification failed" in error
        )
        self.assertIsNone(bundle)
        self.assertTrue(
            any("issuer name matches but signature verification failed" in line for line in lcm.output)
        )

    def test_011_rewrite_skip_unlinked_intermediate(self):
        """BoundCAHandler rewrite fails when skip leaves an unlinked chain"""
        from acme2certifier.acme_srv.helpers.cahandler_registry import BoundCAHandler

        bound = BoundCAHandler(
            object,
            "CAhandler",
            "default",
            cert_chain_skip_list=[_fingerprint(CERT_ICA)],
        )
        error, bundle = bound.cert_chain_rewrite(self.logger, BUNDLE)
        self.assertTrue(
            error.startswith(
                "Configuration error: certificate does not certify the previous one"
            )
        )
        self.assertIsNone(bundle)


class TestBoundCAHandlerAppend(unittest.TestCase):
    """BoundCAHandler.from_config() loads cert_chain_append from its section"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.cahandler_registry import BoundCAHandler

        self.BoundCAHandler = BoundCAHandler
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_001_classical_section(self):
        """[CAhandler] append PEMs are loaded onto the bound factory"""
        path = _write_pem(self.tmpdir.name, "root.pem", CERT_ROOT)
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": json.dumps([path])}
        bound = self.BoundCAHandler.from_config(
            self.logger, object, "CAhandler", "default", parser
        )
        self.assertIsNone(bound.cert_chain_append_error)
        self.assertEqual([_pem(CERT_ROOT)], bound.cert_chain_append)

    def test_002_named_section(self):
        """named handler section is loaded without inheriting [CAhandler]"""
        root_path = _write_pem(self.tmpdir.name, "root.pem", CERT_ROOT)
        ica_path = _write_pem(self.tmpdir.name, "ica.pem", CERT_ICA2)
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_append": json.dumps([root_path])}
        parser["CAhandler:ejbca"] = {"cert_chain_append": json.dumps([ica_path])}
        bound = self.BoundCAHandler.from_config(
            self.logger, object, "CAhandler:ejbca", "ejbca", parser
        )
        self.assertIsNone(bound.cert_chain_append_error)
        self.assertEqual([_pem(CERT_ICA2)], bound.cert_chain_append)

    def test_003_link_check_default_true(self):
        """unset cert_chain_link_check stays fail-closed"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {}
        bound = self.BoundCAHandler.from_config(
            self.logger, object, "CAhandler", "default", parser
        )
        self.assertTrue(bound.cert_chain_link_check)
        self.assertIsNone(bound.cert_chain_link_check_error)

    def test_004_link_check_false(self):
        """named section can disable RFC link checking"""
        parser = configparser.ConfigParser()
        parser["CAhandler:openssl"] = {"cert_chain_link_check": "False"}
        bound = self.BoundCAHandler.from_config(
            self.logger, object, "CAhandler:openssl", "openssl", parser
        )
        self.assertFalse(bound.cert_chain_link_check)
        self.assertIsNone(bound.cert_chain_link_check_error)


class TestCertChainProfileLoad(unittest.TestCase):
    """config_cert_chain_profile_load()"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.config import (
            config_cert_chain_profile_load,
        )

        self.load = config_cert_chain_profile_load

    def test_001_skip_list(self):
        """kid-profile skip-list fingerprints are normalized"""
        error, loaded = self.load(
            self.logger, "cert_chain_skip_list", ["AA:BB", "cc dd"]
        )
        self.assertIsNone(error)
        self.assertEqual(["aabb", "ccdd"], loaded)

    def test_002_unknown_key(self):
        """unknown keys are ignored"""
        error, loaded = self.load(self.logger, "profile_id", ["aa"])
        self.assertIsNone(error)
        self.assertIsNone(loaded)

    def test_003_invalid_json(self):
        """invalid skip-list JSON fails closed"""
        error, loaded = self.load(self.logger, "cert_chain_skip_list", "nope")
        self.assertEqual(
            "Configuration error: Failed to parse cert_chain_skip_list", error
        )
        self.assertIsNone(loaded)

    def test_004_link_check_false(self):
        """kid-profile cert_chain_link_check False is parsed"""
        error, loaded = self.load(self.logger, "cert_chain_link_check", False)
        self.assertIsNone(error)
        self.assertFalse(loaded)

    def test_005_link_check_invalid(self):
        """invalid cert_chain_link_check fails closed"""
        error, loaded = self.load(self.logger, "cert_chain_link_check", "maybe")
        self.assertEqual(
            "Configuration error: cert_chain_link_check must be a boolean", error
        )
        self.assertTrue(loaded)

    def test_006_link_check_true_string(self):
        """kid-profile string true values are accepted"""
        error, loaded = self.load(self.logger, "cert_chain_link_check", "yes")
        self.assertIsNone(error)
        self.assertTrue(loaded)

    def test_007_link_check_false_string(self):
        """kid-profile string false values are accepted"""
        error, loaded = self.load(self.logger, "cert_chain_link_check", "off")
        self.assertIsNone(error)
        self.assertFalse(loaded)


class TestCertChainLinkCheckLoad(unittest.TestCase):
    """config_cert_chain_link_check_load()"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.config import (
            config_cert_chain_link_check_load,
        )

        self.load = config_cert_chain_link_check_load

    def test_001_getboolean_exception(self):
        """invalid ConfigParser boolean fails closed"""
        parser = configparser.ConfigParser()
        parser["CAhandler"] = {"cert_chain_link_check": "maybe"}
        with self.assertLogs("test_a2c", level="ERROR") as lcm:
            error, value = self.load(self.logger, parser)
        self.assertEqual(
            "Configuration error: Failed to parse cert_chain_link_check", error
        )
        self.assertTrue(value)
        self.assertTrue(
            any("Failed to parse cert_chain_link_check" in line for line in lcm.output)
        )


class TestBoundCAHandlerEabOverlay(unittest.TestCase):
    """BoundCAHandler.eab_chain_overlay()"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.cahandler_registry import BoundCAHandler

        self.BoundCAHandler = BoundCAHandler
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_001_skip_replaces_without_mutating(self):
        """kid skip-list replaces bound values on a copy"""
        bound = self.BoundCAHandler(
            object,
            "CAhandler",
            "default",
            cert_chain_skip_list=["cfg"],
        )
        error, overlaid = bound.eab_chain_overlay(
            self.logger, {"cert_chain_skip_list": ["EAB"]}
        )
        self.assertIsNone(error)
        self.assertIsNot(overlaid, bound)
        self.assertEqual(["cfg"], bound.cert_chain_skip_list)
        self.assertEqual(["eab"], overlaid.cert_chain_skip_list)

    def test_002_omitted_keys_keep_bound_factory(self):
        """profile without chain keys does not copy"""
        bound = self.BoundCAHandler(
            object,
            "CAhandler",
            "default",
            cert_chain_skip_list=["cfg"],
        )
        error, overlaid = bound.eab_chain_overlay(self.logger, {"profile_id": "tls"})
        self.assertIsNone(error)
        self.assertIs(overlaid, bound)

    def test_003_empty_skip_clears_bound_list(self):
        """empty kid skip-list clears the bound skip-list"""
        bound = self.BoundCAHandler(
            object,
            "CAhandler",
            "default",
            cert_chain_skip_list=["cfg"],
        )
        error, overlaid = bound.eab_chain_overlay(
            self.logger, {"cert_chain_skip_list": []}
        )
        self.assertIsNone(error)
        self.assertEqual([], overlaid.cert_chain_skip_list)
        self.assertEqual(["cfg"], bound.cert_chain_skip_list)

    def test_004_append_loads_pems(self):
        """kid cert_chain_append paths are read into PEMs"""
        path = _write_pem(self.tmpdir.name, "root.pem", CERT_ROOT)
        bound = self.BoundCAHandler(object, "CAhandler", "default")
        error, overlaid = bound.eab_chain_overlay(
            self.logger, {"cert_chain_append": [path]}
        )
        self.assertIsNone(error)
        self.assertEqual([_pem(CERT_ROOT)], overlaid.cert_chain_append)
        self.assertEqual([], bound.cert_chain_append)

    def test_005_invalid_skip_fails_closed(self):
        """invalid kid skip-list returns error and keeps the bound factory"""
        bound = self.BoundCAHandler(
            object,
            "CAhandler",
            "default",
            cert_chain_skip_list=["cfg"],
        )
        error, overlaid = bound.eab_chain_overlay(
            self.logger, {"cert_chain_skip_list": "nope"}
        )
        self.assertEqual(
            "Configuration error: Failed to parse cert_chain_skip_list", error
        )
        self.assertIs(overlaid, bound)

    def test_006_overlay_then_rewrite(self):
        """kid skip-list is used for rewrite"""
        bound = self.BoundCAHandler(
            object,
            "CAhandler",
            "default",
            cert_chain_skip_list=[_fingerprint(CERT_ROOT)],
        )
        error, overlaid = bound.eab_chain_overlay(
            self.logger,
            {
                "cert_chain_skip_list": [
                    _fingerprint(CERT_ICA),
                    _fingerprint(CERT_ROOT),
                ]
            },
        )
        self.assertIsNone(error)
        rewrite_error, bundle = overlaid.cert_chain_rewrite(self.logger, BUNDLE)
        self.assertIsNone(rewrite_error)
        self.assertEqual(_pem(CERT_LEAF), bundle)

    def test_007_link_check_false_allows_unlinked_append(self):
        """kid cert_chain_link_check False overlays without mutating the factory"""
        bound = self.BoundCAHandler(
            object,
            "CAhandler",
            "default",
            cert_chain_append=[_pem(CERT_OTHER)],
        )
        error, overlaid = bound.eab_chain_overlay(
            self.logger, {"cert_chain_link_check": False}
        )
        self.assertIsNone(error)
        self.assertIsNot(overlaid, bound)
        self.assertTrue(bound.cert_chain_link_check)
        self.assertFalse(overlaid.cert_chain_link_check)
        with self.assertLogs("test_a2c", level="WARNING") as lcm:
            rewrite_error, bundle = overlaid.cert_chain_rewrite(
                self.logger, _pem(CERT_LEAF, CERT_ICA)
            )
        self.assertIsNone(rewrite_error)
        self.assertEqual(_pem(CERT_LEAF, CERT_ICA, CERT_OTHER), bundle)
        self.assertTrue(
            any("cert_chain_link_check is False" in line for line in lcm.output)
        )

    def test_008_empty_profile_returns_self(self):
        """empty or missing profile dict does not copy the factory"""
        bound = self.BoundCAHandler(
            object,
            "CAhandler",
            "default",
            cert_chain_skip_list=["cfg"],
        )
        error, overlaid = bound.eab_chain_overlay(self.logger, {})
        self.assertIsNone(error)
        self.assertIs(overlaid, bound)
        error, overlaid = bound.eab_chain_overlay(self.logger, None)
        self.assertIsNone(error)
        self.assertIs(overlaid, bound)


class TestCertCertifies(unittest.TestCase):
    """_cert_certifies() key-type branches"""

    def setUp(self):
        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        from acme2certifier.acme_srv.helpers.certificates import _cert_certifies

        self.certifies = _cert_certifies

    def _subject_for(self, issuer, hash_alg=hashes.SHA256()):
        subject = MagicMock()
        subject.issuer = issuer.subject
        subject.signature_hash_algorithm = hash_alg
        subject.signature = b"sig"
        subject.tbs_certificate_bytes = b"tbs"
        return subject

    def test_001_rsa_certifies(self):
        """RSA issuer verifies with PKCS1v15"""
        issuer = MagicMock()
        pub = MagicMock(spec=rsa.RSAPublicKey)
        issuer.public_key.return_value = pub
        self.assertTrue(self.certifies(issuer, self._subject_for(issuer)))
        pub.verify.assert_called_once()

    def test_002_rsa_missing_hash(self):
        """RSA without a signature hash algorithm does not certify"""
        issuer = MagicMock()
        issuer.public_key.return_value = MagicMock(spec=rsa.RSAPublicKey)
        self.assertFalse(self.certifies(issuer, self._subject_for(issuer, None)))

    def test_003_ec_missing_hash(self):
        """EC without a signature hash algorithm does not certify"""
        issuer = MagicMock()
        issuer.public_key.return_value = MagicMock(spec=ec.EllipticCurvePublicKey)
        self.assertFalse(self.certifies(issuer, self._subject_for(issuer, None)))

    def test_004_dsa_certifies(self):
        """DSA issuer verifies with the signature hash"""
        issuer = MagicMock()
        pub = MagicMock(spec=dsa.DSAPublicKey)
        issuer.public_key.return_value = pub
        self.assertTrue(self.certifies(issuer, self._subject_for(issuer)))
        pub.verify.assert_called_once()

    def test_005_dsa_missing_hash(self):
        """DSA without a signature hash algorithm does not certify"""
        issuer = MagicMock()
        issuer.public_key.return_value = MagicMock(spec=dsa.DSAPublicKey)
        self.assertFalse(self.certifies(issuer, self._subject_for(issuer, None)))

    def test_006_ed25519_certifies(self):
        """Ed25519 issuer verifies without a hash algorithm"""
        issuer = MagicMock()
        pub = MagicMock(spec=ed25519.Ed25519PublicKey)
        issuer.public_key.return_value = pub
        self.assertTrue(self.certifies(issuer, self._subject_for(issuer, None)))
        pub.verify.assert_called_once()

    def test_007_verify_exception(self):
        """signature verification errors mean the link is broken"""
        issuer = MagicMock()
        pub = MagicMock(spec=rsa.RSAPublicKey)
        pub.verify.side_effect = ValueError("bad sig")
        issuer.public_key.return_value = pub
        self.assertFalse(self.certifies(issuer, self._subject_for(issuer)))

    def test_008_unknown_key_type(self):
        """unsupported public key types do not certify"""
        issuer = MagicMock()
        issuer.public_key.return_value = object()
        self.assertFalse(self.certifies(issuer, self._subject_for(issuer)))


if __name__ == "__main__":
    unittest.main()
