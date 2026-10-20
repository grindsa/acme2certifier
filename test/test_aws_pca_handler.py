# -*- coding: utf-8 -*-
"""unittests for aws_pca_ca_handler"""

# pylint: disable=C0415, R0904, W0212
import base64
import sys
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, ".")
sys.path.insert(1, "..")

try:
    import boto3
    from moto import mock_aws
except ImportError:  # pragma: no cover
    boto3 = None
    mock_aws = None


def _skip_without_moto(func):
    if boto3 is None or mock_aws is None:
        return unittest.skip("boto3/moto not installed")(func)
    return func


def _make_csr_b64url(cn: str = "host.example.internal") -> str:
    """return urlsafe b64 of DER CSR (ACME style, no padding)"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    der = csr.public_bytes(serialization.Encoding.DER)
    return base64.urlsafe_b64encode(der).decode("ascii").rstrip("=")


@_skip_without_moto
class TestAWSPCAHandler(unittest.TestCase):
    """tests against moto-backed ACM PCA"""

    def setUp(self):
        import logging
        from acme2certifier.cahandlers.aws_pca_ca_handler import CAhandler

        logging.basicConfig(level=logging.CRITICAL)
        self.logger = logging.getLogger("test_a2c")
        self.cahandler = CAhandler(False, self.logger)
        self.region = "eu-central-1"

    def _activate_root_ca(self) -> str:
        """create + activate a ROOT CA in moto; return ARN"""
        client = boto3.client("acm-pca", region_name=self.region)
        create = client.create_certificate_authority(
            CertificateAuthorityConfiguration={
                "KeyAlgorithm": "RSA_2048",
                "SigningAlgorithm": "SHA256WITHRSA",
                "Subject": {
                    "Country": "DE",
                    "Organization": "a2c-test",
                    "CommonName": "a2c-test-root",
                },
            },
            CertificateAuthorityType="ROOT",
        )
        ca_arn = create["CertificateAuthorityArn"]
        csr = client.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn)[
            "Csr"
        ]
        issued = client.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr.encode("utf-8") if isinstance(csr, str) else csr,
            SigningAlgorithm="SHA256WITHRSA",
            TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
            Validity={"Value": 10, "Type": "YEARS"},
        )
        cert_arn = issued["CertificateArn"]
        # moto may return immediately
        get_cert = client.get_certificate(
            CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn
        )
        import_kwargs = {
            "CertificateAuthorityArn": ca_arn,
            "Certificate": get_cert["Certificate"],
        }
        if get_cert.get("CertificateChain"):
            import_kwargs["CertificateChain"] = get_cert["CertificateChain"]
        client.import_certificate_authority_certificate(**import_kwargs)
        status = client.describe_certificate_authority(CertificateAuthorityArn=ca_arn)[
            "CertificateAuthority"
        ]["Status"]
        self.assertEqual(status, "ACTIVE")
        return ca_arn

    def test_001_trigger_not_implemented(self):
        error, cert_bundle, cert_raw = self.cahandler.trigger("payload")
        self.assertEqual(error, "Method not implemented.")
        self.assertIsNone(cert_bundle)
        self.assertIsNone(cert_raw)

    def test_002_config_check_missing_params(self):
        err = self.cahandler._config_check()
        self.assertIn("aws_region", err)

    def test_003_config_check_ok(self):
        self.cahandler.aws_region = self.region
        self.cahandler.certificate_authority_arn = (
            "arn:aws:acm-pca:eu-central-1:1:certificate-authority/x"
        )
        self.assertIsNone(self.cahandler._config_check())

    def test_004_revocation_reason_mapping(self):
        self.assertEqual(
            self.cahandler._revocation_reason("keyCompromise"), "KEY_COMPROMISE"
        )
        self.assertEqual(
            self.cahandler._revocation_reason("unspecified"), "UNSPECIFIED"
        )

    @mock_aws
    def test_005_enroll_and_revoke(self):
        ca_arn = self._activate_root_ca()
        self.cahandler.aws_region = self.region
        self.cahandler.certificate_authority_arn = ca_arn
        self.cahandler.poll_timeout = 10
        self.cahandler.poll_interval = 0.1

        csr = _make_csr_b64url("svc.example.internal")
        error, bundle, cert_raw, poll_id = self.cahandler.enroll(csr)
        self.assertIsNone(error, msg=error)
        self.assertIsNotNone(bundle)
        self.assertIn("BEGIN CERTIFICATE", bundle)
        self.assertIsNotNone(cert_raw)
        self.assertTrue(poll_id.startswith("arn:aws:acm-pca:"))

        code, message, detail = self.cahandler.revoke(cert_raw, "keyCompromise")
        self.assertEqual(code, 200, msg=detail)
        self.assertIsNone(message)

    @mock_aws
    def test_006_handler_check(self):
        ca_arn = self._activate_root_ca()
        self.cahandler.aws_region = self.region
        self.cahandler.certificate_authority_arn = ca_arn
        self.assertIsNone(self.cahandler.handler_check())

    @mock_aws
    def test_007_endpoint_url_placeholder_keys(self):
        """LocalStack-style endpoint_url uses placeholder credentials"""
        ca_arn = self._activate_root_ca()
        self.cahandler.aws_region = self.region
        self.cahandler.certificate_authority_arn = ca_arn
        # moto does not use endpoint_url; still verify client construction path
        self.cahandler.endpoint_url = None
        client = self.cahandler._client_get()
        self.assertIsNotNone(client)

    @patch("acme2certifier.cahandlers.aws_pca_ca_handler.boto3", None)
    def test_008_missing_boto3(self):
        self.cahandler.aws_region = self.region
        self.cahandler.certificate_authority_arn = (
            "arn:aws:acm-pca:eu-central-1:1:certificate-authority/x"
        )
        err = self.cahandler._config_check()
        self.assertIn("boto3", err)


if __name__ == "__main__":
    unittest.main()
