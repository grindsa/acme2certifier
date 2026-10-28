# -*- coding: utf-8 -*-
"""Mini-PKI helpers for the Google Private CAS REST mock (cryptography only)."""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass
class CaMaterial:
    """Issuing hierarchy used by the mock."""

    root_key: rsa.RSAPrivateKey
    root_cert: x509.Certificate
    issuing_key: rsa.RSAPrivateKey
    issuing_cert: x509.Certificate
    issuing_ca_id: str = "mock-issuing-ca"

    @property
    def root_pem(self) -> str:
        return _cert_pem(self.root_cert)

    @property
    def issuing_pem(self) -> str:
        return _cert_pem(self.issuing_cert)

    @property
    def chain_pems(self) -> list:
        """Issuer-to-root order (RFC 5246 / CAS pemCertificateChain)."""
        return [self.issuing_pem, self.root_pem]

    @property
    def trust_bundle_pem(self) -> str:
        return self.issuing_pem.rstrip() + "\n" + self.root_pem


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _build_ca_cert(
    *,
    subject: x509.Name,
    issuer: x509.Name,
    public_key,
    signing_key: rsa.RSAPrivateKey,
    days: int,
    path_length: Optional[int],
    serial: int,
) -> x509.Certificate:
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )
    return builder.sign(private_key=signing_key, algorithm=hashes.SHA256())


def create_hierarchy(
    *,
    root_cn: str = "Mock Private CAS Root",
    issuing_cn: str = "Mock Private CAS Issuing",
    root_days: int = 3650,
    issuing_days: int = 1825,
    key_size: int = 2048,
    issuing_ca_id: str = "mock-issuing-ca",
) -> CaMaterial:
    """Create a 2-level CA hierarchy (root + pathLen 0 issuing)."""
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    root_name = _name(root_cn)
    root_cert = _build_ca_cert(
        subject=root_name,
        issuer=root_name,
        public_key=root_key.public_key(),
        signing_key=root_key,
        days=root_days,
        path_length=1,
        serial=x509.random_serial_number(),
    )

    issuing_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    issuing_name = _name(issuing_cn)
    issuing_cert = _build_ca_cert(
        subject=issuing_name,
        issuer=root_name,
        public_key=issuing_key.public_key(),
        signing_key=root_key,
        days=issuing_days,
        path_length=0,
        serial=x509.random_serial_number(),
    )
    return CaMaterial(
        root_key=root_key,
        root_cert=root_cert,
        issuing_key=issuing_key,
        issuing_cert=issuing_cert,
        issuing_ca_id=issuing_ca_id,
    )


def write_hierarchy(material: CaMaterial, output_dir: str) -> dict:
    """Write PEM files; return absolute paths."""
    import os

    os.makedirs(output_dir, exist_ok=True)
    paths = {
        "root_key": os.path.join(output_dir, "root-key.pem"),
        "root_cert": os.path.join(output_dir, "root-cert.pem"),
        "issuing_key": os.path.join(output_dir, "issuing-key.pem"),
        "issuing_cert": os.path.join(output_dir, "issuing-cert.pem"),
        "trust_bundle": os.path.join(output_dir, "trust-bundle.pem"),
        "issuing_ca_id": os.path.join(output_dir, "issuing-ca-id.txt"),
    }
    with open(paths["root_key"], "w", encoding="ascii") as handle:
        handle.write(_key_pem(material.root_key))
    with open(paths["root_cert"], "w", encoding="ascii") as handle:
        handle.write(material.root_pem)
    with open(paths["issuing_key"], "w", encoding="ascii") as handle:
        handle.write(_key_pem(material.issuing_key))
    with open(paths["issuing_cert"], "w", encoding="ascii") as handle:
        handle.write(material.issuing_pem)
    with open(paths["trust_bundle"], "w", encoding="ascii") as handle:
        handle.write(material.trust_bundle_pem)
    with open(paths["issuing_ca_id"], "w", encoding="utf-8") as handle:
        handle.write(material.issuing_ca_id + "\n")
    return {key: os.path.abspath(value) for key, value in paths.items()}


def load_hierarchy(ca_dir: str, issuing_ca_id: str = "mock-issuing-ca") -> CaMaterial:
    """Load PEMs previously written by write_hierarchy / bootstrap_ca."""
    import os

    def _load_key(name: str) -> rsa.RSAPrivateKey:
        with open(os.path.join(ca_dir, name), "rb") as handle:
            key = serialization.load_pem_private_key(handle.read(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError(f"{name} is not an RSA private key")
        return key

    def _load_cert(name: str) -> x509.Certificate:
        with open(os.path.join(ca_dir, name), "rb") as handle:
            return x509.load_pem_x509_certificate(handle.read())

    ca_id_path = os.path.join(ca_dir, "issuing-ca-id.txt")
    if os.path.isfile(ca_id_path):
        with open(ca_id_path, encoding="utf-8") as handle:
            issuing_ca_id = handle.read().strip() or issuing_ca_id

    return CaMaterial(
        root_key=_load_key("root-key.pem"),
        root_cert=_load_cert("root-cert.pem"),
        issuing_key=_load_key("issuing-key.pem"),
        issuing_cert=_load_cert("issuing-cert.pem"),
        issuing_ca_id=issuing_ca_id,
    )


def sign_csr(
    material: CaMaterial,
    csr_pem: str,
    *,
    lifetime_seconds: int,
) -> Tuple[str, str, str]:
    """
    Sign a PEM CSR with the issuing CA.

    Returns (leaf_pem, serial_hex, not_after_rfc3339).
    """
    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(seconds=max(lifetime_seconds, 60))
    # Do not exceed issuing CA lifetime
    issuing_until = material.issuing_cert.not_valid_after_utc
    if not_after > issuing_until:
        not_after = issuing_until

    serial = x509.random_serial_number()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(material.issuing_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                material.issuing_key.public_key()
            ),
            critical=False,
        )
    )
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san.value, critical=san.critical)
    except x509.ExtensionNotFound:
        pass

    leaf = builder.sign(private_key=material.issuing_key, algorithm=hashes.SHA256())
    serial_hex = format(leaf.serial_number, "x")
    not_after_s = not_after.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return _cert_pem(leaf), serial_hex, not_after_s
